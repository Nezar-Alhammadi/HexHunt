use super::{
    AgentAction, AgentBudgetRemaining, Evidence, FinalOutput, ReconDecision, ReconSnapshot, RunId,
    StructuredData, Task, ToolResult, CORE_SCHEMA_VERSION,
};
use reqwest::{blocking::Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    error::Error,
    fmt,
    io::Read,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;
use uuid::Uuid;

pub const DEFAULT_OPENROUTER_BASE_URL: &str = "https://openrouter.ai/api/v1";
pub const DEFAULT_OPENROUTER_MODEL: &str = "deepseek/deepseek-v4-flash";
const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;
const DEFAULT_PROVIDER_ATTEMPTS: u32 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelProviderKind {
    OpenRouter,
}

#[derive(Clone)]
pub struct ModelConfig {
    pub provider: ModelProviderKind,
    pub model: String,
    pub base_url: String,
    api_key: String,
    pub temperature: f32,
    pub max_output_tokens: u64,
    pub reasoning_effort: Option<String>,
    pub seed: Option<u64>,
    pub request_timeout_ms: u64,
    pub max_attempts: u32,
    pub app_name: Option<String>,
    pub app_url: Option<String>,
}

impl ModelConfig {
    pub fn from_env() -> Result<Self, ModelConfigError> {
        let api_key = std::env::var("OPENROUTER_API_KEY").map_err(|_| {
            ModelConfigError::new(
                "MODEL_API_KEY_MISSING",
                "OPENROUTER_API_KEY is not configured.",
            )
        })?;
        if api_key.trim().is_empty() {
            return Err(ModelConfigError::new(
                "MODEL_API_KEY_MISSING",
                "OPENROUTER_API_KEY is empty.",
            ));
        }
        let max_output_tokens = env_u64("HEXHUNT_MODEL_MAX_OUTPUT_TOKENS", 8192)?;
        let request_timeout_ms = env_u64("HEXHUNT_MODEL_TIMEOUT_MS", 60_000)?;
        let max_attempts = env_u64(
            "HEXHUNT_MODEL_MAX_ATTEMPTS",
            u64::from(DEFAULT_PROVIDER_ATTEMPTS),
        )?
        .clamp(1, 5) as u32;

        Ok(Self {
            provider: ModelProviderKind::OpenRouter,
            model: std::env::var("HEXHUNT_MODEL")
                .unwrap_or_else(|_| DEFAULT_OPENROUTER_MODEL.into()),
            base_url: std::env::var("OPENROUTER_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_OPENROUTER_BASE_URL.into()),
            api_key,
            temperature: 0.1,
            max_output_tokens,
            reasoning_effort: std::env::var("HEXHUNT_REASONING_EFFORT")
                .ok()
                .or_else(|| Some("max".to_string())),
            seed: std::env::var("HEXHUNT_MODEL_SEED")
                .ok()
                .and_then(|value| value.parse().ok()),
            request_timeout_ms,
            max_attempts,
            app_name: std::env::var("HEXHUNT_OPENROUTER_APP_NAME").ok(),
            app_url: std::env::var("HEXHUNT_OPENROUTER_APP_URL").ok(),
        })
    }

    fn api_key(&self) -> &str {
        &self.api_key
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfigError {
    pub code: String,
    pub message: String,
}

impl ModelConfigError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ModelConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for ModelConfigError {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequest {
    pub system_instructions: String,
    pub prompt_id: String,
    pub prompt_version: u32,
    pub prompt_hash: String,
    pub task: Task,
    pub run_id: RunId,
    pub current_step: u64,
    pub tools: Vec<ModelToolDefinition>,
    pub tool_results: Vec<ToolResult>,
    pub evidence: Vec<Evidence>,
    pub remaining_budget: AgentBudgetRemaining,
    pub last_rejection: Option<String>,
    pub recon_snapshot: ReconSnapshot,
    pub recon_plan: Option<ReconDecision>,
    pub recon_memory: super::ReconMemory,
    pub recon_critique: super::ReconCritique,
    pub browser_identities: Vec<super::BrowserIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallFailure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallRecord {
    pub schema_version: u32,
    pub id: String,
    pub run_id: RunId,
    pub provider: ModelProviderKind,
    pub model: String,
    #[serde(default)]
    pub api_response_model: Option<String>,
    #[serde(default)]
    pub actual_provider: Option<String>,
    #[serde(default)]
    pub quantization: Option<String>,
    #[serde(default)]
    pub reasoning_effort: Option<String>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub max_output_tokens: u64,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default)]
    pub prompt_id: String,
    #[serde(default)]
    pub prompt_version: u32,
    #[serde(default)]
    pub prompt_hash: String,
    pub started_at_ms: u64,
    pub success: bool,
    pub request_count: u64,
    pub attempt_number: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_tokens: u64,
    #[serde(default)]
    pub usage_reported: bool,
    pub duration_ms: u64,
    pub error: Option<ModelCallFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelProviderErrorCode {
    AuthenticationFailed,
    RateLimited,
    ProviderUnavailable,
    ProviderRejected,
    ProviderTimeout,
    ProviderConnectionFailed,
    EmptyResponse,
    InvalidResponse,
    AttemptsExhausted,
    InvalidConfiguration,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProviderError {
    pub code: ModelProviderErrorCode,
    pub message: String,
    pub retryable: bool,
    pub call: ModelCallRecord,
}

impl fmt::Display for ModelProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for ModelProviderError {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelGeneration {
    pub action: AgentAction,
    pub call: ModelCallRecord,
}

pub trait ModelProvider: Send + Sync {
    fn generate_next_action(
        &self,
        request: &ModelRequest,
    ) -> Result<ModelGeneration, ModelProviderError>;
}

pub struct OpenRouterProvider {
    config: ModelConfig,
    client: Client,
}

impl OpenRouterProvider {
    pub fn new(config: ModelConfig) -> Result<Self, ModelConfigError> {
        if config.provider != ModelProviderKind::OpenRouter {
            return Err(ModelConfigError::new(
                "MODEL_PROVIDER_UNSUPPORTED",
                "OpenRouterProvider requires the open_router provider kind.",
            ));
        }
        let parsed = Url::parse(&config.base_url).map_err(|_| {
            ModelConfigError::new("MODEL_BASE_URL_INVALID", "The model base URL is invalid.")
        })?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(ModelConfigError::new(
                "MODEL_BASE_URL_INVALID",
                "The model base URL must be an absolute HTTP or HTTPS URL.",
            ));
        }
        let loopback = parsed
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "::1"));
        if parsed.scheme() != "https" && !loopback {
            return Err(ModelConfigError::new(
                "MODEL_BASE_URL_INSECURE",
                "The model base URL must use HTTPS unless it is loopback-only.",
            ));
        }
        let client = Client::builder().build().map_err(|_| {
            ModelConfigError::new(
                "MODEL_CLIENT_INIT_FAILED",
                "Unable to initialize the model HTTP client.",
            )
        })?;
        Ok(Self { config, client })
    }

    fn call_record(
        &self,
        request: &ModelRequest,
        request_count: u64,
        input_tokens: u64,
        output_tokens: u64,
        reasoning_tokens: u64,
        duration_ms: u64,
        error: Option<ModelCallFailure>,
    ) -> ModelCallRecord {
        ModelCallRecord {
            schema_version: CORE_SCHEMA_VERSION,
            id: Uuid::new_v4().to_string(),
            run_id: request.run_id.clone(),
            provider: self.config.provider,
            model: self.config.model.clone(),
            api_response_model: None,
            actual_provider: None,
            quantization: None,
            reasoning_effort: self.config.reasoning_effort.clone(),
            temperature: Some(self.config.temperature),
            max_output_tokens: self.config.max_output_tokens,
            seed: self.config.seed,
            prompt_id: request.prompt_id.clone(),
            prompt_version: request.prompt_version,
            prompt_hash: request.prompt_hash.clone(),
            started_at_ms: unix_now_ms().saturating_sub(duration_ms),
            success: error.is_none(),
            request_count,
            attempt_number: request_count,
            input_tokens,
            output_tokens,
            reasoning_tokens,
            usage_reported: false,
            duration_ms,
            error,
        }
    }

    fn provider_error(
        &self,
        request: &ModelRequest,
        code: ModelProviderErrorCode,
        message: impl Into<String>,
        retryable: bool,
        request_count: u64,
        started: Instant,
    ) -> ModelProviderError {
        let message = message.into();
        let failure = ModelCallFailure {
            code: format!("{code:?}").to_ascii_uppercase(),
            message: message.clone(),
            retryable,
        };
        ModelProviderError {
            code,
            message,
            retryable,
            call: self.call_record(
                request,
                request_count,
                0,
                0,
                0,
                elapsed_ms(started),
                Some(failure),
            ),
        }
    }
}

impl ModelProvider for OpenRouterProvider {
    fn generate_next_action(
        &self,
        request: &ModelRequest,
    ) -> Result<ModelGeneration, ModelProviderError> {
        let started = Instant::now();
        let allowed_attempts = self.config.max_attempts.min(
            request
                .remaining_budget
                .model_calls
                .min(u64::from(u32::MAX)) as u32,
        );
        if allowed_attempts == 0 {
            return Err(self.provider_error(
                request,
                ModelProviderErrorCode::AttemptsExhausted,
                "No model-call budget remains.",
                false,
                0,
                started,
            ));
        }

        let endpoint = format!(
            "{}/chat/completions",
            self.config.base_url.trim_end_matches('/')
        );
        let body = openrouter_body(&self.config, request);
        let mut request_count = 0_u64;

        loop {
            request_count += 1;
            let mut builder = self
                .client
                .post(&endpoint)
                .bearer_auth(self.config.api_key())
                .timeout(Duration::from_millis(self.config.request_timeout_ms))
                .json(&body);
            if let Some(app_name) = &self.config.app_name {
                builder = builder.header("X-Title", app_name);
            }
            if let Some(app_url) = &self.config.app_url {
                builder = builder.header("HTTP-Referer", app_url);
            }

            let response = match builder.send() {
                Ok(response) => response,
                Err(error) => {
                    let (code, message) = if error.is_timeout() {
                        (
                            ModelProviderErrorCode::ProviderTimeout,
                            "The model request timed out.",
                        )
                    } else {
                        (
                            ModelProviderErrorCode::ProviderConnectionFailed,
                            "The model provider connection failed.",
                        )
                    };
                    if request_count < u64::from(allowed_attempts) {
                        continue;
                    }
                    return Err(self.provider_error(
                        request,
                        code,
                        message,
                        true,
                        request_count,
                        started,
                    ));
                }
            };

            let status = response.status();
            let response_body = match read_limited(response) {
                Ok(body) => body,
                Err(_) => {
                    if request_count < u64::from(allowed_attempts) {
                        continue;
                    }
                    return Err(self.provider_error(
                        request,
                        ModelProviderErrorCode::InvalidResponse,
                        "Unable to read the model provider response.",
                        true,
                        request_count,
                        started,
                    ));
                }
            };

            if !status.is_success() {
                let (code, retryable) = classify_status(status);
                if retryable && request_count < u64::from(allowed_attempts) {
                    continue;
                }
                return Err(self.provider_error(
                    request,
                    code,
                    provider_error_message(status, &response_body),
                    retryable,
                    request_count,
                    started,
                ));
            }

            let response_json: Value = match serde_json::from_slice(&response_body) {
                Ok(value) => value,
                Err(_) if request_count < u64::from(allowed_attempts) => continue,
                Err(_) => {
                    return Err(self.provider_error(
                        request,
                        ModelProviderErrorCode::InvalidResponse,
                        "The model provider returned invalid JSON.",
                        false,
                        request_count,
                        started,
                    ));
                }
            };
            let content = match response_json
                .pointer("/choices/0/message/content")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                Some(content) => content,
                None if request_count < u64::from(allowed_attempts) => continue,
                None => {
                    return Err(self.provider_error(
                        request,
                        ModelProviderErrorCode::EmptyResponse,
                        "The model provider returned no structured action.",
                        false,
                        request_count,
                        started,
                    ));
                }
            };
            let structured: StructuredModelAction = match serde_json::from_str(content) {
                Ok(action) => action,
                Err(_) if request_count < u64::from(allowed_attempts) => continue,
                Err(_) => {
                    return Err(self.provider_error(
                        request,
                        ModelProviderErrorCode::InvalidResponse,
                        "The model action is not valid structured JSON.",
                        false,
                        request_count,
                        started,
                    ));
                }
            };
            let action = match structured.into_agent_action() {
                Ok(action) => action,
                Err(_) if request_count < u64::from(allowed_attempts) => continue,
                Err(message) => {
                    return Err(self.provider_error(
                        request,
                        ModelProviderErrorCode::InvalidResponse,
                        message,
                        false,
                        request_count,
                        started,
                    ));
                }
            };
            let input_tokens = response_json
                .pointer("/usage/prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let output_tokens = response_json
                .pointer("/usage/completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let reasoning_tokens = response_json
                .pointer("/usage/completion_tokens_details/reasoning_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let mut call = self.call_record(
                request,
                request_count,
                input_tokens,
                output_tokens,
                reasoning_tokens,
                elapsed_ms(started),
                None,
            );
            call.usage_reported = response_json
                .pointer("/usage/prompt_tokens")
                .and_then(Value::as_u64)
                .is_some()
                && response_json
                    .pointer("/usage/completion_tokens")
                    .and_then(Value::as_u64)
                    .is_some();
            call.api_response_model = response_json
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_owned);
            call.actual_provider = response_json
                .get("provider")
                .and_then(Value::as_str)
                .map(str::to_owned);
            call.quantization = response_json
                .pointer("/provider_metadata/quantization")
                .and_then(Value::as_str)
                .map(str::to_owned);
            return Ok(ModelGeneration { action, call });
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StructuredModelAction {
    Tool {
        tool_name: String,
        arguments: StructuredData,
        #[serde(default)]
        reason: String,
    },
    Finish {
        final_output: FinalOutput,
        #[serde(default)]
        reason: String,
    },
}

impl StructuredModelAction {
    fn into_agent_action(self) -> Result<AgentAction, String> {
        match self {
            Self::Tool {
                tool_name,
                arguments,
                reason,
            } => {
                if tool_name.trim().is_empty() {
                    return Err("The structured tool action has an empty tool_name.".into());
                }
                Ok(AgentAction {
                    schema_version: CORE_SCHEMA_VERSION,
                    name: tool_name,
                    arguments,
                    reason,
                })
            }
            Self::Finish {
                final_output,
                reason,
            } => Ok(AgentAction {
                schema_version: CORE_SCHEMA_VERSION,
                name: "finish".into(),
                arguments: StructuredData::from([(
                    "final_output".into(),
                    serde_json::to_value(final_output)
                        .map_err(|_| "Unable to encode the model FinalOutput.".to_string())?,
                )]),
                reason,
            }),
        }
    }
}

fn openrouter_body(config: &ModelConfig, request: &ModelRequest) -> Value {
    let max_output_tokens = config
        .max_output_tokens
        .min(request.remaining_budget.output_tokens)
        .max(1);
    let context = json!({
        "task": request.task,
        "run_id": request.run_id,
        "current_step": request.current_step,
        "remaining_budget": request.remaining_budget,
        "available_tools": request.tools,
        "tool_results": request.tool_results,
        "evidence": request.evidence,
        "recon_snapshot": request.recon_snapshot,
        "recon_plan": request.recon_plan,
        "recon_memory": request.recon_memory,
        "recon_critique": request.recon_critique,
        "browser_identities": request.browser_identities,
        "last_rejection": request.last_rejection,
    });
    let mut body = json!({
        "model": config.model,
        "temperature": config.temperature,
        "max_tokens": max_output_tokens,
        "messages": [
            {"role": "system", "content": request.system_instructions},
            {"role": "user", "content": context.to_string()}
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "hexhunt_agent_action",
                "strict": true,
                "schema": structured_action_schema(&request.tools)
            }
        }
    });
    if let Some(effort) = &config.reasoning_effort {
        body["reasoning"] = json!({"effort": effort});
    }
    if let Some(seed) = config.seed {
        body["seed"] = json!(seed);
    }
    body
}

fn structured_action_schema(tools: &[ModelToolDefinition]) -> Value {
    let mut actions = tools
        .iter()
        .map(|tool| {
            json!({
                "properties": {
                    "type": {"const": "tool"},
                    "tool_name": {"const": tool.name},
                    "arguments": tool.input_schema,
                    "reason": {"type": "string"}
                },
                "required": ["type", "tool_name", "arguments", "reason"],
                "additionalProperties": false
            })
        })
        .collect::<Vec<_>>();
    actions.push(json!({
                "properties": {
                    "type": {"const": "finish"},
                    "final_output": {
                        "type": "object",
                        "properties": {
                            "schema_version": {"type": "integer"},
                            "status": {"enum": ["completed", "inconclusive", "budget_exhausted", "error"]},
                            "answer": {"type": "string"},
                            "evidence_ids": {"type": "array", "items": {"type": "string"}},
                            "limitations": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["schema_version", "status", "answer", "evidence_ids", "limitations"],
                        "additionalProperties": false
                    },
                    "reason": {"type": "string"}
                },
                "required": ["type", "final_output", "reason"],
                "additionalProperties": false
            }));
    json!({
        "type": "object",
        "oneOf": actions
    })
}

fn read_limited(response: reqwest::blocking::Response) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::with_capacity(MAX_PROVIDER_RESPONSE_BYTES.min(16 * 1024));
    response
        .take((MAX_PROVIDER_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROVIDER_RESPONSE_BYTES {
        bytes.truncate(MAX_PROVIDER_RESPONSE_BYTES);
    }
    Ok(bytes)
}

fn classify_status(status: StatusCode) -> (ModelProviderErrorCode, bool) {
    match status.as_u16() {
        401 | 403 => (ModelProviderErrorCode::AuthenticationFailed, false),
        429 => (ModelProviderErrorCode::RateLimited, true),
        500..=599 => (ModelProviderErrorCode::ProviderUnavailable, true),
        _ => (ModelProviderErrorCode::ProviderRejected, false),
    }
}

fn provider_error_message(status: StatusCode, body: &[u8]) -> String {
    let detail = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "The provider rejected the request.".into());
    format!("OpenRouter returned HTTP {}: {}", status.as_u16(), detail)
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_action_schema_enforces_each_tools_arguments() {
        let schema = structured_action_schema(&[ModelToolDefinition {
            name: "probe_http".into(),
            description: "Probe the authorized target.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
                "additionalProperties": false
            }),
        }]);

        assert_eq!(
            schema.pointer("/oneOf/0/properties/tool_name/const"),
            Some(&Value::String("probe_http".into()))
        );
        assert_eq!(
            schema.pointer("/oneOf/0/properties/arguments/required/0"),
            Some(&Value::String("url".into()))
        );
        assert_eq!(
            schema.pointer("/oneOf/1/properties/type/const"),
            Some(&Value::String("finish".into()))
        );
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn env_u64(name: &str, default: u64) -> Result<u64, ModelConfigError> {
    match std::env::var(name) {
        Ok(value) => value.parse::<u64>().map_err(|_| {
            ModelConfigError::new(
                "MODEL_CONFIG_INVALID",
                format!("{name} must be a positive integer."),
            )
        }),
        Err(_) => Ok(default),
    }
}
