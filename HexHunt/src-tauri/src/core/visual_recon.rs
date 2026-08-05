use super::{
    redact_text, AgentAction, StructuredData, Task, ToolExecutionError, ToolExecutionOutcome,
    ToolResult, ToolResultId, CORE_SCHEMA_VERSION,
};
use crate::scope_guard::{validate, ScopeGuardState, ScopeProject};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use headless_chrome::{
    browser::{default_executable, tab::RequestPausedDecision},
    protocol::cdp::{Fetch, Network, Page},
    Browser, LaunchOptions,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

pub const DEFAULT_VISION_MODEL: &str = "google/gemini-3-flash-preview";
const DEFAULT_VISION_BASE_URL: &str = "https://openrouter.ai/api/v1";
const MAX_SCREENSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_VISION_RESPONSE_BYTES: usize = 256 * 1024;
const VIEWPORT_WIDTH: u32 = 1365;
const VIEWPORT_HEIGHT: u32 = 768;

#[derive(Clone, Debug)]
pub struct PreparedVisualReconCall {
    pub url: String,
    pub scope: ScopeProject,
    pub timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VisualPageKind {
    Landing,
    Authentication,
    Administration,
    Dashboard,
    Application,
    Documentation,
    Error,
    Placeholder,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VisualFormKind {
    Login,
    Registration,
    PasswordReset,
    Search,
    Upload,
    Contact,
    Payment,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VisualElementKind {
    LoginForm,
    AdminPanel,
    DebugOutput,
    StackTrace,
    DirectoryListing,
    ApiDocumentation,
    FileUpload,
    AccessDenied,
    ErrorMessage,
    PlaceholderPage,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VisualConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VisualObservation {
    pub page_kind: VisualPageKind,
    pub summary: String,
    pub authentication_surface: bool,
    pub administration_surface: bool,
    pub form_kinds: Vec<VisualFormKind>,
    pub technology_hints: Vec<String>,
    pub security_relevant_elements: Vec<VisualElementKind>,
    pub confidence: VisualConfidence,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug)]
struct ScreenshotArtifact {
    bytes: Vec<u8>,
    final_url: String,
    blocked_out_of_scope_requests: u64,
}

#[derive(Clone, Debug)]
struct VisualModelResult {
    observation: VisualObservation,
    model: String,
    api_response_model: Option<String>,
    actual_provider: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
    usage_reported: bool,
}

trait ScreenshotCapture: Send + Sync {
    fn capture(
        &self,
        call: &PreparedVisualReconCall,
    ) -> Result<ScreenshotArtifact, ToolExecutionError>;
}

trait VisualAnalyzer: Send + Sync {
    fn analyze(
        &self,
        page_url: &str,
        screenshot_png: &[u8],
    ) -> Result<VisualModelResult, ToolExecutionError>;
}

pub struct VisualReconTool {
    scope_guard: Arc<ScopeGuardState>,
    capture: Arc<dyn ScreenshotCapture>,
    analyzer: Arc<dyn VisualAnalyzer>,
}

impl VisualReconTool {
    pub fn new(scope_guard: Arc<ScopeGuardState>) -> Self {
        Self {
            scope_guard,
            capture: Arc::new(ChromiumScreenshotCapture),
            analyzer: Arc::new(OpenRouterVisualAnalyzer),
        }
    }

    #[cfg(test)]
    fn with_components(
        scope_guard: Arc<ScopeGuardState>,
        capture: Arc<dyn ScreenshotCapture>,
        analyzer: Arc<dyn VisualAnalyzer>,
    ) -> Self {
        Self {
            scope_guard,
            capture,
            analyzer,
        }
    }

    #[cfg(test)]
    pub(crate) fn deterministic(scope_guard: Arc<ScopeGuardState>) -> Self {
        Self::with_components(
            scope_guard,
            Arc::new(DeterministicScreenshotCapture),
            Arc::new(DeterministicVisualAnalyzer),
        )
    }

    pub fn prepare(
        &self,
        action: &AgentAction,
        task: &Task,
    ) -> Result<PreparedVisualReconCall, ToolExecutionError> {
        let url = action
            .arguments
            .get("url")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                visual_error(
                    "INVALID_VISUAL_ARGUMENTS",
                    "analyze_visual_page requires a non-empty url.",
                    false,
                )
            })?;
        let decision = self.scope_guard.authorize_request(&task.scope, url);
        if !decision.allowed {
            return Err(visual_error(
                if decision.code == "rate-limit" {
                    "RATE_LIMITED"
                } else {
                    "SCOPE_BLOCKED"
                },
                decision.reason,
                false,
            ));
        }
        let timeout_ms = action
            .arguments
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(20_000)
            .clamp(1_000, 30_000);
        Ok(PreparedVisualReconCall {
            url: url.to_string(),
            scope: task.scope.clone(),
            timeout_ms,
        })
    }

    pub fn execute(
        &self,
        call: PreparedVisualReconCall,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        let started = Instant::now();
        let screenshot = self.capture.capture(&call)?;
        if screenshot.bytes.is_empty() || screenshot.bytes.len() > MAX_SCREENSHOT_BYTES {
            return Err(visual_error(
                "VISUAL_SCREENSHOT_INVALID",
                "The browser screenshot was empty or exceeded the safe size limit.",
                true,
            ));
        }
        let analysis = self
            .analyzer
            .analyze(&screenshot.final_url, &screenshot.bytes)?;
        let screenshot_sha256 = hex_sha256(&screenshot.bytes);
        let observation = sanitize_observation(analysis.observation);
        let mut data = StructuredData::new();
        data.insert("requested_url".into(), Value::String(call.url));
        data.insert("final_url".into(), Value::String(screenshot.final_url));
        data.insert("screenshot_sha256".into(), Value::String(screenshot_sha256));
        data.insert(
            "screenshot_bytes".into(),
            Value::from(screenshot.bytes.len() as u64),
        );
        data.insert("screenshot_retained".into(), Value::Bool(false));
        data.insert("viewport_width".into(), Value::from(VIEWPORT_WIDTH));
        data.insert("viewport_height".into(), Value::from(VIEWPORT_HEIGHT));
        data.insert(
            "blocked_out_of_scope_requests".into(),
            Value::from(screenshot.blocked_out_of_scope_requests),
        );
        data.insert("visual_model".into(), Value::String(analysis.model));
        data.insert(
            "api_response_model".into(),
            analysis
                .api_response_model
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        data.insert(
            "actual_provider".into(),
            analysis
                .actual_provider
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        data.insert("input_tokens".into(), Value::from(analysis.input_tokens));
        data.insert("output_tokens".into(), Value::from(analysis.output_tokens));
        data.insert(
            "usage_reported".into(),
            Value::Bool(analysis.usage_reported),
        );
        data.insert(
            "visual_observation".into(),
            serde_json::to_value(observation).map_err(|_| {
                visual_error(
                    "VISUAL_RESULT_ENCODING_FAILED",
                    "The structured visual observation could not be encoded.",
                    true,
                )
            })?,
        );

        Ok(ToolExecutionOutcome {
            result: ToolResult {
                schema_version: CORE_SCHEMA_VERSION,
                id: ToolResultId(Uuid::new_v4().to_string()),
                tool_name: "analyze_visual_page".into(),
                success: true,
                data,
                error: None,
                duration_ms: elapsed_ms(started),
            },
            http_requests: 1,
            model_calls: 1,
            input_tokens: analysis.input_tokens,
            output_tokens: analysis.output_tokens,
        })
    }
}

#[cfg(test)]
struct DeterministicScreenshotCapture;

#[cfg(test)]
impl ScreenshotCapture for DeterministicScreenshotCapture {
    fn capture(
        &self,
        call: &PreparedVisualReconCall,
    ) -> Result<ScreenshotArtifact, ToolExecutionError> {
        Ok(ScreenshotArtifact {
            bytes: b"deterministic-visual-png".to_vec(),
            final_url: call.url.clone(),
            blocked_out_of_scope_requests: 1,
        })
    }
}

#[cfg(test)]
struct DeterministicVisualAnalyzer;

#[cfg(test)]
impl VisualAnalyzer for DeterministicVisualAnalyzer {
    fn analyze(
        &self,
        _page_url: &str,
        _screenshot_png: &[u8],
    ) -> Result<VisualModelResult, ToolExecutionError> {
        Ok(VisualModelResult {
            observation: VisualObservation {
                page_kind: VisualPageKind::Authentication,
                summary: "A login form is visible in the authorized page.".into(),
                authentication_surface: true,
                administration_surface: false,
                form_kinds: vec![VisualFormKind::Login],
                technology_hints: vec!["React".into()],
                security_relevant_elements: vec![VisualElementKind::LoginForm],
                confidence: VisualConfidence::High,
                limitations: vec!["Only the visible viewport was analyzed.".into()],
            },
            model: "fake-vision".into(),
            api_response_model: Some("fake-vision".into()),
            actual_provider: Some("local-test".into()),
            input_tokens: 120,
            output_tokens: 40,
            usage_reported: true,
        })
    }
}

struct ChromiumScreenshotCapture;

impl ScreenshotCapture for ChromiumScreenshotCapture {
    fn capture(
        &self,
        call: &PreparedVisualReconCall,
    ) -> Result<ScreenshotArtifact, ToolExecutionError> {
        let executable = chromium_executable().ok_or_else(|| {
            visual_error(
                "VISUAL_BROWSER_NOT_FOUND",
                "Chromium was not found. Install Chromium or set HEXHUNT_CHROMIUM_PATH.",
                false,
            )
        })?;
        let options = LaunchOptions::default_builder()
            .path(Some(executable))
            .headless(true)
            .sandbox(true)
            .window_size(Some((VIEWPORT_WIDTH, VIEWPORT_HEIGHT)))
            .idle_browser_timeout(Duration::from_millis(call.timeout_ms))
            .build()
            .map_err(|_| {
                visual_error(
                    "VISUAL_BROWSER_CONFIGURATION_FAILED",
                    "Chromium launch options could not be created.",
                    false,
                )
            })?;
        let browser = Browser::new(options).map_err(|_| {
            visual_error(
                "VISUAL_BROWSER_START_FAILED",
                "Chromium could not be started for Visual Recon.",
                false,
            )
        })?;
        let tab = browser.new_tab().map_err(|_| {
            visual_error(
                "VISUAL_BROWSER_TAB_FAILED",
                "Chromium could not create a Visual Recon tab.",
                false,
            )
        })?;
        tab.set_default_timeout(Duration::from_millis(call.timeout_ms));
        let blocked = Arc::new(AtomicU64::new(0));
        let blocked_for_interceptor = blocked.clone();
        let scope = call.scope.clone();
        tab.enable_fetch(
            Some(&[Fetch::RequestPattern {
                url_pattern: Some("*".into()),
                resource_Type: None,
                request_stage: None,
            }]),
            Some(false),
        )
        .map_err(|_| {
            visual_error(
                "VISUAL_BROWSER_INTERCEPTION_FAILED",
                "Chromium request interception could not be enabled.",
                false,
            )
        })?;
        tab.enable_request_interception(Arc::new(
            move |_transport, _session_id, event: Fetch::events::RequestPausedEvent| {
                let url = &event.params.request.url;
                if is_non_network_url(url) || validate(&scope, url).allowed {
                    RequestPausedDecision::Continue(None)
                } else {
                    blocked_for_interceptor.fetch_add(1, Ordering::SeqCst);
                    RequestPausedDecision::Fail(Fetch::FailRequest {
                        request_id: event.params.request_id.clone(),
                        error_reason: Network::ErrorReason::BlockedByClient,
                    })
                }
            },
        ))
        .map_err(|_| {
            visual_error(
                "VISUAL_BROWSER_INTERCEPTION_FAILED",
                "Chromium request interception could not be installed.",
                false,
            )
        })?;
        tab.navigate_to(&call.url)
            .and_then(|tab| tab.wait_until_navigated())
            .map_err(|_| {
                visual_error(
                    "VISUAL_NAVIGATION_FAILED",
                    "Chromium could not finish the authorized page navigation.",
                    true,
                )
            })?;
        let final_url = tab.get_url();
        if !validate(&call.scope, &final_url).allowed {
            return Err(visual_error(
                "SCOPE_BLOCKED",
                "Visual Recon stopped because the page redirected outside the authorized scope.",
                true,
            ));
        }
        tab.evaluate(
            r#"(() => {
                for (const field of document.querySelectorAll('input, textarea')) {
                    field.value = '';
                    field.removeAttribute('value');
                    field.removeAttribute('placeholder');
                }
                for (const sensitive of document.querySelectorAll('[data-sensitive], [data-secret]')) {
                    sensitive.textContent = '[redacted]';
                }
            })()"#,
            false,
        )
        .map_err(|_| {
            visual_error(
                "VISUAL_REDACTION_FAILED",
                "The browser could not redact visible form values before capture.",
                true,
            )
        })?;
        let bytes = tab
            .capture_screenshot(Page::CaptureScreenshotFormatOption::Png, None, None, true)
            .map_err(|_| {
                visual_error(
                    "VISUAL_SCREENSHOT_FAILED",
                    "Chromium could not capture the authorized page.",
                    true,
                )
            })?;
        Ok(ScreenshotArtifact {
            bytes,
            final_url,
            blocked_out_of_scope_requests: blocked.load(Ordering::SeqCst),
        })
    }
}

struct OpenRouterVisualAnalyzer;

impl VisualAnalyzer for OpenRouterVisualAnalyzer {
    fn analyze(
        &self,
        page_url: &str,
        screenshot_png: &[u8],
    ) -> Result<VisualModelResult, ToolExecutionError> {
        let api_key = std::env::var("OPENROUTER_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                visual_error(
                    "MODEL_API_KEY_MISSING",
                    "OpenRouter API key is required for Visual Recon.",
                    true,
                )
            })?;
        let model =
            std::env::var("HEXHUNT_VISION_MODEL").unwrap_or_else(|_| DEFAULT_VISION_MODEL.into());
        let base_url =
            std::env::var("OPENROUTER_BASE_URL").unwrap_or_else(|_| DEFAULT_VISION_BASE_URL.into());
        let endpoint = format!("{}/chat/completions", base_url.trim_end_matches('/'));
        let image_url = format!(
            "data:image/png;base64,{}",
            BASE64_STANDARD.encode(screenshot_png)
        );
        let body = json!({
            "model": model,
            "temperature": 0.1,
            "max_tokens": 1200,
            "messages": [
                {
                    "role": "system",
                    "content": "You are HexHunt Visual Recon. Analyze only visible security-relevant page structure. Return the required JSON object. Do not transcribe passwords, tokens, cookies, personal data, or suspected secret values. Do not provide chain-of-thought."
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": format!("Classify the authorized page at {page_url}. Report only concise structured visual observations; never reproduce sensitive values.")
                        },
                        {"type": "image_url", "image_url": {"url": image_url}}
                    ]
                }
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "hexhunt_visual_observation",
                    "strict": true,
                    "schema": visual_observation_schema()
                }
            }
        });
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| {
                visual_error(
                    "VISUAL_MODEL_CONFIGURATION_FAILED",
                    "The Visual Recon model client could not be initialized.",
                    true,
                )
            })?;
        let response = client
            .post(endpoint)
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .map_err(|_| {
                visual_error(
                    "VISUAL_MODEL_REQUEST_FAILED",
                    "The Visual Recon model request failed.",
                    true,
                )
            })?;
        let status = response.status();
        let bytes = read_limited(response).map_err(|_| {
            visual_error(
                "VISUAL_MODEL_RESPONSE_FAILED",
                "The Visual Recon model response could not be read.",
                true,
            )
        })?;
        if !status.is_success() {
            return Err(visual_error(
                "VISUAL_MODEL_REJECTED",
                format!(
                    "OpenRouter rejected the Visual Recon request with HTTP {}.",
                    status.as_u16()
                ),
                true,
            ));
        }
        let response_json: Value = serde_json::from_slice(&bytes).map_err(|_| {
            visual_error(
                "VISUAL_MODEL_RESPONSE_INVALID",
                "OpenRouter returned invalid JSON for Visual Recon.",
                true,
            )
        })?;
        let content = response_json
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                visual_error(
                    "VISUAL_MODEL_RESPONSE_EMPTY",
                    "OpenRouter returned no Visual Recon observation.",
                    true,
                )
            })?;
        let observation: VisualObservation = serde_json::from_str(content).map_err(|_| {
            visual_error(
                "VISUAL_MODEL_OUTPUT_INVALID",
                "The visual model did not return the required structured observation.",
                true,
            )
        })?;
        let input_tokens = response_json
            .pointer("/usage/prompt_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let output_tokens = response_json
            .pointer("/usage/completion_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        Ok(VisualModelResult {
            observation,
            model,
            api_response_model: response_json
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_owned),
            actual_provider: response_json
                .get("provider")
                .and_then(Value::as_str)
                .map(str::to_owned),
            input_tokens,
            output_tokens,
            usage_reported: response_json.pointer("/usage/prompt_tokens").is_some()
                && response_json.pointer("/usage/completion_tokens").is_some(),
        })
    }
}

fn visual_observation_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "page_kind": {"enum": ["landing", "authentication", "administration", "dashboard", "application", "documentation", "error", "placeholder", "unknown"]},
            "summary": {"type": "string"},
            "authentication_surface": {"type": "boolean"},
            "administration_surface": {"type": "boolean"},
            "form_kinds": {"type": "array", "items": {"enum": ["login", "registration", "password_reset", "search", "upload", "contact", "payment", "other"]}},
            "technology_hints": {"type": "array", "items": {"type": "string"}},
            "security_relevant_elements": {"type": "array", "items": {"enum": ["login_form", "admin_panel", "debug_output", "stack_trace", "directory_listing", "api_documentation", "file_upload", "access_denied", "error_message", "placeholder_page"]}},
            "confidence": {"enum": ["low", "medium", "high"]},
            "limitations": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["page_kind", "summary", "authentication_surface", "administration_surface", "form_kinds", "technology_hints", "security_relevant_elements", "confidence", "limitations"],
        "additionalProperties": false
    })
}

fn sanitize_observation(mut observation: VisualObservation) -> VisualObservation {
    observation.summary = redact_text(observation.summary.chars().take(512).collect());
    observation.technology_hints = observation
        .technology_hints
        .into_iter()
        .map(|value| redact_text(value.chars().take(80).collect()))
        .filter(|value| !value.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(25)
        .collect();
    observation.limitations = observation
        .limitations
        .into_iter()
        .map(|value| redact_text(value.chars().take(160).collect()))
        .filter(|value| !value.trim().is_empty())
        .take(10)
        .collect();
    observation.form_kinds.sort();
    observation.form_kinds.dedup();
    observation.security_relevant_elements.sort();
    observation.security_relevant_elements.dedup();
    observation
}

fn chromium_executable() -> Option<PathBuf> {
    std::env::var("HEXHUNT_CHROMIUM_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| default_executable().ok())
}

fn is_non_network_url(value: &str) -> bool {
    Url::parse(value)
        .ok()
        .is_some_and(|url| matches!(url.scheme(), "about" | "data" | "blob"))
}

fn read_limited(response: reqwest::blocking::Response) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    response
        .take((MAX_VISION_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_VISION_RESPONSE_BYTES {
        bytes.truncate(MAX_VISION_RESPONSE_BYTES);
    }
    Ok(bytes)
}

fn visual_error(
    code: impl Into<String>,
    message: impl Into<String>,
    request_started: bool,
) -> ToolExecutionError {
    ToolExecutionError {
        code: code.into(),
        message: message.into(),
        request_started,
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope_guard::ScopeProject;
    use crate::{
        core::{TaskBudget, TaskId},
        scope_guard::ScopeGuardState,
    };

    struct FakeCapture;

    impl ScreenshotCapture for FakeCapture {
        fn capture(
            &self,
            call: &PreparedVisualReconCall,
        ) -> Result<ScreenshotArtifact, ToolExecutionError> {
            Ok(ScreenshotArtifact {
                bytes: b"fake-png-with-secret-value".to_vec(),
                final_url: call.url.clone(),
                blocked_out_of_scope_requests: 2,
            })
        }
    }

    struct FakeAnalyzer;

    impl VisualAnalyzer for FakeAnalyzer {
        fn analyze(
            &self,
            _page_url: &str,
            _screenshot_png: &[u8],
        ) -> Result<VisualModelResult, ToolExecutionError> {
            Ok(VisualModelResult {
                observation: VisualObservation {
                    page_kind: VisualPageKind::Authentication,
                    summary: "A login page with username and password fields.".into(),
                    authentication_surface: true,
                    administration_surface: false,
                    form_kinds: vec![VisualFormKind::Login, VisualFormKind::Login],
                    technology_hints: vec!["React".into(), "React".into()],
                    security_relevant_elements: vec![VisualElementKind::LoginForm],
                    confidence: VisualConfidence::High,
                    limitations: vec!["Only the visible viewport was analyzed.".into()],
                },
                model: "fake-vision".into(),
                api_response_model: Some("fake-vision-resolved".into()),
                actual_provider: Some("local-test".into()),
                input_tokens: 120,
                output_tokens: 40,
                usage_reported: true,
            })
        }
    }

    fn task() -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: TaskId("visual-task".into()),
            objective: "Visual Recon".into(),
            primary_target: "http://127.0.0.1:8080".into(),
            scope: ScopeProject {
                id: "visual-scope".into(),
                allowed_domains: vec!["127.0.0.1".into()],
                excluded_domains: vec![],
                allowed_ports: vec![8080],
                request_rate: 5,
                authorized: true,
            },
            budget: TaskBudget {
                max_steps: 0,
                max_http_requests: 0,
                max_model_calls: 0,
                max_input_tokens: 0,
                max_output_tokens: 0,
                max_duration_ms: 0,
            },
            available_tools: vec!["analyze_visual_page".into()],
            memory_policy: Default::default(),
        }
    }

    #[test]
    fn visual_tool_persists_only_hash_and_structured_observation() {
        let tool = VisualReconTool::with_components(
            Arc::new(ScopeGuardState::default()),
            Arc::new(FakeCapture),
            Arc::new(FakeAnalyzer),
        );
        let action = AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "analyze_visual_page".into(),
            arguments: StructuredData::from([(
                "url".into(),
                Value::String("http://127.0.0.1:8080/login".into()),
            )]),
            reason: "Classify the visible page.".into(),
        };
        let prepared = tool.prepare(&action, &task()).unwrap();
        let outcome = tool.execute(prepared).unwrap();
        let serialized = serde_json::to_string(&outcome.result).unwrap();

        assert_eq!(outcome.model_calls, 1);
        assert_eq!(outcome.input_tokens, 120);
        assert_eq!(outcome.output_tokens, 40);
        assert_eq!(outcome.result.data["screenshot_retained"], false);
        assert_eq!(outcome.result.data["blocked_out_of_scope_requests"], 2);
        assert_eq!(
            outcome.result.data["visual_observation"]["authentication_surface"],
            true
        );
        assert!(!serialized.contains("fake-png-with-secret-value"));
    }

    #[test]
    fn visual_tool_rejects_out_of_scope_navigation_before_browser_start() {
        let tool = VisualReconTool::with_components(
            Arc::new(ScopeGuardState::default()),
            Arc::new(FakeCapture),
            Arc::new(FakeAnalyzer),
        );
        let action = AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "analyze_visual_page".into(),
            arguments: StructuredData::from([(
                "url".into(),
                Value::String("https://outside.invalid/login".into()),
            )]),
            reason: "Try an invalid target.".into(),
        };
        assert_eq!(
            tool.prepare(&action, &task()).unwrap_err().code,
            "SCOPE_BLOCKED"
        );
    }

    #[test]
    fn chromium_capture_renders_local_lab_and_blocks_out_of_scope_subresources() {
        if chromium_executable().is_none() {
            return;
        }
        let lab = super::super::LocalLab::start().unwrap();
        let call = PreparedVisualReconCall {
            url: lab.base_url(),
            scope: ScopeProject {
                id: "visual-browser-lab".into(),
                allowed_domains: vec!["127.0.0.1".into()],
                excluded_domains: vec![],
                allowed_ports: vec![lab.port()],
                request_rate: 10,
                authorized: true,
            },
            timeout_ms: 20_000,
        };

        let artifact = ChromiumScreenshotCapture.capture(&call).unwrap();
        assert!(artifact.bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(artifact.final_url.trim_end_matches('/'), lab.base_url());
        assert!(artifact.blocked_out_of_scope_requests >= 1);
    }
}
