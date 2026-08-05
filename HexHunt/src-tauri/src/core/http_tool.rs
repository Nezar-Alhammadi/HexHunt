use super::{
    AgentAction, Task, ToolExecutionError, ToolExecutionOutcome, ToolResult, ToolResultId,
    CORE_SCHEMA_VERSION,
};
use crate::scope_guard::ScopeGuardState;
use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

pub const DEFAULT_HTTP_TIMEOUT_MS: u64 = 5_000;
pub const MAX_HTTP_TIMEOUT_MS: u64 = 30_000;
pub const MAX_HTTP_RESPONSE_BODY_BYTES: usize = 64 * 1024;
pub const MAX_HTTP_REQUEST_BODY_BYTES: usize = 64 * 1024;
const MAX_HTTP_HEADERS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpMethod {
    Get,
    Head,
    Post,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PreparedHttpRequest {
    method: HttpMethod,
    url: String,
    headers: HeaderMap,
    body: Option<String>,
    timeout: Duration,
    max_response_body_bytes: usize,
}

pub struct HttpRequestTool {
    client: Client,
    scope_guard: Arc<ScopeGuardState>,
}

impl HttpRequestTool {
    pub fn new(scope_guard: Arc<ScopeGuardState>) -> Result<Self, ToolExecutionError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .tls_info(true)
            .build()
            .map_err(|error| ToolExecutionError {
                code: "HTTP_CONNECTION_FAILED".into(),
                message: format!("Unable to initialize the HTTP client: {error}"),
                request_started: false,
            })?;
        Ok(Self {
            client,
            scope_guard,
        })
    }

    pub(crate) fn scope_guard(&self) -> Arc<ScopeGuardState> {
        self.scope_guard.clone()
    }

    pub fn prepare(
        &self,
        action: &AgentAction,
        task: &Task,
    ) -> Result<PreparedHttpRequest, ToolExecutionError> {
        let request = PreparedHttpRequest::from_action(action)?;
        let decision = self
            .scope_guard
            .authorize_request(&task.scope, &request.url);
        if !decision.allowed {
            let code = if decision.code == "rate-limit" {
                "RATE_LIMITED"
            } else {
                "SCOPE_BLOCKED"
            };
            return Err(ToolExecutionError {
                code: code.into(),
                message: format!("{} ({})", decision.reason, decision.code),
                request_started: false,
            });
        }
        Ok(request)
    }

    pub fn execute(
        &self,
        request: PreparedHttpRequest,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        let started_at = Instant::now();
        let requested_url = request.url.clone();
        let mut builder = match request.method {
            HttpMethod::Get => self.client.get(&request.url),
            HttpMethod::Head => self.client.head(&request.url),
            HttpMethod::Post => self.client.post(&request.url),
        }
        .headers(request.headers)
        .timeout(request.timeout);

        if let Some(body) = request.body {
            builder = builder.body(body);
        }

        let response = builder.send().map_err(|error| ToolExecutionError {
            code: if error.is_timeout() {
                "HTTP_TIMEOUT".into()
            } else {
                "HTTP_CONNECTION_FAILED".into()
            },
            message: format!("HTTP request failed: {error}"),
            request_started: true,
        })?;

        let status_code = response.status().as_u16();
        let final_url = response.url().as_str().to_string();
        let response_headers = response_headers_json(response.headers());
        let tls = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(reqwest::tls::TlsInfo::peer_certificate)
            .map(|certificate| {
                let digest = Sha256::digest(certificate);
                serde_json::json!({
                    "present": true,
                    "peer_certificate_sha256": digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    "peer_certificate_der_bytes": certificate.len()
                })
            })
            .unwrap_or_else(|| serde_json::json!({"present": false}));
        let max_response_body_bytes = request.max_response_body_bytes;
        let mut limited_body = Vec::with_capacity(max_response_body_bytes.min(64 * 1024) + 1);
        response
            .take((max_response_body_bytes + 1) as u64)
            .read_to_end(&mut limited_body)
            .map_err(|error| ToolExecutionError {
                code: "HTTP_RESPONSE_READ_FAILED".into(),
                message: format!("Unable to read the HTTP response body: {error}"),
                request_started: true,
            })?;
        let response_body_truncated = limited_body.len() > max_response_body_bytes;
        limited_body.truncate(max_response_body_bytes);
        let response_body = String::from_utf8_lossy(&limited_body).into_owned();
        let redirected = final_url != requested_url;

        let data = std::collections::BTreeMap::from([
            (
                "method".into(),
                Value::String(request.method.as_str().into()),
            ),
            ("requested_url".into(), Value::String(requested_url.clone())),
            ("final_url".into(), Value::String(final_url)),
            ("status_code".into(), Value::from(status_code)),
            ("response_headers".into(), Value::Object(response_headers)),
            ("response_body".into(), Value::String(response_body)),
            (
                "response_body_truncated".into(),
                Value::Bool(response_body_truncated),
            ),
            ("redirected".into(), Value::Bool(redirected)),
            ("tls".into(), tls),
        ]);

        Ok(ToolExecutionOutcome {
            result: ToolResult {
                schema_version: CORE_SCHEMA_VERSION,
                id: ToolResultId(Uuid::new_v4().to_string()),
                tool_name: "http_request".into(),
                success: true,
                data,
                error: None,
                duration_ms: started_at
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            },
            http_requests: 1,
            model_calls: 0,
            input_tokens: 0,
            output_tokens: 0,
        })
    }
}

impl PreparedHttpRequest {
    fn from_action(action: &AgentAction) -> Result<Self, ToolExecutionError> {
        if action.name != "http_request" {
            return Err(invalid_arguments("Expected an http_request action."));
        }
        for key in action.arguments.keys() {
            if !matches!(
                key.as_str(),
                "method" | "url" | "headers" | "body" | "timeout_ms"
            ) {
                return Err(invalid_arguments(format!(
                    "Unknown http_request argument '{key}'."
                )));
            }
        }

        let method_value = required_string(&action.arguments, "method")?;
        let method = match method_value.to_ascii_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "HEAD" => HttpMethod::Head,
            "POST" => HttpMethod::Post,
            _ => {
                return Err(ToolExecutionError {
                    code: "INVALID_HTTP_METHOD".into(),
                    message: "Only GET, HEAD, and POST are supported.".into(),
                    request_started: false,
                });
            }
        };

        let url_value = required_string(&action.arguments, "url")?;
        let parsed_url = Url::parse(url_value).map_err(|_| ToolExecutionError {
            code: "INVALID_HTTP_URL".into(),
            message: "http_request requires a valid absolute URL.".into(),
            request_started: false,
        })?;
        if !matches!(parsed_url.scheme(), "http" | "https") || parsed_url.host_str().is_none() {
            return Err(ToolExecutionError {
                code: "INVALID_HTTP_URL".into(),
                message: "Only absolute HTTP and HTTPS URLs are supported.".into(),
                request_started: false,
            });
        }
        if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
            return Err(ToolExecutionError {
                code: "INVALID_HTTP_URL".into(),
                message: "Credentials in HTTP URLs are not supported.".into(),
                request_started: false,
            });
        }

        let headers = parse_headers(action.arguments.get("headers"))?;
        let body = match action.arguments.get("body") {
            None | Some(Value::Null) => None,
            Some(Value::String(body)) => Some(body.clone()),
            Some(_) => return Err(invalid_arguments("body must be a string when provided.")),
        };
        if matches!(method, HttpMethod::Get | HttpMethod::Head) && body.is_some() {
            return Err(invalid_arguments(
                "GET and HEAD requests cannot include a body.",
            ));
        }
        if body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_HTTP_REQUEST_BODY_BYTES)
        {
            return Err(invalid_arguments(format!(
                "Request body exceeds {MAX_HTTP_REQUEST_BODY_BYTES} bytes."
            )));
        }

        let timeout_ms = match action.arguments.get("timeout_ms") {
            None | Some(Value::Null) => DEFAULT_HTTP_TIMEOUT_MS,
            Some(value) => value.as_u64().ok_or_else(|| {
                invalid_arguments("timeout_ms must be a positive integer in milliseconds.")
            })?,
        };
        if timeout_ms == 0 || timeout_ms > MAX_HTTP_TIMEOUT_MS {
            return Err(invalid_arguments(format!(
                "timeout_ms must be between 1 and {MAX_HTTP_TIMEOUT_MS}."
            )));
        }

        Ok(Self {
            method,
            url: parsed_url.to_string(),
            headers,
            body,
            timeout: Duration::from_millis(timeout_ms),
            max_response_body_bytes: MAX_HTTP_RESPONSE_BODY_BYTES,
        })
    }

    pub(crate) fn with_response_body_limit(mut self, maximum: usize) -> Self {
        self.max_response_body_bytes = maximum.max(1);
        self
    }
}

fn required_string<'a>(
    arguments: &'a std::collections::BTreeMap<String, Value>,
    name: &str,
) -> Result<&'a str, ToolExecutionError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_arguments(format!("{name} must be a non-empty string.")))
}

fn parse_headers(value: Option<&Value>) -> Result<HeaderMap, ToolExecutionError> {
    let Some(value) = value else {
        return Ok(HeaderMap::new());
    };
    if value.is_null() {
        return Ok(HeaderMap::new());
    }
    let object = value
        .as_object()
        .ok_or_else(|| invalid_arguments("headers must be an object of string values."))?;
    if object.len() > MAX_HTTP_HEADERS {
        return Err(invalid_arguments(format!(
            "headers cannot contain more than {MAX_HTTP_HEADERS} entries."
        )));
    }

    let mut headers = HeaderMap::new();
    for (name, value) in object {
        let value = value
            .as_str()
            .ok_or_else(|| invalid_arguments("Every header value must be a string."))?;
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid_arguments("A header name is invalid."))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| invalid_arguments("A header value is invalid."))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

fn response_headers_json(headers: &HeaderMap) -> Map<String, Value> {
    let mut result = Map::new();
    for (name, value) in headers {
        let value = value
            .to_str()
            .map(str::to_owned)
            .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned());
        result.insert(name.as_str().to_string(), Value::String(value));
    }
    result
}

fn invalid_arguments(message: impl Into<String>) -> ToolExecutionError {
    ToolExecutionError {
        code: "INVALID_HTTP_ARGUMENTS".into(),
        message: message.into(),
        request_started: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{local_lab::LocalLab, StructuredData, TaskBudget, TaskId},
        scope_guard::ScopeProject,
    };

    fn task(port: u16) -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: TaskId("http-tool-task".into()),
            objective: "Exercise the local HTTP lab.".into(),
            primary_target: format!("http://127.0.0.1:{port}"),
            scope: ScopeProject {
                id: "http-lab-scope".into(),
                allowed_domains: vec!["127.0.0.1".into()],
                excluded_domains: vec![],
                allowed_ports: vec![port],
                request_rate: 10,
                authorized: true,
            },
            budget: TaskBudget {
                max_steps: 5,
                max_http_requests: 5,
                max_model_calls: 0,
                max_input_tokens: 0,
                max_output_tokens: 0,
                max_duration_ms: 30_000,
            },
            available_tools: vec!["http_request".into()],
            memory_policy: Default::default(),
        }
    }

    fn action(method: &str, url: String, body: Option<&str>) -> AgentAction {
        let mut arguments = StructuredData::from([
            ("method".into(), Value::String(method.into())),
            ("url".into(), Value::String(url)),
            ("timeout_ms".into(), Value::from(2_000)),
        ]);
        if let Some(body) = body {
            arguments.insert("body".into(), Value::String(body.into()));
        }
        AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "http_request".into(),
            arguments,
            reason: "Exercise the local lab.".into(),
        }
    }

    #[test]
    fn local_lab_supports_profile_echo_redirect_policy_and_truncation() {
        let lab = LocalLab::start().unwrap();
        let task = task(lab.port());
        let tool = HttpRequestTool::new(Arc::new(ScopeGuardState::default())).unwrap();

        let profile = tool
            .execute(
                tool.prepare(
                    &action("GET", format!("{}/profile", lab.base_url()), None),
                    &task,
                )
                .unwrap(),
            )
            .unwrap()
            .result;
        assert_eq!(profile.data["status_code"], 200);
        assert!(profile.data["response_body"]
            .as_str()
            .unwrap()
            .contains("alice"));

        let echo = tool
            .execute(
                tool.prepare(
                    &action(
                        "POST",
                        format!("{}/echo", lab.base_url()),
                        Some(r#"{"hello":"lab"}"#),
                    ),
                    &task,
                )
                .unwrap(),
            )
            .unwrap()
            .result;
        assert_eq!(echo.data["response_body"], r#"{"hello":"lab"}"#);

        let redirect = tool
            .execute(
                tool.prepare(
                    &action("GET", format!("{}/redirect", lab.base_url()), None),
                    &task,
                )
                .unwrap(),
            )
            .unwrap()
            .result;
        assert_eq!(redirect.data["status_code"], 302);
        assert_eq!(redirect.data["redirected"], false);

        let large = tool
            .execute(
                tool.prepare(
                    &action("GET", format!("{}/large", lab.base_url()), None),
                    &task,
                )
                .unwrap(),
            )
            .unwrap()
            .result;
        assert_eq!(large.data["response_body_truncated"], true);
        assert_eq!(
            large.data["response_body"].as_str().unwrap().len(),
            MAX_HTTP_RESPONSE_BODY_BYTES
        );
    }

    #[test]
    fn invalid_arguments_and_scope_are_rejected_before_network() {
        let lab = LocalLab::start().unwrap();
        let task = task(lab.port());
        let tool = HttpRequestTool::new(Arc::new(ScopeGuardState::default())).unwrap();

        let invalid = tool
            .prepare(
                &action("DELETE", format!("{}/health", lab.base_url()), None),
                &task,
            )
            .unwrap_err();
        assert_eq!(invalid.code, "INVALID_HTTP_METHOD");
        assert!(!invalid.request_started);

        let blocked = tool
            .prepare(
                &action("GET", "http://example.invalid/".into(), None),
                &task,
            )
            .unwrap_err();
        assert_eq!(blocked.code, "SCOPE_BLOCKED");
        assert!(!blocked.request_started);
    }
}
