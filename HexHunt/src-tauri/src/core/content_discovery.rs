use super::{
    AgentAction, HttpRequestTool, PreparedHttpRequest, StructuredData, Task, ToolExecutionError,
    ToolExecutionOutcome, ToolResult, ToolResultId, CORE_SCHEMA_VERSION,
};
use crate::scope_guard::validate;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    thread,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

const MAX_DISCOVERY_PATHS: usize = 32;

#[derive(Clone, Debug)]
pub struct PreparedContentDiscovery {
    base_url: String,
    task: Task,
    requests: Vec<(String, AgentAction)>,
}

pub fn prepare_content_discovery(
    action: &AgentAction,
    task: &Task,
    _http: &HttpRequestTool,
) -> Result<PreparedContentDiscovery, ToolExecutionError> {
    for key in action.arguments.keys() {
        if !matches!(key.as_str(), "base_url" | "paths" | "timeout_ms") {
            return Err(invalid(format!(
                "Unknown discover_content argument '{key}'."
            )));
        }
    }
    let raw_base = action
        .arguments
        .get("base_url")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid("discover_content requires base_url."))?;
    let mut base = Url::parse(raw_base)
        .map_err(|_| invalid("base_url must be an absolute HTTP or HTTPS URL."))?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err(invalid("base_url must be an absolute HTTP or HTTPS URL."));
    }
    base.set_query(None);
    base.set_fragment(None);
    let paths = action
        .arguments
        .get("paths")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("discover_content requires a paths array."))?;
    if paths.is_empty() || paths.len() > MAX_DISCOVERY_PATHS {
        return Err(invalid(format!(
            "paths must contain between 1 and {MAX_DISCOVERY_PATHS} entries."
        )));
    }
    let mut unique = BTreeSet::new();
    let mut requests = Vec::new();
    for path in paths {
        let path = path
            .as_str()
            .ok_or_else(|| invalid("Every discovery path must be a string."))?
            .trim();
        if !path.starts_with('/')
            || path.contains('?')
            || path.contains('#')
            || path.split('/').any(|part| part == "..")
        {
            return Err(invalid(
                "Discovery paths must be absolute paths without queries, fragments, or traversal.",
            ));
        }
        let url = base
            .join(path)
            .map_err(|_| invalid("A discovery path could not be normalized."))?;
        if url.origin() != base.origin() {
            return Err(invalid(
                "Discovery paths must remain on the authorized origin.",
            ));
        }
        if !unique.insert(url.to_string()) {
            continue;
        }
        let decision = validate(&task.scope, url.as_str());
        if !decision.allowed {
            return Err(ToolExecutionError {
                code: "SCOPE_BLOCKED".into(),
                message: decision.reason.into(),
                request_started: false,
            });
        }
        let mut arguments = StructuredData::from([
            ("method".into(), Value::String("HEAD".into())),
            ("url".into(), Value::String(url.to_string())),
        ]);
        if let Some(timeout) = action.arguments.get("timeout_ms") {
            arguments.insert("timeout_ms".into(), timeout.clone());
        }
        requests.push((
            path.to_string(),
            AgentAction {
                schema_version: CORE_SCHEMA_VERSION,
                name: "http_request".into(),
                arguments,
                reason: action.reason.clone(),
            },
        ));
    }
    Ok(PreparedContentDiscovery {
        base_url: base.to_string(),
        task: task.clone(),
        requests,
    })
}

pub fn execute_content_discovery(
    prepared: PreparedContentDiscovery,
    http: &HttpRequestTool,
) -> ToolExecutionOutcome {
    let started = Instant::now();
    let mut request_count = 0_u64;
    let mut findings = Vec::new();
    for (path, action) in prepared.requests {
        let execution = prepare_with_rate_pacing(http, &action, &prepared.task)
            .and_then(|request| http.execute(request));
        match execution {
            Ok(outcome) => {
                request_count = request_count.saturating_add(outcome.http_requests);
                let status = outcome
                    .result
                    .data
                    .get("status_code")
                    .cloned()
                    .unwrap_or(Value::Null);
                let url = outcome
                    .result
                    .data
                    .get("final_url")
                    .cloned()
                    .or_else(|| outcome.result.data.get("requested_url").cloned())
                    .unwrap_or(Value::Null);
                let content_type = outcome
                    .result
                    .data
                    .get("response_headers")
                    .and_then(Value::as_object)
                    .and_then(|headers| headers.get("content-type"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let location = outcome
                    .result
                    .data
                    .get("response_headers")
                    .and_then(Value::as_object)
                    .and_then(|headers| headers.get("location"))
                    .cloned()
                    .unwrap_or(Value::Null);
                findings.push(serde_json::json!({
                    "path": path,
                    "url": url,
                    "status_code": status,
                    "content_type": content_type,
                    "location": location,
                    "error_code": null,
                }));
            }
            Err(error) => {
                request_count = request_count.saturating_add(u64::from(error.request_started));
                findings.push(serde_json::json!({
                    "path": path,
                    "url": null,
                    "status_code": null,
                    "content_type": null,
                    "location": null,
                    "error_code": error.code,
                }));
            }
        }
    }
    let discovered_count = findings
        .iter()
        .filter(|finding| {
            finding
                .get("status_code")
                .and_then(Value::as_u64)
                .is_some_and(|status| !matches!(status, 404 | 410))
        })
        .count();
    ToolExecutionOutcome {
        result: ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId(Uuid::new_v4().to_string()),
            tool_name: "discover_content".into(),
            success: true,
            data: StructuredData::from([
                ("base_url".into(), Value::String(prepared.base_url)),
                ("finding_count".into(), Value::from(discovered_count as u64)),
                ("findings".into(), Value::Array(findings)),
                ("response_bodies_retained".into(), Value::Bool(false)),
                ("method".into(), Value::String("HEAD".into())),
            ]),
            error: None,
            duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        },
        http_requests: request_count,
        model_calls: 0,
        input_tokens: 0,
        output_tokens: 0,
    }
}

fn prepare_with_rate_pacing(
    http: &HttpRequestTool,
    action: &AgentAction,
    task: &Task,
) -> Result<PreparedHttpRequest, ToolExecutionError> {
    const MAX_RATE_RETRIES: usize = 12;
    for attempt in 0..=MAX_RATE_RETRIES {
        match http.prepare(action, task) {
            Err(error) if error.code == "RATE_LIMITED" && attempt < MAX_RATE_RETRIES => {
                thread::sleep(Duration::from_millis(100));
            }
            result => return result,
        }
    }
    unreachable!("The bounded rate-limit loop always returns on its final attempt")
}

fn invalid(message: impl Into<String>) -> ToolExecutionError {
    ToolExecutionError {
        code: "INVALID_CONTENT_DISCOVERY_ARGUMENTS".into(),
        message: message.into(),
        request_started: false,
    }
}
