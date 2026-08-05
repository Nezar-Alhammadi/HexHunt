use super::{AgentAction, RunEvent, RunEventKind, ToolResult};
use serde_json::Value;

const REDACTED: &str = "[REDACTED]";

pub fn redact_tool_result(mut result: ToolResult) -> ToolResult {
    for value in result.data.values_mut() {
        redact_value(value, None);
    }
    result
}

pub fn redact_agent_action(mut action: AgentAction) -> AgentAction {
    for value in action.arguments.values_mut() {
        redact_value(value, None);
    }
    action.reason = redact_text(action.reason);
    action
}

pub fn redact_event(mut event: RunEvent) -> RunEvent {
    event.kind = match event.kind {
        RunEventKind::ActionReceived { action } => RunEventKind::ActionReceived {
            action: redact_agent_action(action),
        },
        RunEventKind::ActionRejected { action, reason } => RunEventKind::ActionRejected {
            action: redact_agent_action(action),
            reason: redact_text(reason),
        },
        kind => kind,
    };
    event
}

pub fn redact_text(value: String) -> String {
    let lower = value.to_ascii_lowercase();
    if contains_bearer_token(&value)
        || lower.contains("sk-or-v1-")
        || lower.contains("openrouter_api_key=")
        || lower.contains("api_key=")
    {
        REDACTED.into()
    } else {
        value
    }
}

pub fn redact_value(value: &mut Value, key: Option<&str>) {
    if key.is_some_and(is_sensitive_key) {
        *value = Value::String(REDACTED.into());
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                redact_value(value, Some(key));
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_value(value, key);
            }
        }
        Value::String(text) => {
            if contains_bearer_token(text) {
                *text = REDACTED.into();
            } else if let Ok(mut nested) = serde_json::from_str::<Value>(text) {
                if nested.is_object() || nested.is_array() {
                    redact_value(&mut nested, None);
                    if let Ok(redacted) = serde_json::to_string(&nested) {
                        *text = redacted;
                    }
                }
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "proxy_authorization"
            | "cookie"
            | "set-cookie"
            | "set_cookie"
            | "x-api-key"
            | "x_api_key"
            | "api-key"
            | "api_key"
            | "openrouter_api_key"
            | "access_token"
            | "refresh_token"
            | "token"
            | "secret"
            | "client_secret"
            | "password"
    )
}

fn contains_bearer_token(value: &str) -> bool {
    value
        .trim_start()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
}
