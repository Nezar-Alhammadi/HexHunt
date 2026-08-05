use super::recon_tools::scoped_hostname;
use super::{
    AgentAction, StructuredData, Task, ToolError, ToolExecutionError, ToolExecutionOutcome,
    ToolResult, ToolResultId, CORE_SCHEMA_VERSION,
};
use reqwest::{blocking::Client, redirect::Policy};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io::Read,
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};
use uuid::Uuid;

const RDAP_BASE_URL: &str = "https://rdap.org";
const RDAP_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RDAP_RESPONSE_BYTES: usize = 1024 * 1024;
const DEFAULT_TCP_TIMEOUT_MS: u64 = 2_000;
const MAX_TCP_TIMEOUT_MS: u64 = 10_000;

#[derive(Clone, Debug)]
pub enum PreparedInfrastructureCall {
    InspectRdap {
        target: String,
    },
    ProbeTcpService {
        hostname: String,
        port: u16,
        timeout: Duration,
    },
}

pub struct InfrastructureReconTools {
    client: Client,
}

impl Default for InfrastructureReconTools {
    fn default() -> Self {
        Self {
            client: Client::builder()
                .redirect(Policy::limited(2))
                .user_agent("HexHunt/0.1 infrastructure-recon")
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }
}

impl InfrastructureReconTools {
    pub fn prepare(
        &self,
        action: &AgentAction,
        task: &Task,
    ) -> Result<PreparedInfrastructureCall, ToolExecutionError> {
        match action.name.as_str() {
            "inspect_rdap" => {
                ensure_arguments(action, &["target"])?;
                let target = required_string(action, "target")?;
                let target = scoped_hostname(task, target)?;
                Ok(PreparedInfrastructureCall::InspectRdap { target })
            }
            "probe_tcp_service" => {
                ensure_arguments(action, &["hostname", "port", "timeout_ms"])?;
                let hostname = scoped_hostname(task, required_string(action, "hostname")?)?;
                let port = action
                    .arguments
                    .get("port")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("probe_tcp_service requires an integer port."))?;
                let port = u16::try_from(port)
                    .map_err(|_| invalid("TCP port must be between 1 and 65535."))?;
                if port == 0 || !task.scope.allowed_ports.contains(&port) {
                    return Err(ToolExecutionError {
                        code: "SCOPE_BLOCKED".into(),
                        message: format!("TCP port {port} is not present in the authorized scope."),
                        request_started: false,
                    });
                }
                let timeout_ms = action
                    .arguments
                    .get("timeout_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_TCP_TIMEOUT_MS);
                if timeout_ms == 0 || timeout_ms > MAX_TCP_TIMEOUT_MS {
                    return Err(invalid(format!(
                        "timeout_ms must be between 1 and {MAX_TCP_TIMEOUT_MS}."
                    )));
                }
                Ok(PreparedInfrastructureCall::ProbeTcpService {
                    hostname,
                    port,
                    timeout: Duration::from_millis(timeout_ms),
                })
            }
            _ => Err(invalid(format!(
                "Unsupported infrastructure Recon tool '{}'.",
                action.name
            ))),
        }
    }

    pub fn execute(
        &self,
        prepared: PreparedInfrastructureCall,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        match prepared {
            PreparedInfrastructureCall::InspectRdap { target } => self.inspect_rdap(target),
            PreparedInfrastructureCall::ProbeTcpService {
                hostname,
                port,
                timeout,
            } => Ok(probe_tcp_service(hostname, port, timeout)),
        }
    }

    fn inspect_rdap(&self, target: String) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        let started = Instant::now();
        let kind = if target.parse::<std::net::IpAddr>().is_ok() {
            "ip"
        } else {
            "domain"
        };
        let endpoint = format!("{RDAP_BASE_URL}/{kind}/{target}");
        let response = self
            .client
            .get(endpoint)
            .timeout(RDAP_TIMEOUT)
            .send()
            .map_err(|error| ToolExecutionError {
                code: if error.is_timeout() {
                    "RDAP_TIMEOUT".into()
                } else {
                    "RDAP_CONNECTION_FAILED".into()
                },
                message: format!("RDAP lookup failed: {error}"),
                request_started: true,
            })?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            return Ok(outcome_error(
                "inspect_rdap",
                StructuredData::from([
                    ("target".into(), Value::String(target)),
                    ("status_code".into(), Value::from(status)),
                ]),
                "RDAP_PROVIDER_ERROR",
                format!("RDAP provider returned HTTP {status}."),
                started,
                1,
            ));
        }
        let mut bytes = Vec::with_capacity(64 * 1024);
        response
            .take((MAX_RDAP_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| ToolExecutionError {
                code: "RDAP_RESPONSE_READ_FAILED".into(),
                message: format!("Unable to read RDAP response: {error}"),
                request_started: true,
            })?;
        if bytes.len() > MAX_RDAP_RESPONSE_BYTES {
            return Err(ToolExecutionError {
                code: "RDAP_RESPONSE_TOO_LARGE".into(),
                message: "RDAP response exceeded the safe read limit.".into(),
                request_started: true,
            });
        }
        let document: Value =
            serde_json::from_slice(&bytes).map_err(|error| ToolExecutionError {
                code: "RDAP_INVALID_RESPONSE".into(),
                message: format!("RDAP provider returned invalid JSON: {error}"),
                request_started: true,
            })?;
        let nameservers = document
            .get("nameservers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("ldhName").and_then(Value::as_str))
            .map(|value| Value::String(value.to_ascii_lowercase()))
            .take(100)
            .collect();
        let statuses = document
            .get("status")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let events = document
            .get("events")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|event| {
                Some(serde_json::json!({
                    "action": event.get("eventAction")?.as_str()?,
                    "date": event.get("eventDate")?.as_str()?,
                }))
            })
            .take(30)
            .collect();
        let cidr_blocks = document
            .get("cidr0_cidrs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let origin_asns = document
            .get("arin_originas0_originautnums")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let data = StructuredData::from([
            ("target".into(), Value::String(target)),
            (
                "object_class".into(),
                document
                    .get("objectClassName")
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            (
                "handle".into(),
                document.get("handle").cloned().unwrap_or(Value::Null),
            ),
            (
                "name".into(),
                document.get("name").cloned().unwrap_or(Value::Null),
            ),
            (
                "country".into(),
                document.get("country").cloned().unwrap_or(Value::Null),
            ),
            (
                "ip_version".into(),
                document.get("ipVersion").cloned().unwrap_or(Value::Null),
            ),
            (
                "start_address".into(),
                document.get("startAddress").cloned().unwrap_or(Value::Null),
            ),
            (
                "end_address".into(),
                document.get("endAddress").cloned().unwrap_or(Value::Null),
            ),
            ("statuses".into(), Value::Array(statuses)),
            ("nameservers".into(), Value::Array(nameservers)),
            ("events".into(), Value::Array(events)),
            ("cidr_blocks".into(), Value::Array(cidr_blocks)),
            ("origin_asns".into(), Value::Array(origin_asns)),
            ("contact_entities_retained".into(), Value::Bool(false)),
            ("provider".into(), Value::String("rdap.org".into())),
        ]);
        Ok(ToolExecutionOutcome {
            result: ToolResult {
                schema_version: CORE_SCHEMA_VERSION,
                id: ToolResultId(Uuid::new_v4().to_string()),
                tool_name: "inspect_rdap".into(),
                success: true,
                data,
                error: None,
                duration_ms: elapsed_ms(started),
            },
            http_requests: 1,
            model_calls: 0,
            input_tokens: 0,
            output_tokens: 0,
        })
    }
}

fn probe_tcp_service(hostname: String, port: u16, timeout: Duration) -> ToolExecutionOutcome {
    let started = Instant::now();
    let addresses = (hostname.as_str(), port)
        .to_socket_addrs()
        .map(|items| items.take(8).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut connected_address = None;
    let mut errors = BTreeSet::new();
    for address in &addresses {
        match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => {
                connected_address = Some(
                    stream
                        .peer_addr()
                        .map(|value| value.ip().to_string())
                        .unwrap_or_else(|_| address.ip().to_string()),
                );
                break;
            }
            Err(error) => {
                errors.insert(error.kind().to_string());
            }
        }
    }
    let open = connected_address.is_some();
    ToolExecutionOutcome {
        result: ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId(Uuid::new_v4().to_string()),
            tool_name: "probe_tcp_service".into(),
            success: true,
            data: StructuredData::from([
                ("hostname".into(), Value::String(hostname)),
                ("port".into(), Value::from(port)),
                ("open".into(), Value::Bool(open)),
                (
                    "connected_address".into(),
                    connected_address.map(Value::String).unwrap_or(Value::Null),
                ),
                (
                    "resolved_address_count".into(),
                    Value::from(addresses.len() as u64),
                ),
                (
                    "connection_errors".into(),
                    Value::Array(errors.into_iter().map(Value::String).collect()),
                ),
                ("banner_requested".into(), Value::Bool(false)),
            ]),
            error: None,
            duration_ms: elapsed_ms(started),
        },
        http_requests: 0,
        model_calls: 0,
        input_tokens: 0,
        output_tokens: 0,
    }
}

fn outcome_error(
    tool_name: &str,
    data: StructuredData,
    code: &str,
    message: String,
    started: Instant,
    http_requests: u64,
) -> ToolExecutionOutcome {
    ToolExecutionOutcome {
        result: ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId(Uuid::new_v4().to_string()),
            tool_name: tool_name.into(),
            success: false,
            data,
            error: Some(ToolError {
                code: code.into(),
                message,
                retryable: true,
            }),
            duration_ms: elapsed_ms(started),
        },
        http_requests,
        model_calls: 0,
        input_tokens: 0,
        output_tokens: 0,
    }
}

fn required_string<'a>(action: &'a AgentAction, key: &str) -> Result<&'a str, ToolExecutionError> {
    action
        .arguments
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid(format!("{key} must be a non-empty string.")))
}

fn ensure_arguments(action: &AgentAction, allowed: &[&str]) -> Result<(), ToolExecutionError> {
    if let Some(key) = action
        .arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(invalid(format!(
            "Unknown {} argument '{key}'.",
            action.name
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ToolExecutionError {
    ToolExecutionError {
        code: "INVALID_INFRASTRUCTURE_ARGUMENTS".into(),
        message: message.into(),
        request_started: false,
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}
