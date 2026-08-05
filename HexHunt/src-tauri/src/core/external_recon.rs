use super::recon_tools::scoped_hostname;
use super::{
    AgentAction, StructuredData, Task, ToolExecutionError, ToolExecutionOutcome, ToolResult,
    ToolResultId, CORE_SCHEMA_VERSION,
};
use reqwest::{
    blocking::{Client, RequestBuilder},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io::Read,
    time::{Duration, Instant},
};
use uuid::Uuid;

const MAX_EXTERNAL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const EXTERNAL_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSourceStatus {
    pub shodan: bool,
    pub censys: bool,
    pub passive_dns: bool,
    pub github: bool,
}

impl ExternalSourceStatus {
    pub fn any(&self) -> bool {
        self.shodan || self.censys || self.passive_dns || self.github
    }
}

pub fn external_source_status() -> ExternalSourceStatus {
    ExternalSourceStatus {
        shodan: env_present("SHODAN_API_KEY"),
        censys: env_present("CENSYS_API_ID") && env_present("CENSYS_API_SECRET"),
        passive_dns: env_present("SECURITYTRAILS_API_KEY"),
        github: env_present("GITHUB_TOKEN"),
    }
}

pub fn external_sources_configured() -> bool {
    external_source_status().any()
}

#[derive(Clone, Debug)]
pub struct PreparedExternalReconCall {
    target: String,
}

pub struct ExternalReconTool {
    client: Client,
}

impl Default for ExternalReconTool {
    fn default() -> Self {
        Self {
            client: Client::builder()
                .redirect(Policy::limited(2))
                .user_agent("HexHunt/0.1 external-recon")
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }
}

impl ExternalReconTool {
    pub fn prepare(
        &self,
        action: &AgentAction,
        task: &Task,
    ) -> Result<PreparedExternalReconCall, ToolExecutionError> {
        if action.arguments.keys().any(|key| key != "target") {
            return Err(error(
                "INVALID_EXTERNAL_RECON_ARGUMENTS",
                "query_external_intelligence accepts only target.",
                false,
            ));
        }
        let target = action
            .arguments
            .get("target")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                error(
                    "INVALID_EXTERNAL_RECON_ARGUMENTS",
                    "query_external_intelligence requires target.",
                    false,
                )
            })?;
        Ok(PreparedExternalReconCall {
            target: scoped_hostname(task, target)?,
        })
    }

    pub fn execute(
        &self,
        call: PreparedExternalReconCall,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        let started = Instant::now();
        let status = external_source_status();
        let mut sources = Vec::new();
        let mut request_count = 0_u64;
        if status.shodan && call.target.parse::<std::net::IpAddr>().is_ok() {
            request_count += 1;
            let key = std::env::var("SHODAN_API_KEY").unwrap_or_default();
            sources.push(
                self.source_result(
                    "shodan",
                    self.client
                        .get(format!("https://api.shodan.io/shodan/host/{}", call.target))
                        .query(&[("key", key)]),
                    sanitize_shodan,
                ),
            );
        }
        if status.censys && call.target.parse::<std::net::IpAddr>().is_ok() {
            request_count += 1;
            let id = std::env::var("CENSYS_API_ID").unwrap_or_default();
            let secret = std::env::var("CENSYS_API_SECRET").unwrap_or_default();
            sources.push(
                self.source_result(
                    "censys",
                    self.client
                        .get(format!(
                            "https://search.censys.io/api/v2/hosts/{}",
                            call.target
                        ))
                        .basic_auth(id, Some(secret)),
                    sanitize_censys,
                ),
            );
        }
        if status.passive_dns && call.target.parse::<std::net::IpAddr>().is_err() {
            request_count += 1;
            let key = std::env::var("SECURITYTRAILS_API_KEY").unwrap_or_default();
            sources.push(
                self.source_result(
                    "securitytrails",
                    self.client
                        .get(format!(
                            "https://api.securitytrails.com/v1/history/{}/dns/a",
                            call.target
                        ))
                        .header("apikey", key.clone()),
                    sanitize_securitytrails,
                ),
            );
            request_count += 1;
            let domain = call.target.clone();
            sources.push(
                self.source_result(
                    "securitytrails_subdomains",
                    self.client
                        .get(format!(
                            "https://api.securitytrails.com/v1/domain/{}/subdomains",
                            call.target
                        ))
                        .header("apikey", key),
                    |value| sanitize_securitytrails_subdomains(value, &domain),
                ),
            );
        }
        if status.github && call.target.parse::<std::net::IpAddr>().is_err() {
            request_count += 1;
            let token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
            sources.push(
                self.source_result(
                    "github",
                    self.client
                        .get("https://api.github.com/search/code")
                        .bearer_auth(token)
                        .query(&[
                            ("q", format!("{} in:file", call.target)),
                            ("per_page", "30".into()),
                        ]),
                    sanitize_github,
                ),
            );
        }
        let configured = status.any();
        Ok(ToolExecutionOutcome {
            result: ToolResult {
                schema_version: CORE_SCHEMA_VERSION,
                id: ToolResultId(Uuid::new_v4().to_string()),
                tool_name: "query_external_intelligence".into(),
                success: configured,
                data: StructuredData::from([
                    ("target".into(), Value::String(call.target)),
                    ("sources".into(), Value::Array(sources)),
                    (
                        "configured_sources".into(),
                        serde_json::to_value(status).unwrap_or(Value::Null),
                    ),
                    ("raw_responses_retained".into(), Value::Bool(false)),
                    ("credentials_retained".into(), Value::Bool(false)),
                ]),
                error: (!configured).then(|| super::ToolError {
                    code: "EXTERNAL_SOURCES_NOT_CONFIGURED".into(),
                    message: "No optional external Recon source credential is configured.".into(),
                    retryable: false,
                }),
                duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            },
            http_requests: request_count,
            model_calls: 0,
            input_tokens: 0,
            output_tokens: 0,
        })
    }

    fn source_result<F>(&self, provider: &str, request: RequestBuilder, sanitizer: F) -> Value
    where
        F: FnOnce(&Value) -> Value,
    {
        match read_json(request) {
            Ok(document) => {
                serde_json::json!({"provider": provider, "success": true, "findings": sanitizer(&document), "error_code": null})
            }
            Err(code) => {
                serde_json::json!({"provider": provider, "success": false, "findings": {}, "error_code": code})
            }
        }
    }
}

fn read_json(request: RequestBuilder) -> Result<Value, String> {
    let response = request.timeout(EXTERNAL_TIMEOUT).send().map_err(|error| {
        if error.is_timeout() {
            String::from("EXTERNAL_SOURCE_TIMEOUT")
        } else {
            String::from("EXTERNAL_SOURCE_CONNECTION_FAILED")
        }
    })?;
    if !response.status().is_success() {
        return Err(format!(
            "EXTERNAL_SOURCE_HTTP_{}",
            response.status().as_u16()
        ));
    }
    let mut bytes = Vec::with_capacity(64 * 1024);
    response
        .take((MAX_EXTERNAL_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "EXTERNAL_SOURCE_READ_FAILED".to_string())?;
    if bytes.len() > MAX_EXTERNAL_RESPONSE_BYTES {
        return Err("EXTERNAL_SOURCE_RESPONSE_TOO_LARGE".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "EXTERNAL_SOURCE_INVALID_JSON".into())
}

fn sanitize_shodan(value: &Value) -> Value {
    serde_json::json!({
        "addresses": string_values(value.get("ip_str")),
        "hostnames": array_strings(value.get("hostnames"), 100),
        "domains": array_strings(value.get("domains"), 100),
        "ports": number_values(value.get("ports"), 200),
        "organization": value.get("org").and_then(Value::as_str),
        "asn": value.get("asn").and_then(Value::as_str),
        "country_code": value.get("country_code").and_then(Value::as_str),
        "vulnerability_ids": value.get("vulns").and_then(Value::as_object).map(|items| items.keys().take(200).cloned().collect::<Vec<_>>()).unwrap_or_default(),
        "banners_retained": false
    })
}

fn sanitize_censys(value: &Value) -> Value {
    let result = value.get("result").unwrap_or(value);
    let services = result.get("services").and_then(Value::as_array).into_iter().flatten().take(200).map(|service| serde_json::json!({
        "port": service.get("port"), "service_name": service.get("service_name"), "transport_protocol": service.get("transport_protocol"), "observed_at": service.get("observed_at")
    })).collect::<Vec<_>>();
    serde_json::json!({
        "addresses": string_values(result.get("ip")),
        "services": services,
        "asn": result.get("autonomous_system").and_then(|value| value.get("asn")),
        "organization": result.get("autonomous_system").and_then(|value| value.get("name")),
        "country_code": result.get("location").and_then(|value| value.get("country_code")),
        "banners_retained": false
    })
}

fn sanitize_securitytrails(value: &Value) -> Value {
    let records = value.get("records").and_then(Value::as_array).into_iter().flatten().take(500).map(|record| serde_json::json!({
        "first_seen": record.get("first_seen"), "last_seen": record.get("last_seen"),
        "addresses": record.get("values").and_then(Value::as_array).into_iter().flatten().filter_map(|item| item.get("ip").and_then(Value::as_str)).take(100).collect::<Vec<_>>()
    })).collect::<Vec<_>>();
    serde_json::json!({"records": records})
}

fn sanitize_securitytrails_subdomains(value: &Value, domain: &str) -> Value {
    let hostnames = value
        .get("subdomains")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|label| {
            let label = label.trim().trim_matches('.').to_ascii_lowercase();
            if label.is_empty()
                || label.len() > 253
                || !label.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '.')
                })
            {
                return None;
            }
            Some(
                if label == domain || label.ends_with(&format!(".{domain}")) {
                    label
                } else {
                    format!("{label}.{domain}")
                },
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(500)
        .collect::<Vec<_>>();
    serde_json::json!({"hostnames": hostnames})
}

fn sanitize_github(value: &Value) -> Value {
    let repositories = value
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(100)
        .filter_map(|item| {
            Some(serde_json::json!({
                "repository": item.get("repository")?.get("full_name")?.as_str()?,
                "path": item.get("path")?.as_str()?,
                "url": item.get("html_url").and_then(Value::as_str),
            }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({"repositories": repositories, "code_content_retained": false})
}

fn array_strings(value: Option<&Value>, maximum: usize) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(maximum)
        .collect()
}

fn number_values(value: Option<&Value>, maximum: usize) -> Vec<u64> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(maximum)
        .collect()
}

fn string_values(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_str)
        .map(|value| vec![value.to_string()])
        .unwrap_or_default()
}

fn env_present(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

fn error(code: &str, message: impl Into<String>, request_started: bool) -> ToolExecutionError {
    ToolExecutionError {
        code: code.into(),
        message: message.into(),
        request_started,
    }
}
