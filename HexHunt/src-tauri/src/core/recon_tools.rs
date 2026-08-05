use super::{
    AgentAction, StructuredData, Task, ToolError, ToolExecutionError, ToolExecutionOutcome,
    ToolResult, ToolResultId, CORE_SCHEMA_VERSION,
};
use crate::scope_guard::validate;
use regex::Regex;
use reqwest::{blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::{IpAddr, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

const CRT_SH_ENDPOINT: &str = "https://crt.sh/";
const CT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CT_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CT_HOSTNAMES: usize = 2_000;
pub const MAX_JAVASCRIPT_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_API_DESCRIPTION_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JS_FINDINGS: usize = 500;
const MAX_WEB_LINKS: usize = 500;
const MAX_WEB_FORMS: usize = 100;
const DNS_OVER_HTTPS_ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";
const MAX_DNS_RESPONSE_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug)]
pub enum PreparedPassiveReconCall {
    CertificateTransparency {
        domain: String,
    },
    ResolveDns {
        hostname: String,
        wildcard_zone: Option<String>,
    },
    InspectDnsOwnership {
        hostname: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateTransparencyResult {
    pub record_count: usize,
    pub hostnames: Vec<String>,
}

pub trait CertificateTransparencyProvider: Send + Sync {
    fn search(&self, domain: &str) -> Result<CertificateTransparencyResult, ToolExecutionError>;
}

pub trait DnsResolver: Send + Sync {
    fn resolve_addresses(&self, hostname: &str) -> Result<Vec<IpAddr>, String>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsOwnershipRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub ttl: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsOwnershipResult {
    pub records: Vec<DnsOwnershipRecord>,
    pub provider_hints: Vec<String>,
    pub dangling_candidate: bool,
    pub query_count: u64,
}

pub trait DnsOwnershipProvider: Send + Sync {
    fn inspect(&self, hostname: &str) -> Result<DnsOwnershipResult, ToolExecutionError>;
}

pub struct CloudflareDnsOwnershipProvider {
    client: Client,
}

impl Default for CloudflareDnsOwnershipProvider {
    fn default() -> Self {
        Self {
            client: Client::builder()
                .redirect(Policy::limited(2))
                .user_agent("HexHunt/0.1 dns-ownership")
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }
}

impl DnsOwnershipProvider for CloudflareDnsOwnershipProvider {
    fn inspect(&self, hostname: &str) -> Result<DnsOwnershipResult, ToolExecutionError> {
        let mut records = Vec::new();
        let mut has_address = false;
        for record_type in ["CNAME", "A", "AAAA", "NS", "MX", "TXT"] {
            let response = self
                .client
                .get(DNS_OVER_HTTPS_ENDPOINT)
                .header("accept", "application/dns-json")
                .query(&[("name", hostname), ("type", record_type)])
                .timeout(CT_TIMEOUT)
                .send()
                .map_err(|error| ToolExecutionError {
                    code: if error.is_timeout() {
                        "DNS_OWNERSHIP_TIMEOUT".into()
                    } else {
                        "DNS_OWNERSHIP_CONNECTION_FAILED".into()
                    },
                    message: format!("DNS ownership lookup failed: {error}"),
                    request_started: true,
                })?;
            if !response.status().is_success() {
                return Err(ToolExecutionError {
                    code: "DNS_OWNERSHIP_PROVIDER_ERROR".into(),
                    message: format!(
                        "DNS ownership provider returned HTTP {}.",
                        response.status().as_u16()
                    ),
                    request_started: true,
                });
            }
            let mut bytes = Vec::with_capacity(32 * 1024);
            response
                .take((MAX_DNS_RESPONSE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|error| ToolExecutionError {
                    code: "DNS_OWNERSHIP_RESPONSE_READ_FAILED".into(),
                    message: format!("Unable to read DNS ownership response: {error}"),
                    request_started: true,
                })?;
            if bytes.len() > MAX_DNS_RESPONSE_BYTES {
                return Err(ToolExecutionError {
                    code: "DNS_OWNERSHIP_RESPONSE_TOO_LARGE".into(),
                    message: "DNS ownership response exceeded the safe read limit.".into(),
                    request_started: true,
                });
            }
            let payload: Value =
                serde_json::from_slice(&bytes).map_err(|error| ToolExecutionError {
                    code: "DNS_OWNERSHIP_INVALID_RESPONSE".into(),
                    message: format!("DNS ownership provider returned invalid JSON: {error}"),
                    request_started: true,
                })?;
            for answer in payload
                .get("Answer")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(value) = answer.get("data").and_then(Value::as_str) else {
                    continue;
                };
                let normalized_value = if record_type == "TXT" {
                    format!("[redacted:{}]", classify_txt_record(value))
                } else {
                    value.trim_end_matches('.').to_string()
                };
                if matches!(record_type, "A" | "AAAA") {
                    has_address = true;
                }
                records.push(DnsOwnershipRecord {
                    record_type: record_type.into(),
                    name: answer
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(hostname)
                        .trim_end_matches('.')
                        .to_string(),
                    value: normalized_value,
                    ttl: answer.get("TTL").and_then(Value::as_u64).unwrap_or(0),
                });
            }
        }
        records.sort_by(|left, right| {
            left.record_type
                .cmp(&right.record_type)
                .then_with(|| left.value.cmp(&right.value))
        });
        records.dedup();
        let provider_hints = records
            .iter()
            .filter_map(|record| cloud_provider_hint(&record.value))
            .map(str::to_string)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let has_cname = records.iter().any(|record| record.record_type == "CNAME");
        Ok(DnsOwnershipResult {
            records,
            provider_hints,
            dangling_candidate: has_cname && !has_address,
            query_count: 6,
        })
    }
}

pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve_addresses(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
        (hostname, 0)
            .to_socket_addrs()
            .map(|addresses| {
                addresses
                    .map(|address| address.ip())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            })
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DnsAddressProfile {
    address: String,
    family: &'static str,
    classification: &'static str,
}

pub struct CrtShProvider {
    client: Client,
}

impl Default for CrtShProvider {
    fn default() -> Self {
        Self {
            client: Client::builder()
                .redirect(Policy::limited(2))
                .user_agent("HexHunt/0.1 passive-recon")
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }
}

impl CertificateTransparencyProvider for CrtShProvider {
    fn search(&self, domain: &str) -> Result<CertificateTransparencyResult, ToolExecutionError> {
        let response = self
            .client
            .get(CRT_SH_ENDPOINT)
            .query(&[("q", format!("%.{domain}")), ("output", "json".into())])
            .timeout(CT_TIMEOUT)
            .send()
            .map_err(|error| ToolExecutionError {
                code: if error.is_timeout() {
                    "CT_TIMEOUT".into()
                } else {
                    "CT_CONNECTION_FAILED".into()
                },
                message: format!("Certificate Transparency search failed: {error}"),
                request_started: true,
            })?;
        if !response.status().is_success() {
            return Err(ToolExecutionError {
                code: "CT_PROVIDER_ERROR".into(),
                message: format!(
                    "Certificate Transparency provider returned HTTP {}.",
                    response.status().as_u16()
                ),
                request_started: true,
            });
        }
        let mut bytes = Vec::with_capacity(MAX_CT_RESPONSE_BYTES.min(64 * 1024));
        response
            .take((MAX_CT_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| ToolExecutionError {
                code: "CT_RESPONSE_READ_FAILED".into(),
                message: format!("Unable to read Certificate Transparency response: {error}"),
                request_started: true,
            })?;
        if bytes.len() > MAX_CT_RESPONSE_BYTES {
            return Err(ToolExecutionError {
                code: "CT_RESPONSE_TOO_LARGE".into(),
                message: "Certificate Transparency response exceeded the safe read limit.".into(),
                request_started: true,
            });
        }
        parse_crt_sh_response(domain, &bytes).map_err(|message| ToolExecutionError {
            code: "CT_INVALID_RESPONSE".into(),
            message,
            request_started: true,
        })
    }
}

pub struct PassiveReconTools {
    certificate_transparency: Arc<dyn CertificateTransparencyProvider>,
    dns_resolver: Arc<dyn DnsResolver>,
    dns_ownership: Arc<dyn DnsOwnershipProvider>,
}

impl Default for PassiveReconTools {
    fn default() -> Self {
        Self {
            certificate_transparency: Arc::new(CrtShProvider::default()),
            dns_resolver: Arc::new(SystemDnsResolver),
            dns_ownership: Arc::new(CloudflareDnsOwnershipProvider::default()),
        }
    }
}

impl PassiveReconTools {
    #[cfg(test)]
    pub(crate) fn with_certificate_transparency(
        provider: Arc<dyn CertificateTransparencyProvider>,
    ) -> Self {
        Self {
            certificate_transparency: provider,
            dns_resolver: Arc::new(SystemDnsResolver),
            dns_ownership: Arc::new(CloudflareDnsOwnershipProvider::default()),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_providers(
        certificate_transparency: Arc<dyn CertificateTransparencyProvider>,
        dns_resolver: Arc<dyn DnsResolver>,
    ) -> Self {
        Self {
            certificate_transparency,
            dns_resolver,
            dns_ownership: Arc::new(CloudflareDnsOwnershipProvider::default()),
        }
    }

    pub fn prepare(
        &self,
        action: &AgentAction,
        task: &Task,
    ) -> Result<PreparedPassiveReconCall, ToolExecutionError> {
        match action.name.as_str() {
            "search_certificate_transparency" => {
                ensure_only_arguments(action, &["domain"])?;
                let domain = scoped_hostname(task, required_string(action, "domain")?)?;
                Ok(PreparedPassiveReconCall::CertificateTransparency { domain })
            }
            "resolve_dns" => {
                ensure_only_arguments(action, &["hostname"])?;
                let hostname = scoped_hostname(task, required_string(action, "hostname")?)?;
                let wildcard_zone = wildcard_probe_zone(task, &hostname);
                Ok(PreparedPassiveReconCall::ResolveDns {
                    hostname,
                    wildcard_zone,
                })
            }
            "inspect_dns_ownership" => {
                ensure_only_arguments(action, &["hostname"])?;
                let hostname = scoped_hostname(task, required_string(action, "hostname")?)?;
                Ok(PreparedPassiveReconCall::InspectDnsOwnership { hostname })
            }
            _ => Err(invalid_recon_arguments(format!(
                "Unsupported passive Recon tool '{}'.",
                action.name
            ))),
        }
    }

    pub fn execute(
        &self,
        prepared: PreparedPassiveReconCall,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        match prepared {
            PreparedPassiveReconCall::CertificateTransparency { domain } => {
                let started = Instant::now();
                let result = match self.certificate_transparency.search(&domain) {
                    Ok(result) => result,
                    Err(error) => {
                        return Ok(ToolExecutionOutcome {
                            result: ToolResult {
                                schema_version: CORE_SCHEMA_VERSION,
                                id: ToolResultId(Uuid::new_v4().to_string()),
                                tool_name: "search_certificate_transparency".into(),
                                success: false,
                                data: StructuredData::from([(
                                    "domain".into(),
                                    Value::String(domain),
                                )]),
                                error: Some(ToolError {
                                    code: error.code,
                                    message: error.message,
                                    retryable: true,
                                }),
                                duration_ms: elapsed_ms(started),
                            },
                            http_requests: u64::from(error.request_started),
                            model_calls: 0,
                            input_tokens: 0,
                            output_tokens: 0,
                        });
                    }
                };
                Ok(ToolExecutionOutcome {
                    result: ToolResult {
                        schema_version: CORE_SCHEMA_VERSION,
                        id: ToolResultId(Uuid::new_v4().to_string()),
                        tool_name: "search_certificate_transparency".into(),
                        success: true,
                        data: StructuredData::from([
                            ("domain".into(), Value::String(domain)),
                            (
                                "record_count".into(),
                                Value::from(result.record_count as u64),
                            ),
                            (
                                "subdomains".into(),
                                Value::Array(
                                    result.hostnames.into_iter().map(Value::String).collect(),
                                ),
                            ),
                            ("provider".into(), Value::String("crt.sh".into())),
                        ]),
                        error: None,
                        duration_ms: elapsed_ms(started),
                    },
                    http_requests: 1,
                    model_calls: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                })
            }
            PreparedPassiveReconCall::ResolveDns {
                hostname,
                wildcard_zone,
            } => {
                let started = Instant::now();
                let lookup = self.dns_resolver.resolve_addresses(&hostname);
                let (addresses, lookup_error) = match lookup {
                    Ok(addresses) => (addresses, Value::Null),
                    Err(error) => (vec![], Value::String(error)),
                };
                let resolved = !addresses.is_empty();
                let (wildcard_detected, wildcard_match, wildcard_addresses, wildcard_probe_count) =
                    wildcard_zone
                        .as_deref()
                        .map(|zone| self.detect_wildcard_dns(zone, &addresses))
                        .unwrap_or((false, false, vec![], 0));
                let address_profiles = addresses
                    .iter()
                    .copied()
                    .map(address_profile)
                    .map(|profile| serde_json::to_value(profile).unwrap_or(Value::Null))
                    .collect::<Vec<_>>();
                Ok(ToolExecutionOutcome {
                    result: ToolResult {
                        schema_version: CORE_SCHEMA_VERSION,
                        id: ToolResultId(Uuid::new_v4().to_string()),
                        tool_name: "resolve_dns".into(),
                        success: true,
                        data: StructuredData::from([
                            ("hostname".into(), Value::String(hostname)),
                            (
                                "addresses".into(),
                                Value::Array(
                                    addresses
                                        .iter()
                                        .map(ToString::to_string)
                                        .map(Value::String)
                                        .collect(),
                                ),
                            ),
                            ("address_profiles".into(), Value::Array(address_profiles)),
                            ("resolved".into(), Value::Bool(resolved)),
                            ("lookup_error".into(), lookup_error),
                            (
                                "wildcard_zone".into(),
                                wildcard_zone.map(Value::String).unwrap_or(Value::Null),
                            ),
                            ("wildcard_detected".into(), Value::Bool(wildcard_detected)),
                            ("wildcard_match".into(), Value::Bool(wildcard_match)),
                            (
                                "wildcard_addresses".into(),
                                Value::Array(
                                    wildcard_addresses
                                        .into_iter()
                                        .map(|address| Value::String(address.to_string()))
                                        .collect(),
                                ),
                            ),
                            (
                                "dns_query_count".into(),
                                Value::from(1_u64 + wildcard_probe_count),
                            ),
                        ]),
                        error: None,
                        duration_ms: elapsed_ms(started),
                    },
                    http_requests: 0,
                    model_calls: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                })
            }
            PreparedPassiveReconCall::InspectDnsOwnership { hostname } => {
                let started = Instant::now();
                let (inspection, provider, degraded, warnings, http_requests) = match self
                    .dns_ownership
                    .inspect(&hostname)
                {
                    Ok(inspection) => {
                        let http_requests = inspection.query_count;
                        (
                            inspection,
                            "cloudflare_dns_over_https",
                            false,
                            Vec::<String>::new(),
                            http_requests,
                        )
                    }
                    Err(primary_error) => match self.dns_resolver.resolve_addresses(&hostname) {
                        Ok(addresses) => {
                            let mut records = addresses
                                .into_iter()
                                .map(|address| DnsOwnershipRecord {
                                    record_type: if address.is_ipv4() {
                                        "A".into()
                                    } else {
                                        "AAAA".into()
                                    },
                                    name: hostname.clone(),
                                    value: address.to_string(),
                                    ttl: 0,
                                })
                                .collect::<Vec<_>>();
                            records.sort_by(|left, right| {
                                left.record_type
                                    .cmp(&right.record_type)
                                    .then_with(|| left.value.cmp(&right.value))
                            });
                            let provider_hints = records
                                .iter()
                                .filter_map(|record| cloud_provider_hint(&record.value))
                                .map(str::to_string)
                                .collect::<BTreeSet<_>>()
                                .into_iter()
                                .collect();
                            (
                                DnsOwnershipResult {
                                    records,
                                    provider_hints,
                                    dangling_candidate: false,
                                    query_count: 1,
                                },
                                "system_dns_fallback",
                                true,
                                vec![primary_error.code],
                                u64::from(primary_error.request_started),
                            )
                        }
                        Err(_) => {
                            return Ok(ToolExecutionOutcome {
                                        result: ToolResult {
                                            schema_version: CORE_SCHEMA_VERSION,
                                            id: ToolResultId(Uuid::new_v4().to_string()),
                                            tool_name: "inspect_dns_ownership".into(),
                                            success: false,
                                            data: StructuredData::from([
                                                ("hostname".into(), Value::String(hostname)),
                                                (
                                                    "providers_attempted".into(),
                                                    Value::Array(vec![
                                                        Value::String(
                                                            "cloudflare_dns_over_https".into(),
                                                        ),
                                                        Value::String(
                                                            "system_dns_fallback".into(),
                                                        ),
                                                    ]),
                                                ),
                                                ("degraded".into(), Value::Bool(true)),
                                            ]),
                                            error: Some(ToolError {
                                                code: "DNS_OWNERSHIP_UNAVAILABLE".into(),
                                                message: "Primary and fallback DNS ownership resolvers were unavailable; the Run may continue with reduced DNS coverage.".into(),
                                                retryable: true,
                                            }),
                                            duration_ms: elapsed_ms(started),
                                        },
                                        http_requests: u64::from(primary_error.request_started),
                                        model_calls: 0,
                                        input_tokens: 0,
                                        output_tokens: 0,
                                    });
                        }
                    },
                };
                Ok(ToolExecutionOutcome {
                    result: ToolResult {
                        schema_version: CORE_SCHEMA_VERSION,
                        id: ToolResultId(Uuid::new_v4().to_string()),
                        tool_name: "inspect_dns_ownership".into(),
                        success: true,
                        data: StructuredData::from([
                            ("hostname".into(), Value::String(hostname)),
                            (
                                "records".into(),
                                serde_json::to_value(inspection.records)
                                    .unwrap_or_else(|_| Value::Array(vec![])),
                            ),
                            (
                                "provider_hints".into(),
                                Value::Array(
                                    inspection
                                        .provider_hints
                                        .into_iter()
                                        .map(Value::String)
                                        .collect(),
                                ),
                            ),
                            (
                                "dangling_candidate".into(),
                                Value::Bool(inspection.dangling_candidate),
                            ),
                            (
                                "dns_query_count".into(),
                                Value::from(inspection.query_count),
                            ),
                            ("txt_values_redacted".into(), Value::Bool(true)),
                            ("degraded".into(), Value::Bool(degraded)),
                            (
                                "warnings".into(),
                                Value::Array(warnings.into_iter().map(Value::String).collect()),
                            ),
                            ("provider".into(), Value::String(provider.into())),
                        ]),
                        error: None,
                        duration_ms: elapsed_ms(started),
                    },
                    http_requests,
                    model_calls: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                })
            }
        }
    }

    fn detect_wildcard_dns(
        &self,
        zone: &str,
        target_addresses: &[IpAddr],
    ) -> (bool, bool, Vec<IpAddr>, u64) {
        const SAMPLE_COUNT: usize = 2;
        let samples = (0..SAMPLE_COUNT)
            .map(|_| {
                let hostname = format!("hexhunt-{}.{}", Uuid::new_v4().simple(), zone);
                self.dns_resolver
                    .resolve_addresses(&hostname)
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        let baseline = samples.first().cloned().unwrap_or_default();
        let detected = !baseline.is_empty() && samples.iter().all(|sample| *sample == baseline);
        let matches_target =
            detected && !target_addresses.is_empty() && baseline == target_addresses;
        (detected, matches_target, baseline, SAMPLE_COUNT as u64)
    }
}

pub fn recon_http_action(
    action: &AgentAction,
) -> Option<Result<(String, AgentAction), ToolExecutionError>> {
    let path = match action.name.as_str() {
        "probe_http"
        | "validate_url_metadata"
        | "analyze_web_page"
        | "analyze_javascript"
        | "describe_api" => None,
        "fetch_robots_txt" => Some("/robots.txt"),
        "fetch_sitemap" => Some("/sitemap.xml"),
        _ => return None,
    };
    Some((|| {
        let allowed = if path.is_some() {
            ["base_url", "timeout_ms"].as_slice()
        } else {
            ["url", "timeout_ms"].as_slice()
        };
        ensure_only_arguments(action, allowed)?;
        let raw_url = required_string(action, if path.is_some() { "base_url" } else { "url" })?;
        let mut url = Url::parse(raw_url)
            .map_err(|_| invalid_recon_arguments("Recon HTTP tool requires an absolute URL."))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(invalid_recon_arguments(
                "Recon HTTP tool supports only absolute HTTP or HTTPS URLs.",
            ));
        }
        if let Some(path) = path {
            url.set_path(path);
            url.set_query(None);
            url.set_fragment(None);
        }
        let method = if action.name == "validate_url_metadata" {
            "HEAD"
        } else {
            "GET"
        };
        let mut arguments = StructuredData::from([
            ("method".into(), Value::String(method.into())),
            ("url".into(), Value::String(url.to_string())),
        ]);
        if let Some(timeout) = action.arguments.get("timeout_ms") {
            arguments.insert("timeout_ms".into(), timeout.clone());
        }
        Ok((
            action.name.clone(),
            AgentAction {
                schema_version: action.schema_version,
                name: "http_request".into(),
                arguments,
                reason: action.reason.clone(),
            },
        ))
    })())
}

pub fn enrich_recon_http_result(result: &mut ToolResult) {
    if matches!(
        result.tool_name.as_str(),
        "probe_http"
            | "validate_url_metadata"
            | "analyze_web_page"
            | "fetch_robots_txt"
            | "fetch_sitemap"
            | "analyze_javascript"
            | "describe_api"
    ) {
        analyze_http_service_result(result);
    }
    match result.tool_name.as_str() {
        "analyze_web_page" => analyze_web_page_result(result),
        "analyze_javascript" => analyze_javascript_result(result),
        "describe_api" => analyze_api_description_result(result),
        _ => {}
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WebFormSummary {
    method: String,
    action: String,
    input_names: Vec<String>,
    input_types: Vec<String>,
    has_password_input: bool,
    has_file_upload: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JavascriptEndpointSummary {
    url: String,
    methods: Vec<String>,
    parameter_names: Vec<String>,
    discovery_kinds: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphqlOperationSummary {
    operation_type: String,
    name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientSecuritySignalSummary {
    kind: String,
    count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ApiOperationSummary {
    path: String,
    method: String,
    parameter_names: Vec<String>,
    parameter_locations: Vec<String>,
    parameters: Vec<ApiParameterSummary>,
    request_content_types: Vec<String>,
    response_statuses: Vec<String>,
    tags: Vec<String>,
    authentication_required: bool,
    deprecated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ApiParameterSummary {
    name: String,
    location: String,
    required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ApiSecuritySchemeSummary {
    name: String,
    kind: String,
    scheme: Option<String>,
    location: Option<String>,
}

fn analyze_web_page_result(result: &mut ToolResult) {
    let body = result
        .data
        .remove("response_body")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let base = result
        .data
        .get("final_url")
        .or_else(|| result.data.get("requested_url"))
        .and_then(Value::as_str)
        .and_then(|value| Url::parse(value).ok());
    let content_type = result
        .data
        .get("response_headers")
        .and_then(Value::as_object)
        .and_then(|headers| headers.get("content-type"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lower = body.to_ascii_lowercase();
    let is_html = content_type.contains("html")
        || lower.contains("<html")
        || lower.contains("<!doctype html");
    let title = Regex::new(r"(?is)<title[^>]*>\s*(.*?)\s*</title>")
        .unwrap()
        .captures(&body)
        .and_then(|captures| captures.get(1))
        .map(|value| collapse_whitespace(value.as_str()))
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(200).collect::<String>());

    let mut links = BTreeSet::new();
    let mut parameter_names = BTreeSet::new();
    let mut external_link_count = 0_u64;
    if let Some(base) = &base {
        let link_pattern = Regex::new(r#"(?is)<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']"#).unwrap();
        for raw in link_pattern
            .captures_iter(&body)
            .filter_map(|captures| captures.get(1))
            .map(|value| value.as_str().trim())
            .take(MAX_WEB_LINKS * 4)
        {
            match normalize_same_origin_url(base, raw) {
                Some((url, names)) => {
                    links.insert(url);
                    parameter_names.extend(names);
                }
                None => external_link_count = external_link_count.saturating_add(1),
            }
            if links.len() >= MAX_WEB_LINKS {
                break;
            }
        }
    }

    let mut scripts = BTreeSet::new();
    if let Some(base) = &base {
        let script_pattern = Regex::new(r#"(?is)<script[^>]+src\s*=\s*["']([^"']+)["']"#).unwrap();
        for raw in script_pattern
            .captures_iter(&body)
            .filter_map(|captures| captures.get(1))
            .map(|value| value.as_str().trim())
            .take(MAX_WEB_LINKS)
        {
            if let Some((url, names)) = normalize_same_origin_url(base, raw) {
                scripts.insert(url);
                parameter_names.extend(names);
            }
        }
    }

    let mut forms = Vec::new();
    if let Some(base) = &base {
        let form_pattern = Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form>").unwrap();
        let input_pattern = Regex::new(r"(?is)<(?:input|select|textarea)\b([^>]*)>").unwrap();
        for captures in form_pattern.captures_iter(&body).take(MAX_WEB_FORMS) {
            let attributes = captures
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let contents = captures
                .get(2)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let method = html_attribute(attributes, "method")
                .unwrap_or_else(|| "GET".into())
                .to_ascii_uppercase();
            let raw_action =
                html_attribute(attributes, "action").unwrap_or_else(|| base.to_string());
            let Some((action, action_parameters)) = normalize_same_origin_url(base, &raw_action)
            else {
                external_link_count = external_link_count.saturating_add(1);
                continue;
            };
            parameter_names.extend(action_parameters);
            let mut input_names = BTreeSet::new();
            let mut input_types = BTreeSet::new();
            for input in input_pattern
                .captures_iter(contents)
                .filter_map(|capture| capture.get(1))
                .map(|value| value.as_str())
                .take(200)
            {
                if let Some(name) = html_attribute(input, "name") {
                    input_names.insert(name.chars().take(100).collect::<String>());
                }
                input_types.insert(
                    html_attribute(input, "type")
                        .unwrap_or_else(|| "text".into())
                        .to_ascii_lowercase(),
                );
            }
            forms.push(WebFormSummary {
                method,
                action,
                has_password_input: input_types.contains("password"),
                has_file_upload: input_types.contains("file"),
                input_names: input_names.into_iter().collect(),
                input_types: input_types.into_iter().collect(),
            });
        }
    }

    let mut page_signals = BTreeSet::new();
    for (needle, signal) in [
        ("password", "authentication"),
        ("sign in", "authentication"),
        ("login", "authentication"),
        ("admin", "administration"),
        ("swagger", "api_documentation"),
        ("openapi", "api_documentation"),
        ("graphql", "api"),
        ("stack trace", "error_detail"),
        ("exception", "error_detail"),
    ] {
        if lower.contains(needle) {
            page_signals.insert(signal.to_string());
        }
    }
    if forms.iter().any(|form| form.has_password_input) {
        page_signals.insert("authentication".into());
    }
    result.data.insert(
        "body_sha256".into(),
        Value::String(hex_sha256(body.as_bytes())),
    );
    result
        .data
        .insert("body_bytes".into(), Value::from(body.len() as u64));
    result.data.insert("is_html".into(), Value::Bool(is_html));
    result.data.insert(
        "page_title".into(),
        title.map(Value::String).unwrap_or(Value::Null),
    );
    result.data.insert("links".into(), values(links));
    result.data.insert("script_urls".into(), values(scripts));
    result.data.insert(
        "forms".into(),
        serde_json::to_value(forms).unwrap_or_else(|_| Value::Array(vec![])),
    );
    result.data.insert(
        "parameter_names".into(),
        values(parameter_names.into_iter()),
    );
    result
        .data
        .insert("page_signals".into(), values(page_signals.into_iter()));
    result.data.insert(
        "external_link_count".into(),
        Value::from(external_link_count),
    );
    result
        .data
        .insert("same_origin_links_only".into(), Value::Bool(true));
    result
        .data
        .insert("raw_body_retained".into(), Value::Bool(false));
}

fn normalize_same_origin_url(base: &Url, raw: &str) -> Option<(String, Vec<String>)> {
    let mut url = base.join(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.scheme() != base.scheme()
        || url.host_str()?.to_ascii_lowercase() != base.host_str()?.to_ascii_lowercase()
        || url.port_or_known_default() != base.port_or_known_default()
    {
        return None;
    }
    let parameter_names = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    Some((url.to_string(), parameter_names))
}

fn html_attribute(attributes: &str, name: &str) -> Option<String> {
    let pattern = Regex::new(&format!(
        r#"(?is)\b{}\s*=\s*(?:["']([^"']*)["']|([^\s>]+))"#,
        regex::escape(name)
    ))
    .ok()?;
    let captures = pattern.captures(attributes)?;
    captures
        .get(1)
        .or_else(|| captures.get(2))
        .map(|value| value.as_str().trim().to_string())
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn analyze_http_service_result(result: &mut ToolResult) {
    let Some(url) = result
        .data
        .get("final_url")
        .or_else(|| result.data.get("requested_url"))
        .and_then(Value::as_str)
        .and_then(|value| Url::parse(value).ok())
    else {
        return;
    };
    let headers = result
        .data
        .get("response_headers")
        .and_then(Value::as_object);
    let header = |name: &str| {
        headers
            .and_then(|headers| headers.get(name))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let mut infrastructure_hints = BTreeSet::new();
    if header("cf-ray").is_some()
        || header("server").is_some_and(|value| value.to_ascii_lowercase().contains("cloudflare"))
    {
        infrastructure_hints.insert("Cloudflare".to_string());
    }
    if header("x-amz-cf-id").is_some()
        || header("x-cache").is_some_and(|value| value.to_ascii_lowercase().contains("cloudfront"))
    {
        infrastructure_hints.insert("AWS CloudFront".to_string());
    }
    if header("x-served-by").is_some()
        || header("x-fastly-request-id").is_some()
        || header("via").is_some_and(|value| value.to_ascii_lowercase().contains("fastly"))
    {
        infrastructure_hints.insert("Fastly".to_string());
    }
    if header("x-akamai-transformed").is_some() || header("akamai-grn").is_some() {
        infrastructure_hints.insert("Akamai".to_string());
    }
    if header("x-vercel-id").is_some()
        || header("server").is_some_and(|value| value.eq_ignore_ascii_case("vercel"))
    {
        infrastructure_hints.insert("Vercel".to_string());
    }
    if header("x-nf-request-id").is_some() {
        infrastructure_hints.insert("Netlify".to_string());
    }
    let security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]
    .into_iter()
    .filter(|name| header(name).is_some())
    .map(Value::from)
    .collect::<Vec<_>>();
    let scheme = url.scheme().to_string();
    let port = url.port_or_known_default().map(u64::from);
    let status_code = result.data.get("status_code").and_then(Value::as_u64);
    let tls_present = result
        .data
        .get("tls")
        .and_then(Value::as_object)
        .and_then(|tls| tls.get("present"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let profile = serde_json::json!({
        "scheme": scheme,
        "hostname": url.host_str(),
        "port": port,
        "live": status_code.is_some(),
        "status_class": status_code.map(|status| format!("{}xx", status / 100)),
        "server": header("server"),
        "content_type": header("content-type"),
        "content_length": header("content-length"),
        "redirect_location": header("location"),
        "tls_present": tls_present,
        "security_headers_present": security_headers,
        "infrastructure_hints": infrastructure_hints,
    });
    result.data.insert("service_profile".into(), profile);
}

fn analyze_javascript_result(result: &mut ToolResult) {
    let body = result
        .data
        .remove("response_body")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let base_url = result
        .data
        .get("final_url")
        .or_else(|| result.data.get("requested_url"))
        .and_then(Value::as_str)
        .and_then(|value| Url::parse(value).ok());
    let digest = hex_sha256(body.as_bytes());
    let absolute_pattern = Regex::new(r#"https?://[^\s\"'<>\\]{1,500}"#).unwrap();
    let route_pattern = Regex::new(
        r#"[\"']((?:/|\./)(?:api|v\d+|graphql|openapi|swagger|oauth2?|auth|login|logout|admin|internal|account|users?|session)[^\"'\\\s]{0,300})[\"']"#,
    )
    .unwrap();
    let fetch_pattern =
        Regex::new(r#"(?is)fetch\s*\(\s*[\"']([^\"']+)[\"']\s*(?:,\s*\{(.*?)\})?\s*\)"#).unwrap();
    let client_pattern = Regex::new(
        r#"(?is)(?:axios|http|client)\.(get|post|put|patch|delete|head|options)\s*\(\s*[\"']([^\"']+)[\"']"#,
    )
    .unwrap();
    let route_declaration_pattern =
        Regex::new(r#"(?is)\bpath\s*:\s*[\"'](/[^\"']{1,300})[\"']"#).unwrap();
    let method_pattern =
        Regex::new(r#"(?is)\bmethod\s*:\s*[\"'](get|post|put|patch|delete|head|options)[\"']"#)
            .unwrap();
    let source_map_pattern = Regex::new(r#"(?m)sourceMappingURL\s*=\s*([^\s*]+)"#).unwrap();
    let import_pattern =
        Regex::new(r#"(?is)(?:import\s*\(|from\s+)[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']"#).unwrap();
    let graphql_operation_pattern =
        Regex::new(r#"(?i)\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{0,100})"#)
            .unwrap();
    let api_base_pattern = Regex::new(
        r#"(?i)(?:api[_-]?base(?:[_-]?url)?|baseurl|graphql[_-]?url)\s*[:=]\s*[\"']([^\"']{1,500})[\"']"#,
    )
    .unwrap();
    let websocket_pattern = Regex::new(r#"(?i)wss?://[^\s\"'<>\\]{1,500}"#).unwrap();

    let mut endpoint_profiles: BTreeMap<
        String,
        (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>),
    > = BTreeMap::new();
    let mut register_endpoint = |raw: &str, method: Option<&str>, kind: &str| {
        let Some((url, parameters)) = sanitize_discovered_url(base_url.as_ref(), raw) else {
            return;
        };
        let profile = endpoint_profiles.entry(url).or_default();
        if let Some(method) = method {
            profile.0.insert(method.to_ascii_uppercase());
        }
        profile.1.extend(parameters);
        profile.2.insert(kind.into());
    };

    for found in absolute_pattern.find_iter(&body).take(MAX_JS_FINDINGS) {
        register_endpoint(trim_url_punctuation(found.as_str()), None, "absolute_url");
    }
    for captures in route_pattern.captures_iter(&body).take(MAX_JS_FINDINGS) {
        if let Some(value) = captures.get(1) {
            register_endpoint(value.as_str(), None, "route_literal");
        }
    }
    for captures in route_declaration_pattern
        .captures_iter(&body)
        .take(MAX_JS_FINDINGS)
    {
        if let Some(value) = captures.get(1) {
            register_endpoint(value.as_str(), None, "client_route");
        }
    }
    for captures in fetch_pattern.captures_iter(&body).take(MAX_JS_FINDINGS) {
        let Some(raw) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let method = captures
            .get(2)
            .and_then(|options| method_pattern.captures(options.as_str()))
            .and_then(|captures| captures.get(1))
            .map(|value| value.as_str())
            .unwrap_or("GET");
        register_endpoint(raw, Some(method), "fetch_call");
    }
    for captures in client_pattern.captures_iter(&body).take(MAX_JS_FINDINGS) {
        if let (Some(method), Some(raw)) = (captures.get(1), captures.get(2)) {
            register_endpoint(raw.as_str(), Some(method.as_str()), "http_client_call");
        }
    }

    let mut parameter_names = BTreeSet::new();
    let endpoint_profiles = endpoint_profiles
        .into_iter()
        .take(MAX_JS_FINDINGS)
        .map(|(url, (methods, parameters, discovery_kinds))| {
            parameter_names.extend(parameters.iter().cloned());
            JavascriptEndpointSummary {
                url,
                methods: methods.into_iter().collect(),
                parameter_names: parameters.into_iter().collect(),
                discovery_kinds: discovery_kinds.into_iter().collect(),
            }
        })
        .collect::<Vec<_>>();
    let absolute_urls = endpoint_profiles
        .iter()
        .filter(|profile| {
            profile
                .discovery_kinds
                .iter()
                .any(|kind| kind == "absolute_url")
        })
        .map(|profile| profile.url.clone())
        .collect::<BTreeSet<_>>();
    let endpoints = endpoint_profiles
        .iter()
        .map(|profile| profile.url.clone())
        .collect::<BTreeSet<_>>();

    let mut source_maps = BTreeSet::new();
    for captures in source_map_pattern
        .captures_iter(&body)
        .take(MAX_JS_FINDINGS)
    {
        let Some(value) = captures.get(1).map(|value| value.as_str().trim()) else {
            continue;
        };
        if let Some((url, parameters)) = sanitize_discovered_url(base_url.as_ref(), value) {
            source_maps.insert(url);
            parameter_names.extend(parameters);
        }
    }
    let mut source_map_candidates = source_maps.clone();
    if let Some(base) = base_url.as_ref().filter(|url| url.path().ends_with(".js")) {
        let mut candidate = base.clone();
        candidate.set_path(&format!("{}.map", base.path()));
        candidate.set_query(None);
        candidate.set_fragment(None);
        source_map_candidates.insert(candidate.to_string());
    }

    let mut javascript_imports = BTreeSet::new();
    for captures in import_pattern.captures_iter(&body).take(MAX_JS_FINDINGS) {
        if let Some(value) = captures.get(1) {
            if let Some((url, parameters)) =
                sanitize_discovered_url(base_url.as_ref(), value.as_str())
            {
                javascript_imports.insert(url);
                parameter_names.extend(parameters);
            }
        }
    }

    let mut api_candidates = BTreeSet::new();
    let mut auth_candidates = BTreeSet::new();
    for candidate in &endpoints {
        let lower = candidate.to_ascii_lowercase();
        if lower.contains("openapi")
            || lower.contains("swagger")
            || lower.contains("graphql")
            || lower.contains("/api/")
        {
            api_candidates.insert(candidate.clone());
        }
        if ["login", "logout", "oauth", "auth", "session", "sso"]
            .iter()
            .any(|needle| lower.contains(needle))
        {
            auth_candidates.insert(candidate.clone());
        }
    }

    let lower = body.to_ascii_lowercase();
    let auth_signals = [
        ("bearer", "bearer_token"),
        ("oauth", "oauth"),
        ("openid", "oidc"),
        ("jwt", "jwt"),
        ("localstorage", "browser_storage"),
        ("sessionstorage", "browser_storage"),
        ("document.cookie", "cookie"),
        ("credentials:", "credentialed_request"),
        ("csrf", "csrf"),
    ]
    .into_iter()
    .filter(|(needle, _)| lower.contains(needle))
    .map(|(_, signal)| signal.to_string())
    .collect::<BTreeSet<_>>();
    let technology_hints = [
        ("__next_data__", "Next.js"),
        ("react.createelement", "React"),
        ("reactdom", "React"),
        ("__vue__", "Vue"),
        ("createapp(", "Vue"),
        ("@angular/", "Angular"),
        ("svelte", "Svelte"),
        ("__webpack_require__", "Webpack"),
        ("import.meta.env", "Vite"),
        ("apollo", "Apollo GraphQL"),
    ]
    .into_iter()
    .filter(|(needle, _)| lower.contains(needle))
    .map(|(_, technology)| technology.to_string())
    .collect::<BTreeSet<_>>();
    let graphql_operations = graphql_operation_pattern
        .captures_iter(&body)
        .take(MAX_JS_FINDINGS)
        .filter_map(|captures| {
            Some(GraphqlOperationSummary {
                operation_type: captures.get(1)?.as_str().to_ascii_lowercase(),
                name: captures.get(2)?.as_str().to_string(),
            })
        })
        .collect::<Vec<_>>();

    let mut api_base_urls = BTreeSet::new();
    for captures in api_base_pattern.captures_iter(&body).take(MAX_JS_FINDINGS) {
        let Some(value) = captures.get(1) else {
            continue;
        };
        if let Some((url, parameters)) = sanitize_discovered_url(base_url.as_ref(), value.as_str())
        {
            api_base_urls.insert(url);
            parameter_names.extend(parameters);
        }
    }
    let websocket_endpoints = websocket_pattern
        .find_iter(&body)
        .take(MAX_JS_FINDINGS)
        .filter_map(|value| sanitize_websocket_url(value.as_str()))
        .collect::<BTreeSet<_>>();
    let client_signal_patterns = [
        (
            "dynamic_code_execution",
            r#"(?i)\b(?:eval|new\s+Function)\s*\("#,
        ),
        (
            "html_injection_sink",
            r#"(?i)(?:\.innerHTML\s*=|dangerouslySetInnerHTML)"#,
        ),
        (
            "cross_window_messaging",
            r#"(?i)(?:postMessage\s*\(|addEventListener\s*\(\s*[\"']message[\"'])"#,
        ),
        (
            "client_redirect",
            r#"(?i)(?:window\.)?location(?:\.href)?\s*="#,
        ),
        ("service_worker", r#"(?i)serviceWorker\.register\s*\("#),
    ];
    let client_security_signals = client_signal_patterns
        .into_iter()
        .filter_map(|(kind, pattern)| {
            let count = Regex::new(pattern)
                .ok()?
                .find_iter(&body)
                .take(MAX_JS_FINDINGS)
                .count();
            (count > 0).then(|| ClientSecuritySignalSummary {
                kind: kind.into(),
                count,
            })
        })
        .collect::<Vec<_>>();

    let secret_patterns = [
        ("aws_access_key_id", r#"AKIA[0-9A-Z]{16}"#),
        (
            "jwt",
            r#"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"#,
        ),
        (
            "generic_secret_assignment",
            r#"(?i)(?:api[_-]?key|secret|access[_-]?token)\s*[:=]\s*[\"'][^\"']{8,}[\"']"#,
        ),
    ];
    let mut secret_kinds = Vec::new();
    let mut secret_indicator_count = 0_u64;
    for (kind, pattern) in secret_patterns {
        let count = Regex::new(pattern)
            .unwrap()
            .find_iter(&body)
            .take(MAX_JS_FINDINGS)
            .count();
        if count > 0 {
            secret_kinds.push(Value::String(kind.into()));
            secret_indicator_count = secret_indicator_count.saturating_add(count as u64);
        }
    }

    result
        .data
        .insert("body_sha256".into(), Value::String(digest));
    result
        .data
        .insert("body_bytes".into(), Value::from(body.len() as u64));
    result
        .data
        .insert("absolute_urls".into(), values(absolute_urls.into_iter()));
    result
        .data
        .insert("endpoints".into(), values(endpoints.into_iter()));
    result.data.insert(
        "endpoint_profiles".into(),
        serde_json::to_value(endpoint_profiles).unwrap_or_else(|_| Value::Array(vec![])),
    );
    result
        .data
        .insert("source_map_urls".into(), values(source_maps.into_iter()));
    result.data.insert(
        "source_map_candidates".into(),
        values(source_map_candidates.into_iter()),
    );
    result.data.insert(
        "javascript_imports".into(),
        values(javascript_imports.into_iter()),
    );
    result
        .data
        .insert("api_candidates".into(), values(api_candidates.into_iter()));
    result.data.insert(
        "auth_candidates".into(),
        values(auth_candidates.into_iter()),
    );
    result.data.insert(
        "parameter_names".into(),
        values(parameter_names.into_iter()),
    );
    result
        .data
        .insert("auth_signals".into(), values(auth_signals.into_iter()));
    result.data.insert(
        "technology_hints".into(),
        values(technology_hints.into_iter()),
    );
    result.data.insert(
        "graphql_operations".into(),
        serde_json::to_value(graphql_operations).unwrap_or_else(|_| Value::Array(vec![])),
    );
    result
        .data
        .insert("api_base_urls".into(), values(api_base_urls.into_iter()));
    result.data.insert(
        "websocket_endpoints".into(),
        values(websocket_endpoints.into_iter()),
    );
    result.data.insert(
        "client_security_signals".into(),
        serde_json::to_value(client_security_signals).unwrap_or_else(|_| Value::Array(vec![])),
    );
    result
        .data
        .insert("secret_indicator_kinds".into(), Value::Array(secret_kinds));
    result.data.insert(
        "secret_indicator_count".into(),
        Value::from(secret_indicator_count),
    );
    result
        .data
        .insert("raw_body_retained".into(), Value::Bool(false));
}

fn analyze_api_description_result(result: &mut ToolResult) {
    let body = result
        .data
        .remove("response_body")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let digest = hex_sha256(body.as_bytes());
    let base_url = result
        .data
        .get("final_url")
        .or_else(|| result.data.get("requested_url"))
        .and_then(Value::as_str)
        .and_then(|value| Url::parse(value).ok());
    let parsed = serde_json::from_str::<Value>(&body).ok();
    let version = parsed.as_ref().and_then(|document| {
        document
            .get("openapi")
            .or_else(|| document.get("swagger"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let yaml_version = if version.is_none() {
        Regex::new(r#"(?m)^\s*(?:openapi|swagger)\s*:\s*[\"']?([^\s\"']+)"#)
            .unwrap()
            .captures(&body)
            .and_then(|captures| captures.get(1))
            .map(|value| value.as_str().trim().to_string())
    } else {
        None
    };
    let mut paths = parsed
        .as_ref()
        .and_then(|document| document.get("paths"))
        .and_then(Value::as_object)
        .map(|paths| {
            paths
                .keys()
                .take(MAX_JS_FINDINGS)
                .cloned()
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if paths.is_empty() && yaml_version.is_some() {
        let yaml_path_pattern = Regex::new(r"(?m)^\s{2,}(/[^\s:]+)\s*:\s*$").unwrap();
        paths.extend(
            yaml_path_pattern
                .captures_iter(&body)
                .filter_map(|captures| captures.get(1))
                .map(|value| value.as_str().to_string())
                .take(MAX_JS_FINDINGS),
        );
    }
    let servers = parsed
        .as_ref()
        .and_then(|document| document.get("servers"))
        .and_then(Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .filter_map(|server| server.get("url"))
                .filter_map(Value::as_str)
                .take(100)
                .filter_map(|value| sanitize_discovered_url(base_url.as_ref(), value))
                .map(|(url, _)| url)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let schema_names = parsed
        .as_ref()
        .and_then(|document| document.pointer("/components/schemas"))
        .and_then(Value::as_object)
        .map(|schemas| {
            schemas
                .keys()
                .take(MAX_JS_FINDINGS)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let global_security = parsed
        .as_ref()
        .and_then(|document| document.get("security"))
        .and_then(Value::as_array)
        .is_some_and(|security| !security.is_empty());
    let security_schemes = parsed
        .as_ref()
        .and_then(|document| document.pointer("/components/securitySchemes"))
        .and_then(Value::as_object)
        .map(|schemes| {
            schemes
                .iter()
                .take(100)
                .map(|(name, scheme)| ApiSecuritySchemeSummary {
                    name: name.clone(),
                    kind: scheme
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                    scheme: scheme
                        .get("scheme")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    location: scheme.get("in").and_then(Value::as_str).map(str::to_owned),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut operation_profiles = Vec::new();
    if let Some(path_items) = parsed
        .as_ref()
        .and_then(|document| document.get("paths"))
        .and_then(Value::as_object)
    {
        for (path, path_item) in path_items.iter().take(MAX_JS_FINDINGS) {
            let path_parameter_profiles = api_parameter_profiles(path_item.get("parameters"));
            for method in ["get", "post", "put", "patch", "delete", "head", "options"] {
                let Some(operation) = path_item.get(method).and_then(Value::as_object) else {
                    continue;
                };
                let mut parameter_profiles = path_parameter_profiles.clone();
                parameter_profiles.extend(api_parameter_profiles(operation.get("parameters")));
                parameter_profiles.sort_by(|left, right| {
                    left.location
                        .cmp(&right.location)
                        .then_with(|| left.name.cmp(&right.name))
                });
                parameter_profiles.dedup_by(|left, right| {
                    left.location == right.location && left.name == right.name
                });
                let parameter_names = parameter_profiles
                    .iter()
                    .map(|parameter| parameter.name.clone())
                    .collect::<BTreeSet<_>>();
                let parameter_locations = parameter_profiles
                    .iter()
                    .map(|parameter| parameter.location.clone())
                    .collect::<BTreeSet<_>>();
                let request_content_types = operation
                    .get("requestBody")
                    .and_then(|request| request.get("content"))
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|content| content.keys().cloned())
                    .collect::<BTreeSet<_>>();
                let response_statuses = operation
                    .get("responses")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|responses| responses.keys().cloned())
                    .collect::<BTreeSet<_>>();
                let tags = operation
                    .get("tags")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>();
                let operation_security = operation.get("security").and_then(Value::as_array);
                let authentication_required = operation_security
                    .map(|security| !security.is_empty())
                    .unwrap_or(global_security);
                let deprecated = operation
                    .get("deprecated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                operation_profiles.push(ApiOperationSummary {
                    path: path.clone(),
                    method: method.to_ascii_uppercase(),
                    parameter_names: parameter_names.into_iter().collect(),
                    parameter_locations: parameter_locations.into_iter().collect(),
                    parameters: parameter_profiles,
                    request_content_types: request_content_types.into_iter().collect(),
                    response_statuses: response_statuses.into_iter().collect(),
                    tags: tags.into_iter().collect(),
                    authentication_required,
                    deprecated,
                });
            }
        }
    }
    let graphql_schema = parsed
        .as_ref()
        .and_then(|document| document.pointer("/data/__schema"))
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|document| document.get("__schema"))
        });
    let graphql_root_types = graphql_schema
        .map(|schema| {
            ["queryType", "mutationType", "subscriptionType"]
                .into_iter()
                .filter_map(|kind| schema.get(kind))
                .filter_map(|kind| kind.get("name"))
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let graphql_type_count = graphql_schema
        .and_then(|schema| schema.get("types"))
        .and_then(Value::as_array)
        .map(|types| types.len() as u64)
        .unwrap_or(0);
    let recognized_openapi = version.is_some() || yaml_version.is_some();
    let graphql_detected = graphql_schema.is_some()
        || base_url.as_ref().is_some_and(|url| {
            url.path().to_ascii_lowercase().contains("graphql")
                && parsed
                    .as_ref()
                    .is_some_and(|document| document.get("errors").is_some())
        });
    let api_format = if graphql_schema.is_some() {
        "graphql_introspection"
    } else if version.is_some() {
        "openapi_json"
    } else if yaml_version.is_some() {
        "openapi_yaml"
    } else if graphql_detected {
        "graphql_endpoint"
    } else {
        "unknown"
    };
    let authenticated_operation_count = operation_profiles
        .iter()
        .filter(|operation| operation.authentication_required)
        .count() as u64;
    let deprecated_operation_count = operation_profiles
        .iter()
        .filter(|operation| operation.deprecated)
        .count() as u64;
    result
        .data
        .insert("body_sha256".into(), Value::String(digest));
    result
        .data
        .insert("body_bytes".into(), Value::from(body.len() as u64));
    result.data.insert(
        "recognized_api_description".into(),
        Value::Bool(recognized_openapi || graphql_detected),
    );
    result.data.insert(
        "api_version".into(),
        version
            .or(yaml_version)
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    result
        .data
        .insert("api_format".into(), Value::String(api_format.into()));
    result
        .data
        .insert("api_paths".into(), values(paths.into_iter()));
    result
        .data
        .insert("server_urls".into(), values(servers.into_iter()));
    result.data.insert(
        "schema_count".into(),
        Value::from(schema_names.len() as u64),
    );
    result
        .data
        .insert("schema_names".into(), values(schema_names));
    result.data.insert(
        "operation_profiles".into(),
        serde_json::to_value(&operation_profiles).unwrap_or_else(|_| Value::Array(vec![])),
    );
    result.data.insert(
        "operation_count".into(),
        Value::from(operation_profiles.len() as u64),
    );
    result.data.insert(
        "authenticated_operation_count".into(),
        Value::from(authenticated_operation_count),
    );
    result.data.insert(
        "public_operation_count".into(),
        Value::from(operation_profiles.len() as u64 - authenticated_operation_count),
    );
    result.data.insert(
        "deprecated_operation_count".into(),
        Value::from(deprecated_operation_count),
    );
    result.data.insert(
        "security_schemes".into(),
        serde_json::to_value(security_schemes).unwrap_or_else(|_| Value::Array(vec![])),
    );
    result
        .data
        .insert("graphql_detected".into(), Value::Bool(graphql_detected));
    result.data.insert(
        "graphql_root_types".into(),
        values(graphql_root_types.into_iter()),
    );
    result
        .data
        .insert("graphql_type_count".into(), Value::from(graphql_type_count));
    result
        .data
        .insert("raw_body_retained".into(), Value::Bool(false));
}

fn sanitize_discovered_url(base: Option<&Url>, raw: &str) -> Option<(String, Vec<String>)> {
    let mut url = match Url::parse(raw.trim()) {
        Ok(url) => url,
        Err(_) => base?.join(raw.trim()).ok()?,
    };
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let parameter_names = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    Some((url.to_string(), parameter_names))
}

fn sanitize_websocket_url(raw: &str) -> Option<String> {
    let mut url = Url::parse(trim_url_punctuation(raw.trim())).ok()?;
    if !matches!(url.scheme(), "ws" | "wss") || url.host_str().is_none() {
        return None;
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

fn api_parameter_profiles(value: Option<&Value>) -> Vec<ApiParameterSummary> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|parameter| {
            let name = parameter.get("name").and_then(Value::as_str)?;
            let location = parameter
                .get("in")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            Some(ApiParameterSummary {
                name: name.chars().take(100).collect(),
                location: location.chars().take(40).collect(),
                required: parameter
                    .get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .take(MAX_JS_FINDINGS)
        .collect()
}

fn values(items: impl IntoIterator<Item = String>) -> Value {
    Value::Array(items.into_iter().map(Value::String).collect())
}

fn classify_txt_record(value: &str) -> &'static str {
    let lower = value.to_ascii_lowercase();
    if lower.contains("v=spf1") {
        "spf"
    } else if lower.contains("v=dmarc1") {
        "dmarc"
    } else if lower.contains("google-site-verification") {
        "site_verification"
    } else if lower.contains("verification") || lower.contains("verify") {
        "domain_verification"
    } else {
        "other"
    }
}

fn cloud_provider_hint(value: &str) -> Option<&'static str> {
    let value = value.to_ascii_lowercase();
    [
        ("amazonaws.com", "aws"),
        ("cloudfront.net", "aws_cloudfront"),
        ("azurewebsites.net", "azure"),
        ("azurefd.net", "azure_front_door"),
        ("trafficmanager.net", "azure_traffic_manager"),
        ("herokudns.com", "heroku"),
        ("herokuapp.com", "heroku"),
        ("github.io", "github_pages"),
        ("netlify.app", "netlify"),
        ("netlifyglobalcdn.com", "netlify"),
        ("vercel-dns.com", "vercel"),
        ("vercel.app", "vercel"),
        ("fastly.net", "fastly"),
        ("cloudflare.net", "cloudflare"),
        ("zendesk.com", "zendesk"),
        ("readme.io", "readme"),
        ("pantheonsite.io", "pantheon"),
        ("myshopify.com", "shopify"),
    ]
    .into_iter()
    .find_map(|(suffix, provider)| value.contains(suffix).then_some(provider))
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn trim_url_punctuation(value: &str) -> &str {
    value.trim_end_matches([')', ']', '}', ',', ';'])
}

pub fn recon_action_target(action: &AgentAction) -> String {
    action
        .arguments
        .get("url")
        .or_else(|| action.arguments.get("base_url"))
        .or_else(|| action.arguments.get("domain"))
        .or_else(|| action.arguments.get("hostname"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn parse_crt_sh_response(
    domain: &str,
    bytes: &[u8],
) -> Result<CertificateTransparencyResult, String> {
    #[derive(Deserialize)]
    struct Entry {
        name_value: String,
    }

    let entries = serde_json::from_slice::<Vec<Entry>>(bytes)
        .map_err(|error| format!("Certificate Transparency JSON is invalid: {error}"))?;
    let normalized_domain = normalize_hostname(domain)
        .ok_or_else(|| "Certificate Transparency domain is invalid.".to_string())?;
    let mut hostnames = BTreeSet::new();
    for entry in &entries {
        for candidate in entry.name_value.lines() {
            let candidate = candidate.trim().trim_start_matches("*.");
            let Some(candidate) = normalize_hostname(candidate) else {
                continue;
            };
            if candidate == normalized_domain
                || candidate.ends_with(&format!(".{normalized_domain}"))
            {
                hostnames.insert(candidate);
                if hostnames.len() >= MAX_CT_HOSTNAMES {
                    break;
                }
            }
        }
        if hostnames.len() >= MAX_CT_HOSTNAMES {
            break;
        }
    }
    Ok(CertificateTransparencyResult {
        record_count: entries.len(),
        hostnames: hostnames.into_iter().collect(),
    })
}

pub(crate) fn scoped_hostname(task: &Task, raw: &str) -> Result<String, ToolExecutionError> {
    let hostname = normalize_hostname(raw)
        .ok_or_else(|| invalid_recon_arguments("Recon hostname is invalid."))?;
    let port = if task.scope.allowed_ports.contains(&443) {
        443
    } else if task.scope.allowed_ports.contains(&80) {
        80
    } else {
        task.scope.allowed_ports.first().copied().unwrap_or(443)
    };
    let scheme = if port == 80 { "http" } else { "https" };
    let target = if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        format!("{scheme}://{hostname}")
    } else {
        format!("{scheme}://{hostname}:{port}")
    };
    let decision = validate(&task.scope, &target);
    if !decision.allowed {
        return Err(ToolExecutionError {
            code: "SCOPE_BLOCKED".into(),
            message: format!("{} ({})", decision.reason, decision.code),
            request_started: false,
        });
    }
    Ok(hostname)
}

fn wildcard_probe_zone(task: &Task, hostname: &str) -> Option<String> {
    task.scope
        .allowed_domains
        .iter()
        .filter_map(|pattern| {
            pattern
                .trim()
                .to_ascii_lowercase()
                .strip_prefix("*.")
                .map(str::to_owned)
        })
        .filter(|zone| hostname != zone && hostname.ends_with(&format!(".{zone}")))
        .max_by_key(String::len)
}

fn address_profile(address: IpAddr) -> DnsAddressProfile {
    let classification = match address {
        IpAddr::V4(address) if address.is_private() => "private",
        IpAddr::V4(address) if address.is_loopback() => "loopback",
        IpAddr::V4(address) if address.is_link_local() => "link_local",
        IpAddr::V4(address) if address.is_documentation() => "documentation",
        IpAddr::V4(address) if address.is_multicast() => "multicast",
        IpAddr::V4(address) if address.is_unspecified() => "unspecified",
        IpAddr::V6(address) if address.is_loopback() => "loopback",
        IpAddr::V6(address) if address.is_unspecified() => "unspecified",
        IpAddr::V6(address) if address.is_multicast() => "multicast",
        IpAddr::V6(address) if address.segments()[0] & 0xfe00 == 0xfc00 => "private",
        IpAddr::V6(address) if address.segments()[0] & 0xffc0 == 0xfe80 => "link_local",
        IpAddr::V6(address)
            if address.segments()[0] == 0x2001 && address.segments()[1] == 0x0db8 =>
        {
            "documentation"
        }
        _ => "public",
    };
    DnsAddressProfile {
        address: address.to_string(),
        family: if address.is_ipv4() { "ipv4" } else { "ipv6" },
        classification,
    }
}

fn normalize_hostname(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if raw.is_empty() || raw.len() > 253 || raw.contains(['/', ':', ' ', '\\']) {
        return None;
    }
    let parsed = Url::parse(&format!("https://{raw}"))
        .ok()?
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if parsed != raw || parsed.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(parsed)
}

fn ensure_only_arguments(action: &AgentAction, allowed: &[&str]) -> Result<(), ToolExecutionError> {
    if let Some(key) = action
        .arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(invalid_recon_arguments(format!(
            "Unknown {} argument '{key}'.",
            action.name
        )));
    }
    Ok(())
}

fn required_string<'a>(action: &'a AgentAction, name: &str) -> Result<&'a str, ToolExecutionError> {
    action
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            invalid_recon_arguments(format!("{} requires a non-empty {name}.", action.name))
        })
}

fn invalid_recon_arguments(message: impl Into<String>) -> ToolExecutionError {
    ToolExecutionError {
        code: "INVALID_RECON_ARGUMENTS".into(),
        message: message.into(),
        request_started: false,
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope_guard::ScopeProject;

    struct EmptyCertificateProvider;

    impl CertificateTransparencyProvider for EmptyCertificateProvider {
        fn search(
            &self,
            _domain: &str,
        ) -> Result<CertificateTransparencyResult, ToolExecutionError> {
            Ok(CertificateTransparencyResult {
                record_count: 0,
                hostnames: vec![],
            })
        }
    }

    struct WildcardDnsResolver;

    impl DnsResolver for WildcardDnsResolver {
        fn resolve_addresses(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
            if hostname.ends_with(".example.test") {
                Ok(vec!["192.0.2.25".parse().unwrap()])
            } else {
                Ok(vec![])
            }
        }
    }

    fn recon_task() -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: super::super::TaskId("task-recon-tool".into()),
            objective: "Passive Recon".into(),
            primary_target: "https://example.test".into(),
            scope: ScopeProject {
                id: "scope-recon-tool".into(),
                allowed_domains: vec!["example.test".into(), "*.example.test".into()],
                excluded_domains: vec!["admin.example.test".into()],
                allowed_ports: vec![443],
                request_rate: 5,
                authorized: true,
            },
            budget: super::super::TaskBudget {
                max_steps: 0,
                max_http_requests: 0,
                max_model_calls: 0,
                max_input_tokens: 0,
                max_output_tokens: 0,
                max_duration_ms: 0,
            },
            available_tools: vec!["resolve_dns".into()],
            memory_policy: Default::default(),
        }
    }

    #[test]
    fn crt_sh_names_are_normalized_deduplicated_and_restricted_to_the_domain() {
        let json = br#"[
            {"name_value":"*.api.example.test\nexample.test"},
            {"name_value":"API.example.test\noutside.test"}
        ]"#;
        let result = parse_crt_sh_response("example.test", json).unwrap();
        assert_eq!(result.record_count, 2);
        assert_eq!(result.hostnames, vec!["api.example.test", "example.test"]);
    }

    #[test]
    fn passive_hostname_actions_are_scope_checked_before_execution() {
        let task = recon_task();
        let tools = PassiveReconTools::default();
        let allowed = AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "resolve_dns".into(),
            arguments: StructuredData::from([(
                "hostname".into(),
                Value::String("api.example.test".into()),
            )]),
            reason: "Resolve an in-scope candidate.".into(),
        };
        assert!(tools.prepare(&allowed, &task).is_ok());
        let blocked = AgentAction {
            arguments: StructuredData::from([(
                "hostname".into(),
                Value::String("outside.test".into()),
            )]),
            ..allowed
        };
        assert_eq!(
            tools.prepare(&blocked, &task).unwrap_err().code,
            "SCOPE_BLOCKED"
        );
    }

    #[test]
    fn dns_resolution_detects_a_consistent_wildcard_baseline() {
        let tools = PassiveReconTools::with_providers(
            Arc::new(EmptyCertificateProvider),
            Arc::new(WildcardDnsResolver),
        );
        let action = AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "resolve_dns".into(),
            arguments: StructuredData::from([(
                "hostname".into(),
                Value::String("api.example.test".into()),
            )]),
            reason: "Verify one candidate against the wildcard baseline.".into(),
        };
        let result = tools
            .execute(tools.prepare(&action, &recon_task()).unwrap())
            .unwrap()
            .result;
        assert_eq!(result.data["resolved"], true);
        assert_eq!(result.data["wildcard_detected"], true);
        assert_eq!(result.data["wildcard_match"], true);
        assert_eq!(result.data["dns_query_count"], 3);
        assert_eq!(
            result.data["address_profiles"][0]["classification"],
            "documentation"
        );
    }

    #[test]
    fn http_probe_builds_a_structured_service_and_infrastructure_profile() {
        let mut result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-result-service-profile".into()),
            tool_name: "probe_http".into(),
            success: true,
            data: StructuredData::from([
                (
                    "final_url".into(),
                    Value::String("https://api.example.test/".into()),
                ),
                ("status_code".into(), Value::from(200)),
                (
                    "response_headers".into(),
                    serde_json::json!({
                        "server": "cloudflare",
                        "cf-ray": "redacted-observation",
                        "content-type": "application/json",
                        "strict-transport-security": "max-age=31536000"
                    }),
                ),
                ("tls".into(), serde_json::json!({"present": true})),
            ]),
            error: None,
            duration_ms: 1,
        };
        enrich_recon_http_result(&mut result);
        assert_eq!(result.data["service_profile"]["live"], true);
        assert_eq!(result.data["service_profile"]["tls_present"], true);
        assert_eq!(
            result.data["service_profile"]["infrastructure_hints"][0],
            "Cloudflare"
        );
    }

    #[test]
    fn javascript_analysis_keeps_findings_but_never_the_raw_source_or_secret_value() {
        let source = br#"
            const endpoint = '/api/v1/users?role=admin';
            const api_key = 'lab-placeholder-value';
            fetch('/login?return_to=private-dashboard', { method: 'POST' });
            axios.get('/api/v1/accounts?page=private-page');
            const operation = `query AccountOverview { viewer { id } }`;
            localStorage.setItem('session', 'never-retain-this');
            ReactDOM.render(app, root);
            import('/chunks/admin.js?v=private-build');
            //# sourceMappingURL=app.js.map?token=private-map
        "#;
        let mut result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-result-js-analysis".into()),
            tool_name: "http_request".into(),
            success: true,
            data: StructuredData::from([
                (
                    "requested_url".into(),
                    Value::String("http://127.0.0.1/app.js".into()),
                ),
                (
                    "response_body".into(),
                    Value::String(String::from_utf8_lossy(source).into_owned()),
                ),
            ]),
            error: None,
            duration_ms: 1,
        };

        result.tool_name = "analyze_javascript".into();
        enrich_recon_http_result(&mut result);

        let serialized = serde_json::to_string(&result).unwrap();
        assert_eq!(result.tool_name, "analyze_javascript");
        assert!(result.data.get("response_body").is_none());
        assert_eq!(result.data["raw_body_retained"], false);
        assert_eq!(result.data["secret_indicator_count"], 1);
        assert!(serialized.contains("/api/v1/users"));
        assert_eq!(
            result.data["graphql_operations"][0]["name"],
            "AccountOverview"
        );
        assert!(result.data["auth_signals"]
            .as_array()
            .unwrap()
            .contains(&Value::String("browser_storage".into())));
        assert!(result.data["technology_hints"]
            .as_array()
            .unwrap()
            .contains(&Value::String("React".into())));
        assert!(result.data["endpoint_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile["url"] == "http://127.0.0.1/login"
                && profile["methods"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("POST".into()))));
        assert!(serialized.contains("app.js.map"));
        for secret in [
            "lab-placeholder-value",
            "role=admin",
            "private-dashboard",
            "private-page",
            "private-build",
            "private-map",
            "never-retain-this",
        ] {
            assert!(!serialized.contains(secret));
        }
    }

    #[test]
    fn api_description_maps_operations_parameters_and_security_without_raw_document() {
        let body = r#"{
          "openapi":"3.1.0",
          "info":{"title":"Accounts API","description":"private-description-value"},
          "servers":[{"url":"/api?tenant=private-tenant"}],
          "security":[{"bearerAuth":[]}],
          "paths":{
            "/users/{id}":{
              "parameters":[{"name":"id","in":"path","required":true}],
              "get":{"tags":["users"],"responses":{"200":{}},"security":[]},
              "patch":{"parameters":[{"name":"trace","in":"header"}],"requestBody":{"content":{"application/json":{}}},"responses":{"204":{}},"deprecated":true}
            }
          },
          "components":{
            "schemas":{"User":{"type":"object"}},
            "securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer","bearerFormat":"JWT"}}
          }
        }"#;
        let mut result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-result-api-description".into()),
            tool_name: "describe_api".into(),
            success: true,
            data: StructuredData::from([
                (
                    "final_url".into(),
                    Value::String("https://example.test/openapi.json".into()),
                ),
                ("response_body".into(), Value::String(body.into())),
            ]),
            error: None,
            duration_ms: 2,
        };

        enrich_recon_http_result(&mut result);

        let serialized = serde_json::to_string(&result).unwrap();
        assert!(result.data.get("response_body").is_none());
        assert_eq!(result.data["api_format"], "openapi_json");
        assert_eq!(result.data["operation_count"], 2);
        assert_eq!(result.data["public_operation_count"], 1);
        assert_eq!(result.data["authenticated_operation_count"], 1);
        assert_eq!(result.data["deprecated_operation_count"], 1);
        assert_eq!(result.data["security_schemes"][0]["scheme"], "bearer");
        assert!(result.data["operation_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["method"] == "PATCH"
                && operation["authentication_required"] == true
                && operation["parameter_names"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("trace".into()))));
        assert!(result.data["operation_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["method"] == "GET"
                && operation["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|parameter| {
                        parameter["name"] == "id"
                            && parameter["location"] == "path"
                            && parameter["required"] == true
                    })));
        assert_eq!(
            result.data["server_urls"],
            serde_json::json!(["https://example.test/api"])
        );
        assert!(!serialized.contains("private-description-value"));
        assert!(!serialized.contains("private-tenant"));
    }

    #[test]
    fn api_description_recognizes_graphql_introspection_metadata() {
        let mut result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-result-graphql".into()),
            tool_name: "describe_api".into(),
            success: true,
            data: StructuredData::from([
                (
                    "final_url".into(),
                    Value::String("https://example.test/graphql".into()),
                ),
                (
                    "response_body".into(),
                    serde_json::json!({
                        "data": {"__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {"name": "Mutation"},
                            "types": [{"name": "Query"}, {"name": "Mutation"}, {"name": "User"}]
                        }}
                    })
                    .to_string()
                    .into(),
                ),
            ]),
            error: None,
            duration_ms: 2,
        };

        enrich_recon_http_result(&mut result);

        assert_eq!(result.data["recognized_api_description"], true);
        assert_eq!(result.data["api_format"], "graphql_introspection");
        assert_eq!(result.data["graphql_detected"], true);
        assert_eq!(result.data["graphql_type_count"], 3);
        assert_eq!(
            result.data["graphql_root_types"],
            serde_json::json!(["Mutation", "Query"])
        );
        assert!(result.data.get("response_body").is_none());
    }

    #[test]
    fn web_page_analysis_keeps_structure_without_raw_html_or_query_values() {
        let body = r#"<!doctype html><html><head><title>  Account Portal </title></head>
            <body>
              <a href="/admin?token=private-value&next=dashboard#top">Admin</a>
              <a href="https://outside.test/tracker?secret=external-value">External</a>
              <form method="post" action="/login?csrf=form-secret">
                <input name="username">
                <input type="password" name="password" value="never-store-me">
                <input type="hidden" name="csrf" value="hidden-secret">
              </form>
              <script src="/assets/app.js?v=cache-secret"></script>
            </body></html>"#;
        let mut result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId("tool-result-web-page".into()),
            tool_name: "analyze_web_page".into(),
            success: true,
            data: StructuredData::from([
                (
                    "final_url".into(),
                    Value::String("https://example.test/start".into()),
                ),
                (
                    "response_headers".into(),
                    serde_json::json!({"content-type": "text/html; charset=utf-8"}),
                ),
                ("response_body".into(), Value::String(body.into())),
            ]),
            error: None,
            duration_ms: 2,
        };

        enrich_recon_http_result(&mut result);

        let serialized = serde_json::to_string(&result).unwrap();
        assert!(result.data.get("response_body").is_none());
        assert_eq!(result.data["raw_body_retained"], false);
        assert_eq!(result.data["page_title"], "Account Portal");
        assert_eq!(
            result.data["links"],
            serde_json::json!(["https://example.test/admin"])
        );
        assert_eq!(result.data["external_link_count"], 1);
        assert_eq!(result.data["forms"][0]["method"], "POST");
        assert_eq!(result.data["forms"][0]["has_password_input"], true);
        assert_eq!(
            result.data["script_urls"],
            serde_json::json!(["https://example.test/assets/app.js"])
        );
        for name in ["csrf", "next", "token", "v"] {
            assert!(result.data["parameter_names"]
                .as_array()
                .unwrap()
                .contains(&Value::String(name.into())));
        }
        for secret in [
            "private-value",
            "external-value",
            "form-secret",
            "never-store-me",
            "hidden-secret",
            "cache-secret",
            "outside.test",
        ] {
            assert!(!serialized.contains(secret));
        }
    }
}
