use super::{
    Clock, Evidence, EvidenceId, EvidenceSource, RunId, RunService, RunServiceError, SystemClock,
    ToolResult, CORE_SCHEMA_VERSION,
};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub const MAX_EVIDENCE_EXCERPT_CHARS: usize = 512;

pub struct EvidenceRecorder {
    clock: Arc<dyn Clock>,
}

impl Default for EvidenceRecorder {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl EvidenceRecorder {
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }

    pub fn record_tool_result(
        &self,
        service: &RunService,
        run_id: &RunId,
        step: u64,
        result: &ToolResult,
    ) -> Result<Option<Evidence>, RunServiceError> {
        if !result.success {
            return Ok(None);
        }
        let (description, excerpt) = match result.tool_name.as_str() {
            "http_request"
            | "probe_http"
            | "validate_url_metadata"
            | "fetch_robots_txt"
            | "fetch_sitemap" => {
                let method = string_field(&result.data, "method").unwrap_or("HTTP");
                let url = string_field(&result.data, "final_url")
                    .or_else(|| string_field(&result.data, "requested_url"))
                    .unwrap_or("unknown URL");
                let status = result
                    .data
                    .get("status_code")
                    .and_then(Value::as_u64)
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into());
                let truncated = result
                    .data
                    .get("response_body_truncated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let body = string_field(&result.data, "response_body").unwrap_or_default();
                let note = if truncated {
                    "; response truncated"
                } else {
                    ""
                };
                let infrastructure = result
                    .data
                    .get("service_profile")
                    .and_then(Value::as_object)
                    .and_then(|profile| profile.get("infrastructure_hints"))
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .take(10)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let infrastructure_note = if infrastructure.is_empty() {
                    String::new()
                } else {
                    format!(" Infrastructure: {infrastructure}.")
                };
                (
                    format!(
                        "HTTP observation: {method} {url} returned status {status}{note}.{infrastructure_note}"
                    ),
                    truncate_chars(body, MAX_EVIDENCE_EXCERPT_CHARS),
                )
            }
            "search_certificate_transparency" => {
                let domain = string_field(&result.data, "domain").unwrap_or("unknown domain");
                let names = result
                    .data
                    .get("subdomains")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .take(25)
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default();
                (
                    format!("Certificate Transparency observation for {domain}."),
                    truncate_chars(&names, MAX_EVIDENCE_EXCERPT_CHARS),
                )
            }
            "resolve_dns" => {
                let hostname = string_field(&result.data, "hostname").unwrap_or("unknown hostname");
                let wildcard_match = result
                    .data
                    .get("wildcard_match")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let addresses = result
                    .data
                    .get("addresses")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                (
                    format!(
                        "DNS observation for {hostname}; wildcard baseline match: {wildcard_match}."
                    ),
                    if addresses.is_empty() {
                        "No address resolved.".into()
                    } else {
                        format!(
                            "{}{}",
                            addresses,
                            if wildcard_match {
                                " (matches the wildcard DNS baseline)"
                            } else {
                                ""
                            }
                        )
                    },
                )
            }
            "inspect_dns_ownership" => {
                let hostname = string_field(&result.data, "hostname").unwrap_or("unknown hostname");
                let record_count = result
                    .data
                    .get("records")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                let providers = joined_array(&result.data, "provider_hints", 20);
                let dangling = result
                    .data
                    .get("dangling_candidate")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                (
                    format!("DNS ownership metadata for {hostname}: {record_count} normalized records; unresolved cloud-alias candidate: {dangling}."),
                    if providers.is_empty() { "No recognized cloud-provider hint.".into() } else { format!("Provider hints: {providers}") },
                )
            }
            "inspect_rdap" => {
                let target = string_field(&result.data, "target").unwrap_or("unknown target");
                let handle = string_field(&result.data, "handle").unwrap_or("unknown");
                let range = match (
                    string_field(&result.data, "start_address"),
                    string_field(&result.data, "end_address"),
                ) {
                    (Some(start), Some(end)) => format!("{start} – {end}"),
                    _ => "not supplied".into(),
                };
                (
                    format!("Public RDAP ownership metadata for {target}."),
                    format!("Handle: {handle}; network range: {range}; contact entities were not retained."),
                )
            }
            "probe_tcp_service" => {
                let hostname = string_field(&result.data, "hostname").unwrap_or("unknown host");
                let port = result.data.get("port").and_then(Value::as_u64).unwrap_or(0);
                let open = result
                    .data
                    .get("open")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                (
                    format!("Authorized TCP reachability observation for {hostname}:{port}."),
                    format!("Reachable: {open}; no banner or protocol payload was requested."),
                )
            }
            "discover_content" => {
                let base_url = string_field(&result.data, "base_url").unwrap_or("unknown origin");
                let count = result
                    .data
                    .get("finding_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let paths = result
                    .data
                    .get("findings")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|finding| finding.get("path").and_then(Value::as_str))
                    .take(25)
                    .collect::<Vec<_>>()
                    .join("\n");
                (
                    format!("Evidence-guided content discovery at {base_url} found {count} responding candidates."),
                    truncate_chars(&paths, MAX_EVIDENCE_EXCERPT_CHARS),
                )
            }
            "adaptive_browser_recon" => {
                let url = string_field(&result.data, "requested_url").unwrap_or("unknown page");
                let views = result
                    .data
                    .get("identity_views")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                let differs = result
                    .data
                    .get("identity_comparison")
                    .and_then(|value| value.get("views_differ"))
                    .and_then(Value::as_bool);
                (
                    format!("Adaptive Browser Recon captured sanitized dynamic metadata for {url}."),
                    format!("Identity views: {views}; views differ: {}; response bodies and secret values were not retained.", differs.map(|value| value.to_string()).unwrap_or_else(|| "not compared".into())),
                )
            }
            "query_external_intelligence" => {
                let target = string_field(&result.data, "target").unwrap_or("unknown target");
                let providers = result
                    .data
                    .get("sources")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|source| source.get("provider").and_then(Value::as_str))
                    .take(10)
                    .collect::<Vec<_>>()
                    .join(", ");
                (
                    format!("Passive external intelligence metadata for {target}."),
                    format!("Queried sources: {providers}; raw responses, credentials, banners, and code contents were not retained."),
                )
            }
            "lookup_web_archive" => {
                let domain = string_field(&result.data, "domain").unwrap_or("unknown domain");
                let count = result
                    .data
                    .get("historical_url_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let javascript = result
                    .data
                    .get("historical_javascript_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let endpoints = result
                    .data
                    .get("historical_endpoint_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let urls = result
                    .data
                    .get("historical_urls")
                    .and_then(Value::as_array)
                    .map(|records| {
                        records
                            .iter()
                            .filter_map(|record| record.get("url"))
                            .filter_map(Value::as_str)
                            .take(25)
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default();
                (
                    format!(
                        "Historical archive metadata for {domain}: {count} URLs, {javascript} JavaScript files, and {endpoints} endpoint clues."
                    ),
                    truncate_chars(&urls, MAX_EVIDENCE_EXCERPT_CHARS),
                )
            }
            "analyze_web_page" => {
                let url = string_field(&result.data, "final_url")
                    .or_else(|| string_field(&result.data, "requested_url"))
                    .unwrap_or("unknown web page");
                let title = string_field(&result.data, "page_title").unwrap_or("untitled page");
                let link_count = result
                    .data
                    .get("links")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                let form_count = result
                    .data
                    .get("forms")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                let links = joined_array(&result.data, "links", 25);
                (
                    format!(
                        "Web surface analysis for {url}: '{title}', {link_count} in-scope links and {form_count} forms."
                    ),
                    truncate_chars(&links, MAX_EVIDENCE_EXCERPT_CHARS),
                )
            }
            "analyze_javascript" => {
                let url = string_field(&result.data, "final_url")
                    .or_else(|| string_field(&result.data, "requested_url"))
                    .unwrap_or("unknown JavaScript URL");
                let endpoints = joined_array(&result.data, "endpoints", 25);
                let secret_count = result
                    .data
                    .get("secret_indicator_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let endpoint_count = result
                    .data
                    .get("endpoint_profiles")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                let graphql_count = result
                    .data
                    .get("graphql_operations")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                let signal_count = result
                    .data
                    .get("client_security_signals")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                let source_map_count = result
                    .data
                    .get("source_map_candidates")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                (
                    format!(
                        "JavaScript analysis for {url}: {endpoint_count} endpoint profiles, {graphql_count} GraphQL operations, {source_map_count} source-map candidates, {signal_count} client security signal categories, and {secret_count} potential secret indicators (values not retained)."
                    ),
                    truncate_chars(&endpoints, MAX_EVIDENCE_EXCERPT_CHARS),
                )
            }
            "describe_api" => {
                let url = string_field(&result.data, "final_url")
                    .or_else(|| string_field(&result.data, "requested_url"))
                    .unwrap_or("unknown API description URL");
                let paths = joined_array(&result.data, "api_paths", 25);
                let format = string_field(&result.data, "api_format").unwrap_or("unknown");
                let operations = result
                    .data
                    .get("operation_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let public_operations = result
                    .data
                    .get("public_operation_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                (
                    format!(
                        "API description analysis for {url}: {format}, {operations} operation groups, {public_operations} without declared authentication."
                    ),
                    truncate_chars(&paths, MAX_EVIDENCE_EXCERPT_CHARS),
                )
            }
            "analyze_visual_page" => {
                let url = string_field(&result.data, "final_url")
                    .or_else(|| string_field(&result.data, "requested_url"))
                    .unwrap_or("unknown visual page");
                let observation = result
                    .data
                    .get("visual_observation")
                    .and_then(Value::as_object);
                let page_kind = observation
                    .and_then(|value| value.get("page_kind"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let summary = observation
                    .and_then(|value| value.get("summary"))
                    .and_then(Value::as_str)
                    .unwrap_or("No visual summary was returned.");
                (
                    format!("Visual Recon observation for {url}; classified as {page_kind}."),
                    truncate_chars(summary, MAX_EVIDENCE_EXCERPT_CHARS),
                )
            }
            _ => return Ok(None),
        };

        let evidence = Evidence {
            schema_version: CORE_SCHEMA_VERSION,
            id: EvidenceId(Uuid::new_v4().to_string()),
            run_id: run_id.clone(),
            source: EvidenceSource::ToolResult {
                tool_result_id: result.id.clone(),
            },
            description,
            value_or_excerpt: excerpt,
            recorded_at_ms: self.clock.now_ms(),
        };
        let evidence = service.append_evidence_recorded(run_id, evidence, step)?;
        Ok(Some(evidence))
    }
}

fn string_field<'a>(data: &'a super::StructuredData, key: &str) -> Option<&'a str> {
    data.get(key).and_then(Value::as_str)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn joined_array(data: &super::StructuredData, key: &str, maximum: usize) -> String {
    data.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .take(maximum)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}
