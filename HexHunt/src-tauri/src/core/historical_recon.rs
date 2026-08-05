use super::{
    AgentAction, StructuredData, Task, ToolError, ToolExecutionError, ToolExecutionOutcome,
    ToolResult, ToolResultId, CORE_SCHEMA_VERSION,
};
use crate::scope_guard::{validate, ScopeProject};
use reqwest::{blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

const WAYBACK_CDX_ENDPOINT: &str = "https://web.archive.org/cdx/search/cdx";
const COMMON_CRAWL_COLLECTIONS_ENDPOINT: &str = "https://index.commoncrawl.org/collinfo.json";
const ARCHIVE_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_ARCHIVE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVIDER_RECORDS: usize = 500;
const MAX_COMBINED_RECORDS: usize = 750;

#[derive(Clone, Debug)]
pub struct PreparedHistoricalReconCall {
    pub domain: String,
    pub scope: ScopeProject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalCapture {
    pub url: String,
    pub timestamp: String,
    pub status: Option<u16>,
    pub mime_type: Option<String>,
    pub digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalProviderResult {
    pub provider: String,
    pub captures: Vec<HistoricalCapture>,
    pub http_requests: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalProviderError {
    pub provider: String,
    pub code: String,
    pub message: String,
    pub http_requests: u64,
}

pub trait HistoricalReconProvider: Send + Sync {
    fn lookup(&self, domain: &str) -> Result<HistoricalProviderResult, HistoricalProviderError>;
}

pub struct WaybackCdxProvider {
    client: Client,
}

impl Default for WaybackCdxProvider {
    fn default() -> Self {
        Self {
            client: archive_client(),
        }
    }
}

impl HistoricalReconProvider for WaybackCdxProvider {
    fn lookup(&self, domain: &str) -> Result<HistoricalProviderResult, HistoricalProviderError> {
        let response = self
            .client
            .get(WAYBACK_CDX_ENDPOINT)
            .query(&[
                ("url", format!("{domain}/*")),
                ("matchType", "domain".into()),
                ("output", "json".into()),
                ("fl", "timestamp,original,statuscode,mimetype,digest".into()),
                ("filter", "statuscode:200".into()),
                ("collapse", "digest".into()),
                ("limit", MAX_PROVIDER_RECORDS.to_string()),
            ])
            .timeout(ARCHIVE_TIMEOUT)
            .send()
            .map_err(|error| {
                provider_error("wayback", "WAYBACK_CONNECTION_FAILED", error.to_string(), 1)
            })?;
        let bytes = read_archive_response("wayback", response)?;
        let captures = parse_wayback_response(&bytes)
            .map_err(|message| provider_error("wayback", "WAYBACK_INVALID_RESPONSE", message, 1))?;
        Ok(HistoricalProviderResult {
            provider: "wayback".into(),
            captures,
            http_requests: 1,
        })
    }
}

pub struct CommonCrawlProvider {
    client: Client,
}

impl Default for CommonCrawlProvider {
    fn default() -> Self {
        Self {
            client: archive_client(),
        }
    }
}

#[derive(Deserialize)]
struct CommonCrawlCollection {
    id: String,
    #[serde(rename = "cdx-api")]
    cdx_api: Option<String>,
}

#[derive(Deserialize)]
struct CommonCrawlRecord {
    timestamp: Option<String>,
    url: String,
    status: Option<String>,
    mime: Option<String>,
    digest: Option<String>,
}

impl HistoricalReconProvider for CommonCrawlProvider {
    fn lookup(&self, domain: &str) -> Result<HistoricalProviderResult, HistoricalProviderError> {
        let collections = self
            .client
            .get(COMMON_CRAWL_COLLECTIONS_ENDPOINT)
            .timeout(ARCHIVE_TIMEOUT)
            .send()
            .map_err(|error| {
                provider_error(
                    "common_crawl",
                    "COMMON_CRAWL_COLLECTION_FAILED",
                    error.to_string(),
                    1,
                )
            })?;
        let collections = read_archive_response("common_crawl", collections)?;
        let mut collections: Vec<CommonCrawlCollection> = serde_json::from_slice(&collections)
            .map_err(|_| {
                provider_error(
                    "common_crawl",
                    "COMMON_CRAWL_COLLECTION_INVALID",
                    "Common Crawl returned an invalid collection list.",
                    1,
                )
            })?;
        collections.sort_by(|left, right| right.id.cmp(&left.id));
        let collection = collections.into_iter().next().ok_or_else(|| {
            provider_error(
                "common_crawl",
                "COMMON_CRAWL_COLLECTION_EMPTY",
                "Common Crawl returned no available collection.",
                1,
            )
        })?;
        let endpoint = collection
            .cdx_api
            .unwrap_or_else(|| format!("https://index.commoncrawl.org/{}-index", collection.id));
        let response = self
            .client
            .get(endpoint)
            .query(&[
                ("url", format!("{domain}/*")),
                ("matchType", "domain".into()),
                ("output", "json".into()),
                ("fl", "timestamp,url,status,mime,digest".into()),
                ("filter", "status:200".into()),
                ("collapse", "digest".into()),
                ("limit", MAX_PROVIDER_RECORDS.to_string()),
            ])
            .timeout(ARCHIVE_TIMEOUT)
            .send()
            .map_err(|error| {
                provider_error(
                    "common_crawl",
                    "COMMON_CRAWL_QUERY_FAILED",
                    error.to_string(),
                    2,
                )
            })?;
        let bytes = read_archive_response("common_crawl", response).map_err(|mut error| {
            error.http_requests = 2;
            error
        })?;
        let captures = parse_common_crawl_response(&bytes).map_err(|message| {
            provider_error("common_crawl", "COMMON_CRAWL_INVALID_RESPONSE", message, 2)
        })?;
        Ok(HistoricalProviderResult {
            provider: "common_crawl".into(),
            captures,
            http_requests: 2,
        })
    }
}

pub struct HistoricalReconTool {
    providers: Vec<Arc<dyn HistoricalReconProvider>>,
}

impl Default for HistoricalReconTool {
    fn default() -> Self {
        Self {
            providers: vec![
                Arc::new(WaybackCdxProvider::default()),
                Arc::new(CommonCrawlProvider::default()),
            ],
        }
    }
}

impl HistoricalReconTool {
    #[cfg(test)]
    pub(crate) fn with_providers(providers: Vec<Arc<dyn HistoricalReconProvider>>) -> Self {
        Self { providers }
    }

    pub fn prepare(
        &self,
        action: &AgentAction,
        task: &Task,
    ) -> Result<PreparedHistoricalReconCall, ToolExecutionError> {
        if action.arguments.keys().any(|key| key != "domain") {
            return Err(tool_error(
                "INVALID_HISTORICAL_ARGUMENTS",
                "lookup_web_archive accepts only domain.",
                false,
            ));
        }
        let domain = action
            .arguments
            .get("domain")
            .and_then(Value::as_str)
            .map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                tool_error(
                    "INVALID_HISTORICAL_ARGUMENTS",
                    "lookup_web_archive requires a non-empty domain.",
                    false,
                )
            })?;
        let decision = validate(&task.scope, &format!("https://{domain}"));
        if !decision.allowed {
            return Err(tool_error(
                "SCOPE_BLOCKED",
                format!("{} ({})", decision.reason, decision.code),
                false,
            ));
        }
        Ok(PreparedHistoricalReconCall {
            domain,
            scope: task.scope.clone(),
        })
    }

    pub fn execute(
        &self,
        prepared: PreparedHistoricalReconCall,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        let started = Instant::now();
        let mut provider_results = Vec::new();
        let mut captures = Vec::new();
        let mut http_requests = 0_u64;
        for provider in &self.providers {
            match provider.lookup(&prepared.domain) {
                Ok(result) => {
                    http_requests = http_requests.saturating_add(result.http_requests);
                    provider_results.push(ArchiveProviderSummary {
                        provider: result.provider.clone(),
                        success: true,
                        record_count: result.captures.len() as u64,
                        error_code: None,
                    });
                    captures.extend(
                        result
                            .captures
                            .into_iter()
                            .map(|capture| (result.provider.clone(), capture)),
                    );
                }
                Err(error) => {
                    http_requests = http_requests.saturating_add(error.http_requests);
                    provider_results.push(ArchiveProviderSummary {
                        provider: error.provider,
                        success: false,
                        record_count: 0,
                        error_code: Some(error.code),
                    });
                }
            }
        }
        let any_provider_succeeded = provider_results.iter().any(|result| result.success);
        if !any_provider_succeeded {
            return Ok(ToolExecutionOutcome {
                result: ToolResult {
                    schema_version: CORE_SCHEMA_VERSION,
                    id: ToolResultId(Uuid::new_v4().to_string()),
                    tool_name: "lookup_web_archive".into(),
                    success: false,
                    data: StructuredData::from([
                        ("domain".into(), Value::String(prepared.domain)),
                        (
                            "provider_results".into(),
                            serde_json::to_value(provider_results).unwrap_or(Value::Array(vec![])),
                        ),
                    ]),
                    error: Some(ToolError {
                        code: "HISTORICAL_PROVIDERS_UNAVAILABLE".into(),
                        message: "All configured historical metadata providers failed.".into(),
                        retryable: true,
                    }),
                    duration_ms: elapsed_ms(started),
                },
                http_requests,
                model_calls: 0,
                input_tokens: 0,
                output_tokens: 0,
            });
        }

        let normalized = normalize_captures(captures, &prepared.scope);
        let javascript_count = normalized
            .records
            .iter()
            .filter(|record| record.kind == HistoricalUrlKind::Javascript)
            .count();
        let endpoint_count = normalized
            .records
            .iter()
            .filter(|record| record.kind == HistoricalUrlKind::Endpoint)
            .count();
        let subdomains = normalized
            .records
            .iter()
            .filter_map(|record| Url::parse(&record.url).ok())
            .filter_map(|url| url.host_str().map(str::to_owned))
            .filter(|hostname| !hostname.eq_ignore_ascii_case(&prepared.domain))
            .collect::<BTreeSet<_>>();
        let data = StructuredData::from([
            ("domain".into(), Value::String(prepared.domain)),
            (
                "provider_results".into(),
                serde_json::to_value(provider_results).unwrap_or(Value::Array(vec![])),
            ),
            (
                "historical_urls".into(),
                serde_json::to_value(&normalized.records).unwrap_or(Value::Array(vec![])),
            ),
            (
                "historical_url_count".into(),
                Value::from(normalized.records.len() as u64),
            ),
            (
                "historical_javascript_count".into(),
                Value::from(javascript_count as u64),
            ),
            (
                "historical_endpoint_count".into(),
                Value::from(endpoint_count as u64),
            ),
            (
                "historical_subdomains".into(),
                Value::Array(subdomains.into_iter().map(Value::String).collect()),
            ),
            (
                "parameter_names".into(),
                Value::Array(
                    normalized
                        .parameter_names
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            ),
            ("raw_archive_records_retained".into(), Value::Bool(false)),
        ]);
        Ok(ToolExecutionOutcome {
            result: ToolResult {
                schema_version: CORE_SCHEMA_VERSION,
                id: ToolResultId(Uuid::new_v4().to_string()),
                tool_name: "lookup_web_archive".into(),
                success: true,
                data,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalUrlKind {
    Page,
    Javascript,
    Endpoint,
    ApiDescription,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalUrlSummary {
    pub url: String,
    pub kind: HistoricalUrlKind,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub capture_count: u64,
    pub mime_types: Vec<String>,
    pub providers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveProviderSummary {
    provider: String,
    success: bool,
    record_count: u64,
    error_code: Option<String>,
}

struct NormalizedCaptures {
    records: Vec<HistoricalUrlSummary>,
    parameter_names: BTreeSet<String>,
}

struct HistoricalAggregate {
    kind: HistoricalUrlKind,
    first_seen: Option<String>,
    last_seen: Option<String>,
    capture_count: u64,
    mime_types: BTreeSet<String>,
    providers: BTreeSet<String>,
}

fn normalize_captures(
    captures: Vec<(String, HistoricalCapture)>,
    scope: &ScopeProject,
) -> NormalizedCaptures {
    let mut grouped = BTreeMap::<String, HistoricalAggregate>::new();
    let mut parameter_names = BTreeSet::new();
    for (provider, capture) in captures {
        let Ok(mut url) = Url::parse(&capture.url) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") || !validate(scope, url.as_str()).allowed {
            continue;
        }
        if !url.username().is_empty() || url.password().is_some() {
            let _ = url.set_username("");
            let _ = url.set_password(None);
        }
        for (name, _) in url.query_pairs() {
            let name = name.trim();
            if !name.is_empty() && name.len() <= 64 {
                parameter_names.insert(name.to_string());
            }
        }
        url.set_query(None);
        url.set_fragment(None);
        let canonical = url.to_string();
        let kind = historical_kind(&url, capture.mime_type.as_deref());
        let aggregate = grouped
            .entry(canonical)
            .or_insert_with(|| HistoricalAggregate {
                kind,
                first_seen: None,
                last_seen: None,
                capture_count: 0,
                mime_types: BTreeSet::new(),
                providers: BTreeSet::new(),
            });
        aggregate.capture_count = aggregate.capture_count.saturating_add(1);
        aggregate.providers.insert(provider);
        if let Some(mime_type) = capture
            .mime_type
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.to_ascii_lowercase())
        {
            aggregate.mime_types.insert(mime_type);
        }
        if valid_timestamp(&capture.timestamp) {
            if aggregate
                .first_seen
                .as_ref()
                .is_none_or(|value| capture.timestamp < *value)
            {
                aggregate.first_seen = Some(capture.timestamp.clone());
            }
            if aggregate
                .last_seen
                .as_ref()
                .is_none_or(|value| capture.timestamp > *value)
            {
                aggregate.last_seen = Some(capture.timestamp);
            }
        }
        if grouped.len() >= MAX_COMBINED_RECORDS {
            break;
        }
    }
    NormalizedCaptures {
        records: grouped
            .into_iter()
            .map(|(url, aggregate)| HistoricalUrlSummary {
                url,
                kind: aggregate.kind,
                first_seen: aggregate.first_seen,
                last_seen: aggregate.last_seen,
                capture_count: aggregate.capture_count,
                mime_types: aggregate.mime_types.into_iter().collect(),
                providers: aggregate.providers.into_iter().collect(),
            })
            .collect(),
        parameter_names,
    }
}

fn historical_kind(url: &Url, mime_type: Option<&str>) -> HistoricalUrlKind {
    let path = url.path().to_ascii_lowercase();
    let mime = mime_type.unwrap_or_default().to_ascii_lowercase();
    if path.ends_with(".js") || mime.contains("javascript") {
        HistoricalUrlKind::Javascript
    } else if path.contains("openapi") || path.contains("swagger") {
        HistoricalUrlKind::ApiDescription
    } else if path.starts_with("/api/")
        || path.contains("/graphql")
        || path.contains("/oauth")
        || path.contains("/login")
        || path.contains("/admin")
    {
        HistoricalUrlKind::Endpoint
    } else if mime.contains("html") || path.ends_with('/') || !path.contains('.') {
        HistoricalUrlKind::Page
    } else {
        HistoricalUrlKind::Other
    }
}

fn parse_wayback_response(bytes: &[u8]) -> Result<Vec<HistoricalCapture>, String> {
    let rows: Vec<Vec<Value>> = serde_json::from_slice(bytes)
        .map_err(|_| "Wayback returned malformed JSON rows.".to_string())?;
    let Some(header) = rows.first() else {
        return Ok(vec![]);
    };
    let index = |name: &str| header.iter().position(|value| value.as_str() == Some(name));
    let timestamp = index("timestamp").ok_or("Wayback response omitted timestamp.")?;
    let original = index("original").ok_or("Wayback response omitted original URL.")?;
    let status = index("statuscode");
    let mime = index("mimetype");
    let digest = index("digest");
    Ok(rows
        .into_iter()
        .skip(1)
        .take(MAX_PROVIDER_RECORDS)
        .filter_map(|row| {
            Some(HistoricalCapture {
                url: row.get(original)?.as_str()?.to_string(),
                timestamp: row.get(timestamp)?.as_str()?.to_string(),
                status: status
                    .and_then(|index| row.get(index))
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse().ok()),
                mime_type: mime
                    .and_then(|index| row.get(index))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                digest: digest
                    .and_then(|index| row.get(index))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
        })
        .collect())
}

fn parse_common_crawl_response(bytes: &[u8]) -> Result<Vec<HistoricalCapture>, String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(MAX_PROVIDER_RECORDS)
        .map(|line| {
            let record: CommonCrawlRecord = serde_json::from_str(line)
                .map_err(|_| "Common Crawl returned malformed JSON lines.".to_string())?;
            Ok(HistoricalCapture {
                url: record.url,
                timestamp: record.timestamp.unwrap_or_default(),
                status: record.status.and_then(|value| value.parse().ok()),
                mime_type: record.mime,
                digest: record.digest,
            })
        })
        .collect()
}

fn read_archive_response(
    provider: &str,
    response: reqwest::blocking::Response,
) -> Result<Vec<u8>, HistoricalProviderError> {
    if !response.status().is_success() {
        return Err(provider_error(
            provider,
            "ARCHIVE_PROVIDER_ERROR",
            format!(
                "Archive provider returned HTTP {}.",
                response.status().as_u16()
            ),
            1,
        ));
    }
    let mut bytes = Vec::with_capacity(64 * 1024);
    response
        .take((MAX_ARCHIVE_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            provider_error(
                provider,
                "ARCHIVE_RESPONSE_READ_FAILED",
                "Archive provider response could not be read.",
                1,
            )
        })?;
    if bytes.len() > MAX_ARCHIVE_RESPONSE_BYTES {
        return Err(provider_error(
            provider,
            "ARCHIVE_RESPONSE_TOO_LARGE",
            "Archive provider response exceeded the safe read limit.",
            1,
        ));
    }
    Ok(bytes)
}

fn archive_client() -> Client {
    Client::builder()
        .redirect(Policy::limited(2))
        .user_agent("HexHunt/0.1 authorized-historical-recon")
        .build()
        .unwrap_or_else(|_| Client::new())
}

fn valid_timestamp(value: &str) -> bool {
    value.len() == 14 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn provider_error(
    provider: impl Into<String>,
    code: impl Into<String>,
    message: impl Into<String>,
    http_requests: u64,
) -> HistoricalProviderError {
    HistoricalProviderError {
        provider: provider.into(),
        code: code.into(),
        message: message.into(),
        http_requests,
    }
}

fn tool_error(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{TaskBudget, TaskId},
        scope_guard::ScopeProject,
    };

    struct FakeArchiveProvider {
        name: &'static str,
        captures: Vec<HistoricalCapture>,
        requests: u64,
    }

    impl HistoricalReconProvider for FakeArchiveProvider {
        fn lookup(
            &self,
            _domain: &str,
        ) -> Result<HistoricalProviderResult, HistoricalProviderError> {
            Ok(HistoricalProviderResult {
                provider: self.name.into(),
                captures: self.captures.clone(),
                http_requests: self.requests,
            })
        }
    }

    fn task() -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: TaskId("historical-task".into()),
            objective: "Historical Recon".into(),
            primary_target: "https://example.test".into(),
            scope: ScopeProject {
                id: "historical-scope".into(),
                allowed_domains: vec!["example.test".into(), "*.example.test".into()],
                excluded_domains: vec!["excluded.example.test".into()],
                allowed_ports: vec![80, 443],
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
            available_tools: vec!["lookup_web_archive".into()],
            memory_policy: Default::default(),
        }
    }

    fn capture(url: &str, timestamp: &str, mime: &str) -> HistoricalCapture {
        HistoricalCapture {
            url: url.into(),
            timestamp: timestamp.into(),
            status: Some(200),
            mime_type: Some(mime.into()),
            digest: None,
        }
    }

    #[test]
    fn archive_parsers_accept_wayback_rows_and_common_crawl_lines() {
        let wayback = br#"[["timestamp","original","statuscode","mimetype","digest"],["20200101000000","https://example.test/old","200","text/html","ABC"]]"#;
        assert_eq!(parse_wayback_response(wayback).unwrap().len(), 1);
        let common = br#"{"timestamp":"20210101000000","url":"https://example.test/app.js","status":"200","mime":"application/javascript","digest":"DEF"}
"#;
        assert_eq!(parse_common_crawl_response(common).unwrap().len(), 1);
    }

    #[test]
    fn historical_tool_deduplicates_sources_drops_query_values_and_filters_scope() {
        let tool = HistoricalReconTool::with_providers(vec![
            Arc::new(FakeArchiveProvider {
                name: "wayback",
                captures: vec![
                    capture(
                        "https://example.test/app.js?token=secret-value",
                        "20200101000000",
                        "application/javascript",
                    ),
                    capture(
                        "https://excluded.example.test/admin",
                        "20200101000000",
                        "text/html",
                    ),
                ],
                requests: 1,
            }),
            Arc::new(FakeArchiveProvider {
                name: "common_crawl",
                captures: vec![capture(
                    "https://example.test/app.js?token=another-value",
                    "20240101000000",
                    "application/javascript",
                )],
                requests: 2,
            }),
        ]);
        let action = AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "lookup_web_archive".into(),
            arguments: StructuredData::from([(
                "domain".into(),
                Value::String("example.test".into()),
            )]),
            reason: "Search passive history.".into(),
        };
        let outcome = tool
            .execute(tool.prepare(&action, &task()).unwrap())
            .unwrap();
        let serialized = serde_json::to_string(&outcome.result).unwrap();

        assert_eq!(outcome.http_requests, 3);
        assert_eq!(outcome.result.data["historical_url_count"], 1);
        assert_eq!(outcome.result.data["historical_javascript_count"], 1);
        assert_eq!(outcome.result.data["parameter_names"][0], "token");
        assert_eq!(outcome.result.data["raw_archive_records_retained"], false);
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("another-value"));
        assert!(!serialized.contains("excluded.example.test"));
    }

    #[test]
    fn historical_tool_rejects_out_of_scope_domain_before_provider_calls() {
        let tool = HistoricalReconTool::with_providers(vec![]);
        let action = AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "lookup_web_archive".into(),
            arguments: StructuredData::from([(
                "domain".into(),
                Value::String("outside.invalid".into()),
            )]),
            reason: "Invalid target.".into(),
        };
        assert_eq!(
            tool.prepare(&action, &task()).unwrap_err().code,
            "SCOPE_BLOCKED"
        );
    }
}
