use super::{
    redact_text, AgentAction, StructuredData, Task, ToolExecutionError, ToolExecutionOutcome,
    ToolResult, ToolResultId, CORE_SCHEMA_VERSION,
};
use crate::scope_guard::{validate, ScopeGuardState, ScopeProject};
use headless_chrome::{
    browser::{default_executable, tab::RequestPausedDecision},
    protocol::cdp::{types::Event, Fetch, Network},
    Browser, LaunchOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    path::PathBuf,
    sync::{Arc, OnceLock, RwLock},
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

const MAX_BROWSER_IDENTITIES: usize = 4;
const MAX_BROWSER_NETWORK_EVENTS: usize = 500;
const DEFAULT_BROWSER_TIMEOUT_MS: u64 = 20_000;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BrowserIdentityId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserIdentity {
    pub schema_version: u32,
    pub id: BrowserIdentityId,
    pub name: String,
    pub scope_id: String,
    pub origin: String,
    pub cookie_names: Vec<String>,
    pub header_names: Vec<String>,
    pub created_at_ms: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserCookieSecret {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserIdentityInput {
    pub id: Option<BrowserIdentityId>,
    pub name: String,
    pub scope_id: String,
    pub origin: String,
    pub cookies: Vec<BrowserCookieSecret>,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone)]
struct StoredIdentity {
    descriptor: BrowserIdentity,
    cookies: Vec<BrowserCookieSecret>,
    headers: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct BrowserSessionVault {
    identities: RwLock<BTreeMap<String, StoredIdentity>>,
}

impl BrowserSessionVault {
    pub fn save(&self, input: BrowserIdentityInput) -> Result<BrowserIdentity, String> {
        let origin = Url::parse(input.origin.trim()).map_err(|_| {
            "IDENTITY_INVALID_ORIGIN: origin must be an absolute HTTP or HTTPS URL.".to_string()
        })?;
        if !matches!(origin.scheme(), "http" | "https") || origin.host_str().is_none() {
            return Err(
                "IDENTITY_INVALID_ORIGIN: origin must be an absolute HTTP or HTTPS URL.".into(),
            );
        }
        if input.name.trim().is_empty() || input.scope_id.trim().is_empty() {
            return Err("IDENTITY_INVALID: name and scope_id are required.".into());
        }
        if input.cookies.len() > 100 || input.headers.len() > 20 {
            return Err(
                "IDENTITY_TOO_LARGE: identity exceeds the safe cookie or header limit.".into(),
            );
        }
        for cookie in &input.cookies {
            if cookie.name.trim().is_empty() || cookie.value.is_empty() {
                return Err(
                    "IDENTITY_INVALID_COOKIE: cookie names and values cannot be empty.".into(),
                );
            }
        }
        for (name, value) in &input.headers {
            let normalized = name.to_ascii_lowercase();
            if name.trim().is_empty()
                || value.is_empty()
                || matches!(normalized.as_str(), "cookie" | "host" | "content-length")
            {
                return Err("IDENTITY_INVALID_HEADER: empty and transport-controlled headers are not allowed.".into());
            }
        }
        let id = input
            .id
            .unwrap_or_else(|| BrowserIdentityId(Uuid::new_v4().to_string()));
        let descriptor = BrowserIdentity {
            schema_version: CORE_SCHEMA_VERSION,
            id: id.clone(),
            name: input.name.trim().chars().take(100).collect(),
            scope_id: input.scope_id,
            origin: normalized_origin(&origin),
            cookie_names: input
                .cookies
                .iter()
                .map(|cookie| cookie.name.clone())
                .collect(),
            header_names: input.headers.keys().cloned().collect(),
            created_at_ms: now_ms(),
        };
        self.identities
            .write()
            .map_err(|_| "IDENTITY_VAULT_LOCKED: session vault is unavailable.".to_string())?
            .insert(
                id.0,
                StoredIdentity {
                    descriptor: descriptor.clone(),
                    cookies: input.cookies,
                    headers: input.headers,
                },
            );
        Ok(descriptor)
    }

    pub fn list(&self) -> Result<Vec<BrowserIdentity>, String> {
        Ok(self
            .identities
            .read()
            .map_err(|_| "IDENTITY_VAULT_LOCKED: session vault is unavailable.".to_string())?
            .values()
            .map(|identity| identity.descriptor.clone())
            .collect())
    }

    pub fn delete(&self, id: &BrowserIdentityId) -> Result<bool, String> {
        Ok(self
            .identities
            .write()
            .map_err(|_| "IDENTITY_VAULT_LOCKED: session vault is unavailable.".to_string())?
            .remove(&id.0)
            .is_some())
    }

    fn snapshot(
        &self,
        id: &BrowserIdentityId,
        task: &Task,
        url: &Url,
    ) -> Result<BrowserSessionSnapshot, ToolExecutionError> {
        let identities = self.identities.read().map_err(|_| {
            browser_error(
                "IDENTITY_VAULT_LOCKED",
                "Session vault is unavailable.",
                false,
            )
        })?;
        let stored = identities.get(&id.0).ok_or_else(|| {
            browser_error(
                "IDENTITY_NOT_FOUND",
                format!("Browser identity '{}' was not found.", id.0),
                false,
            )
        })?;
        if stored.descriptor.scope_id != task.scope.id
            || stored.descriptor.origin != normalized_origin(url)
        {
            return Err(browser_error(
                "IDENTITY_SCOPE_MISMATCH",
                "The selected identity is not bound to this Run scope and origin.",
                false,
            ));
        }
        Ok(BrowserSessionSnapshot {
            id: stored.descriptor.id.clone(),
            name: stored.descriptor.name.clone(),
            origin: stored.descriptor.origin.clone(),
            cookies: stored.cookies.clone(),
            headers: stored.headers.clone(),
        })
    }
}

pub fn browser_session_vault() -> Arc<BrowserSessionVault> {
    static VAULT: OnceLock<Arc<BrowserSessionVault>> = OnceLock::new();
    VAULT
        .get_or_init(|| Arc::new(BrowserSessionVault::default()))
        .clone()
}

#[derive(Clone)]
struct BrowserSessionSnapshot {
    id: BrowserIdentityId,
    name: String,
    origin: String,
    cookies: Vec<BrowserCookieSecret>,
    headers: BTreeMap<String, String>,
}

impl fmt::Debug for BrowserSessionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserSessionSnapshot")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("origin", &self.origin)
            .field("cookie_count", &self.cookies.len())
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct PreparedAdaptiveBrowserCall {
    url: String,
    scope: ScopeProject,
    timeout_ms: u64,
    identities: Vec<Option<BrowserSessionSnapshot>>,
}

pub struct AdaptiveBrowserReconTool {
    scope_guard: Arc<ScopeGuardState>,
    vault: Arc<BrowserSessionVault>,
}

impl AdaptiveBrowserReconTool {
    pub fn new(scope_guard: Arc<ScopeGuardState>) -> Self {
        Self {
            scope_guard,
            vault: browser_session_vault(),
        }
    }

    pub fn prepare(
        &self,
        action: &AgentAction,
        task: &Task,
    ) -> Result<PreparedAdaptiveBrowserCall, ToolExecutionError> {
        for key in action.arguments.keys() {
            if !matches!(key.as_str(), "url" | "identity_ids" | "timeout_ms") {
                return Err(browser_error(
                    "INVALID_BROWSER_ARGUMENTS",
                    format!("Unknown adaptive_browser_recon argument '{key}'."),
                    false,
                ));
            }
        }
        let raw_url = action
            .arguments
            .get("url")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                browser_error(
                    "INVALID_BROWSER_ARGUMENTS",
                    "adaptive_browser_recon requires url.",
                    false,
                )
            })?;
        let url = Url::parse(raw_url).map_err(|_| {
            browser_error(
                "INVALID_BROWSER_ARGUMENTS",
                "Browser URL must be absolute.",
                false,
            )
        })?;
        let decision = self
            .scope_guard
            .authorize_request(&task.scope, url.as_str());
        if !decision.allowed {
            return Err(browser_error(
                if decision.code == "rate-limit" {
                    "RATE_LIMITED"
                } else {
                    "SCOPE_BLOCKED"
                },
                decision.reason,
                false,
            ));
        }
        let ids = action
            .arguments
            .get("identity_ids")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if ids.len() > MAX_BROWSER_IDENTITIES {
            return Err(browser_error(
                "INVALID_BROWSER_ARGUMENTS",
                format!("No more than {MAX_BROWSER_IDENTITIES} identities can be compared."),
                false,
            ));
        }
        let identities = if ids.is_empty() {
            vec![None]
        } else {
            ids.into_iter()
                .map(|id| {
                    let id = id
                        .as_str()
                        .filter(|value| !value.trim().is_empty())
                        .ok_or_else(|| {
                            browser_error(
                                "INVALID_BROWSER_ARGUMENTS",
                                "identity_ids must contain non-empty strings.",
                                false,
                            )
                        })?;
                    self.vault
                        .snapshot(&BrowserIdentityId(id.into()), task, &url)
                        .map(Some)
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let timeout_ms = action
            .arguments
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BROWSER_TIMEOUT_MS)
            .clamp(1_000, 30_000);
        Ok(PreparedAdaptiveBrowserCall {
            url: url.to_string(),
            scope: task.scope.clone(),
            timeout_ms,
            identities,
        })
    }

    pub fn execute(
        &self,
        call: PreparedAdaptiveBrowserCall,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        let started = Instant::now();
        let mut views = Vec::new();
        for identity in &call.identities {
            views.push(capture_browser_view(&call, identity.as_ref())?);
        }
        let comparison = compare_views(&views);
        Ok(ToolExecutionOutcome {
            result: ToolResult {
                schema_version: CORE_SCHEMA_VERSION,
                id: ToolResultId(Uuid::new_v4().to_string()),
                tool_name: "adaptive_browser_recon".into(),
                success: true,
                data: StructuredData::from([
                    ("requested_url".into(), Value::String(call.url)),
                    ("identity_views".into(), Value::Array(views)),
                    ("identity_comparison".into(), comparison),
                    ("secret_values_retained".into(), Value::Bool(false)),
                    ("response_bodies_retained".into(), Value::Bool(false)),
                ]),
                error: None,
                duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            },
            http_requests: call.identities.len() as u64,
            model_calls: 0,
            input_tokens: 0,
            output_tokens: 0,
        })
    }
}

fn capture_browser_view(
    call: &PreparedAdaptiveBrowserCall,
    identity: Option<&BrowserSessionSnapshot>,
) -> Result<Value, ToolExecutionError> {
    let executable = chromium_executable().ok_or_else(|| {
        browser_error(
            "BROWSER_NOT_FOUND",
            "Chromium was not found. Install Chromium or set HEXHUNT_CHROMIUM_PATH.",
            false,
        )
    })?;
    let options = LaunchOptions::default_builder()
        .path(Some(executable))
        .headless(true)
        .sandbox(true)
        .idle_browser_timeout(Duration::from_millis(call.timeout_ms))
        .build()
        .map_err(|_| {
            browser_error(
                "BROWSER_CONFIGURATION_FAILED",
                "Chromium launch options could not be created.",
                false,
            )
        })?;
    let browser = Browser::new(options).map_err(|_| {
        browser_error(
            "BROWSER_START_FAILED",
            "Chromium could not be started.",
            false,
        )
    })?;
    let tab = browser.new_tab().map_err(|_| {
        browser_error(
            "BROWSER_TAB_FAILED",
            "Chromium could not create a tab.",
            false,
        )
    })?;
    tab.set_default_timeout(Duration::from_millis(call.timeout_ms));
    if let Some(identity) = identity {
        let cookies = identity
            .cookies
            .iter()
            .map(|cookie| Network::CookieParam {
                name: cookie.name.clone(),
                value: cookie.value.clone(),
                url: Some(identity.origin.clone()),
                domain: cookie.domain.clone(),
                path: cookie.path.clone(),
                secure: cookie.secure,
                http_only: cookie.http_only,
                same_site: None,
                expires: None,
                priority: None,
                same_party: None,
                source_scheme: None,
                source_port: None,
                partition_key: None,
            })
            .collect();
        tab.set_cookies(cookies).map_err(|_| {
            browser_error(
                "IDENTITY_COOKIE_FAILED",
                "Browser identity cookies could not be applied.",
                false,
            )
        })?;
        let headers = identity
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<HashMap<_, _>>();
        tab.set_extra_http_headers(headers).map_err(|_| {
            browser_error(
                "IDENTITY_HEADER_FAILED",
                "Browser identity headers could not be applied.",
                false,
            )
        })?;
    }
    let network_events = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let responses = network_events.clone();
    let scope_for_events = call.scope.clone();
    tab.add_event_listener(Arc::new(move |event: &Event| {
        if let Event::NetworkResponseReceived(event) = event {
            let response = &event.params.response;
            if !validate(&scope_for_events, &response.url).allowed {
                return;
            }
            let (url, parameter_names) = sanitize_url(&response.url);
            if let Ok(mut events) = responses.lock() {
                if events.len() < MAX_BROWSER_NETWORK_EVENTS {
                    events.push(serde_json::json!({
                        "url": url,
                        "status_code": response.status,
                        "resource_type": format!("{:?}", event.params.Type).to_ascii_lowercase(),
                        "mime_type": response.mime_type,
                        "parameter_names": parameter_names,
                        "from_service_worker": response.from_service_worker.unwrap_or(false),
                    }));
                }
            }
        }
    }))
    .map_err(|_| {
        browser_error(
            "BROWSER_NETWORK_LISTENER_FAILED",
            "Network metadata listener could not be installed.",
            false,
        )
    })?;
    let blocked = Arc::new(std::sync::atomic::AtomicU64::new(0));
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
        browser_error(
            "BROWSER_INTERCEPTION_FAILED",
            "Browser request interception could not be enabled.",
            false,
        )
    })?;
    tab.enable_request_interception(Arc::new(
        move |_transport, _session_id, event: Fetch::events::RequestPausedEvent| {
            let url = &event.params.request.url;
            if is_non_network_url(url) || validate(&scope, url).allowed {
                RequestPausedDecision::Continue(None)
            } else {
                blocked_for_interceptor.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                RequestPausedDecision::Fail(Fetch::FailRequest {
                    request_id: event.params.request_id.clone(),
                    error_reason: Network::ErrorReason::BlockedByClient,
                })
            }
        },
    ))
    .map_err(|_| {
        browser_error(
            "BROWSER_INTERCEPTION_FAILED",
            "Browser request interception could not be installed.",
            false,
        )
    })?;
    tab.navigate_to(&call.url)
        .and_then(|tab| tab.wait_until_navigated())
        .map_err(|_| {
            browser_error(
                "BROWSER_NAVIGATION_FAILED",
                "Chromium could not finish the authorized navigation.",
                true,
            )
        })?;
    let final_url = tab.get_url();
    if !validate(&call.scope, &final_url).allowed {
        return Err(browser_error(
            "SCOPE_BLOCKED",
            "Adaptive Browser Recon stopped after an out-of-scope redirect.",
            true,
        ));
    }
    let _ = tab.evaluate(
        "new Promise(resolve => setTimeout(() => resolve(true), 750))",
        true,
    );
    let dom = tab
        .evaluate(DOM_SNAPSHOT_SCRIPT, true)
        .map_err(|_| {
            browser_error(
                "BROWSER_DOM_FAILED",
                "Dynamic DOM metadata could not be collected.",
                true,
            )
        })?
        .value
        .unwrap_or(Value::Null);
    let events = network_events
        .lock()
        .map(|events| events.clone())
        .unwrap_or_default();
    Ok(serde_json::json!({
        "identity_id": identity.map(|item| item.id.0.clone()),
        "identity_name": identity.map(|item| item.name.clone()).unwrap_or_else(|| "anonymous".into()),
        "final_url": sanitize_url(&final_url).0,
        "dom": dom,
        "network_events": events,
        "blocked_out_of_scope_requests": blocked.load(std::sync::atomic::Ordering::SeqCst),
    }))
}

const DOM_SNAPSHOT_SCRIPT: &str = r#"(() => {
  const cleanUrl = (raw) => { try { const u = new URL(raw, location.href); u.search = ''; u.hash = ''; return u.href; } catch { return null; } };
  const uniq = (items) => [...new Set(items.filter(Boolean))].slice(0, 500);
  const links = uniq([...document.querySelectorAll('a[href]')].map(a => cleanUrl(a.href)));
  const scripts = uniq([...document.querySelectorAll('script[src]')].map(s => cleanUrl(s.src)));
  const forms = [...document.forms].slice(0, 100).map(form => ({
    method: (form.method || 'GET').toUpperCase(), action: cleanUrl(form.action || location.href),
    input_names: uniq([...form.elements].map(el => el.name).filter(Boolean)),
    input_types: uniq([...form.elements].map(el => el.type).filter(Boolean)),
    has_password: !!form.querySelector('input[type=password]'), has_file: !!form.querySelector('input[type=file]')
  }));
  return {
    title: String(document.title || '').slice(0, 200), links, scripts, forms,
    button_count: document.querySelectorAll('button,[role=button]').length,
    iframe_count: document.querySelectorAll('iframe').length,
    shadow_host_count: [...document.querySelectorAll('*')].filter(el => el.shadowRoot).length,
    spa_root_detected: !!document.querySelector('#root,#app,[data-reactroot],[ng-version]'),
    service_worker_controlled: !!navigator.serviceWorker?.controller,
    storage_keys: { local: Object.keys(localStorage).slice(0,100), session: Object.keys(sessionStorage).slice(0,100) },
    values_retained: false
  };
})()"#;

fn compare_views(views: &[Value]) -> Value {
    if views.len() < 2 {
        return Value::Null;
    }
    let summaries = views.iter().map(|view| {
        let dom = view.get("dom").unwrap_or(&Value::Null);
        serde_json::json!({
            "identity_id": view.get("identity_id").cloned().unwrap_or(Value::Null),
            "link_count": dom.get("links").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "form_count": dom.get("forms").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "network_event_count": view.get("network_events").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "final_url": view.get("final_url").cloned().unwrap_or(Value::Null),
        })
    }).collect::<Vec<_>>();
    let signatures = summaries
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    serde_json::json!({ "views_differ": signatures.len() > 1, "summaries": summaries, "authorization_conclusion": "not_inferred" })
}

fn sanitize_url(raw: &str) -> (String, Vec<String>) {
    let Ok(mut url) = Url::parse(raw) else {
        return ("invalid-url".into(), vec![]);
    };
    let parameters = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    url.set_query(None);
    url.set_fragment(None);
    (url.to_string(), parameters)
}

fn normalized_origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn chromium_executable() -> Option<PathBuf> {
    std::env::var_os("HEXHUNT_CHROMIUM_PATH")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| default_executable().ok())
}

fn is_non_network_url(url: &str) -> bool {
    matches!(
        Url::parse(url).ok().as_ref().map(Url::scheme),
        Some("data" | "blob" | "about" | "chrome" | "devtools")
    )
}

fn browser_error(
    code: &str,
    message: impl Into<String>,
    request_started: bool,
) -> ToolExecutionError {
    ToolExecutionError {
        code: code.into(),
        message: redact_text(message.into()),
        request_started,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
