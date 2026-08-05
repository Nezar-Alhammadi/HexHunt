use super::{
    browser_session_vault, AdaptiveBrowserReconTool, AgentAction, BrowserIdentity, Clock,
    DeterministicEvaluator, Evaluator, Evidence, EvidenceRecorder, ExternalReconTool, FinalOutput,
    FinalOutputStatus, HistoricalReconTool, HttpRequestTool, InfrastructureReconTools,
    ModelCallRecord, PassiveReconTools, PreparedAdaptiveBrowserCall, PreparedContentDiscovery,
    PreparedExternalReconCall, PreparedHistoricalReconCall, PreparedHttpRequest,
    PreparedInfrastructureCall, PreparedPassiveReconCall, PreparedVisualReconCall, ReconCritic,
    ReconCritique, ReconDecision, ReconIngestor, ReconMemory, ReconPlanner, ReconSnapshot, Run,
    RunEvent, RunEventKind, RunFailure, RunId, RunService, RunServiceError, RunServiceErrorCode,
    RunStatus, RunUsage, StructuredData, SystemClock, Task, TaskBudget, ToolError, ToolResult,
    ToolResultId, VisualReconTool, CORE_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::VecDeque, error::Error, fmt, sync::Arc, thread, time::Duration};
use uuid::Uuid;

const MAX_CONSECUTIVE_MODEL_REJECTIONS: u8 = 3;

fn is_recoverable_tool_execution_error(error: &ToolExecutionError) -> bool {
    error.request_started
        || [
            "TIMEOUT",
            "CONNECTION_FAILED",
            "REQUEST_FAILED",
            "RESPONSE_READ_FAILED",
            "PROVIDER_ERROR",
            "BROWSER_START_FAILED",
            "BROWSER_NAVIGATION_FAILED",
            "BROWSER_WAIT_FAILED",
        ]
        .iter()
        .any(|suffix| error.code.ends_with(suffix))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBudgetRemaining {
    pub steps: u64,
    pub http_requests: u64,
    pub model_calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentContext {
    pub schema_version: u32,
    pub task: Task,
    pub run_id: RunId,
    pub current_step: u64,
    pub remaining_budget: AgentBudgetRemaining,
    pub tool_results: Vec<ToolResult>,
    pub evidence: Vec<Evidence>,
    pub events: Vec<RunEvent>,
    pub notes: Vec<String>,
    pub recon_snapshot: ReconSnapshot,
    pub recon_plan: Option<ReconDecision>,
    pub recon_memory: ReconMemory,
    pub recon_critique: ReconCritique,
    pub browser_identities: Vec<BrowserIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentError {
    pub code: String,
    pub message: String,
}

pub trait Agent {
    fn next_action(&mut self, context: &AgentContext) -> Result<AgentAction, AgentError>;

    fn is_model_driven(&self) -> bool {
        false
    }

    fn take_last_model_call(&mut self) -> Option<ModelCallRecord> {
        None
    }

    fn on_action_rejected(&mut self, _action: &AgentAction, _reason: &str) {}
}

pub struct ScriptedAgent {
    actions: VecDeque<Result<AgentAction, AgentError>>,
}

impl ScriptedAgent {
    pub fn new(actions: Vec<Result<AgentAction, AgentError>>) -> Self {
        Self {
            actions: actions.into(),
        }
    }

    pub fn successful(
        note: impl Into<String>,
        output: FinalOutput,
    ) -> Result<Self, AgentRuntimeError> {
        let final_output = serde_json::to_value(output).map_err(|error| {
            AgentRuntimeError::new(
                AgentRuntimeErrorCode::InvalidAgentAction,
                format!("Unable to encode the scripted final output: {error}"),
            )
        })?;
        Ok(Self::new(vec![
            Ok(AgentAction {
                schema_version: CORE_SCHEMA_VERSION,
                name: "record_note".into(),
                arguments: StructuredData::from([("text".into(), Value::String(note.into()))]),
                reason: "Record a deterministic note.".into(),
            }),
            Ok(AgentAction {
                schema_version: CORE_SCHEMA_VERSION,
                name: "finish".into(),
                arguments: StructuredData::from([("final_output".into(), final_output)]),
                reason: "Finish the deterministic run.".into(),
            }),
        ]))
    }
}

impl Agent for ScriptedAgent {
    fn next_action(&mut self, context: &AgentContext) -> Result<AgentAction, AgentError> {
        let mut action = self.actions.pop_front().unwrap_or_else(|| {
            Err(AgentError {
                code: "SCRIPT_EXHAUSTED".into(),
                message: "The scripted agent has no remaining actions.".into(),
            })
        })?;

        // Deterministic scripts cannot know generated Evidence IDs in advance. Mirror what a
        // model-driven agent sees in its context so managed scripted runs still exercise the
        // production finish gate with real, stored evidence references.
        if action.name == "finish" && !context.evidence.is_empty() {
            if let Some(final_output) = action.arguments.get_mut("final_output") {
                if let Ok(mut output) = serde_json::from_value::<FinalOutput>(final_output.clone())
                {
                    if output.evidence_ids.is_empty() {
                        output.evidence_ids = context
                            .evidence
                            .iter()
                            .map(|evidence| evidence.id.clone())
                            .collect();
                        if let Ok(value) = serde_json::to_value(output) {
                            *final_output = value;
                        }
                    }
                }
            }
        }

        Ok(action)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolExecutionError {
    pub code: String,
    pub message: String,
    pub request_started: bool,
}

#[derive(Clone, Debug)]
pub enum PreparedToolCall {
    RecordNote {
        note: String,
    },
    HttpRequest(PreparedHttpRequest),
    ReconHttp {
        tool_name: String,
        request: PreparedHttpRequest,
    },
    PassiveRecon(PreparedPassiveReconCall),
    HistoricalRecon(PreparedHistoricalReconCall),
    VisualRecon(PreparedVisualReconCall),
    Infrastructure(PreparedInfrastructureCall),
    ContentDiscovery(PreparedContentDiscovery),
    AdaptiveBrowser(PreparedAdaptiveBrowserCall),
    ExternalRecon(PreparedExternalReconCall),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolExecutionOutcome {
    pub result: ToolResult,
    pub http_requests: u64,
    pub model_calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

pub trait ToolExecutor {
    fn prepare(
        &self,
        action: &AgentAction,
        task: &Task,
    ) -> Result<PreparedToolCall, ToolExecutionError>;

    fn execute(
        &self,
        prepared: PreparedToolCall,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError>;
}

#[derive(Default)]
pub struct FakeToolExecutor;

impl ToolExecutor for FakeToolExecutor {
    fn prepare(
        &self,
        action: &AgentAction,
        _task: &Task,
    ) -> Result<PreparedToolCall, ToolExecutionError> {
        if action.name != "record_note" {
            return Err(ToolExecutionError {
                code: "UNSUPPORTED_FAKE_TOOL".into(),
                message: format!("FakeToolExecutor does not support '{}'.", action.name),
                request_started: false,
            });
        }

        let note = action
            .arguments
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .ok_or_else(|| ToolExecutionError {
                code: "INVALID_NOTE".into(),
                message: "record_note requires a non-empty text argument.".into(),
                request_started: false,
            })?;

        Ok(PreparedToolCall::RecordNote { note: note.into() })
    }

    fn execute(
        &self,
        prepared: PreparedToolCall,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        let PreparedToolCall::RecordNote { note } = prepared else {
            return Err(ToolExecutionError {
                code: "UNSUPPORTED_FAKE_TOOL".into(),
                message: "FakeToolExecutor only executes record_note.".into(),
                request_started: false,
            });
        };

        Ok(ToolExecutionOutcome {
            result: ToolResult {
                schema_version: CORE_SCHEMA_VERSION,
                id: ToolResultId(Uuid::new_v4().to_string()),
                tool_name: "record_note".into(),
                success: true,
                data: StructuredData::from([("note".into(), Value::String(note))]),
                error: None,
                duration_ms: 0,
            },
            http_requests: 0,
            model_calls: 0,
            input_tokens: 0,
            output_tokens: 0,
        })
    }
}

pub struct CoreToolExecutor {
    http: HttpRequestTool,
    passive_recon: PassiveReconTools,
    historical_recon: HistoricalReconTool,
    visual_recon: VisualReconTool,
    infrastructure_recon: InfrastructureReconTools,
    adaptive_browser: AdaptiveBrowserReconTool,
    external_recon: ExternalReconTool,
}

impl CoreToolExecutor {
    pub fn new(http: HttpRequestTool) -> Self {
        let scope_guard = http.scope_guard();
        let visual_recon = VisualReconTool::new(scope_guard.clone());
        let adaptive_browser = AdaptiveBrowserReconTool::new(scope_guard);
        Self {
            http,
            passive_recon: PassiveReconTools::default(),
            historical_recon: HistoricalReconTool::default(),
            visual_recon,
            infrastructure_recon: InfrastructureReconTools::default(),
            adaptive_browser,
            external_recon: ExternalReconTool::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_passive_recon(
        http: HttpRequestTool,
        passive_recon: PassiveReconTools,
    ) -> Self {
        let scope_guard = http.scope_guard();
        let visual_recon = VisualReconTool::new(scope_guard.clone());
        let adaptive_browser = AdaptiveBrowserReconTool::new(scope_guard);
        Self {
            http,
            passive_recon,
            historical_recon: HistoricalReconTool::default(),
            visual_recon,
            infrastructure_recon: InfrastructureReconTools::default(),
            adaptive_browser,
            external_recon: ExternalReconTool::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_deterministic_visual_recon(http: HttpRequestTool) -> Self {
        let scope_guard = http.scope_guard();
        let visual_recon = VisualReconTool::deterministic(scope_guard.clone());
        let adaptive_browser = AdaptiveBrowserReconTool::new(scope_guard);
        Self {
            http,
            passive_recon: PassiveReconTools::default(),
            historical_recon: HistoricalReconTool::default(),
            visual_recon,
            infrastructure_recon: InfrastructureReconTools::default(),
            adaptive_browser,
            external_recon: ExternalReconTool::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_historical_recon(
        http: HttpRequestTool,
        historical_recon: HistoricalReconTool,
    ) -> Self {
        let scope_guard = http.scope_guard();
        let visual_recon = VisualReconTool::new(scope_guard.clone());
        let adaptive_browser = AdaptiveBrowserReconTool::new(scope_guard);
        Self {
            http,
            passive_recon: PassiveReconTools::default(),
            historical_recon,
            visual_recon,
            infrastructure_recon: InfrastructureReconTools::default(),
            adaptive_browser,
            external_recon: ExternalReconTool::default(),
        }
    }
}

impl ToolExecutor for CoreToolExecutor {
    fn prepare(
        &self,
        action: &AgentAction,
        task: &Task,
    ) -> Result<PreparedToolCall, ToolExecutionError> {
        match action.name.as_str() {
            "record_note" => FakeToolExecutor.prepare(action, task),
            "http_request" => self
                .http
                .prepare(action, task)
                .map(PreparedToolCall::HttpRequest),
            "search_certificate_transparency" | "resolve_dns" | "inspect_dns_ownership" => self
                .passive_recon
                .prepare(action, task)
                .map(PreparedToolCall::PassiveRecon),
            "inspect_rdap" | "probe_tcp_service" => self
                .infrastructure_recon
                .prepare(action, task)
                .map(PreparedToolCall::Infrastructure),
            "discover_content" => super::prepare_content_discovery(action, task, &self.http)
                .map(PreparedToolCall::ContentDiscovery),
            "adaptive_browser_recon" => self
                .adaptive_browser
                .prepare(action, task)
                .map(PreparedToolCall::AdaptiveBrowser),
            "query_external_intelligence" => self
                .external_recon
                .prepare(action, task)
                .map(PreparedToolCall::ExternalRecon),
            "lookup_web_archive" => self
                .historical_recon
                .prepare(action, task)
                .map(PreparedToolCall::HistoricalRecon),
            "analyze_visual_page" => self
                .visual_recon
                .prepare(action, task)
                .map(PreparedToolCall::VisualRecon),
            "probe_http"
            | "validate_url_metadata"
            | "fetch_robots_txt"
            | "fetch_sitemap"
            | "analyze_web_page"
            | "analyze_javascript"
            | "describe_api" => {
                let (tool_name, http_action) = super::recon_http_action(action)
                    .expect("Known Recon HTTP action must be translated")?;
                let request = self.http.prepare(&http_action, task)?;
                let request = if tool_name == "analyze_javascript" {
                    request.with_response_body_limit(super::MAX_JAVASCRIPT_RESPONSE_BYTES)
                } else if tool_name == "describe_api" {
                    request.with_response_body_limit(super::MAX_API_DESCRIPTION_RESPONSE_BYTES)
                } else {
                    request
                };
                Ok(PreparedToolCall::ReconHttp { tool_name, request })
            }
            _ => Err(ToolExecutionError {
                code: "UNSUPPORTED_TOOL".into(),
                message: format!("Unsupported tool '{}'.", action.name),
                request_started: false,
            }),
        }
    }

    fn execute(
        &self,
        prepared: PreparedToolCall,
    ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
        match prepared {
            record_note @ PreparedToolCall::RecordNote { .. } => {
                FakeToolExecutor.execute(record_note)
            }
            PreparedToolCall::HttpRequest(request) => self.http.execute(request),
            PreparedToolCall::ReconHttp { tool_name, request } => {
                let mut outcome = self.http.execute(request)?;
                outcome.result.tool_name = tool_name;
                super::enrich_recon_http_result(&mut outcome.result);
                Ok(outcome)
            }
            PreparedToolCall::PassiveRecon(prepared) => self.passive_recon.execute(prepared),
            PreparedToolCall::HistoricalRecon(prepared) => self.historical_recon.execute(prepared),
            PreparedToolCall::VisualRecon(prepared) => self.visual_recon.execute(prepared),
            PreparedToolCall::Infrastructure(prepared) => {
                self.infrastructure_recon.execute(prepared)
            }
            PreparedToolCall::ContentDiscovery(prepared) => {
                Ok(super::execute_content_discovery(prepared, &self.http))
            }
            PreparedToolCall::AdaptiveBrowser(prepared) => self.adaptive_browser.execute(prepared),
            PreparedToolCall::ExternalRecon(prepared) => self.external_recon.execute(prepared),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentRuntimeErrorCode {
    ConfigurationError,
    AgentError,
    InvalidAgentAction,
    ActionNotAllowed,
    ToolExecutionError,
    ScopeBlocked,
    RateLimited,
    AgentDidNotFinish,
    RuntimeAlreadyRunning,
    RunNotFound,
    RunNotRunnable,
    RunServiceError,
}

impl AgentRuntimeErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::ConfigurationError => "CONFIGURATION_ERROR",
            Self::AgentError => "AGENT_ERROR",
            Self::InvalidAgentAction => "INVALID_AGENT_ACTION",
            Self::ActionNotAllowed => "ACTION_NOT_ALLOWED",
            Self::ToolExecutionError => "TOOL_EXECUTION_ERROR",
            Self::ScopeBlocked => "SCOPE_BLOCKED",
            Self::RateLimited => "RATE_LIMITED",
            Self::AgentDidNotFinish => "AGENT_DID_NOT_FINISH",
            Self::RuntimeAlreadyRunning => "RUNTIME_ALREADY_RUNNING",
            Self::RunNotFound => "RUN_NOT_FOUND",
            Self::RunNotRunnable => "RUN_NOT_RUNNABLE",
            Self::RunServiceError => "RUN_SERVICE_ERROR",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeError {
    pub code: AgentRuntimeErrorCode,
    pub message: String,
}

impl AgentRuntimeError {
    pub fn new(code: AgentRuntimeErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn from_service(error: RunServiceError) -> Self {
        let code = match error.code {
            RunServiceErrorCode::RunNotFound => AgentRuntimeErrorCode::RunNotFound,
            _ => AgentRuntimeErrorCode::RunServiceError,
        };
        Self::new(code, error.message)
    }
}

impl fmt::Display for AgentRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for AgentRuntimeError {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRunResult {
    pub run: Run,
    pub context: AgentContext,
}

pub struct AgentRuntime {
    clock: Arc<dyn Clock>,
}

impl Default for AgentRuntime {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl AgentRuntime {
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }

    pub fn execute(
        &self,
        service: &RunService,
        run_id: &RunId,
        agent: &mut dyn Agent,
        executor: &dyn ToolExecutor,
    ) -> Result<AgentRunResult, AgentRuntimeError> {
        self.execute_internal(service, run_id, agent, executor, None)
    }

    pub fn execute_managed(
        &self,
        service: &RunService,
        run_id: &RunId,
        agent: &mut dyn Agent,
        executor: &dyn ToolExecutor,
    ) -> Result<AgentRunResult, AgentRuntimeError> {
        let recorder = EvidenceRecorder::with_clock(self.clock.clone());
        let evaluator = DeterministicEvaluator::with_clock(self.clock.clone());
        self.execute_internal(
            service,
            run_id,
            agent,
            executor,
            Some(ManagedRuntimeComponents {
                recorder: &recorder,
                evaluator: &evaluator,
            }),
        )
    }

    fn execute_internal(
        &self,
        service: &RunService,
        run_id: &RunId,
        agent: &mut dyn Agent,
        executor: &dyn ToolExecutor,
        managed: Option<ManagedRuntimeComponents<'_>>,
    ) -> Result<AgentRunResult, AgentRuntimeError> {
        let existing = service
            .get_run(run_id)
            .map_err(AgentRuntimeError::from_service)?;
        match existing.status {
            RunStatus::Created => {}
            RunStatus::Running => {
                return Err(AgentRuntimeError::new(
                    AgentRuntimeErrorCode::RuntimeAlreadyRunning,
                    "The run is already running.",
                ));
            }
            _ => {
                return Err(AgentRuntimeError::new(
                    AgentRuntimeErrorCode::RunNotRunnable,
                    "Only a created run can be executed.",
                ));
            }
        }

        let task = service
            .get_run_task(run_id)
            .map_err(AgentRuntimeError::from_service)?;
        let started = service
            .start_run(run_id)
            .map_err(AgentRuntimeError::from_service)?;
        let runtime_started_at_ms = self.clock.now_ms();
        let recon_ingestor = ReconIngestor::with_clock(self.clock.clone());
        recon_ingestor
            .seed_task(service, run_id, &task)
            .map_err(AgentRuntimeError::from_service)?;
        let mut context = self.context(service, task, &started, vec![], vec![])?;
        let mut consecutive_rejections = 0_u8;

        loop {
            let run = service
                .get_run(run_id)
                .map_err(AgentRuntimeError::from_service)?;
            let step = run.usage.steps + 1;
            context.current_step = step;
            context.remaining_budget = Self::remaining_budget(&context.task.budget, &run.usage);
            context.events = service
                .get_run_events(run_id)
                .map_err(AgentRuntimeError::from_service)?;
            context.evidence = service
                .get_all_evidence(run_id)
                .map_err(AgentRuntimeError::from_service)?;
            context.recon_snapshot = service
                .get_recon_snapshot(run_id)
                .map_err(AgentRuntimeError::from_service)?;
            context.recon_memory = service
                .build_recon_memory(run_id)
                .map_err(AgentRuntimeError::from_service)?;
            context.browser_identities = browser_session_vault()
                .list()
                .unwrap_or_default()
                .into_iter()
                .filter(|identity| identity.scope_id == context.task.scope.id)
                .collect();
            context.recon_critique =
                ReconCritic::review(&context.recon_snapshot, &context.recon_memory);
            context.recon_plan = ReconPlanner::plan_with_memory(
                &context.task,
                &context.recon_snapshot,
                &context.recon_memory,
                step,
            );

            let action_result = agent.next_action(&context);
            let model_call = agent.take_last_model_call();
            let mut usage = RunUsage {
                steps: step,
                duration_ms: self.clock.now_ms().saturating_sub(runtime_started_at_ms),
                ..run.usage
            };
            if let Some(call) = &model_call {
                usage.model_calls = usage.model_calls.saturating_add(call.request_count);
                usage.input_tokens = usage.input_tokens.saturating_add(call.input_tokens);
                usage.output_tokens = usage.output_tokens.saturating_add(call.output_tokens);
            }
            let run = if let Some(call) = model_call {
                service
                    .commit_model_call(run_id, call, step, usage)
                    .map_err(AgentRuntimeError::from_service)?
            } else {
                service
                    .update_usage(run_id, usage)
                    .map_err(AgentRuntimeError::from_service)?
            };

            let mut action = match action_result {
                Ok(action) => action,
                Err(error) => {
                    let runtime_error = AgentRuntimeError::new(
                        AgentRuntimeErrorCode::AgentError,
                        format!("{}: {}", error.code, error.message),
                    );
                    self.fail_run(service, run_id, &runtime_error)?;
                    return Err(runtime_error);
                }
            };
            Self::apply_safe_action_defaults(&context.task, &mut action);

            let mut planning_rejection = None;
            if let Some(mut decision) = context.recon_plan.clone() {
                ReconPlanner::record_selection(&mut decision, &action);
                planning_rejection =
                    ReconPlanner::selection_rejection_reason(&context.recon_snapshot, &action);
                service
                    .append_recon_decision(run_id, decision.clone())
                    .map_err(AgentRuntimeError::from_service)?;
                context.recon_plan = Some(decision);
            }

            service
                .record_event(
                    run_id,
                    step,
                    RunEventKind::ActionReceived {
                        action: action.clone(),
                    },
                )
                .map_err(AgentRuntimeError::from_service)?;

            if let Some(reason) = planning_rejection {
                let error =
                    AgentRuntimeError::new(AgentRuntimeErrorCode::InvalidAgentAction, reason);
                service
                    .record_event(
                        run_id,
                        step,
                        RunEventKind::ActionRejected {
                            action: action.clone(),
                            reason: error.message.clone(),
                        },
                    )
                    .map_err(AgentRuntimeError::from_service)?;
                if agent.is_model_driven() {
                    consecutive_rejections = consecutive_rejections.saturating_add(1);
                    if consecutive_rejections < MAX_CONSECUTIVE_MODEL_REJECTIONS {
                        agent.on_action_rejected(&action, &error.message);
                        continue;
                    }
                }
                self.fail_run(service, run_id, &error)?;
                return Err(error);
            }

            let validated = match Self::validate_action(&context.task, &action) {
                Ok(validated) => validated,
                Err(error) => {
                    service
                        .record_event(
                            run_id,
                            step,
                            RunEventKind::ActionRejected {
                                action: action.clone(),
                                reason: error.message.clone(),
                            },
                        )
                        .map_err(AgentRuntimeError::from_service)?;
                    if agent.is_model_driven() {
                        consecutive_rejections = consecutive_rejections.saturating_add(1);
                        if consecutive_rejections < MAX_CONSECUTIVE_MODEL_REJECTIONS {
                            agent.on_action_rejected(&action, &error.message);
                            continue;
                        }
                    }
                    self.fail_run(service, run_id, &error)?;
                    return Err(error);
                }
            };

            match validated {
                ValidatedAction::Finish(output) => {
                    if let Some(error) = Self::validate_final_output_evidence(
                        service,
                        run_id,
                        &context.task,
                        &output,
                        managed.is_some(),
                        context.recon_plan.as_ref(),
                    )? {
                        service
                            .record_event(
                                run_id,
                                step,
                                RunEventKind::ActionRejected {
                                    action: action.clone(),
                                    reason: error.message.clone(),
                                },
                            )
                            .map_err(AgentRuntimeError::from_service)?;
                        if agent.is_model_driven() {
                            consecutive_rejections = consecutive_rejections.saturating_add(1);
                            if consecutive_rejections < MAX_CONSECUTIVE_MODEL_REJECTIONS {
                                agent.on_action_rejected(&action, &error.message);
                                continue;
                            }
                        }
                        self.fail_run(service, run_id, &error)?;
                        return Err(error);
                    }
                    let completed = service
                        .complete_run(run_id, output)
                        .map_err(AgentRuntimeError::from_service)?;
                    let completed = if let Some(components) = managed.as_ref() {
                        let final_output = completed.final_output.as_ref().ok_or_else(|| {
                            AgentRuntimeError::new(
                                AgentRuntimeErrorCode::RunServiceError,
                                "The completed run has no FinalOutput.",
                            )
                        })?;
                        let tool_results = service
                            .get_tool_results(run_id)
                            .map_err(AgentRuntimeError::from_service)?;
                        let evidence = service
                            .get_all_evidence(run_id)
                            .map_err(AgentRuntimeError::from_service)?;
                        let events = service
                            .get_run_events(run_id)
                            .map_err(AgentRuntimeError::from_service)?;
                        let evaluation = components.evaluator.evaluate(
                            &context.task,
                            &completed,
                            final_output,
                            &tool_results,
                            &evidence,
                            &events,
                        );
                        service
                            .set_evaluation_result(run_id, evaluation)
                            .map_err(AgentRuntimeError::from_service)?
                    } else {
                        completed
                    };
                    context = self.context(
                        service,
                        context.task,
                        &completed,
                        context.tool_results,
                        context.notes,
                    )?;
                    return Ok(AgentRunResult {
                        run: completed,
                        context,
                    });
                }
                ValidatedAction::Tool => {
                    let mut rate_retry_used = false;
                    let prepared_result = loop {
                        match executor.prepare(&action, &context.task) {
                            Err(error) if error.code == "RATE_LIMITED" && !rate_retry_used => {
                                rate_retry_used = true;
                                thread::sleep(Duration::from_millis(1_050));
                            }
                            result => break result,
                        }
                    };
                    let prepared = match prepared_result {
                        Ok(prepared) => prepared,
                        Err(error) if error.code == "RATE_LIMITED" => {
                            service
                                .record_event(
                                    run_id,
                                    step,
                                    RunEventKind::ActionRejected {
                                        action: action.clone(),
                                        reason: error.message.clone(),
                                    },
                                )
                                .map_err(AgentRuntimeError::from_service)?;
                            if agent.is_model_driven() {
                                agent.on_action_rejected(&action, &error.message);
                                continue;
                            }
                            let runtime_error = AgentRuntimeError::new(
                                AgentRuntimeErrorCode::RateLimited,
                                error.message,
                            );
                            self.fail_run(service, run_id, &runtime_error)?;
                            return Err(runtime_error);
                        }
                        Err(error) if error.code == "SCOPE_BLOCKED" => {
                            service
                                .record_event(
                                    run_id,
                                    step,
                                    RunEventKind::ActionRejected {
                                        action: action.clone(),
                                        reason: error.message.clone(),
                                    },
                                )
                                .map_err(AgentRuntimeError::from_service)?;
                            let target = super::recon_action_target(&action);
                            service
                                .block_scope(run_id, target, error.message.clone())
                                .map_err(AgentRuntimeError::from_service)?;
                            return Err(AgentRuntimeError::new(
                                AgentRuntimeErrorCode::ScopeBlocked,
                                error.message,
                            ));
                        }
                        Err(error) => {
                            let runtime_error = AgentRuntimeError::new(
                                AgentRuntimeErrorCode::ToolExecutionError,
                                format!("{}: {}", error.code, error.message),
                            );
                            service
                                .record_event(
                                    run_id,
                                    step,
                                    RunEventKind::ActionRejected {
                                        action: action.clone(),
                                        reason: runtime_error.message.clone(),
                                    },
                                )
                                .map_err(AgentRuntimeError::from_service)?;
                            if agent.is_model_driven() {
                                consecutive_rejections = consecutive_rejections.saturating_add(1);
                                if consecutive_rejections < MAX_CONSECUTIVE_MODEL_REJECTIONS {
                                    agent.on_action_rejected(&action, &runtime_error.message);
                                    continue;
                                }
                            }
                            self.fail_run(service, run_id, &runtime_error)?;
                            return Err(runtime_error);
                        }
                    };

                    service
                        .record_event(
                            run_id,
                            step,
                            RunEventKind::ToolStarted {
                                tool_name: action.name.clone(),
                            },
                        )
                        .map_err(AgentRuntimeError::from_service)?;

                    let tool_started_at_ms = self.clock.now_ms();
                    let outcome = match executor.execute(prepared) {
                        Ok(outcome) => outcome,
                        Err(error) if is_recoverable_tool_execution_error(&error) => {
                            ToolExecutionOutcome {
                                result: ToolResult {
                                    schema_version: CORE_SCHEMA_VERSION,
                                    id: ToolResultId(Uuid::new_v4().to_string()),
                                    tool_name: action.name.clone(),
                                    success: false,
                                    data: StructuredData::from([
                                        (
                                            "target".into(),
                                            Value::String(super::recon_action_target(&action)),
                                        ),
                                        ("degraded".into(), Value::Bool(true)),
                                    ]),
                                    error: Some(ToolError {
                                        code: error.code,
                                        message: error.message,
                                        retryable: true,
                                    }),
                                    duration_ms: self
                                        .clock
                                        .now_ms()
                                        .saturating_sub(tool_started_at_ms),
                                },
                                http_requests: u64::from(error.request_started),
                                model_calls: 0,
                                input_tokens: 0,
                                output_tokens: 0,
                            }
                        }
                        Err(error) => {
                            if error.request_started {
                                if let Err(usage_error) = self.increment_http_usage(
                                    service,
                                    run_id,
                                    runtime_started_at_ms,
                                ) {
                                    self.fail_run(service, run_id, &usage_error)?;
                                    return Err(usage_error);
                                }
                            }
                            let runtime_error = AgentRuntimeError::new(
                                AgentRuntimeErrorCode::ToolExecutionError,
                                format!("{}: {}", error.code, error.message),
                            );
                            self.fail_run(service, run_id, &runtime_error)?;
                            return Err(runtime_error);
                        }
                    };
                    let tool_http_requests = outcome.http_requests;
                    let tool_model_calls = outcome.model_calls;
                    let tool_input_tokens = outcome.input_tokens;
                    let tool_output_tokens = outcome.output_tokens;
                    let result = outcome.result;
                    let current = service
                        .get_run(run_id)
                        .map_err(AgentRuntimeError::from_service)?;
                    let committed_usage = RunUsage {
                        http_requests: current
                            .usage
                            .http_requests
                            .saturating_add(tool_http_requests),
                        model_calls: current.usage.model_calls.saturating_add(tool_model_calls),
                        input_tokens: current.usage.input_tokens.saturating_add(tool_input_tokens),
                        output_tokens: current
                            .usage
                            .output_tokens
                            .saturating_add(tool_output_tokens),
                        duration_ms: current
                            .usage
                            .duration_ms
                            .max(self.clock.now_ms().saturating_sub(runtime_started_at_ms)),
                        ..current.usage
                    };
                    let result =
                        match service.commit_tool_result(run_id, result, step, committed_usage) {
                            Ok(result) => result,
                            Err(error) => {
                                let runtime_error = AgentRuntimeError::from_service(error);
                                self.fail_run(service, run_id, &runtime_error)?;
                                return Err(runtime_error);
                            }
                        };
                    let evidence = if let Some(components) = managed.as_ref() {
                        match components
                            .recorder
                            .record_tool_result(service, run_id, step, &result)
                        {
                            Ok(evidence) => evidence,
                            Err(error) => {
                                let runtime_error = AgentRuntimeError::from_service(error);
                                self.fail_run(service, run_id, &runtime_error)?;
                                return Err(runtime_error);
                            }
                        }
                    } else {
                        None
                    };
                    if let Err(error) = recon_ingestor.ingest_tool_result(
                        service,
                        run_id,
                        &context.task,
                        &result,
                        evidence.as_ref(),
                    ) {
                        let runtime_error = AgentRuntimeError::from_service(error);
                        self.fail_run(service, run_id, &runtime_error)?;
                        return Err(runtime_error);
                    }

                    if !result.success {
                        let message = result
                            .error
                            .as_ref()
                            .map(|error| error.message.clone())
                            .unwrap_or_else(|| "The fake tool reported failure.".into());
                        let retryable = result.error.as_ref().is_some_and(|error| error.retryable);
                        context.tool_results.push(result);
                        if retryable && agent.is_model_driven() {
                            consecutive_rejections = 0;
                            continue;
                        }
                        let runtime_error = AgentRuntimeError::new(
                            AgentRuntimeErrorCode::ToolExecutionError,
                            message,
                        );
                        self.fail_run(service, run_id, &runtime_error)?;
                        return Err(runtime_error);
                    }

                    if let Some(note) = result.data.get("note").and_then(Value::as_str) {
                        context.notes.push(note.to_string());
                    }
                    consecutive_rejections = 0;
                    context.tool_results.push(result);
                    context.current_step = run.current_step;
                }
            }
        }
    }

    fn increment_http_usage(
        &self,
        service: &RunService,
        run_id: &RunId,
        runtime_started_at_ms: u64,
    ) -> Result<Run, AgentRuntimeError> {
        let run = service
            .get_run(run_id)
            .map_err(AgentRuntimeError::from_service)?;
        let usage = RunUsage {
            http_requests: run.usage.http_requests.saturating_add(1),
            duration_ms: run
                .usage
                .duration_ms
                .max(self.clock.now_ms().saturating_sub(runtime_started_at_ms)),
            ..run.usage
        };
        service
            .update_usage(run_id, usage)
            .map_err(AgentRuntimeError::from_service)
    }

    fn context(
        &self,
        service: &RunService,
        task: Task,
        run: &Run,
        tool_results: Vec<ToolResult>,
        notes: Vec<String>,
    ) -> Result<AgentContext, AgentRuntimeError> {
        let events = service
            .get_run_events(&run.id)
            .map_err(AgentRuntimeError::from_service)?;
        let recon_snapshot = service
            .get_recon_snapshot(&run.id)
            .map_err(AgentRuntimeError::from_service)?;
        let recon_memory = service
            .build_recon_memory(&run.id)
            .map_err(AgentRuntimeError::from_service)?;
        let recon_critique = ReconCritic::review(&recon_snapshot, &recon_memory);
        let browser_identities = browser_session_vault()
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|identity| identity.scope_id == task.scope.id)
            .collect();
        Ok(AgentContext {
            schema_version: CORE_SCHEMA_VERSION,
            remaining_budget: Self::remaining_budget(&task.budget, &run.usage),
            task,
            run_id: run.id.clone(),
            current_step: run.current_step,
            tool_results,
            evidence: service
                .get_all_evidence(&run.id)
                .map_err(AgentRuntimeError::from_service)?,
            events,
            notes,
            recon_snapshot,
            recon_plan: None,
            recon_memory,
            recon_critique,
            browser_identities,
        })
    }

    fn remaining_budget(budget: &TaskBudget, usage: &RunUsage) -> AgentBudgetRemaining {
        let remaining = |maximum: u64, used: u64| {
            if maximum == 0 {
                u64::MAX
            } else {
                maximum.saturating_sub(used)
            }
        };
        AgentBudgetRemaining {
            steps: remaining(budget.max_steps, usage.steps),
            http_requests: remaining(budget.max_http_requests, usage.http_requests),
            model_calls: remaining(budget.max_model_calls, usage.model_calls),
            input_tokens: remaining(budget.max_input_tokens, usage.input_tokens),
            output_tokens: remaining(budget.max_output_tokens, usage.output_tokens),
            duration_ms: remaining(budget.max_duration_ms, usage.duration_ms),
        }
    }

    fn validate_action(
        task: &Task,
        action: &AgentAction,
    ) -> Result<ValidatedAction, AgentRuntimeError> {
        if action.name.trim().is_empty() {
            return Err(AgentRuntimeError::new(
                AgentRuntimeErrorCode::InvalidAgentAction,
                "Agent action name cannot be empty.",
            ));
        }

        match action.name.as_str() {
            "finish" => {
                let value = action.arguments.get("final_output").ok_or_else(|| {
                    AgentRuntimeError::new(
                        AgentRuntimeErrorCode::InvalidAgentAction,
                        "finish requires a final_output argument.",
                    )
                })?;
                let output =
                    serde_json::from_value::<FinalOutput>(value.clone()).map_err(|error| {
                        AgentRuntimeError::new(
                            AgentRuntimeErrorCode::InvalidAgentAction,
                            format!("finish contains an invalid final_output: {error}"),
                        )
                    })?;
                if output.answer.trim().is_empty() {
                    return Err(AgentRuntimeError::new(
                        AgentRuntimeErrorCode::InvalidAgentAction,
                        "finish final_output answer cannot be empty.",
                    ));
                }
                Ok(ValidatedAction::Finish(output))
            }
            "record_note" => {
                if !task.available_tools.iter().any(|name| name == &action.name) {
                    return Err(AgentRuntimeError::new(
                        AgentRuntimeErrorCode::ActionNotAllowed,
                        "record_note is not allowed by this task.",
                    ));
                }
                let valid_text = action
                    .arguments
                    .get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.trim().is_empty());
                if !valid_text {
                    return Err(AgentRuntimeError::new(
                        AgentRuntimeErrorCode::InvalidAgentAction,
                        "record_note requires a non-empty text argument.",
                    ));
                }
                Ok(ValidatedAction::Tool)
            }
            "http_request"
            | "search_certificate_transparency"
            | "resolve_dns"
            | "inspect_dns_ownership"
            | "inspect_rdap"
            | "probe_tcp_service"
            | "probe_http"
            | "validate_url_metadata"
            | "fetch_robots_txt"
            | "fetch_sitemap"
            | "analyze_web_page"
            | "analyze_javascript"
            | "describe_api"
            | "lookup_web_archive"
            | "analyze_visual_page"
            | "discover_content"
            | "adaptive_browser_recon"
            | "query_external_intelligence" => {
                if !task.available_tools.iter().any(|name| name == &action.name) {
                    return Err(AgentRuntimeError::new(
                        AgentRuntimeErrorCode::ActionNotAllowed,
                        format!("{} is not allowed by this task.", action.name),
                    ));
                }
                Ok(ValidatedAction::Tool)
            }
            _ => Err(AgentRuntimeError::new(
                AgentRuntimeErrorCode::ActionNotAllowed,
                format!("Action '{}' is not supported by this runtime.", action.name),
            )),
        }
    }

    fn apply_safe_action_defaults(task: &Task, action: &mut AgentAction) {
        if action.name != "probe_http" {
            return;
        }
        let missing_url = action
            .arguments
            .get("url")
            .and_then(Value::as_str)
            .is_none_or(|url| url.trim().is_empty());
        if missing_url
            && (task.primary_target.starts_with("http://")
                || task.primary_target.starts_with("https://"))
        {
            action
                .arguments
                .insert("url".into(), Value::String(task.primary_target.clone()));
        }
    }

    fn validate_final_output_evidence(
        service: &RunService,
        run_id: &RunId,
        task: &Task,
        output: &FinalOutput,
        require_http_evidence: bool,
        recon_plan: Option<&ReconDecision>,
    ) -> Result<Option<AgentRuntimeError>, AgentRuntimeError> {
        let task_requires_http = (task.primary_target.starts_with("http://")
            || task.primary_target.starts_with("https://"))
            && task.available_tools.iter().any(|tool| {
                matches!(
                    tool.as_str(),
                    "http_request"
                        | "probe_http"
                        | "validate_url_metadata"
                        | "discover_content"
                        | "fetch_robots_txt"
                        | "fetch_sitemap"
                        | "analyze_web_page"
                        | "adaptive_browser_recon"
                        | "analyze_javascript"
                        | "describe_api"
                        | "analyze_visual_page"
                )
            });
        if require_http_evidence && task_requires_http && output.evidence_ids.is_empty() {
            return Ok(Some(AgentRuntimeError::new(
                AgentRuntimeErrorCode::InvalidAgentAction,
                "finish requires at least one stored Evidence ID for this HTTP task.",
            )));
        }
        if output.status == FinalOutputStatus::Completed {
            if output.answer.trim().eq_ignore_ascii_case("finish")
                || output.answer.trim().len() < 20
            {
                return Ok(Some(AgentRuntimeError::new(
                    AgentRuntimeErrorCode::InvalidAgentAction,
                    "finish requires a meaningful final answer, not a placeholder.",
                )));
            }
            if recon_plan.is_some_and(|plan| {
                plan.recommended_action_id.is_some()
                    && plan.knowledge_gaps.iter().any(|gap| gap.actionable)
            }) {
                return Ok(Some(AgentRuntimeError::new(
                    AgentRuntimeErrorCode::InvalidAgentAction,
                    "finish is premature while the current Recon plan has a novel recommended action above the information-gain threshold.",
                )));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for evidence_id in &output.evidence_ids {
            if !seen.insert(evidence_id.clone()) {
                return Ok(Some(AgentRuntimeError::new(
                    AgentRuntimeErrorCode::InvalidAgentAction,
                    format!("finish contains duplicate Evidence ID '{}'.", evidence_id.0),
                )));
            }
            match service.get_evidence(run_id, evidence_id) {
                Ok(_) => {}
                Err(error) if error.code == RunServiceErrorCode::EvidenceNotFound => {
                    return Ok(Some(AgentRuntimeError::new(
                        AgentRuntimeErrorCode::InvalidAgentAction,
                        format!("finish references unknown Evidence ID '{}'.", evidence_id.0),
                    )));
                }
                Err(error) => return Err(AgentRuntimeError::from_service(error)),
            }
        }
        Ok(None)
    }

    fn fail_run(
        &self,
        service: &RunService,
        run_id: &RunId,
        error: &AgentRuntimeError,
    ) -> Result<(), AgentRuntimeError> {
        service
            .fail_run(
                run_id,
                RunFailure {
                    code: error.code.as_str().into(),
                    message: error.message.clone(),
                },
            )
            .map(|_| ())
            .map_err(AgentRuntimeError::from_service)
    }
}

#[derive(Clone, Copy)]
struct ManagedRuntimeComponents<'a> {
    recorder: &'a EvidenceRecorder,
    evaluator: &'a dyn Evaluator,
}

enum ValidatedAction {
    Tool,
    Finish(FinalOutput),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{
            local_lab::LocalLab, CertificateTransparencyProvider, CertificateTransparencyResult,
            FinalOutputStatus, HistoricalCapture, HistoricalProviderError,
            HistoricalProviderResult, HistoricalReconProvider,
        },
        scope_guard::{ScopeGuardState, ScopeProject},
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    struct StepClock(AtomicU64);

    struct FakeCertificateTransparency;

    struct FakeHistoricalProvider {
        name: &'static str,
        requests: u64,
    }

    impl CertificateTransparencyProvider for FakeCertificateTransparency {
        fn search(
            &self,
            domain: &str,
        ) -> Result<CertificateTransparencyResult, ToolExecutionError> {
            Ok(CertificateTransparencyResult {
                record_count: 2,
                hostnames: vec![domain.into(), format!("api.{domain}")],
            })
        }
    }

    impl HistoricalReconProvider for FakeHistoricalProvider {
        fn lookup(
            &self,
            domain: &str,
        ) -> Result<HistoricalProviderResult, HistoricalProviderError> {
            Ok(HistoricalProviderResult {
                provider: self.name.into(),
                captures: vec![HistoricalCapture {
                    url: format!("https://api.{domain}/assets/legacy.js?version=old"),
                    timestamp: if self.name == "wayback" {
                        "20200101000000".into()
                    } else {
                        "20240101000000".into()
                    },
                    status: Some(200),
                    mime_type: Some("application/javascript".into()),
                    digest: None,
                }],
                http_requests: self.requests,
            })
        }
    }

    impl Clock for StepClock {
        fn now_ms(&self) -> u64 {
            self.0.fetch_add(5, Ordering::SeqCst)
        }
    }

    struct FailingExecutor;

    impl ToolExecutor for FailingExecutor {
        fn prepare(
            &self,
            action: &AgentAction,
            task: &Task,
        ) -> Result<PreparedToolCall, ToolExecutionError> {
            FakeToolExecutor.prepare(action, task)
        }

        fn execute(
            &self,
            _prepared: PreparedToolCall,
        ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
            Err(ToolExecutionError {
                code: "FAKE_TOOL_FAILED".into(),
                message: "The fake executor failed intentionally.".into(),
                request_started: false,
            })
        }
    }

    struct DuplicateIdExecutor;

    impl ToolExecutor for DuplicateIdExecutor {
        fn prepare(
            &self,
            action: &AgentAction,
            task: &Task,
        ) -> Result<PreparedToolCall, ToolExecutionError> {
            FakeToolExecutor.prepare(action, task)
        }

        fn execute(
            &self,
            prepared: PreparedToolCall,
        ) -> Result<ToolExecutionOutcome, ToolExecutionError> {
            let PreparedToolCall::RecordNote { note } = prepared else {
                return Err(ToolExecutionError {
                    code: "INVALID_NOTE".into(),
                    message: "Expected a prepared record_note call.".into(),
                    request_started: false,
                });
            };
            Ok(ToolExecutionOutcome {
                result: ToolResult {
                    schema_version: CORE_SCHEMA_VERSION,
                    id: ToolResultId("duplicate-tool-result".into()),
                    tool_name: "record_note".into(),
                    success: true,
                    data: StructuredData::from([("note".into(), Value::String(note))]),
                    error: None,
                    duration_ms: 0,
                },
                http_requests: 0,
                model_calls: 0,
                input_tokens: 0,
                output_tokens: 0,
            })
        }
    }

    fn runtime() -> AgentRuntime {
        AgentRuntime::with_clock(Arc::new(StepClock(AtomicU64::new(10_000))))
    }

    fn task(max_steps: u64) -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: super::super::TaskId("task-runtime".into()),
            objective: "Exercise the deterministic runtime.".into(),
            primary_target: "local://deterministic-test".into(),
            scope: ScopeProject {
                id: "scope-runtime".into(),
                allowed_domains: vec![],
                excluded_domains: vec![],
                allowed_ports: vec![],
                request_rate: 1,
                authorized: true,
            },
            budget: TaskBudget {
                max_steps,
                max_http_requests: 0,
                max_model_calls: 0,
                max_input_tokens: 0,
                max_output_tokens: 0,
                max_duration_ms: 60_000,
            },
            available_tools: vec!["record_note".into()],
            memory_policy: Default::default(),
        }
    }

    fn output() -> FinalOutput {
        FinalOutput {
            schema_version: CORE_SCHEMA_VERSION,
            status: FinalOutputStatus::Completed,
            answer: "The deterministic run completed.".into(),
            evidence_ids: vec![],
            limitations: vec!["No network or model was used.".into()],
        }
    }

    fn note_action(note: &str) -> AgentAction {
        AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "record_note".into(),
            arguments: StructuredData::from([("text".into(), Value::String(note.into()))]),
            reason: "Record a test note.".into(),
        }
    }

    fn http_action(url: String) -> AgentAction {
        AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "http_request".into(),
            arguments: StructuredData::from([
                ("method".into(), Value::String("GET".into())),
                ("url".into(), Value::String(url)),
                ("timeout_ms".into(), Value::from(2_000)),
            ]),
            reason: "Read the authorized local profile.".into(),
        }
    }

    fn recon_http_action(name: &str, key: &str, url: String) -> AgentAction {
        AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: name.into(),
            arguments: StructuredData::from([(key.into(), Value::String(url))]),
            reason: "Collect one lightweight passive HTTP observation.".into(),
        }
    }

    fn finish_action() -> AgentAction {
        AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "finish".into(),
            arguments: StructuredData::from([(
                "final_output".into(),
                serde_json::to_value(output()).unwrap(),
            )]),
            reason: "Finish after the authorized request.".into(),
        }
    }

    fn http_task(port: u16) -> Task {
        let mut task = task(3);
        task.primary_target = format!("http://127.0.0.1:{port}");
        task.scope.allowed_domains = vec!["127.0.0.1".into()];
        task.scope.allowed_ports = vec![port];
        task.scope.request_rate = 5;
        task.budget.max_http_requests = 2;
        task.available_tools = vec!["http_request".into()];
        task
    }

    fn event_names(events: &[RunEvent]) -> Vec<&'static str> {
        events
            .iter()
            .map(|event| match &event.kind {
                RunEventKind::RunCreated { .. } => "run_created",
                RunEventKind::RunStarted { .. } => "run_started",
                RunEventKind::ActionReceived { .. } => "action_received",
                RunEventKind::ActionRejected { .. } => "action_rejected",
                RunEventKind::ToolStarted { .. } => "tool_started",
                RunEventKind::ToolCompleted { .. } => "tool_completed",
                RunEventKind::RunCompleted { .. } => "run_completed",
                RunEventKind::RunFailed { .. } => "run_failed",
                RunEventKind::ScopeBlocked { .. } => "scope_blocked",
                _ => "other",
            })
            .collect()
    }

    #[test]
    fn probe_http_defaults_an_empty_url_to_the_authorized_primary_target() {
        let task = http_task(4_280);
        let mut action = AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "probe_http".into(),
            arguments: StructuredData::new(),
            reason: "Start the authorized HTTP reconnaissance.".into(),
        };

        AgentRuntime::apply_safe_action_defaults(&task, &mut action);

        assert_eq!(
            action.arguments.get("url").and_then(Value::as_str),
            Some(task.primary_target.as_str())
        );
    }

    #[test]
    fn scripted_agent_completes_full_loop_with_ordered_events_and_usage() {
        let service = RunService::default();
        let run = service.create_run(task(3)).unwrap();
        let mut agent = ScriptedAgent::successful("Deterministic note.", output()).unwrap();
        let result = runtime()
            .execute(&service, &run.id, &mut agent, &FakeToolExecutor)
            .unwrap();

        assert_eq!(result.run.status, RunStatus::Completed);
        assert_eq!(result.run.usage.steps, 2);
        assert_eq!(result.run.usage.model_calls, 0);
        assert_eq!(result.run.usage.http_requests, 0);
        assert_eq!(result.context.tool_results.len(), 1);
        assert_eq!(result.context.notes, vec!["Deterministic note."]);
        assert_eq!(
            service.get_tool_results(&run.id).unwrap(),
            result.context.tool_results
        );
        assert_eq!(result.run.final_output, Some(output()));
        assert_eq!(
            event_names(&result.context.events),
            vec![
                "run_created",
                "run_started",
                "action_received",
                "tool_started",
                "tool_completed",
                "action_received",
                "run_completed",
            ]
        );
    }

    #[test]
    fn authorized_http_request_completes_and_persists_result() {
        let lab = LocalLab::start().unwrap();
        let service = RunService::default();
        let run = service.create_run(http_task(lab.port())).unwrap();
        let mut agent = ScriptedAgent::new(vec![
            Ok(http_action(format!("{}/profile", lab.base_url()))),
            Ok(finish_action()),
        ]);
        let executor = CoreToolExecutor::new(
            HttpRequestTool::new(Arc::new(ScopeGuardState::default())).unwrap(),
        );

        let result = runtime()
            .execute(&service, &run.id, &mut agent, &executor)
            .unwrap();
        let stored = service.get_tool_results(&run.id).unwrap();
        assert_eq!(result.run.status, RunStatus::Completed);
        assert_eq!(result.run.usage.steps, 2);
        assert_eq!(result.run.usage.http_requests, 1);
        assert_eq!(result.run.usage.model_calls, 0);
        assert_eq!(stored, result.context.tool_results);
        assert_eq!(stored[0].data["status_code"], 200);
        assert!(stored[0].data["response_body"]
            .as_str()
            .unwrap()
            .contains("alice"));
    }

    #[test]
    fn passive_recon_run_records_evidence_graph_and_adaptive_decisions() {
        let service = RunService::default();
        let mut recon_task = task(0);
        recon_task.primary_target = "https://example.test".into();
        recon_task.scope.allowed_domains = vec!["example.test".into(), "*.example.test".into()];
        recon_task.scope.allowed_ports = vec![443];
        recon_task.scope.request_rate = 5;
        recon_task.available_tools = vec!["search_certificate_transparency".into()];
        let run = service.create_run(recon_task).unwrap();
        let mut agent = ScriptedAgent::new(vec![
            Ok(AgentAction {
                schema_version: CORE_SCHEMA_VERSION,
                name: "search_certificate_transparency".into(),
                arguments: StructuredData::from([(
                    "domain".into(),
                    Value::String("example.test".into()),
                )]),
                reason: "Start with the highest-value passive source.".into(),
            }),
            Ok(finish_action()),
        ]);
        let passive =
            PassiveReconTools::with_certificate_transparency(Arc::new(FakeCertificateTransparency));
        let executor = CoreToolExecutor::with_passive_recon(
            HttpRequestTool::new(Arc::new(ScopeGuardState::default())).unwrap(),
            passive,
        );

        let completed = runtime()
            .execute_managed(&service, &run.id, &mut agent, &executor)
            .unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        assert_eq!(completed.run.status, RunStatus::Completed);
        assert_eq!(completed.run.usage.http_requests, 1);
        assert_eq!(service.get_all_evidence(&run.id).unwrap().len(), 1);
        assert!(snapshot
            .assets
            .iter()
            .any(|asset| asset.canonical_value == "api.example.test"));
        assert_eq!(snapshot.observations.len(), 1);
        assert_eq!(snapshot.decisions.len(), 2);
        assert!(snapshot.decisions[0].selected_action_id.is_some());
        assert_eq!(snapshot.decisions[1].mode, super::super::ReconMode::Stop);
    }

    #[test]
    fn historical_recon_merges_sources_and_persists_graph_clues() {
        let service = RunService::default();
        let mut recon_task = task(0);
        recon_task.primary_target = "https://example.test".into();
        recon_task.scope.allowed_domains = vec!["example.test".into(), "*.example.test".into()];
        recon_task.scope.allowed_ports = vec![443];
        recon_task.available_tools = vec!["lookup_web_archive".into()];
        let run = service.create_run(recon_task).unwrap();
        let mut agent = ScriptedAgent::new(vec![
            Ok(AgentAction {
                schema_version: CORE_SCHEMA_VERSION,
                name: "lookup_web_archive".into(),
                arguments: StructuredData::from([(
                    "domain".into(),
                    Value::String("example.test".into()),
                )]),
                reason: "Fill the historical coverage gap.".into(),
            }),
            Ok(finish_action()),
        ]);
        let historical = HistoricalReconTool::with_providers(vec![
            Arc::new(FakeHistoricalProvider {
                name: "wayback",
                requests: 1,
            }),
            Arc::new(FakeHistoricalProvider {
                name: "common_crawl",
                requests: 2,
            }),
        ]);
        let executor = CoreToolExecutor::with_historical_recon(
            HttpRequestTool::new(Arc::new(ScopeGuardState::default())).unwrap(),
            historical,
        );

        let completed = runtime()
            .execute_managed(&service, &run.id, &mut agent, &executor)
            .unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        let results = service.get_tool_results(&run.id).unwrap();

        assert_eq!(completed.run.status, RunStatus::Completed);
        assert_eq!(completed.run.usage.http_requests, 3);
        assert_eq!(service.get_all_evidence(&run.id).unwrap().len(), 1);
        assert_eq!(results[0].data["historical_url_count"], 1);
        assert!(snapshot
            .assets
            .iter()
            .any(|asset| { asset.kind == super::super::ReconAssetKind::HistoricalUrl }));
        assert!(snapshot
            .assets
            .iter()
            .any(|asset| { asset.kind == super::super::ReconAssetKind::JavascriptBundle }));
        assert!(snapshot.observations.iter().any(|observation| {
            observation.source == super::super::ReconObservationSource::WebArchive
        }));
    }

    #[test]
    fn local_passive_http_package_records_service_metadata_robots_and_sitemap() {
        let lab = LocalLab::start().unwrap();
        let service = RunService::default();
        let mut recon_task = http_task(lab.port());
        recon_task.primary_target = lab.base_url();
        recon_task.available_tools = vec![
            "probe_http".into(),
            "fetch_robots_txt".into(),
            "fetch_sitemap".into(),
        ];
        let run = service.create_run(recon_task).unwrap();
        let mut agent = ScriptedAgent::new(vec![
            Ok(recon_http_action("probe_http", "url", lab.base_url())),
            Ok(recon_http_action(
                "fetch_robots_txt",
                "base_url",
                lab.base_url(),
            )),
            Ok(recon_http_action(
                "fetch_sitemap",
                "base_url",
                lab.base_url(),
            )),
            Ok(finish_action()),
        ]);
        let executor = CoreToolExecutor::new(
            HttpRequestTool::new(Arc::new(ScopeGuardState::default())).unwrap(),
        );

        let completed = runtime()
            .execute_managed(&service, &run.id, &mut agent, &executor)
            .unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        assert_eq!(completed.run.status, RunStatus::Completed);
        assert_eq!(completed.run.usage.http_requests, 3);
        assert_eq!(service.get_all_evidence(&run.id).unwrap().len(), 3);
        assert_eq!(snapshot.observations.len(), 3);
        assert!(snapshot
            .assets
            .iter()
            .any(|asset| asset.kind == super::super::ReconAssetKind::HttpService));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == super::super::ReconAssetKind::Technology
                && asset.canonical_value == "React"
        }));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == super::super::ReconAssetKind::Url
                && asset.canonical_value.ends_with("/private")
        }));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == super::super::ReconAssetKind::Url
                && asset.canonical_value.ends_with("/profile")
        }));
        assert_eq!(
            snapshot.decisions.last().map(|decision| decision.mode),
            Some(super::super::ReconMode::Stop)
        );
    }

    #[test]
    fn javascript_and_openapi_package_persists_sanitized_intelligence() {
        let lab = LocalLab::start().unwrap();
        let service = RunService::default();
        let mut recon_task = http_task(lab.port());
        recon_task.primary_target = lab.base_url();
        recon_task.budget.max_http_requests = 3;
        recon_task.available_tools = vec![
            "probe_http".into(),
            "analyze_javascript".into(),
            "describe_api".into(),
        ];
        let run = service.create_run(recon_task).unwrap();
        let mut agent = ScriptedAgent::new(vec![
            Ok(recon_http_action("probe_http", "url", lab.base_url())),
            Ok(recon_http_action(
                "analyze_javascript",
                "url",
                format!("{}/assets/app.js", lab.base_url()),
            )),
            Ok(recon_http_action(
                "describe_api",
                "url",
                format!("{}/openapi.json", lab.base_url()),
            )),
            Ok(finish_action()),
        ]);
        let executor = CoreToolExecutor::new(
            HttpRequestTool::new(Arc::new(ScopeGuardState::default())).unwrap(),
        );

        let completed = runtime()
            .execute_managed(&service, &run.id, &mut agent, &executor)
            .unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        let results = service.get_tool_results(&run.id).unwrap();
        let javascript = results
            .iter()
            .find(|result| result.tool_name == "analyze_javascript")
            .unwrap();
        let api = results
            .iter()
            .find(|result| result.tool_name == "describe_api")
            .unwrap();
        let serialized = serde_json::to_string(javascript).unwrap();

        assert_eq!(completed.run.status, RunStatus::Completed);
        assert_eq!(completed.run.usage.http_requests, 3);
        assert_eq!(service.get_all_evidence(&run.id).unwrap().len(), 3);
        assert!(javascript.data.get("response_body").is_none());
        assert_eq!(javascript.data["raw_body_retained"], false);
        assert_eq!(javascript.data["secret_indicator_count"], 1);
        assert_eq!(
            javascript.data["graphql_operations"][0]["name"],
            "AccountOverview"
        );
        assert!(javascript.data["endpoint_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile["methods"]
                .as_array()
                .unwrap()
                .contains(&Value::String("POST".into()))));
        assert_eq!(api.data["operation_count"], 3);
        assert_eq!(api.data["public_operation_count"], 2);
        assert_eq!(api.data["authenticated_operation_count"], 1);
        assert!(!serialized.contains("lab-placeholder-value"));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == super::super::ReconAssetKind::JavascriptBundle
                && asset.canonical_value.ends_with("/assets/app.js")
        }));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == super::super::ReconAssetKind::Endpoint
                && asset.canonical_value.contains("/api/v1/users")
        }));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == super::super::ReconAssetKind::AuthenticationSurface
                && asset.canonical_value.ends_with("/login")
        }));
        assert!(snapshot.assets.iter().any(|asset| {
            asset.kind == super::super::ReconAssetKind::AuthenticationSurface
                && asset
                    .canonical_value
                    .contains("hexhunt-auth-scheme-bearerAuth")
        }));
        assert!(snapshot
            .assets
            .iter()
            .any(|asset| asset.kind == super::super::ReconAssetKind::Parameter));
        assert!(snapshot
            .assets
            .iter()
            .any(|asset| asset.kind == super::super::ReconAssetKind::DataModel));
        assert!(snapshot.hypotheses.iter().any(|hypothesis| {
            hypothesis.kind == Some(super::super::ReconHypothesisKind::UndocumentedEndpoint)
        }));
        assert!(snapshot.hypotheses.iter().any(|hypothesis| {
            hypothesis.kind == Some(super::super::ReconHypothesisKind::PublicSensitiveOperation)
        }));
        assert!(snapshot.observations.iter().any(|observation| {
            observation.source == super::super::ReconObservationSource::JavascriptAnalysis
        }));
        assert!(snapshot.observations.iter().any(|observation| {
            observation.source == super::super::ReconObservationSource::ApiDescription
        }));
    }

    #[test]
    fn visual_recon_is_persisted_as_evidence_and_updates_usage_and_graph() {
        let lab = LocalLab::start().unwrap();
        let service = RunService::default();
        let mut recon_task = http_task(lab.port());
        recon_task.primary_target = lab.base_url();
        recon_task.budget.max_http_requests = 1;
        recon_task.available_tools = vec!["analyze_visual_page".into()];
        let run = service.create_run(recon_task).unwrap();
        let mut agent = ScriptedAgent::new(vec![
            Ok(recon_http_action(
                "analyze_visual_page",
                "url",
                lab.base_url(),
            )),
            Ok(finish_action()),
        ]);
        let executor = CoreToolExecutor::with_deterministic_visual_recon(
            HttpRequestTool::new(Arc::new(ScopeGuardState::default())).unwrap(),
        );

        let completed = runtime()
            .execute_managed(&service, &run.id, &mut agent, &executor)
            .unwrap();
        let results = service.get_tool_results(&run.id).unwrap();
        let snapshot = service.get_recon_snapshot(&run.id).unwrap();

        assert_eq!(completed.run.status, RunStatus::Completed);
        assert_eq!(completed.run.usage.http_requests, 1);
        assert_eq!(completed.run.usage.model_calls, 1);
        assert_eq!(completed.run.usage.input_tokens, 120);
        assert_eq!(completed.run.usage.output_tokens, 40);
        assert_eq!(service.get_all_evidence(&run.id).unwrap().len(), 1);
        assert_eq!(results[0].data["screenshot_retained"], false);
        assert!(snapshot
            .assets
            .iter()
            .any(|asset| { asset.kind == super::super::ReconAssetKind::AuthenticationSurface }));
        assert!(snapshot.observations.iter().any(|observation| {
            observation.source == super::super::ReconObservationSource::VisualAnalysis
        }));
    }

    #[test]
    fn out_of_scope_http_request_blocks_without_network_usage() {
        let lab = LocalLab::start().unwrap();
        let service = RunService::default();
        let run = service.create_run(http_task(lab.port())).unwrap();
        let mut agent = ScriptedAgent::new(vec![Ok(http_action(
            "http://example.invalid/profile".into(),
        ))]);
        let executor = CoreToolExecutor::new(
            HttpRequestTool::new(Arc::new(ScopeGuardState::default())).unwrap(),
        );

        let error = runtime()
            .execute(&service, &run.id, &mut agent, &executor)
            .unwrap_err();
        let blocked = service.get_run(&run.id).unwrap();
        assert_eq!(error.code, AgentRuntimeErrorCode::ScopeBlocked);
        assert_eq!(blocked.status, RunStatus::ScopeBlocked);
        assert_eq!(blocked.usage.steps, 1);
        assert_eq!(blocked.usage.http_requests, 0);
        assert!(service.get_tool_results(&run.id).unwrap().is_empty());
        assert_eq!(
            event_names(&service.get_run_events(&run.id).unwrap()),
            vec![
                "run_created",
                "run_started",
                "action_received",
                "action_rejected",
                "scope_blocked",
            ]
        );
    }

    #[test]
    fn disallowed_action_is_rejected_and_run_fails() {
        let service = RunService::default();
        let run = service.create_run(task(2)).unwrap();
        let mut agent = ScriptedAgent::new(vec![Ok(AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "unknown_tool".into(),
            arguments: StructuredData::new(),
            reason: "Attempt an unsupported action.".into(),
        })]);

        let error = runtime()
            .execute(&service, &run.id, &mut agent, &FakeToolExecutor)
            .unwrap_err();
        assert_eq!(error.code, AgentRuntimeErrorCode::ActionNotAllowed);
        assert_eq!(service.get_run(&run.id).unwrap().status, RunStatus::Failed);
        assert_eq!(
            event_names(&service.get_run_events(&run.id).unwrap()),
            vec![
                "run_created",
                "run_started",
                "action_received",
                "action_rejected",
                "run_failed",
            ]
        );
    }

    #[test]
    fn invalid_arguments_are_rejected() {
        let service = RunService::default();
        let run = service.create_run(task(2)).unwrap();
        let mut agent = ScriptedAgent::new(vec![Ok(AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "record_note".into(),
            arguments: StructuredData::new(),
            reason: "Missing note text.".into(),
        })]);

        let error = runtime()
            .execute(&service, &run.id, &mut agent, &FakeToolExecutor)
            .unwrap_err();
        assert_eq!(error.code, AgentRuntimeErrorCode::InvalidAgentAction);
        assert_eq!(service.get_run(&run.id).unwrap().status, RunStatus::Failed);
    }

    #[test]
    fn agent_error_fails_run_without_panicking() {
        let service = RunService::default();
        let run = service.create_run(task(2)).unwrap();
        let mut agent = ScriptedAgent::new(vec![Err(AgentError {
            code: "FAKE_AGENT_ERROR".into(),
            message: "The fake agent failed intentionally.".into(),
        })]);

        let error = runtime()
            .execute(&service, &run.id, &mut agent, &FakeToolExecutor)
            .unwrap_err();
        assert_eq!(error.code, AgentRuntimeErrorCode::AgentError);
        assert_eq!(service.get_run(&run.id).unwrap().status, RunStatus::Failed);
    }

    #[test]
    fn tool_error_fails_run_with_structured_error() {
        let service = RunService::default();
        let run = service.create_run(task(2)).unwrap();
        let mut agent = ScriptedAgent::new(vec![Ok(note_action("Will fail."))]);

        let error = runtime()
            .execute(&service, &run.id, &mut agent, &FailingExecutor)
            .unwrap_err();
        assert_eq!(error.code, AgentRuntimeErrorCode::ToolExecutionError);
        assert_eq!(service.get_run(&run.id).unwrap().status, RunStatus::Failed);
    }

    #[test]
    fn tool_result_persistence_failure_stops_and_fails_run() {
        let service = RunService::default();
        let run = service.create_run(task(3)).unwrap();
        let mut agent = ScriptedAgent::new(vec![
            Ok(note_action("First.")),
            Ok(note_action("Duplicate ID.")),
        ]);

        let error = runtime()
            .execute(&service, &run.id, &mut agent, &DuplicateIdExecutor)
            .unwrap_err();
        assert_eq!(error.code, AgentRuntimeErrorCode::RunServiceError);
        assert_eq!(service.get_run(&run.id).unwrap().status, RunStatus::Failed);
        assert_eq!(service.get_tool_results(&run.id).unwrap().len(), 1);
    }

    #[test]
    fn missing_and_completed_runs_are_rejected() {
        let service = RunService::default();
        let mut agent = ScriptedAgent::successful("Note.", output()).unwrap();
        let missing = runtime()
            .execute(
                &service,
                &RunId("missing".into()),
                &mut agent,
                &FakeToolExecutor,
            )
            .unwrap_err();
        assert_eq!(missing.code, AgentRuntimeErrorCode::RunNotFound);

        let run = service.create_run(task(2)).unwrap();
        let mut first_agent = ScriptedAgent::successful("Note.", output()).unwrap();
        runtime()
            .execute(&service, &run.id, &mut first_agent, &FakeToolExecutor)
            .unwrap();
        let mut second_agent = ScriptedAgent::successful("Another.", output()).unwrap();
        let completed = runtime()
            .execute(&service, &run.id, &mut second_agent, &FakeToolExecutor)
            .unwrap_err();
        assert_eq!(completed.code, AgentRuntimeErrorCode::RunNotRunnable);
    }
}
