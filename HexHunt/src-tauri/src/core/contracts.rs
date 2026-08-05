use crate::scope_guard::ScopeProject;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const CORE_SCHEMA_VERSION: u32 = 1;

pub type StructuredData = BTreeMap<String, Value>;

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

string_id!(TaskId);
string_id!(RunId);
string_id!(RunEventId);
string_id!(ToolResultId);
string_id!(EvidenceId);

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMemoryMode {
    #[default]
    Fresh,
    Continue,
    AutoAssisted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunMemoryPolicy {
    pub mode: RunMemoryMode,
    #[serde(default)]
    pub source_run_ids: Vec<RunId>,
    #[serde(default)]
    pub max_age_ms: Option<u64>,
    #[serde(default = "default_max_source_runs")]
    pub max_source_runs: u16,
}

const fn default_max_source_runs() -> u16 {
    5
}

impl Default for RunMemoryPolicy {
    fn default() -> Self {
        Self {
            mode: RunMemoryMode::Fresh,
            source_run_ids: Vec::new(),
            max_age_ms: None,
            max_source_runs: default_max_source_runs(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBudget {
    pub max_steps: u64,
    pub max_http_requests: u64,
    pub max_model_calls: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_duration_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub schema_version: u32,
    pub id: TaskId,
    pub objective: String,
    pub primary_target: String,
    pub scope: ScopeProject,
    pub budget: TaskBudget,
    pub available_tools: Vec<String>,
    #[serde(default)]
    pub memory_policy: RunMemoryPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Created,
    Running,
    Completed,
    Failed,
    Cancelled,
    BudgetExhausted,
    ScopeBlocked,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunUsage {
    pub steps: u64,
    pub http_requests: u64,
    pub model_calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub schema_version: u32,
    pub id: RunId,
    pub task_id: TaskId,
    pub created_at_ms: u64,
    pub started_at_ms: Option<u64>,
    pub ended_at_ms: Option<u64>,
    pub status: RunStatus,
    pub current_step: u64,
    pub usage: RunUsage,
    pub final_output: Option<FinalOutput>,
    pub evaluation: Option<EvaluationResult>,
}

impl Run {
    pub fn new(id: RunId, task_id: TaskId, created_at_ms: u64) -> Self {
        Self {
            schema_version: CORE_SCHEMA_VERSION,
            id,
            task_id,
            created_at_ms,
            started_at_ms: None,
            ended_at_ms: None,
            status: RunStatus::Created,
            current_step: 0,
            usage: RunUsage::default(),
            final_output: None,
            evaluation: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAction {
    pub schema_version: u32,
    pub name: String,
    pub arguments: StructuredData,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResult {
    pub schema_version: u32,
    pub id: ToolResultId,
    pub tool_name: String,
    pub success: bool,
    pub data: StructuredData,
    pub error: Option<ToolError>,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum EvidenceSource {
    Request { request_id: String },
    ToolResult { tool_result_id: ToolResultId },
    ModelCall { model_call_id: String },
    Manual { reference: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema_version: u32,
    pub id: EvidenceId,
    pub run_id: RunId,
    pub source: EvidenceSource,
    pub description: String,
    pub value_or_excerpt: String,
    pub recorded_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalOutputStatus {
    Completed,
    Inconclusive,
    BudgetExhausted,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalOutput {
    pub schema_version: u32,
    pub status: FinalOutputStatus,
    pub answer: String,
    pub evidence_ids: Vec<EvidenceId>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub schema_version: u32,
    pub verdict: EvaluationVerdict,
    pub passed: bool,
    pub score: Option<f64>,
    pub success_reasons: Vec<String>,
    pub failure_reasons: Vec<String>,
    pub evaluated_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationVerdict {
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunFailure {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKind {
    Steps,
    HttpRequests,
    ModelCalls,
    InputTokens,
    OutputTokens,
    Duration,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "event_type", content = "data")]
pub enum RunEventKind {
    RunCreated {
        task_id: TaskId,
    },
    RunStarted {
        task_id: TaskId,
    },
    ModelCalled {
        model_call_id: String,
        model: Option<String>,
    },
    ActionReceived {
        action: AgentAction,
    },
    ActionRejected {
        action: AgentAction,
        reason: String,
    },
    ToolStarted {
        tool_name: String,
    },
    ToolCompleted {
        tool_result_id: ToolResultId,
        success: bool,
    },
    EvidenceRecorded {
        evidence_id: EvidenceId,
    },
    ScopeBlocked {
        target: String,
        reason: String,
    },
    BudgetExhausted {
        budget: BudgetKind,
    },
    RunCompleted {
        status: FinalOutputStatus,
    },
    RunFailed {
        error: RunFailure,
    },
    RunCancelled {
        reason: Option<String>,
    },
    EvaluationCompleted {
        passed: bool,
        score: Option<f64>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunEvent {
    pub schema_version: u32,
    pub id: RunEventId,
    pub run_id: RunId,
    pub timestamp_ms: u64,
    pub step: u64,
    #[serde(flatten)]
    pub kind: RunEventKind,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    fn scope() -> ScopeProject {
        ScopeProject {
            id: "scope-1".into(),
            allowed_domains: vec!["app.example.test".into(), "*.api.example.test".into()],
            excluded_domains: vec!["admin.example.test".into()],
            allowed_ports: vec![80, 443],
            request_rate: 5,
            authorized: true,
        }
    }

    fn task() -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: TaskId::from("task-1"),
            objective: "Assess the authorized application scope.".into(),
            primary_target: "https://app.example.test".into(),
            scope: scope(),
            budget: TaskBudget {
                max_steps: 25,
                max_http_requests: 100,
                max_model_calls: 20,
                max_input_tokens: 50_000,
                max_output_tokens: 10_000,
                max_duration_ms: 900_000,
            },
            available_tools: vec!["http_request".into(), "browser".into()],
            memory_policy: Default::default(),
        }
    }

    fn round_trip<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).expect("contract should serialize");
        let decoded = serde_json::from_str::<T>(&json).expect("contract should deserialize");
        assert_eq!(&decoded, value);
    }

    fn action() -> AgentAction {
        AgentAction {
            schema_version: CORE_SCHEMA_VERSION,
            name: "http_request".into(),
            arguments: BTreeMap::from([(
                "url".into(),
                Value::String("https://app.example.test".into()),
            )]),
            reason: "Inspect the authorized target.".into(),
        }
    }

    fn evidence() -> Evidence {
        Evidence {
            schema_version: CORE_SCHEMA_VERSION,
            id: EvidenceId::from("evidence-1"),
            run_id: RunId::from("run-1"),
            source: EvidenceSource::ToolResult {
                tool_result_id: ToolResultId::from("tool-result-1"),
            },
            description: "Authorized response header.".into(),
            value_or_excerpt: "server: example".into(),
            recorded_at_ms: 1_700_000_001_000,
        }
    }

    fn final_output() -> FinalOutput {
        FinalOutput {
            schema_version: CORE_SCHEMA_VERSION,
            status: FinalOutputStatus::Completed,
            answer: "Assessment completed within scope.".into(),
            evidence_ids: vec![EvidenceId::from("evidence-1")],
            limitations: vec!["Only the authorized surface was assessed.".into()],
        }
    }

    fn evaluation() -> EvaluationResult {
        EvaluationResult {
            schema_version: CORE_SCHEMA_VERSION,
            verdict: EvaluationVerdict::Passed,
            passed: true,
            score: Some(0.95),
            success_reasons: vec!["All claims reference evidence.".into()],
            failure_reasons: vec![],
            evaluated_at_ms: 1_700_000_002_000,
        }
    }

    #[test]
    fn creates_and_round_trips_a_valid_task() {
        let task = task();
        assert_eq!(task.schema_version, CORE_SCHEMA_VERSION);
        assert!(task.scope.authorized);
        assert_eq!(task.available_tools.len(), 2);
        round_trip(&task);
    }

    #[test]
    fn primary_contracts_round_trip_without_data_loss() {
        let action = action();
        let tool_result = ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId::from("tool-result-1"),
            tool_name: "http_request".into(),
            success: true,
            data: BTreeMap::from([("status_code".into(), Value::from(200))]),
            error: None,
            duration_ms: 42,
        };
        let event = RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: RunEventId::from("event-1"),
            run_id: RunId::from("run-1"),
            timestamp_ms: 1_700_000_000_500,
            step: 1,
            kind: RunEventKind::ActionReceived {
                action: action.clone(),
            },
        };

        round_trip(&action);
        round_trip(&tool_result);
        round_trip(&event);
        round_trip(&evidence());
        round_trip(&final_output());
        round_trip(&evaluation());
        round_trip(&RunUsage::default());
    }

    #[test]
    fn enum_json_names_are_stable() {
        let run_statuses = [
            (RunStatus::Created, "created"),
            (RunStatus::Running, "running"),
            (RunStatus::Completed, "completed"),
            (RunStatus::Failed, "failed"),
            (RunStatus::Cancelled, "cancelled"),
            (RunStatus::BudgetExhausted, "budget_exhausted"),
            (RunStatus::ScopeBlocked, "scope_blocked"),
        ];
        for (status, expected) in run_statuses {
            assert_eq!(serde_json::to_value(status).unwrap(), expected);
        }

        let final_statuses = [
            (FinalOutputStatus::Completed, "completed"),
            (FinalOutputStatus::Inconclusive, "inconclusive"),
            (FinalOutputStatus::BudgetExhausted, "budget_exhausted"),
            (FinalOutputStatus::Error, "error"),
        ];
        for (status, expected) in final_statuses {
            assert_eq!(serde_json::to_value(status).unwrap(), expected);
        }

        let event = RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: RunEventId::from("event-1"),
            run_id: RunId::from("run-1"),
            timestamp_ms: 1,
            step: 0,
            kind: RunEventKind::RunStarted {
                task_id: TaskId::from("task-1"),
            },
        };
        let json = serde_json::to_value(event).unwrap();
        assert_eq!(json["event_type"], "run_started");
    }

    #[test]
    fn unknown_enum_values_are_rejected() {
        assert!(serde_json::from_str::<RunStatus>("\"paused\"").is_err());
        assert!(serde_json::from_str::<FinalOutputStatus>("\"partial\"").is_err());
        assert!(serde_json::from_str::<BudgetKind>("\"credits\"").is_err());
        assert!(serde_json::from_str::<EvidenceSource>(
            r#"{"type":"unknown_source","reference":"value"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<RunEventKind>(
            r#"{"event_type":"unknown_event","data":{}}"#
        )
        .is_err());
    }

    #[test]
    fn new_run_starts_in_created_state() {
        let run = Run::new(
            RunId::from("run-1"),
            TaskId::from("task-1"),
            1_700_000_000_000,
        );
        assert_eq!(run.status, RunStatus::Created);
        assert_eq!(run.created_at_ms, 1_700_000_000_000);
        assert!(run.started_at_ms.is_none());
        assert_eq!(run.current_step, 0);
        assert!(run.final_output.is_none());
        round_trip(&run);
    }

    #[test]
    fn run_can_represent_running_then_completed() {
        let mut run = Run::new(
            RunId::from("run-1"),
            TaskId::from("task-1"),
            1_700_000_000_000,
        );
        run.started_at_ms = Some(1_700_000_000_500);
        run.status = RunStatus::Running;
        run.current_step = 1;
        run.usage.steps = 1;
        assert_eq!(run.status, RunStatus::Running);

        run.status = RunStatus::Completed;
        run.ended_at_ms = Some(1_700_000_003_000);
        run.final_output = Some(final_output());
        assert_eq!(run.status, RunStatus::Completed);
        assert!(run.final_output.is_some());
        round_trip(&run);
    }

    #[test]
    fn evidence_is_linked_to_its_run() {
        let evidence = evidence();
        assert_eq!(evidence.run_id, RunId::from("run-1"));
    }

    #[test]
    fn final_output_contains_evidence_ids() {
        let output = final_output();
        assert_eq!(output.evidence_ids, vec![EvidenceId::from("evidence-1")]);
    }

    #[test]
    fn evaluation_result_can_be_attached_to_a_run() {
        let mut run = Run::new(
            RunId::from("run-1"),
            TaskId::from("task-1"),
            1_700_000_000_000,
        );
        run.evaluation = Some(evaluation());
        assert!(run.evaluation.as_ref().is_some_and(|result| result.passed));
        round_trip(&run);
    }

    #[test]
    fn event_variants_cover_the_initial_vocabulary() {
        let action = action();
        let variants = vec![
            RunEventKind::RunCreated {
                task_id: TaskId::from("task-1"),
            },
            RunEventKind::RunStarted {
                task_id: TaskId::from("task-1"),
            },
            RunEventKind::ModelCalled {
                model_call_id: "model-call-1".into(),
                model: None,
            },
            RunEventKind::ActionReceived {
                action: action.clone(),
            },
            RunEventKind::ActionRejected {
                action,
                reason: "Outside policy.".into(),
            },
            RunEventKind::ToolStarted {
                tool_name: "http_request".into(),
            },
            RunEventKind::ToolCompleted {
                tool_result_id: ToolResultId::from("tool-result-1"),
                success: true,
            },
            RunEventKind::EvidenceRecorded {
                evidence_id: EvidenceId::from("evidence-1"),
            },
            RunEventKind::ScopeBlocked {
                target: "https://blocked.example".into(),
                reason: "Outside scope.".into(),
            },
            RunEventKind::BudgetExhausted {
                budget: BudgetKind::Steps,
            },
            RunEventKind::RunCompleted {
                status: FinalOutputStatus::Completed,
            },
            RunEventKind::RunFailed {
                error: RunFailure {
                    code: "UNEXPECTED_FAILURE".into(),
                    message: "Unexpected failure.".into(),
                },
            },
            RunEventKind::RunCancelled {
                reason: Some("Cancelled by the operator.".into()),
            },
            RunEventKind::EvaluationCompleted {
                passed: true,
                score: Some(1.0),
            },
        ];

        for variant in variants {
            round_trip(&variant);
        }
    }
}
