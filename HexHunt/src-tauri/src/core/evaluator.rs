use super::{
    Clock, EvaluationResult, EvaluationVerdict, Evidence, EvidenceSource, FinalOutput,
    FinalOutputStatus, Run, RunEventKind, RunStatus, SystemClock, Task, ToolResult,
    CORE_SCHEMA_VERSION,
};
use std::{collections::HashMap, sync::Arc};

pub trait Evaluator: Send + Sync {
    fn evaluate(
        &self,
        task: &Task,
        run: &Run,
        final_output: &FinalOutput,
        tool_results: &[ToolResult],
        evidence: &[Evidence],
        events: &[super::RunEvent],
    ) -> EvaluationResult;
}

pub struct DeterministicEvaluator {
    clock: Arc<dyn Clock>,
}

impl Default for DeterministicEvaluator {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl DeterministicEvaluator {
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }
}

impl Evaluator for DeterministicEvaluator {
    fn evaluate(
        &self,
        task: &Task,
        run: &Run,
        final_output: &FinalOutput,
        tool_results: &[ToolResult],
        evidence: &[Evidence],
        events: &[super::RunEvent],
    ) -> EvaluationResult {
        let mut success_reasons = Vec::new();
        let mut failure_reasons = Vec::new();
        let mut inconclusive_reasons = Vec::new();
        let results = tool_results
            .iter()
            .map(|result| (result.id.clone(), result))
            .collect::<HashMap<_, _>>();
        let evidence_by_id = evidence
            .iter()
            .map(|item| (item.id.clone(), item))
            .collect::<HashMap<_, _>>();

        if run.final_output.as_ref() != Some(final_output) {
            failure_reasons
                .push("The evaluated FinalOutput is not the one stored in the run.".into());
        } else {
            success_reasons.push("FinalOutput is stored in the run.".into());
        }

        if run.status != RunStatus::Completed
            || !matches!(
                final_output.status,
                FinalOutputStatus::Completed | FinalOutputStatus::Inconclusive
            )
        {
            failure_reasons.push("Run status and FinalOutput status are inconsistent.".into());
        }
        if events
            .iter()
            .any(|event| matches!(&event.kind, RunEventKind::ScopeBlocked { .. }))
        {
            failure_reasons.push("A scope-blocked run cannot pass evaluation.".into());
        }

        if final_output.evidence_ids.is_empty() {
            inconclusive_reasons.push("FinalOutput contains no evidence references.".into());
        }
        for evidence_id in &final_output.evidence_ids {
            let Some(item) = evidence_by_id.get(evidence_id) else {
                failure_reasons.push(format!(
                    "Evidence reference '{}' does not exist.",
                    evidence_id.0
                ));
                continue;
            };
            if item.run_id != run.id {
                failure_reasons.push(format!("Evidence '{}' belongs to another run.", item.id.0));
            }
            match &item.source {
                EvidenceSource::ToolResult { tool_result_id } => {
                    match results.get(tool_result_id) {
                        Some(result) if result.success => {}
                        Some(_) => failure_reasons.push(format!(
                            "Evidence '{}' refers to a failed ToolResult.",
                            item.id.0
                        )),
                        None => failure_reasons.push(format!(
                            "Evidence '{}' refers to a missing ToolResult.",
                            item.id.0
                        )),
                    }
                }
                EvidenceSource::ModelCall { .. } | EvidenceSource::Request { .. } => {}
                EvidenceSource::Manual { .. } => failure_reasons.push(format!(
                    "Evidence '{}' uses an unverified manual source.",
                    item.id.0
                )),
            }
        }

        if task_requires_http(task)
            && !tool_results
                .iter()
                .any(|result| result.tool_name == "http_request" && result.success)
        {
            inconclusive_reasons
                .push("The task requires HTTP but has no successful HTTP result.".into());
        }

        let (verdict, passed, score) = if !failure_reasons.is_empty() {
            (EvaluationVerdict::Failed, false, Some(0.0))
        } else if !inconclusive_reasons.is_empty() {
            failure_reasons.extend(inconclusive_reasons);
            (EvaluationVerdict::Inconclusive, false, None)
        } else {
            success_reasons.push("All FinalOutput evidence references are valid.".into());
            (EvaluationVerdict::Passed, true, Some(1.0))
        };

        EvaluationResult {
            schema_version: CORE_SCHEMA_VERSION,
            verdict,
            passed,
            score,
            success_reasons,
            failure_reasons,
            evaluated_at_ms: self.clock.now_ms(),
        }
    }
}

fn task_requires_http(task: &Task) -> bool {
    let http_available = task
        .available_tools
        .iter()
        .any(|tool| tool == "http_request");
    let target_is_http =
        task.primary_target.starts_with("http://") || task.primary_target.starts_with("https://");
    http_available && target_is_http
}
