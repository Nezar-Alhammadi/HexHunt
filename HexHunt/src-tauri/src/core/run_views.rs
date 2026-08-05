use super::{
    EvaluationResult, EvaluationVerdict, Evidence, ModelCallRecord, Run, RunEvent, RunEventKind,
    RunFailure, RunId, RunService, RunServiceError, RunServiceErrorCode, RunStatus, Task,
    ToolResult,
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PAGE_LIMIT: usize = 100;
pub const MAX_PAGE_LIMIT: usize = 500;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    pub offset: usize,
    pub limit: usize,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: DEFAULT_PAGE_LIMIT,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub offset: usize,
    pub limit: usize,
    pub total: usize,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunListItem {
    pub run: Run,
    pub task_title: String,
    pub evaluation_verdict: Option<EvaluationVerdict>,
    pub model: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunDetails {
    pub run: Run,
    pub task: Task,
    pub events: Page<RunEvent>,
    pub tool_results: Page<ToolResult>,
    pub evidence: Page<Evidence>,
    pub model_calls: Page<ModelCallRecord>,
    pub evaluation: Option<EvaluationResult>,
    pub failure: Option<RunFailure>,
}

impl RunService {
    pub fn list_run_summaries(
        &self,
        page: PageRequest,
    ) -> Result<Page<RunListItem>, RunServiceError> {
        validate_page(&page)?;
        let mut runs = self.list_runs()?;
        runs.sort_by(|left, right| {
            right
                .created_at_ms
                .cmp(&left.created_at_ms)
                .then_with(|| right.id.0.cmp(&left.id.0))
        });
        let total = runs.len();
        let items = runs
            .into_iter()
            .skip(page.offset)
            .take(page.limit)
            .map(|run| {
                let task = self.get_run_task(&run.id)?;
                let model = self
                    .get_model_calls(&run.id)?
                    .last()
                    .map(|call| call.model.clone());
                Ok(RunListItem {
                    task_title: task.objective,
                    evaluation_verdict: run.evaluation.as_ref().map(|result| result.verdict),
                    model,
                    run,
                })
            })
            .collect::<Result<Vec<_>, RunServiceError>>()?;
        Ok(Page {
            items,
            offset: page.offset,
            limit: page.limit,
            total,
        })
    }

    pub fn get_run_details(
        &self,
        run_id: &RunId,
        page: PageRequest,
    ) -> Result<RunDetails, RunServiceError> {
        validate_page(&page)?;
        let run = self.get_run(run_id).map_err(|error| {
            if error.code == RunServiceErrorCode::RunNotFound {
                RunServiceError::new(
                    RunServiceErrorCode::RunDetailsNotFound,
                    format!("Run details for '{}' were not found.", run_id.0),
                )
            } else {
                error
            }
        })?;
        let task = self.get_run_task(run_id)?;
        let all_events = self.get_run_events(run_id)?;
        let all_tool_results = self.get_tool_results(run_id)?;
        let all_evidence = self.get_all_evidence(run_id)?;
        let all_model_calls = self.get_model_calls(run_id)?;
        let failure = all_events.iter().rev().find_map(|event| match &event.kind {
            RunEventKind::RunFailed { error } => Some(error.clone()),
            _ => None,
        });
        Ok(RunDetails {
            evaluation: self.get_evaluation_result(run_id)?,
            run,
            task,
            events: paginate(all_events, &page),
            tool_results: paginate(all_tool_results, &page),
            evidence: paginate(all_evidence, &page),
            model_calls: paginate(all_model_calls, &page),
            failure,
        })
    }

    pub fn page_run_events(
        &self,
        run_id: &RunId,
        page: PageRequest,
    ) -> Result<Page<RunEvent>, RunServiceError> {
        validate_page(&page)?;
        Ok(paginate(self.get_run_events(run_id)?, &page))
    }

    pub fn page_tool_results(
        &self,
        run_id: &RunId,
        page: PageRequest,
    ) -> Result<Page<ToolResult>, RunServiceError> {
        validate_page(&page)?;
        Ok(paginate(self.get_tool_results(run_id)?, &page))
    }

    pub fn page_evidence(
        &self,
        run_id: &RunId,
        page: PageRequest,
    ) -> Result<Page<Evidence>, RunServiceError> {
        validate_page(&page)?;
        Ok(paginate(self.get_all_evidence(run_id)?, &page))
    }

    pub fn page_model_calls(
        &self,
        run_id: &RunId,
        page: PageRequest,
    ) -> Result<Page<ModelCallRecord>, RunServiceError> {
        validate_page(&page)?;
        Ok(paginate(self.get_model_calls(run_id)?, &page))
    }
}

fn validate_page(page: &PageRequest) -> Result<(), RunServiceError> {
    if page.limit == 0 || page.limit > MAX_PAGE_LIMIT {
        return Err(RunServiceError::new(
            RunServiceErrorCode::InvalidPagination,
            format!("Pagination limit must be between 1 and {MAX_PAGE_LIMIT}."),
        ));
    }
    Ok(())
}

fn paginate<T>(items: Vec<T>, page: &PageRequest) -> Page<T> {
    let total = items.len();
    let items = items
        .into_iter()
        .skip(page.offset)
        .take(page.limit)
        .collect();
    Page {
        items,
        offset: page.offset,
        limit: page.limit,
        total,
    }
}

pub fn is_terminal_status(status: RunStatus) -> bool {
    !matches!(status, RunStatus::Created | RunStatus::Running)
}
