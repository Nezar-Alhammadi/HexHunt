use super::{
    redact_event, redact_tool_result, BudgetKind, EvaluationResult, EvaluationVerdict, Evidence,
    EvidenceId, EvidenceSource, FinalOutput, FinalOutputStatus, InMemoryRunRepository,
    ModelCallRecord, ReconAnalyzer, ReconAsset, ReconAssetId, ReconAssetRelation, ReconDecision,
    ReconHypothesis, ReconHypothesisId, ReconMemory, ReconMemoryAction, ReconMemoryAsset,
    ReconMemoryHypothesis, ReconObservation, ReconReport, ReconScopeClassification, ReconSnapshot,
    ReconSnapshotDelta, ReconSnapshotId, Run, RunEvent, RunEventId, RunEventKind, RunFailure,
    RunId, RunMemoryMode, RunRepository, RunStatus, RunUsage, Task, TaskId, ToolResult,
    ToolResultId, CORE_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    fmt,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub trait IdGenerator: Send + Sync {
    fn task_id(&self) -> TaskId;
    fn run_id(&self) -> RunId;
    fn run_event_id(&self) -> RunEventId;
    fn evidence_id(&self) -> EvidenceId;
}

#[derive(Default)]
pub struct UuidGenerator;

impl IdGenerator for UuidGenerator {
    fn task_id(&self) -> TaskId {
        TaskId(Uuid::new_v4().to_string())
    }

    fn run_id(&self) -> RunId {
        RunId(Uuid::new_v4().to_string())
    }

    fn run_event_id(&self) -> RunEventId {
        RunEventId(Uuid::new_v4().to_string())
    }

    fn evidence_id(&self) -> EvidenceId {
        EvidenceId(Uuid::new_v4().to_string())
    }
}

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunServiceErrorCode {
    DatabaseOpenFailed,
    DatabaseMigrationFailed,
    DatabaseWriteFailed,
    DatabaseReadFailed,
    DatabaseTransactionFailed,
    RunInterrupted,
    RunDetailsNotFound,
    InvalidPagination,
    PersistenceSerializationFailed,
    RunNotFound,
    RunAlreadyExists,
    RunEventAlreadyExists,
    ToolResultNotFound,
    ToolResultAlreadyExists,
    ToolResultRunNotActive,
    ToolResultRunNotFound,
    EvidenceNotFound,
    EvidenceAlreadyExists,
    EvidenceRunNotActive,
    EvidenceRunNotFound,
    EvidenceRunIdMismatch,
    EvidenceSourceNotFound,
    ModelCallAlreadyExists,
    ModelCallRunNotActive,
    ModelCallRunNotFound,
    EvaluationNotFound,
    EvaluationAlreadyExists,
    EvaluationRunNotReady,
    InvalidEvaluation,
    InvalidRunTransition,
    RunAlreadyTerminal,
    EventRunIdMismatch,
    InvalidEvent,
    UsageRegression,
    ReconRunNotFound,
    ReconRunNotActive,
    ReconItemAlreadyExists,
    ReconItemNotFound,
    ReconRunIdMismatch,
    InvalidReconReference,
    InvalidReconDecision,
    InvalidFinalOutput,
    InternalLockError,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunServiceError {
    pub code: RunServiceErrorCode,
    pub message: String,
}

impl RunServiceError {
    pub(crate) fn new(code: RunServiceErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for RunServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for RunServiceError {}

fn normalized_domains(domains: &[String]) -> Vec<String> {
    let mut domains = domains
        .iter()
        .map(|domain| domain.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains
}

#[derive(Clone)]
pub(crate) struct RunRecord {
    pub(crate) task: Task,
    pub(crate) run: Run,
    pub(crate) events: Vec<RunEvent>,
    pub(crate) tool_results: Vec<ToolResult>,
    pub(crate) evidence: Vec<Evidence>,
    pub(crate) model_calls: Vec<ModelCallRecord>,
    pub(crate) recon_snapshot: ReconSnapshot,
}

#[derive(Clone, Default)]
struct RunStore {
    runs: HashMap<RunId, RunRecord>,
    event_ids: HashSet<RunEventId>,
    tool_result_ids: HashSet<ToolResultId>,
    evidence_ids: HashSet<EvidenceId>,
    model_call_ids: HashSet<String>,
}

pub struct RunService {
    // Fully loaded at startup; every mutation is persisted transactionally before it is exposed.
    // External database writers are intentionally unsupported in v0.1.
    store: RwLock<RunStore>,
    repository: Arc<dyn RunRepository>,
    ids: Arc<dyn IdGenerator>,
    clock: Arc<dyn Clock>,
}

impl Default for RunService {
    fn default() -> Self {
        Self::with_sources(Arc::new(UuidGenerator), Arc::new(SystemClock))
    }
}

impl RunService {
    pub fn with_sources(ids: Arc<dyn IdGenerator>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store: RwLock::new(RunStore::default()),
            repository: Arc::new(InMemoryRunRepository::default()),
            ids,
            clock,
        }
    }

    pub(crate) fn with_repository(
        repository: Arc<dyn RunRepository>,
    ) -> Result<Self, RunServiceError> {
        Self::with_repository_and_sources(
            repository,
            Arc::new(UuidGenerator),
            Arc::new(SystemClock),
        )
    }

    pub(crate) fn with_repository_and_sources(
        repository: Arc<dyn RunRepository>,
        ids: Arc<dyn IdGenerator>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, RunServiceError> {
        let records = repository.load_all()?;
        let mut store = RunStore::default();
        for record in records {
            for event in &record.events {
                store.event_ids.insert(event.id.clone());
            }
            for result in &record.tool_results {
                store.tool_result_ids.insert(result.id.clone());
            }
            for evidence in &record.evidence {
                store.evidence_ids.insert(evidence.id.clone());
            }
            for call in &record.model_calls {
                store.model_call_ids.insert(call.id.clone());
            }
            store.runs.insert(record.run.id.clone(), record);
        }
        Ok(Self {
            store: RwLock::new(store),
            repository,
            ids,
            clock,
        })
    }

    pub fn create_run(&self, mut task: Task) -> Result<Run, RunServiceError> {
        if task.id.0.trim().is_empty() {
            task.id = self.ids.task_id();
        }

        let run_id = self.ids.run_id();
        let created_at_ms = self.clock.now_ms();
        let mut store = self.write_store()?;
        let previous = store.clone();

        if store.runs.contains_key(&run_id) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::RunAlreadyExists,
                format!("Run '{}' already exists.", run_id.0),
            ));
        }

        let event = self.make_event(
            run_id.clone(),
            created_at_ms,
            0,
            RunEventKind::RunCreated {
                task_id: task.id.clone(),
            },
        );
        self.ensure_event_id_available(&store, &event.id)?;

        let run = Run::new(run_id.clone(), task.id.clone(), created_at_ms);
        store.event_ids.insert(event.id.clone());
        store.runs.insert(
            run_id.clone(),
            RunRecord {
                task,
                run: run.clone(),
                events: vec![event],
                tool_results: vec![],
                evidence: vec![],
                model_calls: vec![],
                recon_snapshot: ReconSnapshot::empty(
                    ReconSnapshotId(format!("recon-{}", run_id.0)),
                    run_id.clone(),
                    created_at_ms,
                ),
            },
        );
        self.persist_record_locked(&mut store, previous, &run_id)?;
        Ok(run)
    }

    pub fn get_run(&self, run_id: &RunId) -> Result<Run, RunServiceError> {
        self.read_store()?
            .runs
            .get(run_id)
            .map(|record| record.run.clone())
            .ok_or_else(|| Self::run_not_found(run_id))
    }

    pub fn get_run_task(&self, run_id: &RunId) -> Result<Task, RunServiceError> {
        self.read_store()?
            .runs
            .get(run_id)
            .map(|record| record.task.clone())
            .ok_or_else(|| Self::run_not_found(run_id))
    }

    pub fn list_runs(&self) -> Result<Vec<Run>, RunServiceError> {
        let mut runs = self
            .read_store()?
            .runs
            .values()
            .map(|record| record.run.clone())
            .collect::<Vec<_>>();
        runs.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.id.0.cmp(&right.id.0))
        });
        Ok(runs)
    }

    pub fn get_run_events(&self, run_id: &RunId) -> Result<Vec<RunEvent>, RunServiceError> {
        self.read_store()?
            .runs
            .get(run_id)
            .map(|record| record.events.clone())
            .ok_or_else(|| Self::run_not_found(run_id))
    }

    pub fn get_recon_snapshot(&self, run_id: &RunId) -> Result<ReconSnapshot, RunServiceError> {
        self.read_store()?
            .runs
            .get(run_id)
            .map(|record| record.recon_snapshot.clone())
            .ok_or_else(|| Self::recon_run_not_found(run_id))
    }

    pub fn compare_recon_runs(
        &self,
        baseline_run_id: &RunId,
        current_run_id: &RunId,
    ) -> Result<ReconSnapshotDelta, RunServiceError> {
        let baseline = self.get_recon_snapshot(baseline_run_id)?;
        let current = self.get_recon_snapshot(current_run_id)?;
        Ok(ReconAnalyzer::compare(
            &baseline,
            &current,
            self.clock.now_ms(),
        ))
    }

    pub fn build_recon_report(&self, run_id: &RunId) -> Result<ReconReport, RunServiceError> {
        let snapshot = self.get_recon_snapshot(run_id)?;
        let memory = self.build_recon_memory(run_id)?;
        Ok(ReconAnalyzer::report(
            &snapshot,
            &memory,
            self.clock.now_ms(),
        ))
    }

    pub fn build_recon_memory(&self, run_id: &RunId) -> Result<ReconMemory, RunServiceError> {
        let store = self.read_store()?;
        let current = store
            .runs
            .get(run_id)
            .ok_or_else(|| Self::run_not_found(run_id))?;
        let policy = &current.task.memory_policy;
        if policy.mode == RunMemoryMode::Fresh {
            return Ok(ReconMemory::default());
        }
        let now_ms = self.clock.now_ms();
        let source_ids = policy
            .source_run_ids
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let mut records = store
            .runs
            .values()
            .filter(|record| {
                let same_scope = record.task.scope.id == current.task.scope.id
                    || normalized_domains(&record.task.scope.allowed_domains)
                        == normalized_domains(&current.task.scope.allowed_domains);
                let source_allowed = match policy.mode {
                    RunMemoryMode::Fresh => false,
                    RunMemoryMode::Continue => source_ids.contains(&record.run.id),
                    RunMemoryMode::AutoAssisted => record.run.status == RunStatus::Completed,
                };
                let age_allowed = policy.max_age_ms.map_or(true, |max_age_ms| {
                    let timestamp = record.run.ended_at_ms.unwrap_or(record.run.created_at_ms);
                    now_ms.saturating_sub(timestamp) <= max_age_ms
                });
                record.run.id != *run_id
                    && record.run.ended_at_ms.is_some()
                    && same_scope
                    && source_allowed
                    && age_allowed
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.run.ended_at_ms.unwrap_or(record.run.created_at_ms));
        records.reverse();
        records.truncate(usize::from(policy.max_source_runs.clamp(1, 20)));
        let mut memory = ReconMemory::default();
        let mut assets = BTreeMap::<String, ReconMemoryAsset>::new();
        for record in records {
            memory.source_run_ids.push(record.run.id.clone());
            for asset in record
                .recon_snapshot
                .assets
                .iter()
                .filter(|asset| asset.scope == ReconScopeClassification::InScope)
                .take(2_000)
            {
                let key = format!(
                    "{:?}:{}",
                    asset.kind,
                    asset.canonical_value.to_ascii_lowercase()
                );
                let entry = assets.entry(key).or_insert_with(|| ReconMemoryAsset {
                    kind: asset.kind,
                    canonical_value: asset.canonical_value.clone(),
                    confidence: asset.confidence,
                    source_run_ids: vec![],
                    tags: vec![],
                });
                if !entry.source_run_ids.contains(&record.run.id) {
                    entry.source_run_ids.push(record.run.id.clone());
                }
                for tag in &asset.tags {
                    if !entry.tags.contains(tag) {
                        entry.tags.push(tag.clone());
                    }
                }
            }
            for decision in &record.recon_snapshot.decisions {
                let Some(selected_id) = &decision.selected_action_id else {
                    continue;
                };
                let Some(action) = decision
                    .candidate_actions
                    .iter()
                    .find(|action| action.id == *selected_id)
                else {
                    continue;
                };
                let target_values = action
                    .target_asset_ids
                    .iter()
                    .filter_map(|id| {
                        record
                            .recon_snapshot
                            .assets
                            .iter()
                            .find(|asset| asset.id == *id)
                    })
                    .map(|asset| asset.canonical_value.clone())
                    .collect::<Vec<_>>();
                memory.prior_actions.push(ReconMemoryAction {
                    capability: action.capability,
                    target_values,
                    arguments: action.arguments.clone(),
                    source_run_id: record.run.id.clone(),
                });
            }
            for hypothesis in record
                .recon_snapshot
                .hypotheses
                .iter()
                .filter(|hypothesis| {
                    matches!(
                        hypothesis.status,
                        super::ReconHypothesisStatus::Supported
                            | super::ReconHypothesisStatus::Inconclusive
                    )
                })
                .take(500)
            {
                memory.hypotheses.push(ReconMemoryHypothesis {
                    kind: hypothesis.kind,
                    statement: hypothesis.statement.clone(),
                    status: hypothesis.status,
                    source_run_id: record.run.id.clone(),
                });
            }
        }
        memory
            .source_run_ids
            .sort_by(|left, right| left.0.cmp(&right.0));
        memory.source_run_ids.dedup();
        memory.assets = assets.into_values().take(2_000).collect();
        memory.prior_actions.truncate(2_000);
        memory.hypotheses.truncate(1_000);
        Ok(memory)
    }

    pub fn append_recon_asset(
        &self,
        run_id: &RunId,
        asset: ReconAsset,
    ) -> Result<ReconAsset, RunServiceError> {
        self.mutate_recon_snapshot(run_id, |snapshot| {
            if snapshot.assets.iter().any(|stored| {
                stored.id == asset.id
                    || (stored.kind == asset.kind
                        && stored
                            .canonical_value
                            .eq_ignore_ascii_case(&asset.canonical_value))
            }) {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::ReconItemAlreadyExists,
                    format!("Recon asset '{}' already exists.", asset.id.0),
                ));
            }
            snapshot.assets.push(asset.clone());
            Ok(asset)
        })
    }

    pub fn update_recon_asset(
        &self,
        run_id: &RunId,
        asset: ReconAsset,
    ) -> Result<ReconAsset, RunServiceError> {
        self.mutate_recon_snapshot(run_id, |snapshot| {
            if snapshot.assets.iter().any(|stored| {
                stored.id != asset.id
                    && stored.kind == asset.kind
                    && stored
                        .canonical_value
                        .eq_ignore_ascii_case(&asset.canonical_value)
            }) {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::ReconItemAlreadyExists,
                    "Another Recon asset already has this canonical identity.",
                ));
            }
            let stored = snapshot
                .assets
                .iter_mut()
                .find(|stored| stored.id == asset.id)
                .ok_or_else(|| {
                    RunServiceError::new(
                        RunServiceErrorCode::ReconItemNotFound,
                        format!("Recon asset '{}' was not found.", asset.id.0),
                    )
                })?;
            *stored = asset.clone();
            Ok(asset)
        })
    }

    pub fn append_recon_relation(
        &self,
        run_id: &RunId,
        relation: ReconAssetRelation,
    ) -> Result<ReconAssetRelation, RunServiceError> {
        self.mutate_recon_snapshot(run_id, |snapshot| {
            if snapshot.relations.iter().any(|stored| {
                stored.id == relation.id
                    || (stored.from_asset_id == relation.from_asset_id
                        && stored.to_asset_id == relation.to_asset_id
                        && stored.kind == relation.kind)
            }) {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::ReconItemAlreadyExists,
                    format!("Recon relation '{}' already exists.", relation.id.0),
                ));
            }
            Self::ensure_assets_exist(snapshot, [&relation.from_asset_id, &relation.to_asset_id])?;
            snapshot.relations.push(relation.clone());
            Ok(relation)
        })
    }

    pub fn append_recon_observation(
        &self,
        run_id: &RunId,
        observation: ReconObservation,
    ) -> Result<ReconObservation, RunServiceError> {
        self.mutate_recon_snapshot(run_id, |snapshot| {
            if observation.run_id != *run_id {
                return Err(Self::recon_run_id_mismatch(run_id, &observation.run_id));
            }
            if snapshot
                .observations
                .iter()
                .any(|stored| stored.id == observation.id)
            {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::ReconItemAlreadyExists,
                    format!("Recon observation '{}' already exists.", observation.id.0),
                ));
            }
            Self::ensure_assets_exist(snapshot, observation.subject_asset_ids.iter())?;
            snapshot.observations.push(observation.clone());
            Ok(observation)
        })
    }

    pub fn append_recon_hypothesis(
        &self,
        run_id: &RunId,
        hypothesis: ReconHypothesis,
    ) -> Result<ReconHypothesis, RunServiceError> {
        self.mutate_recon_snapshot(run_id, |snapshot| {
            if snapshot
                .hypotheses
                .iter()
                .any(|stored| stored.id == hypothesis.id)
            {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::ReconItemAlreadyExists,
                    format!("Recon hypothesis '{}' already exists.", hypothesis.id.0),
                ));
            }
            Self::validate_hypothesis_references(snapshot, &hypothesis)?;
            snapshot.hypotheses.push(hypothesis.clone());
            Ok(hypothesis)
        })
    }

    pub fn update_recon_hypothesis(
        &self,
        run_id: &RunId,
        hypothesis: ReconHypothesis,
    ) -> Result<ReconHypothesis, RunServiceError> {
        self.mutate_recon_snapshot(run_id, |snapshot| {
            Self::validate_hypothesis_references(snapshot, &hypothesis)?;
            let stored = snapshot
                .hypotheses
                .iter_mut()
                .find(|stored| stored.id == hypothesis.id)
                .ok_or_else(|| {
                    RunServiceError::new(
                        RunServiceErrorCode::ReconItemNotFound,
                        format!("Recon hypothesis '{}' was not found.", hypothesis.id.0),
                    )
                })?;
            *stored = hypothesis.clone();
            Ok(hypothesis)
        })
    }

    pub fn append_recon_decision(
        &self,
        run_id: &RunId,
        decision: ReconDecision,
    ) -> Result<ReconDecision, RunServiceError> {
        self.mutate_recon_snapshot(run_id, |snapshot| {
            if decision.run_id != *run_id {
                return Err(Self::recon_run_id_mismatch(run_id, &decision.run_id));
            }
            if snapshot
                .decisions
                .iter()
                .any(|stored| stored.step == decision.step)
            {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::ReconItemAlreadyExists,
                    format!(
                        "A Recon decision already exists for step {}.",
                        decision.step
                    ),
                ));
            }
            if let Some(hypothesis_id) = &decision.hypothesis_id {
                Self::ensure_hypothesis_exists(snapshot, hypothesis_id)?;
            }
            let mut action_ids = HashSet::new();
            for action in &decision.candidate_actions {
                if !action_ids.insert(&action.id) {
                    return Err(RunServiceError::new(
                        RunServiceErrorCode::InvalidReconDecision,
                        "A Recon decision cannot contain duplicate candidate action IDs.",
                    ));
                }
                Self::ensure_assets_exist(snapshot, action.target_asset_ids.iter())?;
            }
            let mut gap_ids = HashSet::new();
            for gap in &decision.knowledge_gaps {
                if !gap_ids.insert(&gap.id) {
                    return Err(RunServiceError::new(
                        RunServiceErrorCode::InvalidReconDecision,
                        "A Recon decision cannot contain duplicate knowledge gap IDs.",
                    ));
                }
                Self::ensure_assets_exist(snapshot, std::iter::once(&gap.asset_id))?;
                if gap.actionable == gap.blocked_reason.is_some() {
                    return Err(RunServiceError::new(
                        RunServiceErrorCode::InvalidReconDecision,
                        "An actionable knowledge gap cannot have a blocked reason.",
                    ));
                }
            }
            let mut scored_action_ids = HashSet::new();
            for score in &decision.action_scores {
                if !scored_action_ids.insert(&score.action_id)
                    || !action_ids.contains(&score.action_id)
                {
                    return Err(RunServiceError::new(
                        RunServiceErrorCode::InvalidReconDecision,
                        "Every action score must reference one unique candidate action.",
                    ));
                }
            }
            if decision.action_scores.len() != decision.candidate_actions.len() {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::InvalidReconDecision,
                    "Every candidate Recon action must have exactly one score.",
                ));
            }
            if decision
                .recommended_action_id
                .as_ref()
                .is_some_and(|recommended| !action_ids.contains(recommended))
            {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::InvalidReconDecision,
                    "The recommended Recon action must be one of the candidate actions.",
                ));
            }
            if decision
                .coverage
                .as_ref()
                .is_some_and(|coverage| coverage.coverage_percent > 100)
            {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::InvalidReconDecision,
                    "Recon coverage percent cannot exceed 100.",
                ));
            }
            if decision
                .selected_action_id
                .as_ref()
                .is_some_and(|selected| {
                    !decision
                        .candidate_actions
                        .iter()
                        .any(|candidate| candidate.id == *selected)
                })
            {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::InvalidReconDecision,
                    "The selected Recon action must be one of the candidate actions.",
                ));
            }
            snapshot.decisions.push(decision.clone());
            Ok(decision)
        })
    }

    pub fn append_tool_result(
        &self,
        run_id: &RunId,
        result: ToolResult,
    ) -> Result<ToolResult, RunServiceError> {
        let result = redact_tool_result(result);
        let mut store = self.write_store()?;
        let previous = store.clone();
        let status = store
            .runs
            .get(run_id)
            .map(|record| record.run.status)
            .ok_or_else(|| {
                RunServiceError::new(
                    RunServiceErrorCode::ToolResultRunNotFound,
                    format!("Run '{}' was not found for the tool result.", run_id.0),
                )
            })?;

        if status != RunStatus::Running {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ToolResultRunNotActive,
                "Tool results can only be added while the run is running.",
            ));
        }
        if store.tool_result_ids.contains(&result.id) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ToolResultAlreadyExists,
                format!("Tool result '{}' already exists.", result.id.0),
            ));
        }

        let record = store.runs.get_mut(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::ToolResultRunNotFound,
                format!("Run '{}' was not found for the tool result.", run_id.0),
            )
        })?;
        record.tool_results.push(result.clone());
        store.tool_result_ids.insert(result.id.clone());
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(result)
    }

    pub fn get_tool_results(&self, run_id: &RunId) -> Result<Vec<ToolResult>, RunServiceError> {
        self.read_store()?
            .runs
            .get(run_id)
            .map(|record| record.tool_results.clone())
            .ok_or_else(|| {
                RunServiceError::new(
                    RunServiceErrorCode::ToolResultRunNotFound,
                    format!("Run '{}' was not found for tool result lookup.", run_id.0),
                )
            })
    }

    pub fn get_tool_result(
        &self,
        run_id: &RunId,
        result_id: &ToolResultId,
    ) -> Result<ToolResult, RunServiceError> {
        let store = self.read_store()?;
        let record = store.runs.get(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::ToolResultRunNotFound,
                format!("Run '{}' was not found for tool result lookup.", run_id.0),
            )
        })?;
        record
            .tool_results
            .iter()
            .find(|result| &result.id == result_id)
            .cloned()
            .ok_or_else(|| {
                RunServiceError::new(
                    RunServiceErrorCode::ToolResultNotFound,
                    format!(
                        "Tool result '{}' was not found in run '{}'.",
                        result_id.0, run_id.0
                    ),
                )
            })
    }

    pub fn commit_tool_result(
        &self,
        run_id: &RunId,
        result: ToolResult,
        step: u64,
        usage: RunUsage,
    ) -> Result<ToolResult, RunServiceError> {
        let result = redact_tool_result(result);
        let event_id = self.ids.run_event_id();
        let timestamp_ms = self.clock.now_ms();
        let mut store = self.write_store()?;
        let previous = store.clone();
        self.ensure_event_id_available(&store, &event_id)?;
        if store.tool_result_ids.contains(&result.id) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ToolResultAlreadyExists,
                format!("Tool result '{}' already exists.", result.id.0),
            ));
        }
        let record = store.runs.get_mut(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::ToolResultRunNotFound,
                format!("Run '{}' was not found for the tool result.", run_id.0),
            )
        })?;
        if record.run.status != RunStatus::Running {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ToolResultRunNotActive,
                "Tool results can only be added while the run is running.",
            ));
        }
        Self::ensure_usage_is_monotonic(&record.run.usage, &usage)?;
        record.run.current_step = usage.steps;
        record.run.usage = usage;
        record.tool_results.push(result.clone());
        record.events.push(RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: event_id.clone(),
            run_id: run_id.clone(),
            timestamp_ms,
            step,
            kind: RunEventKind::ToolCompleted {
                tool_result_id: result.id.clone(),
                success: result.success,
            },
        });
        store.tool_result_ids.insert(result.id.clone());
        store.event_ids.insert(event_id);
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(result)
    }

    pub fn append_evidence(
        &self,
        run_id: &RunId,
        evidence: Evidence,
    ) -> Result<Evidence, RunServiceError> {
        let mut store = self.write_store()?;
        let previous = store.clone();
        let record = store.runs.get(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::EvidenceRunNotFound,
                format!("Run '{}' was not found for evidence storage.", run_id.0),
            )
        })?;
        if record.run.status != RunStatus::Running {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvidenceRunNotActive,
                "Evidence can only be added while the run is running.",
            ));
        }
        if &evidence.run_id != run_id {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvidenceRunIdMismatch,
                "The evidence run ID does not match the destination run.",
            ));
        }
        if store.evidence_ids.contains(&evidence.id) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvidenceAlreadyExists,
                format!("Evidence '{}' already exists.", evidence.id.0),
            ));
        }
        if !Self::evidence_source_exists(record, &evidence.source) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvidenceSourceNotFound,
                "The evidence source does not exist inside this run.",
            ));
        }

        let record = store.runs.get_mut(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::EvidenceRunNotFound,
                format!("Run '{}' was not found for evidence storage.", run_id.0),
            )
        })?;
        record.evidence.push(evidence.clone());
        store.evidence_ids.insert(evidence.id.clone());
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(evidence)
    }

    pub fn append_evidence_recorded(
        &self,
        run_id: &RunId,
        evidence: Evidence,
        step: u64,
    ) -> Result<Evidence, RunServiceError> {
        let event_id = self.ids.run_event_id();
        let timestamp_ms = self.clock.now_ms();
        let mut store = self.write_store()?;
        let previous = store.clone();
        self.ensure_event_id_available(&store, &event_id)?;
        let record = store.runs.get(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::EvidenceRunNotFound,
                format!("Run '{}' was not found for evidence storage.", run_id.0),
            )
        })?;
        if record.run.status != RunStatus::Running {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvidenceRunNotActive,
                "Evidence can only be added while the run is running.",
            ));
        }
        if &evidence.run_id != run_id {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvidenceRunIdMismatch,
                "The evidence run ID does not match the destination run.",
            ));
        }
        if store.evidence_ids.contains(&evidence.id) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvidenceAlreadyExists,
                format!("Evidence '{}' already exists.", evidence.id.0),
            ));
        }
        if !Self::evidence_source_exists(record, &evidence.source) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvidenceSourceNotFound,
                "The evidence source does not exist inside this run.",
            ));
        }
        let record = store
            .runs
            .get_mut(run_id)
            .ok_or_else(|| Self::run_not_found(run_id))?;
        record.evidence.push(evidence.clone());
        record.events.push(RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: event_id.clone(),
            run_id: run_id.clone(),
            timestamp_ms,
            step,
            kind: RunEventKind::EvidenceRecorded {
                evidence_id: evidence.id.clone(),
            },
        });
        store.evidence_ids.insert(evidence.id.clone());
        store.event_ids.insert(event_id);
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(evidence)
    }

    pub fn get_evidence(
        &self,
        run_id: &RunId,
        evidence_id: &EvidenceId,
    ) -> Result<Evidence, RunServiceError> {
        let store = self.read_store()?;
        let record = store.runs.get(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::EvidenceRunNotFound,
                format!("Run '{}' was not found for evidence lookup.", run_id.0),
            )
        })?;
        record
            .evidence
            .iter()
            .find(|evidence| &evidence.id == evidence_id)
            .cloned()
            .ok_or_else(|| {
                RunServiceError::new(
                    RunServiceErrorCode::EvidenceNotFound,
                    format!(
                        "Evidence '{}' was not found in run '{}'.",
                        evidence_id.0, run_id.0
                    ),
                )
            })
    }

    pub fn get_all_evidence(&self, run_id: &RunId) -> Result<Vec<Evidence>, RunServiceError> {
        self.read_store()?
            .runs
            .get(run_id)
            .map(|record| record.evidence.clone())
            .ok_or_else(|| {
                RunServiceError::new(
                    RunServiceErrorCode::EvidenceRunNotFound,
                    format!("Run '{}' was not found for evidence lookup.", run_id.0),
                )
            })
    }

    pub fn append_model_call(
        &self,
        run_id: &RunId,
        call: ModelCallRecord,
    ) -> Result<ModelCallRecord, RunServiceError> {
        let mut store = self.write_store()?;
        let previous = store.clone();
        let record = store.runs.get(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::ModelCallRunNotFound,
                format!("Run '{}' was not found for model call storage.", run_id.0),
            )
        })?;
        if record.run.status != RunStatus::Running {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ModelCallRunNotActive,
                "Model calls can only be added while the run is running.",
            ));
        }
        if &call.run_id != run_id {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ModelCallRunNotFound,
                "The model call run ID does not match the destination run.",
            ));
        }
        if store.model_call_ids.contains(&call.id) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ModelCallAlreadyExists,
                format!("Model call '{}' already exists.", call.id),
            ));
        }

        let record = store.runs.get_mut(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::ModelCallRunNotFound,
                format!("Run '{}' was not found for model call storage.", run_id.0),
            )
        })?;
        record.model_calls.push(call.clone());
        store.model_call_ids.insert(call.id.clone());
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(call)
    }

    pub fn commit_model_call(
        &self,
        run_id: &RunId,
        call: ModelCallRecord,
        step: u64,
        usage: RunUsage,
    ) -> Result<Run, RunServiceError> {
        let event_id = self.ids.run_event_id();
        let timestamp_ms = self.clock.now_ms();
        let mut store = self.write_store()?;
        let previous = store.clone();
        self.ensure_event_id_available(&store, &event_id)?;
        if store.model_call_ids.contains(&call.id) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ModelCallAlreadyExists,
                format!("Model call '{}' already exists.", call.id),
            ));
        }
        let record = store.runs.get_mut(run_id).ok_or_else(|| {
            RunServiceError::new(
                RunServiceErrorCode::ModelCallRunNotFound,
                format!("Run '{}' was not found for model call storage.", run_id.0),
            )
        })?;
        if record.run.status != RunStatus::Running || &call.run_id != run_id {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ModelCallRunNotActive,
                "The model call cannot be added to this run.",
            ));
        }
        Self::ensure_usage_is_monotonic(&record.run.usage, &usage)?;
        record.run.current_step = usage.steps;
        record.run.usage = usage;
        record.model_calls.push(call.clone());
        record.events.push(RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: event_id.clone(),
            run_id: run_id.clone(),
            timestamp_ms,
            step,
            kind: RunEventKind::ModelCalled {
                model_call_id: call.id.clone(),
                model: Some(call.model.clone()),
            },
        });
        let run = record.run.clone();
        store.model_call_ids.insert(call.id);
        store.event_ids.insert(event_id);
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(run)
    }

    pub fn get_model_calls(&self, run_id: &RunId) -> Result<Vec<ModelCallRecord>, RunServiceError> {
        self.read_store()?
            .runs
            .get(run_id)
            .map(|record| record.model_calls.clone())
            .ok_or_else(|| {
                RunServiceError::new(
                    RunServiceErrorCode::ModelCallRunNotFound,
                    format!("Run '{}' was not found for model call lookup.", run_id.0),
                )
            })
    }

    pub fn set_evaluation_result(
        &self,
        run_id: &RunId,
        evaluation: EvaluationResult,
    ) -> Result<Run, RunServiceError> {
        if evaluation.passed != (evaluation.verdict == EvaluationVerdict::Passed)
            || evaluation
                .score
                .is_some_and(|score| !score.is_finite() || !(0.0..=1.0).contains(&score))
        {
            return Err(RunServiceError::new(
                RunServiceErrorCode::InvalidEvaluation,
                "Evaluation verdict, passed flag, or score is inconsistent.",
            ));
        }
        let now = self.clock.now_ms();
        let event_id = self.ids.run_event_id();
        let mut store = self.write_store()?;
        let previous = store.clone();
        self.ensure_event_id_available(&store, &event_id)?;
        let record = store
            .runs
            .get_mut(run_id)
            .ok_or_else(|| Self::run_not_found(run_id))?;
        if record.run.status != RunStatus::Completed || record.run.final_output.is_none() {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvaluationRunNotReady,
                "A run must have a completed FinalOutput before evaluation is stored.",
            ));
        }
        if record.run.evaluation.is_some() {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EvaluationAlreadyExists,
                "An evaluation result is already stored for this run.",
            ));
        }

        record.run.evaluation = Some(evaluation.clone());
        record.events.push(RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: event_id.clone(),
            run_id: run_id.clone(),
            timestamp_ms: now,
            step: record.run.current_step,
            kind: RunEventKind::EvaluationCompleted {
                passed: evaluation.passed,
                score: evaluation.score,
            },
        });
        let run = record.run.clone();
        store.event_ids.insert(event_id);
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(run)
    }

    pub fn get_evaluation_result(
        &self,
        run_id: &RunId,
    ) -> Result<Option<EvaluationResult>, RunServiceError> {
        self.read_store()?
            .runs
            .get(run_id)
            .map(|record| record.run.evaluation.clone())
            .ok_or_else(|| {
                RunServiceError::new(
                    RunServiceErrorCode::EvaluationNotFound,
                    format!("Run '{}' was not found for evaluation lookup.", run_id.0),
                )
            })
    }

    pub fn record_event(
        &self,
        run_id: &RunId,
        step: u64,
        kind: RunEventKind,
    ) -> Result<RunEvent, RunServiceError> {
        let event = self.make_event(run_id.clone(), self.clock.now_ms(), step, kind);
        self.append_event(run_id, event)
    }

    pub fn start_run(&self, run_id: &RunId) -> Result<Run, RunServiceError> {
        let now = self.clock.now_ms();
        let event_id = self.ids.run_event_id();
        let mut store = self.write_store()?;
        let previous = store.clone();
        self.ensure_event_id_available(&store, &event_id)?;

        let record = store
            .runs
            .get_mut(run_id)
            .ok_or_else(|| Self::run_not_found(run_id))?;
        Self::ensure_transition(record.run.status, RunStatus::Running)?;

        record.run.status = RunStatus::Running;
        record.run.started_at_ms = Some(now);
        let event = RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: event_id.clone(),
            run_id: run_id.clone(),
            timestamp_ms: now,
            step: record.run.current_step,
            kind: RunEventKind::RunStarted {
                task_id: record.run.task_id.clone(),
            },
        };
        record.events.push(event);
        let run = record.run.clone();
        store.event_ids.insert(event_id);
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(run)
    }

    pub fn append_event(
        &self,
        run_id: &RunId,
        event: RunEvent,
    ) -> Result<RunEvent, RunServiceError> {
        let event = redact_event(event);
        if &event.run_id != run_id {
            return Err(RunServiceError::new(
                RunServiceErrorCode::EventRunIdMismatch,
                "The event run ID does not match the requested run.",
            ));
        }
        if event.timestamp_ms == 0 {
            return Err(RunServiceError::new(
                RunServiceErrorCode::InvalidEvent,
                "An event timestamp must be greater than zero.",
            ));
        }
        if Self::is_service_managed_event(&event.kind) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::InvalidEvent,
                "Lifecycle events must be recorded by RunService.",
            ));
        }

        let mut store = self.write_store()?;
        let previous = store.clone();
        self.ensure_event_id_available(&store, &event.id)?;
        let record = store
            .runs
            .get_mut(run_id)
            .ok_or_else(|| Self::run_not_found(run_id))?;
        Self::ensure_run_accepts_updates(record.run.status)?;

        if event.step > record.run.current_step {
            return Err(RunServiceError::new(
                RunServiceErrorCode::InvalidEvent,
                "The event step cannot exceed the run's current step.",
            ));
        }
        if let Some(previous) = record.events.last() {
            if event.step < previous.step || event.timestamp_ms < previous.timestamp_ms {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::InvalidEvent,
                    "Events must preserve step and timestamp ordering.",
                ));
            }
        }

        record.events.push(event.clone());
        store.event_ids.insert(event.id.clone());
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(event)
    }

    pub fn update_usage(&self, run_id: &RunId, usage: RunUsage) -> Result<Run, RunServiceError> {
        let mut store = self.write_store()?;
        let previous = store.clone();
        let record = store
            .runs
            .get_mut(run_id)
            .ok_or_else(|| Self::run_not_found(run_id))?;
        Self::ensure_run_accepts_updates(record.run.status)?;
        Self::ensure_usage_is_monotonic(&record.run.usage, &usage)?;
        record.run.current_step = usage.steps;
        record.run.usage = usage;
        let run = record.run.clone();
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(run)
    }

    pub fn complete_run(
        &self,
        run_id: &RunId,
        output: FinalOutput,
    ) -> Result<Run, RunServiceError> {
        if output.answer.trim().is_empty()
            || !matches!(
                output.status,
                FinalOutputStatus::Completed | FinalOutputStatus::Inconclusive
            )
        {
            return Err(RunServiceError::new(
                RunServiceErrorCode::InvalidFinalOutput,
                "A completed run requires a non-empty completed or inconclusive output.",
            ));
        }
        {
            let store = self.read_store()?;
            let record = store
                .runs
                .get(run_id)
                .ok_or_else(|| Self::run_not_found(run_id))?;
            let mut referenced = HashSet::new();
            for evidence_id in &output.evidence_ids {
                if !referenced.insert(evidence_id) {
                    return Err(RunServiceError::new(
                        RunServiceErrorCode::InvalidFinalOutput,
                        format!("FinalOutput repeats Evidence ID '{}'.", evidence_id.0),
                    ));
                }
                if !record
                    .evidence
                    .iter()
                    .any(|evidence| &evidence.id == evidence_id)
                {
                    return Err(RunServiceError::new(
                        RunServiceErrorCode::InvalidFinalOutput,
                        format!(
                            "FinalOutput references unknown Evidence ID '{}'.",
                            evidence_id.0
                        ),
                    ));
                }
            }
        }
        let event_status = output.status;
        self.finish_run(
            run_id,
            RunStatus::Completed,
            RunEventKind::RunCompleted {
                status: event_status,
            },
            Some(output),
        )
    }

    pub fn fail_run(&self, run_id: &RunId, error: RunFailure) -> Result<Run, RunServiceError> {
        self.finish_run(
            run_id,
            RunStatus::Failed,
            RunEventKind::RunFailed { error },
            None,
        )
    }

    pub fn exhaust_budget(
        &self,
        run_id: &RunId,
        budget: BudgetKind,
    ) -> Result<Run, RunServiceError> {
        self.finish_run(
            run_id,
            RunStatus::BudgetExhausted,
            RunEventKind::BudgetExhausted { budget },
            None,
        )
    }

    pub fn block_scope(
        &self,
        run_id: &RunId,
        target: String,
        reason: String,
    ) -> Result<Run, RunServiceError> {
        self.finish_run(
            run_id,
            RunStatus::ScopeBlocked,
            RunEventKind::ScopeBlocked { target, reason },
            None,
        )
    }

    pub fn cancel_run(
        &self,
        run_id: &RunId,
        reason: Option<String>,
    ) -> Result<Run, RunServiceError> {
        self.finish_run(
            run_id,
            RunStatus::Cancelled,
            RunEventKind::RunCancelled { reason },
            None,
        )
    }

    fn finish_run(
        &self,
        run_id: &RunId,
        next_status: RunStatus,
        event_kind: RunEventKind,
        final_output: Option<FinalOutput>,
    ) -> Result<Run, RunServiceError> {
        let now = self.clock.now_ms();
        let event_id = self.ids.run_event_id();
        let mut store = self.write_store()?;
        let previous = store.clone();
        self.ensure_event_id_available(&store, &event_id)?;
        let record = store
            .runs
            .get_mut(run_id)
            .ok_or_else(|| Self::run_not_found(run_id))?;
        Self::ensure_transition(record.run.status, next_status)?;

        record.run.status = next_status;
        record.run.ended_at_ms = Some(now);
        if let Some(started_at_ms) = record.run.started_at_ms {
            record.run.usage.duration_ms = record
                .run
                .usage
                .duration_ms
                .max(now.saturating_sub(started_at_ms));
        }
        record.run.final_output = final_output;
        record.events.push(RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: event_id.clone(),
            run_id: run_id.clone(),
            timestamp_ms: now,
            step: record.run.current_step,
            kind: event_kind,
        });
        let run = record.run.clone();
        store.event_ids.insert(event_id);
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(run)
    }

    fn make_event(
        &self,
        run_id: RunId,
        timestamp_ms: u64,
        step: u64,
        kind: RunEventKind,
    ) -> RunEvent {
        RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: self.ids.run_event_id(),
            run_id,
            timestamp_ms,
            step,
            kind,
        }
    }

    fn ensure_transition(from: RunStatus, to: RunStatus) -> Result<(), RunServiceError> {
        if Self::is_terminal(from) {
            return Err(RunServiceError::new(
                RunServiceErrorCode::RunAlreadyTerminal,
                format!("Run is already in terminal state '{from:?}'."),
            ));
        }

        let allowed = matches!(
            (from, to),
            (RunStatus::Created, RunStatus::Running)
                | (RunStatus::Created, RunStatus::Cancelled)
                | (RunStatus::Running, RunStatus::Completed)
                | (RunStatus::Running, RunStatus::Failed)
                | (RunStatus::Running, RunStatus::Cancelled)
                | (RunStatus::Running, RunStatus::BudgetExhausted)
                | (RunStatus::Running, RunStatus::ScopeBlocked)
        );
        if allowed {
            Ok(())
        } else {
            Err(RunServiceError::new(
                RunServiceErrorCode::InvalidRunTransition,
                format!("Run cannot transition from '{from:?}' to '{to:?}'."),
            ))
        }
    }

    fn ensure_run_accepts_updates(status: RunStatus) -> Result<(), RunServiceError> {
        if Self::is_terminal(status) {
            Err(RunServiceError::new(
                RunServiceErrorCode::RunAlreadyTerminal,
                format!("Run is already in terminal state '{status:?}'."),
            ))
        } else if status != RunStatus::Running {
            Err(RunServiceError::new(
                RunServiceErrorCode::InvalidRunTransition,
                "Run events and usage can only be updated while running.",
            ))
        } else {
            Ok(())
        }
    }

    fn is_terminal(status: RunStatus) -> bool {
        matches!(
            status,
            RunStatus::Completed
                | RunStatus::Failed
                | RunStatus::Cancelled
                | RunStatus::BudgetExhausted
                | RunStatus::ScopeBlocked
        )
    }

    fn is_service_managed_event(kind: &RunEventKind) -> bool {
        matches!(
            kind,
            RunEventKind::RunCreated { .. }
                | RunEventKind::RunStarted { .. }
                | RunEventKind::RunCompleted { .. }
                | RunEventKind::RunFailed { .. }
                | RunEventKind::RunCancelled { .. }
                | RunEventKind::BudgetExhausted { .. }
                | RunEventKind::ScopeBlocked { .. }
        )
    }

    fn evidence_source_exists(record: &RunRecord, source: &EvidenceSource) -> bool {
        match source {
            EvidenceSource::ToolResult { tool_result_id } => record
                .tool_results
                .iter()
                .any(|result| &result.id == tool_result_id),
            EvidenceSource::ModelCall { model_call_id } => record
                .model_calls
                .iter()
                .any(|call| &call.id == model_call_id),
            EvidenceSource::Request { request_id } => record.tool_results.iter().any(|result| {
                result
                    .data
                    .get("request_id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|stored| stored == request_id)
            }),
            EvidenceSource::Manual { .. } => false,
        }
    }

    fn ensure_usage_is_monotonic(
        current: &RunUsage,
        proposed: &RunUsage,
    ) -> Result<(), RunServiceError> {
        let regressed = proposed.steps < current.steps
            || proposed.http_requests < current.http_requests
            || proposed.model_calls < current.model_calls
            || proposed.input_tokens < current.input_tokens
            || proposed.output_tokens < current.output_tokens
            || proposed.duration_ms < current.duration_ms;
        if regressed {
            Err(RunServiceError::new(
                RunServiceErrorCode::UsageRegression,
                "Run usage counters must be monotonic.",
            ))
        } else {
            Ok(())
        }
    }

    fn ensure_event_id_available(
        &self,
        store: &RunStore,
        event_id: &RunEventId,
    ) -> Result<(), RunServiceError> {
        if store.event_ids.contains(event_id) {
            Err(RunServiceError::new(
                RunServiceErrorCode::RunEventAlreadyExists,
                format!("Run event '{}' already exists.", event_id.0),
            ))
        } else {
            Ok(())
        }
    }

    fn run_not_found(run_id: &RunId) -> RunServiceError {
        RunServiceError::new(
            RunServiceErrorCode::RunNotFound,
            format!("Run '{}' was not found.", run_id.0),
        )
    }

    pub fn recover_interrupted_runs(&self) -> Result<usize, RunServiceError> {
        let mut store = self.write_store()?;
        let interrupted = store
            .runs
            .iter()
            .filter_map(|(run_id, record)| {
                (record.run.status == RunStatus::Running).then_some(run_id.clone())
            })
            .collect::<Vec<_>>();
        let mut recovered = 0;
        for run_id in interrupted {
            let previous = store.clone();
            let now = self.clock.now_ms();
            let event_id = self.ids.run_event_id();
            self.ensure_event_id_available(&store, &event_id)?;
            let record = store
                .runs
                .get_mut(&run_id)
                .ok_or_else(|| Self::run_not_found(&run_id))?;
            record.run.status = RunStatus::Failed;
            record.run.ended_at_ms = Some(now);
            if let Some(started_at_ms) = record.run.started_at_ms {
                record.run.usage.duration_ms = record
                    .run
                    .usage
                    .duration_ms
                    .max(now.saturating_sub(started_at_ms));
            }
            record.events.push(RunEvent {
                schema_version: CORE_SCHEMA_VERSION,
                id: event_id.clone(),
                run_id: run_id.clone(),
                timestamp_ms: now,
                step: record.run.current_step,
                kind: RunEventKind::RunFailed {
                    error: RunFailure {
                        code: "RUN_INTERRUPTED".into(),
                        message: "The application stopped while this run was active.".into(),
                    },
                },
            });
            store.event_ids.insert(event_id);
            self.persist_record_locked(&mut store, previous, &run_id)?;
            recovered += 1;
        }
        Ok(recovered)
    }

    fn mutate_recon_snapshot<T>(
        &self,
        run_id: &RunId,
        mutate: impl FnOnce(&mut ReconSnapshot) -> Result<T, RunServiceError>,
    ) -> Result<T, RunServiceError> {
        let mut store = self.write_store()?;
        let previous = store.clone();
        let record = store
            .runs
            .get_mut(run_id)
            .ok_or_else(|| Self::recon_run_not_found(run_id))?;
        if record.run.status != RunStatus::Running {
            return Err(RunServiceError::new(
                RunServiceErrorCode::ReconRunNotActive,
                "Recon state can only be changed while the run is running.",
            ));
        }
        let value = mutate(&mut record.recon_snapshot)?;
        self.persist_record_locked(&mut store, previous, run_id)?;
        Ok(value)
    }

    fn ensure_assets_exist<'a>(
        snapshot: &ReconSnapshot,
        asset_ids: impl IntoIterator<Item = &'a ReconAssetId>,
    ) -> Result<(), RunServiceError> {
        for asset_id in asset_ids {
            if !snapshot.assets.iter().any(|asset| asset.id == *asset_id) {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::InvalidReconReference,
                    format!("Recon asset '{}' was not found.", asset_id.0),
                ));
            }
        }
        Ok(())
    }

    fn ensure_hypothesis_exists(
        snapshot: &ReconSnapshot,
        hypothesis_id: &ReconHypothesisId,
    ) -> Result<(), RunServiceError> {
        if snapshot
            .hypotheses
            .iter()
            .any(|hypothesis| hypothesis.id == *hypothesis_id)
        {
            Ok(())
        } else {
            Err(RunServiceError::new(
                RunServiceErrorCode::InvalidReconReference,
                format!("Recon hypothesis '{}' was not found.", hypothesis_id.0),
            ))
        }
    }

    fn validate_hypothesis_references(
        snapshot: &ReconSnapshot,
        hypothesis: &ReconHypothesis,
    ) -> Result<(), RunServiceError> {
        Self::ensure_assets_exist(snapshot, hypothesis.subject_asset_ids.iter())?;
        for observation_id in hypothesis
            .supporting_observation_ids
            .iter()
            .chain(hypothesis.contradicting_observation_ids.iter())
        {
            if !snapshot
                .observations
                .iter()
                .any(|observation| observation.id == *observation_id)
            {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::InvalidReconReference,
                    format!("Recon observation '{}' was not found.", observation_id.0),
                ));
            }
        }
        Ok(())
    }

    fn recon_run_not_found(run_id: &RunId) -> RunServiceError {
        RunServiceError::new(
            RunServiceErrorCode::ReconRunNotFound,
            format!("Run '{}' was not found for Recon state.", run_id.0),
        )
    }

    fn recon_run_id_mismatch(expected: &RunId, actual: &RunId) -> RunServiceError {
        RunServiceError::new(
            RunServiceErrorCode::ReconRunIdMismatch,
            format!(
                "Recon data belongs to run '{}', not run '{}'.",
                actual.0, expected.0
            ),
        )
    }

    fn persist_record_locked(
        &self,
        store: &mut RunStore,
        previous: RunStore,
        run_id: &RunId,
    ) -> Result<(), RunServiceError> {
        let result = store
            .runs
            .get(run_id)
            .ok_or_else(|| Self::run_not_found(run_id))
            .and_then(|record| self.repository.save_record(record));
        if let Err(error) = result {
            *store = previous;
            return Err(error);
        }
        Ok(())
    }

    fn read_store(&self) -> Result<RwLockReadGuard<'_, RunStore>, RunServiceError> {
        self.store.read().map_err(|_| {
            RunServiceError::new(
                RunServiceErrorCode::InternalLockError,
                "The in-memory run store lock is unavailable.",
            )
        })
    }

    fn write_store(&self) -> Result<RwLockWriteGuard<'_, RunStore>, RunServiceError> {
        self.store.write().map_err(|_| {
            RunServiceError::new(
                RunServiceErrorCode::InternalLockError,
                "The in-memory run store lock is unavailable.",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ReconAction, ReconActionId, ReconAssetKind, ReconConfidence, ReconHypothesisStatus,
        ReconInformationGain, ReconMode, ReconObservationId, ReconObservationSource,
        ReconRelationId, ReconRelationKind, ReconRisk, ReconScopeClassification,
    };
    use super::*;
    use crate::scope_guard::ScopeProject;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct SequenceIds(AtomicU64);

    impl SequenceIds {
        fn next(&self, prefix: &str) -> String {
            format!("{prefix}-{}", self.0.fetch_add(1, Ordering::SeqCst))
        }
    }

    impl IdGenerator for SequenceIds {
        fn task_id(&self) -> TaskId {
            TaskId(self.next("task"))
        }

        fn run_id(&self) -> RunId {
            RunId(self.next("run"))
        }

        fn run_event_id(&self) -> RunEventId {
            RunEventId(self.next("event"))
        }

        fn evidence_id(&self) -> EvidenceId {
            EvidenceId(self.next("evidence"))
        }
    }

    struct FixedIds;

    impl IdGenerator for FixedIds {
        fn task_id(&self) -> TaskId {
            TaskId("task-fixed".into())
        }

        fn run_id(&self) -> RunId {
            RunId("run-fixed".into())
        }

        fn run_event_id(&self) -> RunEventId {
            RunEventId("event-fixed".into())
        }

        fn evidence_id(&self) -> EvidenceId {
            EvidenceId("evidence-fixed".into())
        }
    }

    struct StepClock(AtomicU64);

    impl Clock for StepClock {
        fn now_ms(&self) -> u64 {
            self.0.fetch_add(10, Ordering::SeqCst)
        }
    }

    fn service() -> RunService {
        RunService::with_sources(
            Arc::new(SequenceIds(AtomicU64::new(1))),
            Arc::new(StepClock(AtomicU64::new(1_000))),
        )
    }

    fn task() -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: TaskId("task-1".into()),
            objective: "Assess the authorized target.".into(),
            primary_target: "https://app.example.test".into(),
            scope: ScopeProject {
                id: "scope-1".into(),
                allowed_domains: vec!["app.example.test".into()],
                excluded_domains: vec![],
                allowed_ports: vec![443],
                request_rate: 5,
                authorized: true,
            },
            budget: super::super::TaskBudget {
                max_steps: 10,
                max_http_requests: 20,
                max_model_calls: 5,
                max_input_tokens: 10_000,
                max_output_tokens: 2_000,
                max_duration_ms: 60_000,
            },
            available_tools: vec![],
            memory_policy: Default::default(),
        }
    }

    fn output() -> FinalOutput {
        FinalOutput {
            schema_version: CORE_SCHEMA_VERSION,
            status: FinalOutputStatus::Completed,
            answer: "Run completed.".into(),
            evidence_ids: vec![],
            limitations: vec![],
        }
    }

    fn tool_result(id: &str, note: &str) -> ToolResult {
        ToolResult {
            schema_version: CORE_SCHEMA_VERSION,
            id: ToolResultId(id.into()),
            tool_name: "record_note".into(),
            success: true,
            data: std::collections::BTreeMap::from([(
                "note".into(),
                serde_json::Value::String(note.into()),
            )]),
            error: None,
            duration_ms: 1,
        }
    }

    fn recon_asset(id: &str, kind: ReconAssetKind, value: &str) -> ReconAsset {
        ReconAsset {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconAssetId(id.into()),
            kind,
            canonical_value: value.into(),
            display_name: None,
            scope: ReconScopeClassification::InScope,
            scope_reason: "Authorized by the Run scope.".into(),
            confidence: ReconConfidence::High,
            first_seen_at_ms: 1_000,
            last_seen_at_ms: 1_000,
            tags: vec![],
        }
    }

    fn recon_observation(run_id: &RunId, asset_id: &ReconAssetId) -> ReconObservation {
        ReconObservation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconObservationId("observation-1".into()),
            run_id: run_id.clone(),
            source: ReconObservationSource::CertificateTransparency,
            subject_asset_ids: vec![asset_id.clone()],
            summary: "A passive source identified the asset.".into(),
            facts: std::collections::BTreeMap::new(),
            confidence: ReconConfidence::High,
            evidence_ids: vec![],
            observed_at_ms: 1_020,
        }
    }

    fn recon_hypothesis(asset_id: &ReconAssetId) -> ReconHypothesis {
        ReconHypothesis {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconHypothesisId("hypothesis-1".into()),
            kind: None,
            statement: "The discovered host may expose an API.".into(),
            status: ReconHypothesisStatus::Proposed,
            subject_asset_ids: vec![asset_id.clone()],
            rationale: "The hostname suggests an API surface.".into(),
            confidence: ReconConfidence::Medium,
            priority: None,
            recommended_capability: None,
            supporting_observation_ids: vec![ReconObservationId("observation-1".into())],
            contradicting_observation_ids: vec![],
        }
    }

    fn assert_code(error: RunServiceError, code: RunServiceErrorCode) {
        assert_eq!(error.code, code);
    }

    #[test]
    fn creates_run_in_created_state_with_a_created_event() {
        let service = service();
        let run = service.create_run(task()).unwrap();

        assert_eq!(run.status, RunStatus::Created);
        assert_eq!(run.created_at_ms, 1_000);
        assert!(run.started_at_ms.is_none());
        assert!(matches!(
            service.get_run_events(&run.id).unwrap()[0].kind,
            RunEventKind::RunCreated { .. }
        ));
    }

    #[test]
    fn recon_snapshot_starts_empty_and_only_changes_while_running() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        let asset = recon_asset("asset-root", ReconAssetKind::RootDomain, "example.test");

        let empty = service.get_recon_snapshot(&run.id).unwrap();
        assert_eq!(empty.run_id, run.id);
        assert!(empty.assets.is_empty());
        assert_code(
            service
                .append_recon_asset(&run.id, asset.clone())
                .unwrap_err(),
            RunServiceErrorCode::ReconRunNotActive,
        );

        service.start_run(&run.id).unwrap();
        service.append_recon_asset(&run.id, asset).unwrap();
        service.complete_run(&run.id, output()).unwrap();
        assert_eq!(service.get_recon_snapshot(&run.id).unwrap().assets.len(), 1);
        assert_code(
            service
                .append_recon_asset(
                    &run.id,
                    recon_asset("asset-api", ReconAssetKind::Subdomain, "api.example.test"),
                )
                .unwrap_err(),
            RunServiceErrorCode::ReconRunNotActive,
        );
    }

    #[test]
    fn recon_graph_preserves_order_and_rejects_duplicates_or_missing_references() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        service.start_run(&run.id).unwrap();
        let root = recon_asset("asset-root", ReconAssetKind::RootDomain, "example.test");
        let api = recon_asset("asset-api", ReconAssetKind::Subdomain, "api.example.test");
        service.append_recon_asset(&run.id, root.clone()).unwrap();
        service.append_recon_asset(&run.id, api.clone()).unwrap();

        assert_code(
            service
                .append_recon_asset(
                    &run.id,
                    recon_asset("asset-other", ReconAssetKind::Subdomain, "API.EXAMPLE.TEST"),
                )
                .unwrap_err(),
            RunServiceErrorCode::ReconItemAlreadyExists,
        );
        let relation = ReconAssetRelation {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconRelationId("relation-1".into()),
            from_asset_id: root.id.clone(),
            to_asset_id: api.id.clone(),
            kind: ReconRelationKind::Owns,
            confidence: ReconConfidence::High,
            evidence_ids: vec![],
            observed_at_ms: 1_020,
        };
        service
            .append_recon_relation(&run.id, relation.clone())
            .unwrap();
        assert_code(
            service
                .append_recon_relation(
                    &run.id,
                    ReconAssetRelation {
                        id: ReconRelationId("relation-2".into()),
                        ..relation
                    },
                )
                .unwrap_err(),
            RunServiceErrorCode::ReconItemAlreadyExists,
        );
        assert_code(
            service
                .append_recon_observation(
                    &run.id,
                    recon_observation(&run.id, &ReconAssetId("asset-missing".into())),
                )
                .unwrap_err(),
            RunServiceErrorCode::InvalidReconReference,
        );

        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        assert_eq!(
            snapshot
                .assets
                .iter()
                .map(|asset| asset.id.0.as_str())
                .collect::<Vec<_>>(),
            vec!["asset-root", "asset-api"]
        );
        assert_eq!(snapshot.relations.len(), 1);
    }

    #[test]
    fn recon_hypothesis_and_adaptive_decision_are_validated_and_update_in_place() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        service.start_run(&run.id).unwrap();
        let asset = recon_asset("asset-api", ReconAssetKind::Subdomain, "api.example.test");
        service.append_recon_asset(&run.id, asset.clone()).unwrap();
        service
            .append_recon_observation(&run.id, recon_observation(&run.id, &asset.id))
            .unwrap();
        let hypothesis = recon_hypothesis(&asset.id);
        service
            .append_recon_hypothesis(&run.id, hypothesis.clone())
            .unwrap();
        service
            .update_recon_hypothesis(
                &run.id,
                ReconHypothesis {
                    status: ReconHypothesisStatus::Testing,
                    ..hypothesis.clone()
                },
            )
            .unwrap();

        let action = ReconAction {
            schema_version: CORE_SCHEMA_VERSION,
            id: ReconActionId("action-1".into()),
            capability: super::super::ReconCapability::ResolveDns,
            target_asset_ids: vec![asset.id],
            arguments: std::collections::BTreeMap::new(),
            reason: "Resolve the candidate to test the hypothesis.".into(),
            expected_information_gain: ReconInformationGain::High,
            risk: ReconRisk::LowImpact,
        };
        let decision = ReconDecision {
            schema_version: CORE_SCHEMA_VERSION,
            run_id: run.id.clone(),
            step: 1,
            mode: ReconMode::Verify,
            hypothesis_id: Some(hypothesis.id),
            knowledge_gaps: vec![],
            candidate_actions: vec![action.clone()],
            action_scores: vec![super::super::ReconActionScore {
                schema_version: CORE_SCHEMA_VERSION,
                action_id: action.id.clone(),
                information_gain: 75,
                relevance: 95,
                confidence: 100,
                novelty: 100,
                estimated_cost: 10,
                risk_penalty: 15,
                repetition_penalty: 0,
                total: 345,
                rationale: vec!["High-value verification.".into()],
            }],
            recommended_action_id: Some(action.id.clone()),
            selected_action_id: Some(action.id),
            coverage: None,
            decision_summary: "Verify the highest-value candidate.".into(),
            stop_reason_code: None,
            stop_reason: None,
        };
        service
            .append_recon_decision(&run.id, decision.clone())
            .unwrap();
        assert_code(
            service
                .append_recon_decision(
                    &run.id,
                    ReconDecision {
                        step: 2,
                        selected_action_id: Some(ReconActionId("not-a-candidate".into())),
                        ..decision
                    },
                )
                .unwrap_err(),
            RunServiceErrorCode::InvalidReconDecision,
        );

        let snapshot = service.get_recon_snapshot(&run.id).unwrap();
        assert_eq!(snapshot.hypotheses.len(), 1);
        assert_eq!(
            snapshot.hypotheses[0].status,
            ReconHypothesisStatus::Testing
        );
        assert_eq!(snapshot.decisions.len(), 1);
    }

    #[test]
    fn generates_different_ids_and_rejects_duplicate_run_ids() {
        let service = service();
        let first = service.create_run(task()).unwrap();
        let second = service.create_run(task()).unwrap();
        assert_ne!(first.id, second.id);

        let fixed = RunService::with_sources(
            Arc::new(FixedIds),
            Arc::new(StepClock(AtomicU64::new(1_000))),
        );
        fixed.create_run(task()).unwrap();
        assert_code(
            fixed.create_run(task()).unwrap_err(),
            RunServiceErrorCode::RunAlreadyExists,
        );
    }

    #[test]
    fn starts_run_once_and_records_real_start_time() {
        let service = service();
        let created = service.create_run(task()).unwrap();
        let running = service.start_run(&created.id).unwrap();

        assert_eq!(running.status, RunStatus::Running);
        assert_eq!(running.started_at_ms, Some(1_010));
        assert_code(
            service.start_run(&created.id).unwrap_err(),
            RunServiceErrorCode::InvalidRunTransition,
        );
    }

    #[test]
    fn rejects_created_to_completed_and_accepts_running_to_completed() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        assert_code(
            service.complete_run(&run.id, output()).unwrap_err(),
            RunServiceErrorCode::InvalidRunTransition,
        );

        service.start_run(&run.id).unwrap();
        let completed = service.complete_run(&run.id, output()).unwrap();
        assert_eq!(completed.status, RunStatus::Completed);
        assert!(completed.ended_at_ms.is_some());
        assert!(completed.final_output.is_some());
    }

    #[test]
    fn fails_running_run_with_structured_error() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        service.start_run(&run.id).unwrap();
        let failed = service
            .fail_run(
                &run.id,
                RunFailure {
                    code: "TEST_FAILURE".into(),
                    message: "Test failure.".into(),
                },
            )
            .unwrap();

        assert_eq!(failed.status, RunStatus::Failed);
        assert!(matches!(
            service
                .get_run_events(&run.id)
                .unwrap()
                .last()
                .unwrap()
                .kind,
            RunEventKind::RunFailed { .. }
        ));
    }

    #[test]
    fn cancels_created_and_running_runs() {
        let service = service();
        let created = service.create_run(task()).unwrap();
        let cancelled = service
            .cancel_run(&created.id, Some("No longer needed.".into()))
            .unwrap();
        assert_eq!(cancelled.status, RunStatus::Cancelled);
        assert!(cancelled.started_at_ms.is_none());

        let running = service.create_run(task()).unwrap();
        service.start_run(&running.id).unwrap();
        let cancelled = service.cancel_run(&running.id, None).unwrap();
        assert_eq!(cancelled.status, RunStatus::Cancelled);
        assert!(cancelled.ended_at_ms.is_some());
        assert!(cancelled.usage.duration_ms > 0);
    }

    #[test]
    fn rejects_every_transition_after_terminal_state() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        service.start_run(&run.id).unwrap();
        service.complete_run(&run.id, output()).unwrap();

        assert_code(
            service.start_run(&run.id).unwrap_err(),
            RunServiceErrorCode::RunAlreadyTerminal,
        );
        assert_code(
            service.cancel_run(&run.id, None).unwrap_err(),
            RunServiceErrorCode::RunAlreadyTerminal,
        );
        assert_code(
            service
                .fail_run(
                    &run.id,
                    RunFailure {
                        code: "LATE".into(),
                        message: "Too late.".into(),
                    },
                )
                .unwrap_err(),
            RunServiceErrorCode::RunAlreadyTerminal,
        );
    }

    #[test]
    fn exhausts_budget_and_blocks_scope_only_from_running() {
        let service = service();
        let budget_run = service.create_run(task()).unwrap();
        service.start_run(&budget_run.id).unwrap();
        assert_eq!(
            service
                .exhaust_budget(&budget_run.id, BudgetKind::Steps)
                .unwrap()
                .status,
            RunStatus::BudgetExhausted
        );

        let scope_run = service.create_run(task()).unwrap();
        service.start_run(&scope_run.id).unwrap();
        assert_eq!(
            service
                .block_scope(
                    &scope_run.id,
                    "https://blocked.example".into(),
                    "Outside scope.".into(),
                )
                .unwrap()
                .status,
            RunStatus::ScopeBlocked
        );
    }

    #[test]
    fn appends_valid_event_and_rejects_run_id_mismatch() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        service.start_run(&run.id).unwrap();
        let event = RunEvent {
            schema_version: CORE_SCHEMA_VERSION,
            id: RunEventId("manual-event-1".into()),
            run_id: run.id.clone(),
            timestamp_ms: 2_000,
            step: 0,
            kind: RunEventKind::ModelCalled {
                model_call_id: "call-1".into(),
                model: None,
            },
        };
        service.append_event(&run.id, event.clone()).unwrap();

        let mut mismatched = event;
        mismatched.id = RunEventId("manual-event-2".into());
        mismatched.run_id = RunId("another-run".into());
        assert_code(
            service.append_event(&run.id, mismatched).unwrap_err(),
            RunServiceErrorCode::EventRunIdMismatch,
        );
    }

    #[test]
    fn updates_usage_monotonically_and_rejects_regression() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        service.start_run(&run.id).unwrap();
        let usage = RunUsage {
            steps: 2,
            http_requests: 3,
            model_calls: 1,
            input_tokens: 100,
            output_tokens: 20,
            duration_ms: 500,
        };
        let updated = service.update_usage(&run.id, usage).unwrap();
        assert_eq!(updated.current_step, 2);

        let regressed = RunUsage {
            steps: 1,
            ..updated.usage
        };
        assert_code(
            service.update_usage(&run.id, regressed).unwrap_err(),
            RunServiceErrorCode::UsageRegression,
        );
    }

    #[test]
    fn lists_runs_and_preserves_event_insertion_order() {
        let service = service();
        let first = service.create_run(task()).unwrap();
        let second = service.create_run(task()).unwrap();
        assert_eq!(service.list_runs().unwrap().len(), 2);

        service.start_run(&first.id).unwrap();
        let events = service.get_run_events(&first.id).unwrap();
        assert!(matches!(events[0].kind, RunEventKind::RunCreated { .. }));
        assert!(matches!(events[1].kind, RunEventKind::RunStarted { .. }));
        assert!(events[0].timestamp_ms <= events[1].timestamp_ms);
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn missing_run_returns_structured_error() {
        let service = service();
        let error = service.get_run(&RunId("missing".into())).unwrap_err();
        assert_eq!(error.code, RunServiceErrorCode::RunNotFound);
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            "RUN_NOT_FOUND"
        );
    }

    #[test]
    fn stores_reads_and_preserves_tool_results_after_completion() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        service.start_run(&run.id).unwrap();
        let first = tool_result("tool-result-1", "First note.");
        let second = tool_result("tool-result-2", "Second note.");

        service.append_tool_result(&run.id, first.clone()).unwrap();
        service.append_tool_result(&run.id, second.clone()).unwrap();
        assert_eq!(service.get_tool_result(&run.id, &first.id).unwrap(), first);

        service.complete_run(&run.id, output()).unwrap();
        assert_eq!(
            service.get_tool_results(&run.id).unwrap(),
            vec![first, second]
        );
    }

    #[test]
    fn rejects_duplicate_and_missing_tool_results() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        service.start_run(&run.id).unwrap();
        let result = tool_result("tool-result-1", "Stored once.");
        service.append_tool_result(&run.id, result.clone()).unwrap();

        assert_code(
            service.append_tool_result(&run.id, result).unwrap_err(),
            RunServiceErrorCode::ToolResultAlreadyExists,
        );
        assert_code(
            service
                .get_tool_result(&run.id, &ToolResultId("missing".into()))
                .unwrap_err(),
            RunServiceErrorCode::ToolResultNotFound,
        );
        assert_code(
            service
                .append_tool_result(
                    &RunId("missing-run".into()),
                    tool_result("tool-result-2", "Missing run."),
                )
                .unwrap_err(),
            RunServiceErrorCode::ToolResultRunNotFound,
        );
    }

    #[test]
    fn rejects_tool_results_before_start_and_after_terminal_state() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        assert_code(
            service
                .append_tool_result(&run.id, tool_result("tool-result-before", "Too early."))
                .unwrap_err(),
            RunServiceErrorCode::ToolResultRunNotActive,
        );

        service.start_run(&run.id).unwrap();
        service.complete_run(&run.id, output()).unwrap();
        assert_code(
            service
                .append_tool_result(&run.id, tool_result("tool-result-after", "Too late."))
                .unwrap_err(),
            RunServiceErrorCode::ToolResultRunNotActive,
        );
    }

    #[test]
    fn generates_task_id_when_the_input_id_is_empty() {
        let service = service();
        let mut input = task();
        input.id = TaskId(String::new());

        let run = service.create_run(input).unwrap();
        assert!(run.task_id.0.starts_with("task-"));
    }

    #[test]
    fn full_run_lifecycle_is_readable() {
        let service = service();
        let run = service.create_run(task()).unwrap();
        service.start_run(&run.id).unwrap();
        service
            .update_usage(
                &run.id,
                RunUsage {
                    steps: 1,
                    duration_ms: 10,
                    ..RunUsage::default()
                },
            )
            .unwrap();
        let completed = service.complete_run(&run.id, output()).unwrap();
        let events = service.get_run_events(&run.id).unwrap();

        assert_eq!(completed.status, RunStatus::Completed);
        assert_eq!(service.get_run(&run.id).unwrap(), completed);
        assert!(matches!(events[0].kind, RunEventKind::RunCreated { .. }));
        assert!(matches!(events[1].kind, RunEventKind::RunStarted { .. }));
        assert!(matches!(
            events.last().unwrap().kind,
            RunEventKind::RunCompleted { .. }
        ));
    }
}
