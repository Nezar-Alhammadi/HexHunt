use super::{RunRecord, RunServiceError, RunServiceErrorCode};
use std::{collections::HashMap, sync::RwLock};

pub(crate) trait RunRepository: Send + Sync {
    fn load_all(&self) -> Result<Vec<RunRecord>, RunServiceError>;
    fn save_record(&self, record: &RunRecord) -> Result<(), RunServiceError>;
}

#[derive(Default)]
pub(crate) struct InMemoryRunRepository {
    runs: RwLock<HashMap<super::RunId, RunRecord>>,
}

impl RunRepository for InMemoryRunRepository {
    fn load_all(&self) -> Result<Vec<RunRecord>, RunServiceError> {
        self.runs
            .read()
            .map(|runs| runs.values().cloned().collect())
            .map_err(|_| {
                RunServiceError::new(
                    RunServiceErrorCode::DatabaseReadFailed,
                    "The in-memory repository is unavailable.",
                )
            })
    }

    fn save_record(&self, record: &RunRecord) -> Result<(), RunServiceError> {
        let mut runs = self.runs.write().map_err(|_| {
            RunServiceError::new(
                RunServiceErrorCode::DatabaseWriteFailed,
                "The in-memory repository is unavailable.",
            )
        })?;

        for other in runs.values().filter(|other| other.run.id != record.run.id) {
            if record
                .events
                .iter()
                .any(|candidate| other.events.iter().any(|stored| stored.id == candidate.id))
                || record.tool_results.iter().any(|candidate| {
                    other
                        .tool_results
                        .iter()
                        .any(|stored| stored.id == candidate.id)
                })
                || record.evidence.iter().any(|candidate| {
                    other
                        .evidence
                        .iter()
                        .any(|stored| stored.id == candidate.id)
                })
                || record.model_calls.iter().any(|candidate| {
                    other
                        .model_calls
                        .iter()
                        .any(|stored| stored.id == candidate.id)
                })
            {
                return Err(RunServiceError::new(
                    RunServiceErrorCode::DatabaseWriteFailed,
                    "A globally unique persisted identifier is already in use.",
                ));
            }
        }
        runs.insert(record.run.id.clone(), record.clone());
        Ok(())
    }
}
