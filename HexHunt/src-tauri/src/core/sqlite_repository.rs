use super::{
    EvaluationResult, Evidence, EvidenceSource, ModelCallRecord, ReconSnapshot, ReconSnapshotId,
    RunEvent, RunEventKind, RunRecord, RunRepository, RunServiceError, RunServiceErrorCode, Task,
    ToolResult,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Serialize};
use std::{path::Path, sync::Mutex};

const DATABASE_SCHEMA_VERSION: i64 = 3;

pub(crate) struct SqliteRunRepository {
    connection: Mutex<Connection>,
}

impl SqliteRunRepository {
    pub(crate) fn open(path: &Path) -> Result<Self, RunServiceError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| {
                RunServiceError::new(
                    RunServiceErrorCode::DatabaseOpenFailed,
                    "Unable to create the HexHunt application-data directory.",
                )
            })?;
        }
        let connection = Connection::open(path).map_err(|_| {
            RunServiceError::new(
                RunServiceErrorCode::DatabaseOpenFailed,
                "Unable to open the HexHunt SQLite database.",
            )
        })?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .map_err(|_| {
                RunServiceError::new(
                    RunServiceErrorCode::DatabaseOpenFailed,
                    "Unable to configure the HexHunt SQLite database.",
                )
            })?;
        let repository = Self {
            connection: Mutex::new(connection),
        };
        repository.migrate()?;
        Ok(repository)
    }

    fn migrate(&self) -> Result<(), RunServiceError> {
        let mut connection = self.connection.lock().map_err(|_| database_lock_error())?;
        let transaction = connection.transaction().map_err(|_| {
            RunServiceError::new(
                RunServiceErrorCode::DatabaseTransactionFailed,
                "Unable to start the database migration transaction.",
            )
        })?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at_ms INTEGER NOT NULL
                );",
            )
            .map_err(|_| migration_error())?;
        let version: Option<i64> = transaction
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| migration_error())?
            .flatten();
        if version.unwrap_or(0) > DATABASE_SCHEMA_VERSION {
            return Err(RunServiceError::new(
                RunServiceErrorCode::DatabaseMigrationFailed,
                "The database schema is newer than this HexHunt version supports.",
            ));
        }
        if version.unwrap_or(0) < 1 {
            apply_migration_v1(&transaction)?;
            transaction
                .execute(
                    "INSERT INTO schema_migrations(version, applied_at_ms) VALUES(1, unixepoch('subsec') * 1000)",
                    [],
                )
                .map_err(|_| migration_error())?;
        }
        if version.unwrap_or(0) < 2 {
            apply_migration_v2(&transaction)?;
            transaction
                .execute(
                    "INSERT INTO schema_migrations(version, applied_at_ms) VALUES(2, unixepoch('subsec') * 1000)",
                    [],
                )
                .map_err(|_| migration_error())?;
        }
        if version.unwrap_or(0) < 3 {
            apply_migration_v3(&transaction)?;
            transaction
                .execute(
                    "INSERT INTO schema_migrations(version, applied_at_ms) VALUES(3, unixepoch('subsec') * 1000)",
                    [],
                )
                .map_err(|_| migration_error())?;
        }
        transaction.commit().map_err(|_| {
            RunServiceError::new(
                RunServiceErrorCode::DatabaseMigrationFailed,
                "Unable to commit the database migration.",
            )
        })
    }
}

impl RunRepository for SqliteRunRepository {
    fn load_all(&self) -> Result<Vec<RunRecord>, RunServiceError> {
        let connection = self.connection.lock().map_err(|_| database_lock_error())?;
        let mut statement = connection
            .prepare("SELECT run_id, task_json, run_json FROM runs ORDER BY created_at_ms ASC")
            .map_err(|_| database_read_error())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|_| database_read_error())?;
        let mut records = Vec::new();
        for row in rows {
            let (run_id, task_json, run_json) = row.map_err(|_| database_read_error())?;
            let task = decode::<Task>(&task_json)?;
            let mut run = decode::<super::Run>(&run_json)?;
            let events = load_json_rows::<RunEvent>(
                &connection,
                "SELECT event_json FROM run_events WHERE run_id = ?1 ORDER BY sequence_number ASC",
                &run_id,
            )?;
            let tool_results = load_json_rows::<ToolResult>(
                &connection,
                "SELECT tool_json FROM tool_results WHERE run_id = ?1 ORDER BY sequence_number ASC",
                &run_id,
            )?;
            let evidence = load_json_rows::<Evidence>(
                &connection,
                "SELECT evidence_json FROM evidence WHERE run_id = ?1 ORDER BY sequence_number ASC",
                &run_id,
            )?;
            let model_calls = load_json_rows::<ModelCallRecord>(
                &connection,
                "SELECT model_call_json FROM model_calls WHERE run_id = ?1 ORDER BY sequence_number ASC",
                &run_id,
            )?;
            let recon_snapshot = connection
                .query_row(
                    "SELECT snapshot_json FROM recon_snapshots WHERE run_id = ?1",
                    params![run_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| database_read_error())?
                .map(|json| decode::<ReconSnapshot>(&json))
                .transpose()?
                .unwrap_or_else(|| {
                    ReconSnapshot::empty(
                        ReconSnapshotId(format!("recon-{run_id}")),
                        super::RunId(run_id.clone()),
                        run.created_at_ms,
                    )
                });
            run.evaluation = connection
                .query_row(
                    "SELECT evaluation_json FROM evaluation_results WHERE run_id = ?1",
                    params![run_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| database_read_error())?
                .map(|json| decode::<EvaluationResult>(&json))
                .transpose()?;
            records.push(RunRecord {
                task,
                run,
                events,
                tool_results,
                evidence,
                model_calls,
                recon_snapshot,
            });
        }
        Ok(records)
    }

    fn save_record(&self, record: &RunRecord) -> Result<(), RunServiceError> {
        let mut connection = self.connection.lock().map_err(|_| database_lock_error())?;
        let transaction = connection.transaction().map_err(|_| {
            RunServiceError::new(
                RunServiceErrorCode::DatabaseTransactionFailed,
                "Unable to start the persistence transaction.",
            )
        })?;
        save_task(&transaction, record)?;
        save_run(&transaction, record)?;
        clear_run_children(&transaction, &record.run.id.0)?;
        replace_events(&transaction, record)?;
        replace_tool_results(&transaction, record)?;
        replace_model_calls(&transaction, record)?;
        replace_evidence(&transaction, record)?;
        replace_evaluation(&transaction, record)?;
        replace_recon_snapshot(&transaction, record)?;
        transaction.commit().map_err(|_| {
            RunServiceError::new(
                RunServiceErrorCode::DatabaseTransactionFailed,
                "Unable to commit the persistence transaction.",
            )
        })
    }
}

fn clear_run_children(transaction: &Transaction<'_>, run_id: &str) -> Result<(), RunServiceError> {
    for table in [
        "recon_snapshots",
        "evidence",
        "model_calls",
        "tool_results",
        "run_events",
    ] {
        transaction
            .execute(
                &format!("DELETE FROM {table} WHERE run_id=?1"),
                params![run_id],
            )
            .map_err(|_| database_write_error())?;
    }
    Ok(())
}

fn apply_migration_v1(transaction: &Transaction<'_>) -> Result<(), RunServiceError> {
    transaction
        .execute_batch(
            "CREATE TABLE tasks (
                task_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                title TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                allowed_tools_json TEXT NOT NULL,
                budget_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                task_json TEXT NOT NULL
            );
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                status TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                started_at_ms INTEGER,
                finished_at_ms INTEGER,
                usage_json TEXT NOT NULL,
                failure_json TEXT,
                final_output_json TEXT,
                task_json TEXT NOT NULL,
                run_json TEXT NOT NULL
            );
            CREATE INDEX runs_created_idx ON runs(created_at_ms DESC);
            CREATE INDEX runs_status_idx ON runs(status);
            CREATE TABLE run_events (
                event_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                event_kind TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                UNIQUE(run_id, sequence_number)
            );
            CREATE TABLE tool_results (
                tool_result_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                tool_name TEXT NOT NULL,
                success INTEGER NOT NULL,
                data_json TEXT NOT NULL,
                error_json TEXT,
                duration_ms INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                tool_json TEXT NOT NULL,
                UNIQUE(run_id, tool_result_id),
                UNIQUE(run_id, sequence_number)
            );
            CREATE TABLE evidence (
                evidence_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                source_json TEXT NOT NULL,
                tool_result_source_id TEXT,
                model_call_source_id TEXT,
                request_source_id TEXT,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                UNIQUE(run_id, sequence_number),
                FOREIGN KEY(run_id, tool_result_source_id) REFERENCES tool_results(run_id, tool_result_id),
                FOREIGN KEY(run_id, model_call_source_id) REFERENCES model_calls(run_id, call_id)
            );
            CREATE TABLE model_calls (
                call_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                success INTEGER NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                reasoning_tokens INTEGER NOT NULL,
                error_code TEXT,
                attempt_number INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                model_call_json TEXT NOT NULL,
                UNIQUE(run_id, call_id),
                UNIQUE(run_id, sequence_number)
            );
            CREATE TABLE evaluation_results (
                run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                verdict TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                evaluation_json TEXT NOT NULL
            );",
        )
        .map_err(|_| migration_error())
}

fn apply_migration_v2(transaction: &Transaction<'_>) -> Result<(), RunServiceError> {
    transaction.execute_batch(
        "ALTER TABLE model_calls ADD COLUMN api_response_model TEXT;
         ALTER TABLE model_calls ADD COLUMN actual_provider TEXT;
         ALTER TABLE model_calls ADD COLUMN quantization TEXT;
         ALTER TABLE model_calls ADD COLUMN prompt_id TEXT;
         ALTER TABLE model_calls ADD COLUMN prompt_version INTEGER;
         ALTER TABLE model_calls ADD COLUMN prompt_hash TEXT;
         ALTER TABLE model_calls ADD COLUMN usage_reported INTEGER NOT NULL DEFAULT 0;
         CREATE TABLE experiments (
            experiment_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            started_at_ms INTEGER,
            completed_at_ms INTEGER,
            observed_bottleneck TEXT NOT NULL DEFAULT '',
            failure_message TEXT,
            experiment_json TEXT NOT NULL
         );
         CREATE INDEX experiments_created_idx ON experiments(created_at_ms DESC);
         CREATE TABLE prompt_versions (
            prompt_id TEXT NOT NULL,
            prompt_version INTEGER NOT NULL,
            prompt_hash TEXT NOT NULL,
            redacted_text TEXT NOT NULL,
            prompt_json TEXT NOT NULL,
            PRIMARY KEY(prompt_id, prompt_version, prompt_hash)
         );
         CREATE TABLE experiment_configs (
            experiment_id TEXT PRIMARY KEY REFERENCES experiments(experiment_id) ON DELETE CASCADE,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            provider_route TEXT NOT NULL,
            prompt_id TEXT NOT NULL,
            prompt_version INTEGER NOT NULL,
            prompt_hash TEXT NOT NULL,
            tool_schema_version TEXT NOT NULL,
            config_json TEXT NOT NULL
         );
         CREATE TABLE pricing_snapshots (
            experiment_id TEXT PRIMARY KEY REFERENCES experiments(experiment_id) ON DELETE CASCADE,
            currency TEXT NOT NULL,
            input_cost_per_million REAL,
            output_cost_per_million REAL,
            reasoning_cost_per_million REAL,
            source TEXT NOT NULL,
            captured_at_ms INTEGER NOT NULL,
            pricing_json TEXT NOT NULL
         );
         CREATE TABLE experiment_cases (
            case_id TEXT NOT NULL,
            experiment_id TEXT NOT NULL REFERENCES experiments(experiment_id) ON DELETE CASCADE,
            case_kind TEXT NOT NULL,
            title TEXT NOT NULL,
            sequence_number INTEGER NOT NULL,
            case_json TEXT NOT NULL,
            PRIMARY KEY(experiment_id, case_id)
         );
         CREATE TABLE experiment_runs (
            experiment_id TEXT NOT NULL REFERENCES experiments(experiment_id) ON DELETE CASCADE,
            case_id TEXT NOT NULL,
            repetition INTEGER NOT NULL,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            composite_success INTEGER NOT NULL,
            run_analysis_json TEXT NOT NULL,
            PRIMARY KEY(experiment_id, case_id, repetition),
            UNIQUE(experiment_id, run_id),
            FOREIGN KEY(experiment_id, case_id) REFERENCES experiment_cases(experiment_id, case_id)
         );
         CREATE TABLE experiment_summaries (
            experiment_id TEXT PRIMARY KEY REFERENCES experiments(experiment_id) ON DELETE CASCADE,
            total_runs INTEGER NOT NULL,
            successful_runs INTEGER NOT NULL,
            success_rate REAL NOT NULL,
            summary_json TEXT NOT NULL
         );
         CREATE TABLE failure_categories (
            experiment_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            category TEXT NOT NULL,
            PRIMARY KEY(experiment_id, run_id, category),
            FOREIGN KEY(experiment_id, run_id) REFERENCES experiment_runs(experiment_id, run_id) ON DELETE CASCADE
         );"
    ).map_err(|_| migration_error())
}

fn apply_migration_v3(transaction: &Transaction<'_>) -> Result<(), RunServiceError> {
    transaction
        .execute_batch(
            "CREATE TABLE recon_snapshots (
                run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                snapshot_json TEXT NOT NULL
            );",
        )
        .map_err(|_| migration_error())
}

fn save_task(transaction: &Transaction<'_>, record: &RunRecord) -> Result<(), RunServiceError> {
    transaction
        .execute(
            "INSERT INTO tasks(task_id, schema_version, title, scope_json, allowed_tools_json, budget_json, created_at_ms, task_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(task_id) DO UPDATE SET schema_version=excluded.schema_version, title=excluded.title,
             scope_json=excluded.scope_json, allowed_tools_json=excluded.allowed_tools_json,
             budget_json=excluded.budget_json, task_json=excluded.task_json",
            params![
                record.task.id.0,
                i64::from(record.task.schema_version),
                record.task.objective,
                encode(&record.task.scope)?,
                encode(&record.task.available_tools)?,
                encode(&record.task.budget)?,
                to_i64(record.run.created_at_ms),
                encode(&record.task)?,
            ],
        )
        .map(|_| ())
        .map_err(|_| database_write_error())
}

fn save_run(transaction: &Transaction<'_>, record: &RunRecord) -> Result<(), RunServiceError> {
    let failure = record
        .events
        .iter()
        .rev()
        .find_map(|event| match &event.kind {
            RunEventKind::RunFailed { error } => Some(error),
            _ => None,
        });
    transaction
        .execute(
            "INSERT INTO runs(run_id, task_id, status, created_at_ms, started_at_ms, finished_at_ms,
             usage_json, failure_json, final_output_json, task_json, run_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(run_id) DO UPDATE SET status=excluded.status, started_at_ms=excluded.started_at_ms,
             finished_at_ms=excluded.finished_at_ms, usage_json=excluded.usage_json,
             failure_json=excluded.failure_json, final_output_json=excluded.final_output_json,
             task_json=excluded.task_json, run_json=excluded.run_json",
            params![
                record.run.id.0,
                record.run.task_id.0,
                enum_text(&record.run.status)?,
                to_i64(record.run.created_at_ms),
                record.run.started_at_ms.map(to_i64),
                record.run.ended_at_ms.map(to_i64),
                encode(&record.run.usage)?,
                encode_option(failure)?,
                encode_option(record.run.final_output.as_ref())?,
                encode(&record.task)?,
                encode(&record.run)?,
            ],
        )
        .map(|_| ())
        .map_err(|_| database_write_error())
}

fn replace_events(
    transaction: &Transaction<'_>,
    record: &RunRecord,
) -> Result<(), RunServiceError> {
    transaction
        .execute(
            "DELETE FROM run_events WHERE run_id=?1",
            params![record.run.id.0],
        )
        .map_err(|_| database_write_error())?;
    for (sequence, event) in record.events.iter().enumerate() {
        transaction.execute(
            "INSERT INTO run_events(event_id, run_id, event_kind, timestamp_ms, payload_json, sequence_number, event_json) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![event.id.0, record.run.id.0, event_kind(&event.kind), to_i64(event.timestamp_ms), encode(&event.kind)?, sequence as i64, encode(event)?],
        ).map_err(|_| database_write_error())?;
    }
    Ok(())
}

fn replace_tool_results(
    transaction: &Transaction<'_>,
    record: &RunRecord,
) -> Result<(), RunServiceError> {
    transaction
        .execute(
            "DELETE FROM tool_results WHERE run_id=?1",
            params![record.run.id.0],
        )
        .map_err(|_| database_write_error())?;
    for (sequence, result) in record.tool_results.iter().enumerate() {
        transaction.execute(
            "INSERT INTO tool_results(tool_result_id,run_id,tool_name,success,data_json,error_json,duration_ms,sequence_number,tool_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![result.id.0, record.run.id.0, result.tool_name, result.success, encode(&result.data)?, encode_option(result.error.as_ref())?, to_i64(result.duration_ms), sequence as i64, encode(result)?],
        ).map_err(|_| database_write_error())?;
    }
    Ok(())
}

fn replace_evidence(
    transaction: &Transaction<'_>,
    record: &RunRecord,
) -> Result<(), RunServiceError> {
    transaction
        .execute(
            "DELETE FROM evidence WHERE run_id=?1",
            params![record.run.id.0],
        )
        .map_err(|_| database_write_error())?;
    for (sequence, evidence) in record.evidence.iter().enumerate() {
        let (tool_result_source_id, model_call_source_id, request_source_id) =
            match &evidence.source {
                EvidenceSource::ToolResult { tool_result_id } => {
                    (Some(tool_result_id.0.as_str()), None, None)
                }
                EvidenceSource::ModelCall { model_call_id } => {
                    (None, Some(model_call_id.as_str()), None)
                }
                EvidenceSource::Request { request_id } => (None, None, Some(request_id.as_str())),
                EvidenceSource::Manual { .. } => (None, None, None),
            };
        transaction.execute(
            "INSERT INTO evidence(evidence_id,run_id,source_json,tool_result_source_id,model_call_source_id,request_source_id,title,summary,metadata_json,created_at_ms,sequence_number,evidence_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![evidence.id.0, record.run.id.0, encode(&evidence.source)?, tool_result_source_id, model_call_source_id, request_source_id, evidence.description, evidence.value_or_excerpt, "{}", to_i64(evidence.recorded_at_ms), sequence as i64, encode(evidence)?],
        ).map_err(|_| database_write_error())?;
    }
    Ok(())
}

fn replace_model_calls(
    transaction: &Transaction<'_>,
    record: &RunRecord,
) -> Result<(), RunServiceError> {
    transaction
        .execute(
            "DELETE FROM model_calls WHERE run_id=?1",
            params![record.run.id.0],
        )
        .map_err(|_| database_write_error())?;
    for (sequence, call) in record.model_calls.iter().enumerate() {
        transaction.execute(
            "INSERT INTO model_calls(call_id,run_id,provider,model,started_at_ms,duration_ms,success,input_tokens,output_tokens,reasoning_tokens,error_code,attempt_number,sequence_number,model_call_json,api_response_model,actual_provider,quantization,prompt_id,prompt_version,prompt_hash,usage_reported) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
            params![call.id, record.run.id.0, enum_text(&call.provider)?, call.model, to_i64(call.started_at_ms), to_i64(call.duration_ms), call.success, to_i64(call.input_tokens), to_i64(call.output_tokens), to_i64(call.reasoning_tokens), call.error.as_ref().map(|error| error.code.clone()), to_i64(call.attempt_number), sequence as i64, encode(call)?, call.api_response_model, call.actual_provider, call.quantization, call.prompt_id, i64::from(call.prompt_version), call.prompt_hash, call.usage_reported],
        ).map_err(|_| database_write_error())?;
    }
    Ok(())
}

fn replace_evaluation(
    transaction: &Transaction<'_>,
    record: &RunRecord,
) -> Result<(), RunServiceError> {
    transaction
        .execute(
            "DELETE FROM evaluation_results WHERE run_id=?1",
            params![record.run.id.0],
        )
        .map_err(|_| database_write_error())?;
    if let Some(evaluation) = &record.run.evaluation {
        let reasons = serde_json::json!({"success": evaluation.success_reasons, "failure": evaluation.failure_reasons});
        transaction.execute(
            "INSERT INTO evaluation_results(run_id,verdict,reasons_json,metadata_json,created_at_ms,evaluation_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![record.run.id.0, enum_text(&evaluation.verdict)?, reasons.to_string(), "{}", to_i64(evaluation.evaluated_at_ms), encode(evaluation)?],
        ).map_err(|_| database_write_error())?;
    }
    Ok(())
}

fn replace_recon_snapshot(
    transaction: &Transaction<'_>,
    record: &RunRecord,
) -> Result<(), RunServiceError> {
    transaction
        .execute(
            "INSERT INTO recon_snapshots(run_id, snapshot_json) VALUES(?1, ?2)
             ON CONFLICT(run_id) DO UPDATE SET snapshot_json=excluded.snapshot_json",
            params![record.run.id.0, encode(&record.recon_snapshot)?],
        )
        .map(|_| ())
        .map_err(|_| database_write_error())
}

fn load_json_rows<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    run_id: &str,
) -> Result<Vec<T>, RunServiceError> {
    let mut statement = connection.prepare(sql).map_err(|_| database_read_error())?;
    let rows = statement
        .query_map(params![run_id], |row| row.get::<_, String>(0))
        .map_err(|_| database_read_error())?;
    let mut values = Vec::new();
    for row in rows {
        values.push(decode(&row.map_err(|_| database_read_error())?)?);
    }
    Ok(values)
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<String, RunServiceError> {
    serde_json::to_string(value).map_err(|_| serialization_error())
}

fn encode_option<T: Serialize>(value: Option<&T>) -> Result<Option<String>, RunServiceError> {
    value.map(encode).transpose()
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<T, RunServiceError> {
    serde_json::from_str(value).map_err(|_| serialization_error())
}

fn enum_text<T: Serialize>(value: &T) -> Result<String, RunServiceError> {
    encode(value).map(|text| text.trim_matches('"').to_string())
}

fn event_kind(kind: &RunEventKind) -> &'static str {
    match kind {
        RunEventKind::RunCreated { .. } => "run_created",
        RunEventKind::RunStarted { .. } => "run_started",
        RunEventKind::ModelCalled { .. } => "model_called",
        RunEventKind::ActionReceived { .. } => "action_received",
        RunEventKind::ActionRejected { .. } => "action_rejected",
        RunEventKind::ToolStarted { .. } => "tool_started",
        RunEventKind::ToolCompleted { .. } => "tool_completed",
        RunEventKind::EvidenceRecorded { .. } => "evidence_recorded",
        RunEventKind::ScopeBlocked { .. } => "scope_blocked",
        RunEventKind::BudgetExhausted { .. } => "budget_exhausted",
        RunEventKind::RunCompleted { .. } => "run_completed",
        RunEventKind::RunFailed { .. } => "run_failed",
        RunEventKind::RunCancelled { .. } => "run_cancelled",
        RunEventKind::EvaluationCompleted { .. } => "evaluation_completed",
    }
}

fn to_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn database_lock_error() -> RunServiceError {
    RunServiceError::new(
        RunServiceErrorCode::DatabaseTransactionFailed,
        "The database connection is unavailable.",
    )
}
fn database_read_error() -> RunServiceError {
    RunServiceError::new(
        RunServiceErrorCode::DatabaseReadFailed,
        "Unable to read persisted HexHunt data.",
    )
}
fn database_write_error() -> RunServiceError {
    RunServiceError::new(
        RunServiceErrorCode::DatabaseWriteFailed,
        "Unable to persist HexHunt data.",
    )
}
fn migration_error() -> RunServiceError {
    RunServiceError::new(
        RunServiceErrorCode::DatabaseMigrationFailed,
        "Unable to apply the HexHunt database migration.",
    )
}
fn serialization_error() -> RunServiceError {
    RunServiceError::new(
        RunServiceErrorCode::PersistenceSerializationFailed,
        "Unable to serialize or deserialize persisted HexHunt data.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{
            FinalOutput, FinalOutputStatus, ReconAsset, ReconAssetId, ReconAssetKind,
            ReconConfidence, ReconScopeClassification, RunService, TaskBudget, TaskId,
            CORE_SCHEMA_VERSION,
        },
        scope_guard::ScopeProject,
    };
    use std::sync::Arc;
    use uuid::Uuid;

    fn task() -> Task {
        Task {
            schema_version: CORE_SCHEMA_VERSION,
            id: TaskId("task-recon-persistence".into()),
            objective: "Preserve the Recon graph.".into(),
            primary_target: "https://example.test".into(),
            scope: ScopeProject {
                id: "scope-recon-persistence".into(),
                allowed_domains: vec!["example.test".into()],
                excluded_domains: vec![],
                allowed_ports: vec![443],
                request_rate: 1,
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
            available_tools: vec![],
            memory_policy: Default::default(),
        }
    }

    #[test]
    fn recon_snapshot_survives_sqlite_reopen() {
        let directory = std::env::temp_dir().join(format!("hexhunt-recon-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("runs.sqlite3");
        let run_id;

        {
            let repository = Arc::new(SqliteRunRepository::open(&path).unwrap());
            let service = RunService::with_repository(repository).unwrap();
            let run = service.create_run(task()).unwrap();
            run_id = run.id.clone();
            service.start_run(&run.id).unwrap();
            service
                .append_recon_asset(
                    &run.id,
                    ReconAsset {
                        schema_version: CORE_SCHEMA_VERSION,
                        id: ReconAssetId("asset-root".into()),
                        kind: ReconAssetKind::RootDomain,
                        canonical_value: "example.test".into(),
                        display_name: None,
                        scope: ReconScopeClassification::InScope,
                        scope_reason: "Authorized target.".into(),
                        confidence: ReconConfidence::Confirmed,
                        first_seen_at_ms: 1,
                        last_seen_at_ms: 1,
                        tags: vec![],
                    },
                )
                .unwrap();
            service
                .complete_run(
                    &run.id,
                    FinalOutput {
                        schema_version: CORE_SCHEMA_VERSION,
                        status: FinalOutputStatus::Completed,
                        answer: "Recon state saved.".into(),
                        evidence_ids: vec![],
                        limitations: vec![],
                    },
                )
                .unwrap();
        }

        {
            let repository = Arc::new(SqliteRunRepository::open(&path).unwrap());
            let service = RunService::with_repository(repository).unwrap();
            let snapshot = service.get_recon_snapshot(&run_id).unwrap();
            assert_eq!(snapshot.assets.len(), 1);
            assert_eq!(snapshot.assets[0].canonical_value, "example.test");
        }

        std::fs::remove_dir_all(directory).unwrap();
    }
}
