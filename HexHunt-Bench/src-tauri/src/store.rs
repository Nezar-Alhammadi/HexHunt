use crate::bench::BenchRunResult;
use rusqlite::{params, Connection};
use std::{path::Path, sync::Mutex};

pub struct BenchStore {
    connection: Mutex<Connection>,
}

impl BenchStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE IF NOT EXISTS bench_results (
                    result_id TEXT PRIMARY KEY,
                    created_at_ms INTEGER NOT NULL,
                    case_id TEXT NOT NULL,
                    variant INTEGER NOT NULL,
                    passed INTEGER NOT NULL,
                    score REAL NOT NULL,
                    result_json TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS bench_results_created_idx
                    ON bench_results(created_at_ms DESC);",
            )
            .map_err(|error| error.to_string())?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn save(&self, result: &BenchRunResult) -> Result<(), String> {
        let json = serde_json::to_string(result).map_err(|error| error.to_string())?;
        self.connection
            .lock()
            .map_err(|_| "BENCH_STORE_LOCK_FAILED".to_string())?
            .execute(
                "INSERT INTO bench_results(result_id,created_at_ms,case_id,variant,passed,score,result_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    result.result_id,
                    result.created_at_ms as i64,
                    result.case_id,
                    i64::from(result.variant),
                    result.passed,
                    result.score,
                    json
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list(&self, limit: usize) -> Result<Vec<BenchRunResult>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "BENCH_STORE_LOCK_FAILED".to_string())?;
        let mut statement = connection
            .prepare(
                "SELECT result_json FROM bench_results
                 ORDER BY created_at_ms DESC LIMIT ?1",
            )
            .map_err(|error| error.to_string())?;
        let results = statement
            .query_map([limit.min(500) as i64], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .map(|row| {
                row.map_err(|error| error.to_string()).and_then(|json| {
                    serde_json::from_str(&json).map_err(|error| error.to_string())
                })
            })
            .collect();
        results
    }
}
