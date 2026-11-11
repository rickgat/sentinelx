//! Execution surface — the abstraction over the actual SQL backend.
//!
//! The crate keeps the executor minimal so it can be implemented over the
//! existing `sx-intel-ioc` `HttpClickHouseLink` without a dependency
//! cycle. The HTTP-side adapter (in `sx-monolith`) wraps that link in a
//! `HuntExecutor` and forwards the named parameters as
//! `param_<name>=<value>` query parameters.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::compile::CompiledQuery;
use crate::error::ExecError;

/// One row in the result set. Keys are column names; values are the raw
/// JSON values returned by `ClickHouse` in `JSONEachRow` mode.
pub type RowMap = BTreeMap<String, serde_json::Value>;

/// Executes a compiled query and returns the row map.
#[async_trait]
pub trait HuntExecutor: Send + Sync {
    /// Run the query. Implementations must:
    ///
    /// * Substitute the named parameters via `ClickHouse`'s `param_<name>`
    ///   query-string convention — **never** by string interpolation into
    ///   the SQL.
    /// * Cap the response size (the compiler already injects a `LIMIT`,
    ///   but defence in depth is recommended).
    /// * Surface transport / backend failures as [`ExecError`].
    async fn run(&self, query: &CompiledQuery) -> Result<Vec<RowMap>, ExecError>;
}

/// In-memory executor for tests. Returns the rows it was constructed with
/// and records the queries it received so tests can assert on the
/// emitted SQL + parameters.
#[derive(Debug, Default)]
pub struct NullExecutor {
    rows: Vec<RowMap>,
    history: tokio::sync::Mutex<Vec<CompiledQuery>>,
}

impl NullExecutor {
    /// Build an empty executor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an executor that returns `rows` for every call.
    #[must_use]
    pub fn with_rows(rows: Vec<RowMap>) -> Self {
        Self {
            rows,
            history: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Snapshot the queries the executor has seen, oldest-first.
    pub async fn history(&self) -> Vec<CompiledQuery> {
        self.history.lock().await.clone()
    }
}

#[async_trait]
impl HuntExecutor for NullExecutor {
    async fn run(&self, query: &CompiledQuery) -> Result<Vec<RowMap>, ExecError> {
        let mut h = self.history.lock().await;
        h.push(query.clone());
        Ok(self.rows.clone())
    }
}

/// Helper response envelope used by some tests and by the JSON view
/// layer. Lives here so callers can deserialise `ClickHouse`'s
/// `JSONEachRow` output trivially.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RowsResponse {
    /// Returned rows.
    pub rows: Vec<RowMap>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ast::{HuntQuery, Source};
    use crate::compile::compile;

    fn fake_query() -> CompiledQuery {
        let q = HuntQuery {
            source: Source {
                name: "events_raw".into(),
            },
            stages: Vec::new(),
        };
        compile(&q, "t").unwrap()
    }

    #[tokio::test]
    async fn null_executor_records_calls() {
        let exec = NullExecutor::new();
        let q = fake_query();
        let rows = exec.run(&q).await.unwrap();
        assert!(rows.is_empty());
        let hist = exec.history().await;
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].table, "events_raw");
    }

    #[tokio::test]
    async fn null_executor_returns_seeded_rows() {
        let mut row = RowMap::new();
        let _ = row.insert(
            "user_name".into(),
            serde_json::Value::String("alice".into()),
        );
        let exec = NullExecutor::with_rows(vec![row.clone()]);
        let q = fake_query();
        let rows = exec.run(&q).await.unwrap();
        assert_eq!(rows, vec![row]);
    }
}
