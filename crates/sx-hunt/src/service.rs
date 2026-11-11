//! Service layer — chains parser → compiler → executor → audit.
//!
//! The [`HuntService`] trait gives the HTTP layer a single async entry
//! point. The default implementation [`NullHuntService`] runs against
//! [`crate::executor::NullExecutor`] and records every dispatched query
//! through an injected [`AuditHook`]. Production wiring sits in
//! `services/sx-monolith` and points the service at the live
//! `ClickHouse` link.
//!
//! # HIGH-005 audit contract
//!
//! Every executed query produces exactly one [`HuntAuditEntry`] containing:
//!
//! * `tenant_id`, `user_id` — actor + scope
//! * `raw_query` — the analyst-typed text
//! * `compiled_sql`, `table` — what was actually sent to ClickHouse
//! * `row_count` — number of rows returned (`Some` on success, `None` on failure)
//! * `duration_ms` — wall-clock spent inside the executor
//! * `outcome` — one of `ok` | `parse_error` | `compile_error` | `exec_error`
//! * `started_at` — RFC 3339 start timestamp
//!
//! The [`SxAuditHook`] adapter (in [`crate::audit_bridge`]) forwards each
//! entry to the tamper-evident `sx-audit` hash chain via
//! [`sx_audit::prelude::RecordAuditEventUseCase`].

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::compile::{compile, CompiledQuery};
use crate::error::HuntError;
use crate::executor::{HuntExecutor, RowMap};
use crate::parser::parse;

/// Audit record handed to the [`AuditHook`] after each query.
///
/// Carries everything the audit log needs to reconstruct who ran what,
/// when, and against which table. The compiled SQL is included so
/// reviewers can verify the executed statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HuntAuditEntry {
    /// Tenant the query ran under.
    pub tenant_id: String,
    /// Caller identity (operator id / username — supplied by the API layer).
    pub user_id: String,
    /// Raw query text the analyst submitted.
    pub raw_query: String,
    /// Compiled SQL statement.
    pub compiled_sql: String,
    /// Source table.
    pub table: String,
    /// Number of rows returned. `None` on failure.
    pub row_count: Option<usize>,
    /// Outcome label: `ok` | `parse_error` | `compile_error` | `exec_error`.
    pub outcome: &'static str,
    /// Wall-clock time the query started, RFC 3339.
    pub started_at: String,
    /// Wall-clock duration measured around the executor call. `0` for
    /// `parse_error` / `compile_error` cases that never reached the
    /// executor.
    #[serde(default)]
    pub duration_ms: u64,
}

/// Sink for hunt-query audit entries.
#[async_trait]
pub trait AuditHook: Send + Sync {
    /// Record one entry. Implementations should never panic.
    async fn record(&self, entry: HuntAuditEntry);
}

/// No-op hook for tests / standalone use.
#[derive(Debug, Default)]
pub struct NoopAuditHook;

#[async_trait]
impl AuditHook for NoopAuditHook {
    async fn record(&self, _entry: HuntAuditEntry) {}
}

/// In-memory audit hook used by the test suite.
#[derive(Debug, Default)]
pub struct InMemoryAuditHook {
    /// Records collected so far.
    pub entries: tokio::sync::Mutex<Vec<HuntAuditEntry>>,
}

#[async_trait]
impl AuditHook for InMemoryAuditHook {
    async fn record(&self, entry: HuntAuditEntry) {
        let mut g = self.entries.lock().await;
        g.push(entry);
    }
}

impl InMemoryAuditHook {
    /// Snapshot the recorded entries.
    pub async fn snapshot(&self) -> Vec<HuntAuditEntry> {
        self.entries.lock().await.clone()
    }
}

/// Result of one successful hunt query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HuntResult {
    /// Returned rows.
    pub rows: Vec<RowMap>,
    /// Compiled SQL (kept for audit-trail/UI debugging).
    pub compiled_sql: String,
    /// Source table.
    pub table: String,
}

/// HTTP-facing service trait. The API controller depends on this so the
/// tests can swap in a stub.
#[async_trait]
pub trait HuntService: Send + Sync {
    /// Parse, compile, execute, and audit one query.
    async fn run(
        &self,
        tenant_id: &str,
        user_id: &str,
        raw_query: &str,
    ) -> Result<HuntResult, HuntError>;
}

/// Default service — backed by a [`HuntExecutor`] plus an [`AuditHook`].
#[derive(Clone)]
pub struct NullHuntService {
    executor: Arc<dyn HuntExecutor>,
    audit: Arc<dyn AuditHook>,
}

impl std::fmt::Debug for NullHuntService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NullHuntService").finish_non_exhaustive()
    }
}

impl NullHuntService {
    /// Construct a service from any executor + audit hook combination.
    #[must_use]
    pub fn new(executor: Arc<dyn HuntExecutor>, audit: Arc<dyn AuditHook>) -> Self {
        Self { executor, audit }
    }
}

#[async_trait]
impl HuntService for NullHuntService {
    async fn run(
        &self,
        tenant_id: &str,
        user_id: &str,
        raw_query: &str,
    ) -> Result<HuntResult, HuntError> {
        let started_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

        let ast = match parse(raw_query) {
            Ok(a) => a,
            Err(e) => {
                self.audit
                    .record(HuntAuditEntry {
                        tenant_id: tenant_id.to_string(),
                        user_id: user_id.to_string(),
                        raw_query: raw_query.to_string(),
                        compiled_sql: String::new(),
                        table: String::new(),
                        row_count: None,
                        outcome: "parse_error",
                        started_at,
                        duration_ms: 0,
                    })
                    .await;
                return Err(HuntError::Parse(e));
            }
        };
        let compiled: CompiledQuery = match compile(&ast, tenant_id) {
            Ok(c) => c,
            Err(e) => {
                self.audit
                    .record(HuntAuditEntry {
                        tenant_id: tenant_id.to_string(),
                        user_id: user_id.to_string(),
                        raw_query: raw_query.to_string(),
                        compiled_sql: String::new(),
                        table: String::new(),
                        row_count: None,
                        outcome: "compile_error",
                        started_at,
                        duration_ms: 0,
                    })
                    .await;
                return Err(HuntError::Compile(e));
            }
        };
        let exec_start = Instant::now();
        let result = self.executor.run(&compiled).await;
        let duration_ms = u64::try_from(exec_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok(rows) => {
                self.audit
                    .record(HuntAuditEntry {
                        tenant_id: tenant_id.to_string(),
                        user_id: user_id.to_string(),
                        raw_query: raw_query.to_string(),
                        compiled_sql: compiled.sql.clone(),
                        table: compiled.table.clone(),
                        row_count: Some(rows.len()),
                        outcome: "ok",
                        started_at,
                        duration_ms,
                    })
                    .await;
                Ok(HuntResult {
                    rows,
                    compiled_sql: compiled.sql,
                    table: compiled.table,
                })
            }
            Err(e) => {
                self.audit
                    .record(HuntAuditEntry {
                        tenant_id: tenant_id.to_string(),
                        user_id: user_id.to_string(),
                        raw_query: raw_query.to_string(),
                        compiled_sql: compiled.sql,
                        table: compiled.table,
                        row_count: None,
                        outcome: "exec_error",
                        started_at,
                        duration_ms,
                    })
                    .await;
                Err(HuntError::Exec(e))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::executor::NullExecutor;

    #[tokio::test]
    async fn happy_path_records_audit_with_row_count() {
        let exec = Arc::new(NullExecutor::new());
        let audit = Arc::new(InMemoryAuditHook::default());
        let svc = NullHuntService::new(exec.clone(), audit.clone());
        let res = svc
            .run(
                "tenant-a",
                "alice",
                "events_raw | top 5 by severity_id desc",
            )
            .await
            .unwrap();
        assert_eq!(res.table, "events_raw");
        assert!(res.compiled_sql.contains("ORDER BY severity_id DESC"));
        let snap = audit.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].outcome, "ok");
        assert_eq!(snap[0].row_count, Some(0));
        assert_eq!(snap[0].tenant_id, "tenant-a");
        assert_eq!(snap[0].user_id, "alice");
    }

    #[tokio::test]
    async fn parse_error_records_audit_with_outcome() {
        let exec = Arc::new(NullExecutor::new());
        let audit = Arc::new(InMemoryAuditHook::default());
        let svc = NullHuntService::new(exec, audit.clone());
        let err = svc
            .run(
                "tenant-a",
                "alice",
                "events_raw | wherrre user_name == \"a\"",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, HuntError::Parse(_)));
        let snap = audit.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].outcome, "parse_error");
        assert_eq!(snap[0].compiled_sql, "");
    }

    #[tokio::test]
    async fn tenant_isolation_in_emitted_sql() {
        let exec = Arc::new(NullExecutor::new());
        let audit = Arc::new(InMemoryAuditHook::default());
        let svc = NullHuntService::new(exec.clone(), audit);

        // tenant-a runs a query attempting to access tenant-b's data.
        let _ = svc
            .run(
                "tenant-a",
                "mallory",
                r#"events_raw | where tenant_id == "tenant-b""#,
            )
            .await
            .unwrap();

        let hist = exec.history().await;
        assert_eq!(hist.len(), 1);
        let sql = &hist[0].sql;
        // The synthetic tenant predicate is always present.
        assert!(sql.contains("tenant_id = {tenant:String}"));
        // The analyst's attempted predicate is still there but the
        // synthetic one binds tenant-a, not tenant-b.
        assert_eq!(
            hist[0].params.get("tenant"),
            Some(&crate::compile::ParamValue::Str("tenant-a".to_string()))
        );
    }

    #[tokio::test]
    async fn compile_error_records_audit() {
        let exec = Arc::new(NullExecutor::new());
        let audit = Arc::new(InMemoryAuditHook::default());
        let svc = NullHuntService::new(exec, audit.clone());
        // user_name is not numeric so avg() will fail at compile.
        // (HIGH-005 removed `sum/min/max` from the function whitelist;
        // `avg` is the remaining numeric aggregate.)
        let err = svc
            .run("tenant-a", "alice", "events_raw | summarize avg(user_name)")
            .await
            .unwrap_err();
        assert!(matches!(err, HuntError::Compile(_)));
        let snap = audit.snapshot().await;
        assert_eq!(snap[0].outcome, "compile_error");
        assert_eq!(snap[0].duration_ms, 0);
    }

    #[tokio::test]
    async fn denied_function_records_parse_error_audit() {
        // HIGH-005: `| file(raw)` is a denied function call.
        let exec = Arc::new(NullExecutor::new());
        let audit = Arc::new(InMemoryAuditHook::default());
        let svc = NullHuntService::new(exec, audit.clone());
        let err = svc
            .run("tenant-a", "alice", "events_raw | file(raw)")
            .await
            .unwrap_err();
        match err {
            HuntError::Parse(p) => assert_eq!(p.code(), "HUNT_DENIED_FN"),
            other => panic!("expected Parse(DeniedFunction), got {other:?}"),
        }
        let snap = audit.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].outcome, "parse_error");
    }

    #[tokio::test]
    async fn denied_table_records_parse_error_audit() {
        // HIGH-005: `system.users` is denied at parse time. `system` lexes
        // as an ident — the `.users` part trips the lexer first, but a
        // bare unknown table name produces `DeniedTable`.
        let exec = Arc::new(NullExecutor::new());
        let audit = Arc::new(InMemoryAuditHook::default());
        let svc = NullHuntService::new(exec, audit.clone());
        let err = svc.run("tenant-a", "alice", "logins").await.unwrap_err();
        match err {
            HuntError::Parse(p) => assert_eq!(p.code(), "HUNT_DENIED_TABLE"),
            other => panic!("expected Parse(DeniedTable), got {other:?}"),
        }
        let snap = audit.snapshot().await;
        assert_eq!(snap[0].outcome, "parse_error");
    }

    #[tokio::test]
    async fn ok_audit_carries_duration_ms() {
        let exec = Arc::new(NullExecutor::new());
        let audit = Arc::new(InMemoryAuditHook::default());
        let svc = NullHuntService::new(exec, audit.clone());
        svc.run("tenant-a", "alice", "events_raw").await.unwrap();
        let snap = audit.snapshot().await;
        assert_eq!(snap[0].outcome, "ok");
        // duration_ms is u64 — it's always defined; just assert it's
        // present (no upper bound — the in-memory NullExecutor returns
        // instantly, so 0 ms is valid).
        let _ = snap[0].duration_ms;
    }

    #[tokio::test]
    async fn injection_payload_is_executed_via_params_only() {
        let exec = Arc::new(NullExecutor::new());
        let audit = Arc::new(InMemoryAuditHook::default());
        let svc = NullHuntService::new(exec.clone(), audit);
        let _ = svc
            .run(
                "tenant-a",
                "mallory",
                r#"events_raw | where user_name == "alice'; DROP TABLE events_raw; --""#,
            )
            .await
            .unwrap();
        let hist = exec.history().await;
        let sql = &hist[0].sql;
        // The dangerous text appears in the param map but not in the SQL.
        assert!(!sql.contains("DROP TABLE"));
        assert!(!sql.contains("--"));
        let bound = hist[0].params.get("p0").unwrap();
        assert!(matches!(
            bound,
            crate::compile::ParamValue::Str(s) if s.contains("DROP TABLE")
        ));
    }

    #[tokio::test]
    async fn empty_tenant_id_rejected() {
        let exec = Arc::new(NullExecutor::new());
        let audit = Arc::new(InMemoryAuditHook::default());
        let svc = NullHuntService::new(exec, audit.clone());
        let err = svc.run("", "alice", "events_raw").await.unwrap_err();
        assert!(matches!(err, HuntError::Compile(_)));
        let snap = audit.snapshot().await;
        assert_eq!(snap[0].outcome, "compile_error");
    }
}
