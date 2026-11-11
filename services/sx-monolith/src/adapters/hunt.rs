//! Hunt adapter (P3-006).
//!
//! Wires [`sx_hunt::NullHuntService`] behind the [`HuntPort`] HTTP trait.
//!
//! ## Topology
//!
//! ```text
//!     POST /v1/hunt/query
//!             |
//!             v
//!     ┌──────────────────┐
//!     │  HuntAdapter     │ ── pulls tenant_id from caller's JWT claims
//!     └──────────────────┘
//!             |
//!             v
//!     ┌──────────────────┐
//!     │  NullHuntService │ ── parser → compiler → executor → audit hook
//!     └──────────────────┘
//!             |
//!             v
//!     ┌──────────────────┐
//!     │  NullExecutor    │ ── in-memory; production wiring lands when the
//!     └──────────────────┘    sx-intel-ioc ClickHouse HTTP client is
//!                             plugged in via a `HuntExecutor` impl.
//! ```
//!
//! ## Why a Null executor
//!
//! The hunt crate compiles to ClickHouse parameterised SQL, but the
//! sibling `sx-intel-ioc::clickhouse_http` client is wired into the
//! existing IOC ingest path on a different lifecycle. Until the shared
//! HTTP client is exposed to the monolith composition root, the
//! adapter installs a `NullExecutor` that returns an empty row set and
//! records every dispatched query for observability. The compiler
//! still produces the wire-ready parameterised SQL (so the audit trail
//! and tenant-isolation contract are fully exercised).

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{HuntPort, HuntPortError};
use sx_api::view::hunt_view::HuntQueryResponse;
use sx_hunt::{
    AuditHook, HuntError, HuntExecutor, HuntResult, HuntService, InMemoryAuditHook, NullExecutor,
    NullHuntService,
};

/// Bundle handed to the composition root.
#[derive(Clone)]
pub(crate) struct HuntBundle {
    /// HTTP-facing port installed onto `AppState`.
    pub hunt: Arc<dyn HuntPort>,
    /// Shared audit hook — exposed so a future hookup to the persistent
    /// audit recorder can read every recorded entry. The in-memory hook
    /// also gives the integration tests a deterministic verification
    /// surface.
    #[allow(dead_code)] // wired when sx-audit recorder is plumbed
    pub audit: Arc<InMemoryAuditHook>,
}

impl std::fmt::Debug for HuntBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HuntBundle").finish_non_exhaustive()
    }
}

/// Build the hunt bundle.
///
/// Pure (no I/O); safe to call synchronously from `build_app_state`.
pub(crate) fn build() -> HuntBundle {
    let executor: Arc<dyn HuntExecutor> = Arc::new(NullExecutor::new());
    let audit_inner: Arc<InMemoryAuditHook> = Arc::new(InMemoryAuditHook::default());
    let audit: Arc<dyn AuditHook> = Arc::clone(&audit_inner) as Arc<dyn AuditHook>;
    let svc = Arc::new(NullHuntService::new(executor, audit));
    let hunt: Arc<dyn HuntPort> = Arc::new(HuntAdapter { svc });
    HuntBundle {
        hunt,
        audit: audit_inner,
    }
}

/// HTTP-facing adapter — translates between the `sx_api` wire types and
/// the in-process `sx_hunt` service.
#[derive(Clone)]
struct HuntAdapter {
    svc: Arc<NullHuntService>,
}

impl std::fmt::Debug for HuntAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HuntAdapter").finish_non_exhaustive()
    }
}

#[async_trait]
impl HuntPort for HuntAdapter {
    async fn query(
        &self,
        tenant_id: &str,
        user_id: &str,
        raw_query: &str,
    ) -> Result<HuntQueryResponse, HuntPortError> {
        if tenant_id.is_empty() {
            return Err(HuntPortError::Invalid("tenant_id is empty".into()));
        }
        if user_id.is_empty() {
            return Err(HuntPortError::Invalid("user_id is empty".into()));
        }
        if raw_query.trim().is_empty() {
            return Err(HuntPortError::Invalid("query is empty".into()));
        }
        match self.svc.run(tenant_id, user_id, raw_query).await {
            Ok(result) => Ok(project(result)),
            Err(HuntError::Parse(e)) => Err(HuntPortError::Invalid(format!("parse: {e}"))),
            Err(HuntError::Compile(e)) => Err(HuntPortError::Invalid(format!("compile: {e}"))),
            Err(HuntError::Exec(e)) => Err(HuntPortError::Dependency(format!("exec: {e}"))),
        }
    }
}

/// Project an in-process [`HuntResult`] onto the wire DTO.
fn project(r: HuntResult) -> HuntQueryResponse {
    let row_count = r.rows.len();
    HuntQueryResponse {
        rows: r.rows,
        compiled_sql: r.compiled_sql,
        table: r.table,
        row_count,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::literal_string_with_formatting_args
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn happy_path_returns_empty_rows_and_compiled_sql() {
        let bundle = build();
        let resp = bundle
            .hunt
            .query(
                "tenant-a",
                "alice",
                "events_raw | top 5 by severity_id desc",
            )
            .await
            .expect("ok");
        assert_eq!(resp.row_count, 0);
        assert!(resp.compiled_sql.contains("tenant_id = {tenant:String}"));
        assert!(resp
            .compiled_sql
            .contains("ORDER BY severity_id DESC LIMIT 5"));
        assert_eq!(resp.table, "events_raw");
    }

    #[tokio::test]
    async fn parse_error_surfaces_as_invalid() {
        let bundle = build();
        let err = bundle
            .hunt
            .query(
                "tenant-a",
                "alice",
                "events_raw | wherrre user_name == \"a\"",
            )
            .await
            .expect_err("should fail");
        assert!(matches!(err, HuntPortError::Invalid(m) if m.contains("parse")));
    }

    #[tokio::test]
    async fn empty_tenant_rejected() {
        let bundle = build();
        let err = bundle
            .hunt
            .query("", "alice", "events_raw")
            .await
            .expect_err("should fail");
        assert!(matches!(err, HuntPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn empty_user_rejected() {
        let bundle = build();
        let err = bundle
            .hunt
            .query("tenant-a", "", "events_raw")
            .await
            .expect_err("should fail");
        assert!(matches!(err, HuntPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn empty_query_rejected() {
        let bundle = build();
        let err = bundle
            .hunt
            .query("tenant-a", "alice", "   ")
            .await
            .expect_err("should fail");
        assert!(matches!(err, HuntPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn injection_payload_does_not_appear_in_compiled_sql() {
        // Adversarial: classic SQL injection inside the analyst query.
        let bundle = build();
        let resp = bundle
            .hunt
            .query(
                "tenant-a",
                "mallory",
                r#"events_raw | where user_name == "alice'; DROP TABLE events_raw; --""#,
            )
            .await
            .expect("ok");
        assert!(!resp.compiled_sql.contains("DROP"));
        assert!(!resp.compiled_sql.contains("--"));
        // The literal value lives in the param map, not the SQL.
        assert!(resp.compiled_sql.contains("user_name = {p0:String}"));
    }

    #[tokio::test]
    async fn tenant_isolation_is_non_bypassable() {
        // Caller is `tenant-a` but the analyst writes a predicate
        // referencing `tenant-b`. The compiler MUST `AND`-inject the real
        // tenant binding so the analyst's predicate can never widen the
        // visibility scope.
        let bundle = build();
        let resp = bundle
            .hunt
            .query(
                "tenant-a",
                "mallory",
                r#"events_raw | where tenant_id == "tenant-b""#,
            )
            .await
            .expect("ok");
        // Both predicates appear; the synthetic one binds the real
        // tenant.
        assert!(resp.compiled_sql.contains("tenant_id = {tenant:String}"));
        assert!(resp.compiled_sql.contains("tenant_id = {p0:String}"));
    }

    #[tokio::test]
    async fn audit_records_every_query() {
        let bundle = build();
        let _ = bundle
            .hunt
            .query("tenant-a", "alice", "events_raw")
            .await
            .expect("ok");
        let _ = bundle
            .hunt
            .query("tenant-a", "alice", "events_raw | bogus stage here")
            .await
            .expect_err("parse should fail");
        let snap = bundle.audit.snapshot().await;
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].outcome, "ok");
        assert_eq!(snap[0].tenant_id, "tenant-a");
        assert_eq!(snap[1].outcome, "parse_error");
    }
}
