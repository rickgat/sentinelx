//! `ApprovalPort` implementations.
//!
//! Two flavours coexist:
//!
//! - [`InMemoryApprovalStore`] — process-local `Mutex<Vec<_>>` used by the
//!   monolith when `database.enabled = false`. Idempotency is enforced in
//!   Rust on the `(engagement_id, technique_id, approver_email)` tuple.
//! - [`PgApprovalAdapter`] — wraps `sx_storage::PgApprovalRepository` so
//!   the live `bas_approvals` table backs the port when
//!   `database.enabled = true`. Tenant isolation is enforced via Postgres
//!   Row-Level Security; idempotency is enforced at the database level via
//!   the `UNIQUE (engagement_id, technique_id, approver_email)` constraint.
//!
//! ## Shape bridge
//!
//! The [`sx_api::port::ApprovalPort`] trait does not carry a `tenant_id`
//! parameter — the controller calls `record(req)` / `list(engagement_id)`
//! with no out-of-band tenant context. The storage repository, by
//! contrast, requires a [`sx_storage::domain::value_object::TenantId`] on
//! every call (the RLS policy keys off `app.current_tenant_id`).
//!
//! [`PgApprovalAdapter`] therefore performs an `engagement_id → tenant_id`
//! resolution on each port call by invoking the
//! `sx_resolve_engagement_tenant(UUID)` SQL function (shipped in
//! migration `20260101000013_create_sx_resolve_engagement_tenant.sql`).
//! That function is declared `SECURITY DEFINER` with a pinned
//! `search_path`, so it executes with the privileges of its owner (the
//! migration runner, which owns `engagements`); the caller's session
//! keeps RLS enforced for everything else and no longer needs
//! `BYPASSRLS` / `row_security = off` to read the single owning
//! `tenant_id`. The function returns only the `tenant_id` UUID, so the
//! definer-bypass cannot leak any other column through the port surface.
//!
//! ## Error mapping
//!
//! `sx_storage::DomainError` → `sx_api::port::Phase3PortError`:
//!
//! | `DomainError` variant      | `Phase3PortError` variant                            |
//! |----------------------------|------------------------------------------------------|
//! | `Conflict(_)`              | `Invalid("approver already recorded")` (idempotency) |
//! | `NotFound { .. }`          | `NotFound`                                           |
//! | `InvalidValue(_)`          | `Invalid(_)`                                         |
//! | `InvariantViolation(_)`    | `Invalid(_)`                                         |
//! | `ScopeViolation(_)`        | `Forbidden(_)`                                       |
//! | `InvalidStateTransition`   | `Invalid(_)`                                         |
//! | `Repository(_)`            | `Dependency(_)`                                      |

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use sx_api::port::{ApprovalPort, Phase3PortError};
use sx_api::view::bas_view::{ApprovalView, RecordApprovalRequest};
use sx_storage::domain::error::DomainError;
use sx_storage::domain::value_object::{EngagementId, TenantId};
use sx_storage::repository::{ApprovalRepository, ApprovalRow, NewApproval, PgApprovalRepository};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// Canonical marker the controller looks for when translating a duplicate
/// approval into the HTTP `409 Conflict` envelope.
const DUPLICATE_APPROVER_MARKER: &str = "approver already recorded";

/// Process-local approval store.
#[derive(Debug, Default)]
pub(crate) struct InMemoryApprovalStore {
    rows: Mutex<Vec<ApprovalView>>,
}

impl InMemoryApprovalStore {
    /// Construct an empty store.
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

fn normalise_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

#[async_trait]
impl ApprovalPort for InMemoryApprovalStore {
    async fn record(&self, req: RecordApprovalRequest) -> Result<ApprovalView, Phase3PortError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|_| Phase3PortError::Internal("approvals lock poisoned".to_owned()))?;
        let approver = normalise_email(&req.approver_email);

        // Idempotency: refuse to insert a row that matches an existing
        // (engagement, technique, approver) triple. The controller maps
        // this marker into a 409 Conflict response.
        if guard.iter().any(|row| {
            row.engagement_id == req.engagement_id
                && row.technique_id == req.technique_id
                && row.approver_email == approver
        }) {
            return Err(Phase3PortError::Invalid(
                DUPLICATE_APPROVER_MARKER.to_owned(),
            ));
        }

        let view = ApprovalView {
            engagement_id: req.engagement_id,
            technique_id: req.technique_id,
            approver_email: approver,
            reason: req.reason,
            recorded_at: now_rfc3339(),
        };
        guard.push(view.clone());
        Ok(view)
    }

    async fn list(&self, engagement_id: &str) -> Result<Vec<ApprovalView>, Phase3PortError> {
        let guard = self
            .rows
            .lock()
            .map_err(|_| Phase3PortError::Internal("approvals lock poisoned".to_owned()))?;
        Ok(guard
            .iter()
            .filter(|row| row.engagement_id == engagement_id)
            .cloned()
            .collect())
    }

    async fn count_distinct_approvers(
        &self,
        engagement_id: &str,
        technique_id: &str,
    ) -> Result<u32, Phase3PortError> {
        let guard = self
            .rows
            .lock()
            .map_err(|_| Phase3PortError::Internal("approvals lock poisoned".to_owned()))?;
        let mut seen: Vec<&str> = Vec::new();
        for row in guard.iter() {
            if row.engagement_id == engagement_id
                && row.technique_id == technique_id
                && !seen.contains(&row.approver_email.as_str())
            {
                seen.push(row.approver_email.as_str());
            }
        }
        u32::try_from(seen.len())
            .map_err(|_| Phase3PortError::Internal("distinct approver count overflow".to_owned()))
    }
}

// ---------------------------------------------------------------------------
// Postgres-backed adapter
// ---------------------------------------------------------------------------

/// Adapter implementing [`ApprovalPort`] on top of `PgApprovalRepository`.
///
/// Bridges the shape mismatch between the `tenant_id`-less HTTP port and
/// the tenant-scoped storage repository (see the module-level docs).
pub(crate) struct PgApprovalAdapter {
    /// The wrapped storage repository (composes the actual SQL).
    repo: PgApprovalRepository,
    /// Direct pool handle, kept so the `engagement_id → tenant_id`
    /// resolver can issue its own (RLS-bypassing) transaction without
    /// going through the repository.
    pool: PgPool,
    /// Per-statement timeout, mirrored on every transaction the adapter
    /// opens itself (the resolver and the wrapping logic).
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgApprovalAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgApprovalAdapter")
            .field("stmt_timeout_ms", &self.stmt_timeout_ms)
            .finish_non_exhaustive()
    }
}

impl PgApprovalAdapter {
    /// Wrap a fresh pool. The constructor does not touch the network so it
    /// is safe to call at boot from a `pub(crate)` factory.
    pub(crate) fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        let repo = PgApprovalRepository::new(pool.clone(), stmt_timeout_ms);
        Self {
            repo,
            pool,
            stmt_timeout_ms,
        }
    }

    /// Resolve the tenant that owns `engagement_id` by invoking the
    /// `sx_resolve_engagement_tenant(UUID)` SQL function. The function
    /// is declared `SECURITY DEFINER` with a pinned `search_path`, so
    /// it executes with the privileges of its owner; the caller's
    /// session keeps RLS enforced, and the function exposes only the
    /// single `tenant_id` UUID, so the definer-bypass cannot leak any
    /// other column through the port surface.
    async fn resolve_tenant(&self, engagement_id: Uuid) -> Result<TenantId, Phase3PortError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Phase3PortError::Dependency(format!("approvals: pool: {e}")))?;

        let bounded = self.stmt_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt)
            .execute(&mut *tx)
            .await
            .map_err(|e| Phase3PortError::Dependency(format!("approvals: timeout set: {e}")))?;

        let row = sqlx::query("SELECT sx_resolve_engagement_tenant($1) AS tenant_id")
            .bind(engagement_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                Phase3PortError::Dependency(format!("approvals: engagement lookup: {e}"))
            })?;

        tx.commit()
            .await
            .map_err(|e| Phase3PortError::Dependency(format!("approvals: commit: {e}")))?;

        // The SQL function returns NULL when no engagement row matches,
        // and `fetch_optional` therefore still returns `Some(row)` — we
        // surface both shapes (no row, or NULL column) as `NotFound`.
        let row = row.ok_or(Phase3PortError::NotFound)?;
        let tenant_uuid: Option<Uuid> = row
            .try_get("tenant_id")
            .map_err(|e| Phase3PortError::Dependency(format!("approvals: decode: {e}")))?;
        let tenant_uuid = tenant_uuid.ok_or(Phase3PortError::NotFound)?;
        Ok(TenantId::from_uuid(tenant_uuid))
    }
}

/// Construct the Postgres-backed [`ApprovalPort`] trait object.
///
/// `statement_timeout_ms` mirrors the field on
/// [`sx_config::DatabaseConfig::statement_timeout_ms`] (a `u64`); the
/// adapter clamps it to `u32::MAX` when issuing `SET LOCAL statement_timeout`.
pub(crate) fn build_postgres(pool: PgPool, statement_timeout_ms: u64) -> Arc<dyn ApprovalPort> {
    Arc::new(PgApprovalAdapter::new(pool, statement_timeout_ms))
}

#[async_trait]
impl ApprovalPort for PgApprovalAdapter {
    async fn record(&self, req: RecordApprovalRequest) -> Result<ApprovalView, Phase3PortError> {
        let engagement_uuid = parse_engagement_id(&req.engagement_id)?;
        let tenant_id = self.resolve_tenant(engagement_uuid).await?;
        let new_row = NewApproval {
            tenant_id,
            engagement_id: EngagementId::from_uuid(engagement_uuid),
            technique_id: req.technique_id,
            approver_email: req.approver_email,
            reason: req.reason,
        };
        match self.repo.record(new_row).await {
            Ok(row) => Ok(row_to_view(&row)),
            Err(e) => Err(map_domain_for_record(e)),
        }
    }

    async fn list(&self, engagement_id: &str) -> Result<Vec<ApprovalView>, Phase3PortError> {
        let engagement_uuid = parse_engagement_id(engagement_id)?;
        let tenant_id = self.resolve_tenant(engagement_uuid).await?;
        let rows = self
            .repo
            .list_by_engagement(tenant_id, EngagementId::from_uuid(engagement_uuid))
            .await
            .map_err(map_domain)?;
        Ok(rows.iter().map(row_to_view).collect())
    }

    async fn count_distinct_approvers(
        &self,
        engagement_id: &str,
        technique_id: &str,
    ) -> Result<u32, Phase3PortError> {
        let engagement_uuid = parse_engagement_id(engagement_id)?;
        let tenant_id = self.resolve_tenant(engagement_uuid).await?;
        self.repo
            .count_distinct_approvers(
                tenant_id,
                EngagementId::from_uuid(engagement_uuid),
                technique_id,
            )
            .await
            .map_err(map_domain)
    }
}

/// Parse `engagement_id` as a UUID, mapping a malformed string onto
/// [`Phase3PortError::Invalid`].
fn parse_engagement_id(raw: &str) -> Result<Uuid, Phase3PortError> {
    Uuid::parse_str(raw).map_err(|e| Phase3PortError::Invalid(format!("engagement_id: {e}")))
}

/// Project a storage [`ApprovalRow`] into the wire [`ApprovalView`].
fn row_to_view(row: &ApprovalRow) -> ApprovalView {
    ApprovalView {
        engagement_id: row.engagement_id.as_uuid().to_string(),
        technique_id: row.technique_id.clone(),
        approver_email: row.approver_email.clone(),
        reason: row.reason.clone(),
        recorded_at: row.recorded_at.format(&Rfc3339).unwrap_or_default(),
    }
}

/// Map a [`DomainError`] from the storage repository onto a
/// [`Phase3PortError`] for the HTTP layer. See the module-level table.
fn map_domain(err: DomainError) -> Phase3PortError {
    match err {
        DomainError::NotFound { .. } => Phase3PortError::NotFound,
        DomainError::InvalidValue(msg) | DomainError::InvariantViolation(msg) => {
            Phase3PortError::Invalid(msg)
        }
        DomainError::ScopeViolation(msg) => Phase3PortError::Forbidden(msg),
        DomainError::InvalidStateTransition { from, to } => {
            Phase3PortError::Invalid(format!("invalid transition from {from} to {to}"))
        }
        DomainError::Conflict(msg) => Phase3PortError::Invalid(msg),
        DomainError::Repository(msg) => Phase3PortError::Dependency(msg),
    }
}

/// Variant of [`map_domain`] used by `record`: a `Conflict` from the
/// underlying repository is always the idempotency-constraint hit on
/// `(engagement_id, technique_id, approver_email)`, so we normalise the
/// message to the canonical marker the controller pattern-matches on.
fn map_domain_for_record(err: DomainError) -> Phase3PortError {
    match err {
        DomainError::Conflict(_) => Phase3PortError::Invalid(DUPLICATE_APPROVER_MARKER.to_owned()),
        other => map_domain(other),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn req(approver: &str) -> RecordApprovalRequest {
        RecordApprovalRequest {
            engagement_id: "11111111-2222-3333-4444-555555555555".into(),
            technique_id: "T1003".into(),
            approver_email: approver.into(),
            reason: "approved".into(),
        }
    }

    // -------------------------------------------------------------------
    // InMemory regressions (pinned by the existing wiring; included here
    // so the file's `cargo test` surface still covers them).
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn idempotent_on_duplicate_approver() {
        let store = InMemoryApprovalStore::new();
        store.record(req("Alice@Example.com")).await.unwrap();
        // Same approver (case-insensitive) on the same (engagement,
        // technique) is rejected with the canonical marker string.
        let err = store.record(req("alice@example.com")).await.unwrap_err();
        assert!(matches!(
            err,
            Phase3PortError::Invalid(ref m) if m == DUPLICATE_APPROVER_MARKER
        ));
    }

    #[tokio::test]
    async fn count_distinct_returns_two_for_two_approvers() {
        let store = InMemoryApprovalStore::new();
        store.record(req("alice@example.com")).await.unwrap();
        store.record(req("bob@example.com")).await.unwrap();
        let n = store
            .count_distinct_approvers("11111111-2222-3333-4444-555555555555", "T1003")
            .await
            .unwrap();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn list_filters_by_engagement() {
        let store = InMemoryApprovalStore::new();
        store.record(req("alice@example.com")).await.unwrap();
        let mut other = req("bob@example.com");
        other.engagement_id = "99999999-9999-9999-9999-999999999999".into();
        store.record(other).await.unwrap();

        let items = store
            .list("11111111-2222-3333-4444-555555555555")
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].approver_email, "alice@example.com");
    }

    // -------------------------------------------------------------------
    // PgApprovalAdapter / bridge unit tests
    // -------------------------------------------------------------------

    /// The constructor must NEVER touch the network. `PgPool::connect_lazy`
    /// returns a pool that defers the actual TCP handshake until the first
    /// query, which lets us verify the adapter just stores its inputs.
    ///
    /// The Tokio context is supplied so the `PgPool::Drop` path — which
    /// schedules a teardown task — finds a runtime; otherwise the test
    /// would panic at shutdown unrelated to the SUT.
    #[tokio::test]
    async fn pg_adapter_constructor_does_not_connect() {
        // `connect_lazy` accepts any well-formed URL; it does not validate
        // it can actually reach the server. Perfect for a constructor
        // smoke test that runs in offline CI.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/none")
            .expect("connect_lazy must not perform I/O");
        let port = build_postgres(pool, 1_500_u64);
        // Trait-object pointer: just verify we got an `Arc<dyn ApprovalPort>`
        // back. We can't call it (no DB); the test is a compile-time + ctor
        // existence check.
        let _: Arc<dyn ApprovalPort> = port;
    }

    /// Pins the `DomainError → Phase3PortError` mapping table documented
    /// at the top of this module.
    #[test]
    fn error_mapping_table_is_stable() {
        assert!(matches!(
            map_domain(DomainError::NotFound {
                entity: "x",
                id: "1".into(),
            }),
            Phase3PortError::NotFound,
        ));
        assert!(matches!(
            map_domain(DomainError::InvalidValue("bad".into())),
            Phase3PortError::Invalid(_),
        ));
        assert!(matches!(
            map_domain(DomainError::InvariantViolation("bad".into())),
            Phase3PortError::Invalid(_),
        ));
        assert!(matches!(
            map_domain(DomainError::ScopeViolation("nope".into())),
            Phase3PortError::Forbidden(_),
        ));
        assert!(matches!(
            map_domain(DomainError::InvalidStateTransition {
                from: "a".into(),
                to: "b".into(),
            }),
            Phase3PortError::Invalid(_),
        ));
        assert!(matches!(
            map_domain(DomainError::Conflict("dup".into())),
            Phase3PortError::Invalid(_),
        ));
        assert!(matches!(
            map_domain(DomainError::Repository("io".into())),
            Phase3PortError::Dependency(_),
        ));
    }

    /// `record` MUST normalise any `Conflict` from the underlying repo
    /// into the canonical "approver already recorded" marker — the
    /// controller pattern-matches on that exact string.
    #[test]
    fn record_normalises_conflict_to_canonical_marker() {
        let mapped = map_domain_for_record(DomainError::Conflict("23505: bas_approvals_…".into()));
        assert!(matches!(
            mapped,
            Phase3PortError::Invalid(ref m) if m == DUPLICATE_APPROVER_MARKER,
        ));
        // Non-conflict variants flow through `map_domain` unchanged.
        let nf = map_domain_for_record(DomainError::NotFound {
            entity: "Engagement",
            id: "x".into(),
        });
        assert!(matches!(nf, Phase3PortError::NotFound));
    }

    /// `parse_engagement_id` rejects malformed input as `Invalid(_)`. The
    /// controller relies on this for proper 400 responses.
    #[test]
    fn parse_engagement_id_rejects_garbage() {
        let err = parse_engagement_id("not-a-uuid").unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
        // Round-trips a valid uuid.
        let good = "11111111-2222-3333-4444-555555555555";
        let uuid = parse_engagement_id(good).unwrap();
        assert_eq!(uuid.to_string(), good);
    }

    /// `row_to_view` must project every field, formatting `recorded_at`
    /// as RFC3339. Pinned because the view shape is what the wire layer
    /// exposes verbatim.
    #[test]
    fn row_to_view_projects_every_field() {
        let now = OffsetDateTime::now_utc();
        let row = ApprovalRow {
            id: Uuid::now_v7(),
            tenant_id: TenantId::new(),
            engagement_id: EngagementId::new(),
            technique_id: "T1003".into(),
            approver_email: "alice@example.com".into(),
            reason: "ok".into(),
            recorded_at: now,
        };
        let view = row_to_view(&row);
        assert_eq!(view.engagement_id, row.engagement_id.as_uuid().to_string());
        assert_eq!(view.technique_id, "T1003");
        assert_eq!(view.approver_email, "alice@example.com");
        assert_eq!(view.reason, "ok");
        assert!(
            view.recorded_at.contains('T'),
            "recorded_at must be RFC3339, got: {}",
            view.recorded_at,
        );
    }

    /// In-memory regression: concurrent `record` + `count_distinct` calls
    /// must not deadlock and must converge on the correct count. Pins the
    /// existing wiring against accidental re-ordering of the Mutex
    /// acquisition.
    #[tokio::test]
    async fn concurrent_record_and_count_is_consistent() {
        let store = Arc::new(InMemoryApprovalStore::new());
        let approvers = ["a@x.com", "b@x.com", "c@x.com", "d@x.com"];
        let mut handles = Vec::new();
        for a in approvers {
            let s = Arc::clone(&store);
            handles.push(tokio::spawn(async move { s.record(req(a)).await }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }
        let n = store
            .count_distinct_approvers("11111111-2222-3333-4444-555555555555", "T1003")
            .await
            .unwrap();
        assert_eq!(n, 4);
    }
}
