//! Concrete adapter behind [`sx_api::port::RemediationTrackingPort`].
//!
//! Backs the `PATCH` / `DELETE /v1/findings/{id}/remediation` endpoints
//! with a tenant-scoped in-memory store. The HTTP surface has already
//! validated the request shape (scheme = https, allow-listed host /
//! marker, at-least-one URL); the adapter is only responsible for parsing
//! tenant + finding ids into [`TenantId`] / [`FindingId`] value objects,
//! upserting the link, and minting the audit metadata (`linked_at`,
//! `linked_by`).
//!
//! ## Topology
//!
//! ```text
//!   HTTP PATCH ─▶ RemediationTrackingPort ─▶ InMemoryRemediationTracking
//!                                              (Mutex<HashMap<(TenantId, FindingId), RemediationLinkView>>)
//! ```
//!
//! The store is keyed by `(TenantId, FindingId)` so cross-tenant lookups
//! are impossible by construction — even a malformed handler that forgot
//! to pass the tenant cannot read another tenant's link, because no key
//! ever crosses that boundary.
//!
//! ## Pg vs. in-memory
//!
//! Phase-3.5+ wires the in-memory store unconditionally. A
//! Postgres-backed implementation will land later; until then operator
//! deployments restart with an empty link table, which is acceptable for
//! the demo / dev path that ships today.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::PgPool;
use sx_api::port::{Phase3PortError, RemediationTrackingPort};
use sx_api::view::finding_view::{RemediationLinkRequest, RemediationLinkView};
use sx_core::value_object::ids::{FindingId, TenantId};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Bundle exposing the single remediation-tracking trait object the
/// composition root stuffs into [`sx_api::AppState::remediation_tracking`].
///
/// Mirrors the [`crate::adapters::asset_write::AssetWriteBundle`] shape so
/// the wiring stays uniform across adapters.
pub(crate) struct RemediationTrackingBundle {
    /// Trait object plugged into [`sx_api::AppState`].
    pub tracking: Arc<dyn RemediationTrackingPort>,
}

impl std::fmt::Debug for RemediationTrackingBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemediationTrackingBundle")
            .finish_non_exhaustive()
    }
}

impl RemediationTrackingBundle {
    /// Build a fresh in-memory remediation-tracking bundle.
    ///
    /// Pure (no I/O) — safe to call synchronously from `build_app_state`.
    pub(crate) fn build() -> Self {
        let adapter = InMemoryRemediationTracking::default();
        Self {
            tracking: Arc::new(adapter),
        }
    }

    /// Build a durable Postgres-backed bundle. Selected by the composition
    /// root when the DB is enabled so remediation links (finding → PR/ticket)
    /// survive a restart instead of living in a throwaway map.
    pub(crate) fn build_pg(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            tracking: Arc::new(PgRemediationTracking {
                pool,
                stmt_timeout_ms,
            }),
        }
    }
}

/// In-memory implementation of [`RemediationTrackingPort`].
///
/// Stores the [`RemediationLinkView`] verbatim under a
/// `(TenantId, FindingId)` key. The mutex serialises both reads and
/// writes — acceptable for the dev / demo workload the bundle targets.
#[derive(Debug, Default)]
struct InMemoryRemediationTracking {
    store: Mutex<HashMap<(TenantId, FindingId), RemediationLinkView>>,
}

impl InMemoryRemediationTracking {
    /// Parse the tenant + finding id pair into the canonical value objects.
    ///
    /// Adapter-level parsing keeps the HTTP layer free of UUID handling
    /// for this trait. Both ids must be canonical UUIDs.
    fn parse_key(
        tenant_id: &str,
        finding_id: &str,
    ) -> Result<(TenantId, FindingId), Phase3PortError> {
        let tenant: TenantId = tenant_id
            .parse()
            .map_err(|e: sx_core::DomainError| Phase3PortError::Invalid(e.to_string()))?;
        let finding: FindingId = finding_id
            .parse()
            .map_err(|e: sx_core::DomainError| Phase3PortError::Invalid(e.to_string()))?;
        Ok((tenant, finding))
    }
}

#[async_trait]
impl RemediationTrackingPort for InMemoryRemediationTracking {
    async fn link(
        &self,
        tenant_id: &str,
        finding_id: &str,
        actor_id: &str,
        req: RemediationLinkRequest,
    ) -> Result<RemediationLinkView, Phase3PortError> {
        let key = Self::parse_key(tenant_id, finding_id)?;
        let linked_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| Phase3PortError::Internal(e.to_string()))?;
        let view = RemediationLinkView {
            pr_url: req.pr_url,
            ticket_url: req.ticket_url,
            comment: req.comment,
            linked_at,
            linked_by: actor_id.to_owned(),
        };
        let mut guard = self
            .store
            .lock()
            .map_err(|e| Phase3PortError::Internal(format!("mutex poisoned: {e}")))?;
        guard.insert(key, view.clone());
        Ok(view)
    }

    async fn unlink(&self, tenant_id: &str, finding_id: &str) -> Result<(), Phase3PortError> {
        let key = Self::parse_key(tenant_id, finding_id)?;
        let mut guard = self
            .store
            .lock()
            .map_err(|e| Phase3PortError::Internal(format!("mutex poisoned: {e}")))?;
        if guard.remove(&key).is_some() {
            Ok(())
        } else {
            Err(Phase3PortError::NotFound)
        }
    }
}

/// Durable Postgres-backed [`RemediationTrackingPort`].
///
/// The composition root built remediation-link tracking unconditionally
/// in-memory, so a finding→PR/ticket link created via `PATCH` was lost on a
/// monolith restart even on Postgres deployments. This persists the
/// [`RemediationLinkView`] as JSONB in `remediation_links`, keyed by
/// `(tenant_id, finding_id)`.
///
/// Both ids are bound explicitly on every statement, so — like the other
/// id-keyed stores in this program — the table is not under tenant RLS;
/// isolation is by the `(tenant_id, finding_id)` key.
struct PgRemediationTracking {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgRemediationTracking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgRemediationTracking")
            .finish_non_exhaustive()
    }
}

impl PgRemediationTracking {
    fn err(e: impl std::fmt::Display) -> Phase3PortError {
        Phase3PortError::Internal(format!("remediation tracking store: {e}"))
    }

    /// Parse + validate the id pair (shared with the in-memory adapter's
    /// contract) and return the UUIDs for binding.
    fn parse_uuids(
        tenant_id: &str,
        finding_id: &str,
    ) -> Result<(uuid::Uuid, uuid::Uuid), Phase3PortError> {
        // Reuse the value-object parse for identical validation semantics.
        let (tenant, finding) = InMemoryRemediationTracking::parse_key(tenant_id, finding_id)?;
        Ok((*tenant.as_uuid(), *finding.as_uuid()))
    }

    async fn begin(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, Phase3PortError> {
        let mut tx = self.pool.begin().await.map_err(Self::err)?;
        let bounded = self.stmt_timeout_ms.clamp(1, 60_000);
        sqlx::query(&format!("SET LOCAL statement_timeout = {bounded}"))
            .execute(&mut *tx)
            .await
            .map_err(Self::err)?;
        Ok(tx)
    }
}

#[async_trait]
impl RemediationTrackingPort for PgRemediationTracking {
    async fn link(
        &self,
        tenant_id: &str,
        finding_id: &str,
        actor_id: &str,
        req: RemediationLinkRequest,
    ) -> Result<RemediationLinkView, Phase3PortError> {
        let (tenant_uuid, finding_uuid) = Self::parse_uuids(tenant_id, finding_id)?;
        let linked_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| Phase3PortError::Internal(e.to_string()))?;
        let view = RemediationLinkView {
            pr_url: req.pr_url,
            ticket_url: req.ticket_url,
            comment: req.comment,
            linked_at,
            linked_by: actor_id.to_owned(),
        };
        let mut tx = self.begin().await?;
        // Upsert: a second link for the same finding replaces in place
        // (matching the in-memory `second_link_upserts_in_place` contract).
        sqlx::query(
            "INSERT INTO remediation_links (tenant_id, finding_id, aggregate, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (tenant_id, finding_id) DO UPDATE SET \
                 aggregate = EXCLUDED.aggregate, updated_at = now()",
        )
        .bind(tenant_uuid)
        .bind(finding_uuid)
        .bind(Json(&view))
        .execute(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        Ok(view)
    }

    async fn unlink(&self, tenant_id: &str, finding_id: &str) -> Result<(), Phase3PortError> {
        let (tenant_uuid, finding_uuid) = Self::parse_uuids(tenant_id, finding_id)?;
        let mut tx = self.begin().await?;
        let res =
            sqlx::query("DELETE FROM remediation_links WHERE tenant_id = $1 AND finding_id = $2")
                .bind(tenant_uuid)
                .bind(finding_uuid)
                .execute(&mut *tx)
                .await
                .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        if res.rows_affected() == 0 {
            return Err(Phase3PortError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";
    const FINDING: &str = "f0000001-0000-0000-0000-000000000000";
    const ACTOR: &str = "u-1";

    fn pr_only_request() -> RemediationLinkRequest {
        RemediationLinkRequest {
            pr_url: Some("https://github.com/acme/widgets/pull/42".into()),
            ticket_url: None,
            comment: Some("auto-patch".into()),
        }
    }

    fn ticket_only_request() -> RemediationLinkRequest {
        RemediationLinkRequest {
            pr_url: None,
            ticket_url: Some("https://acme.atlassian.net/browse/SEC-91".into()),
            comment: None,
        }
    }

    #[tokio::test]
    async fn pr_only_round_trip_succeeds() {
        let bundle = RemediationTrackingBundle::build();
        let view = bundle
            .tracking
            .link(TENANT, FINDING, ACTOR, pr_only_request())
            .await
            .expect("pr-only link ok");
        assert_eq!(
            view.pr_url.as_deref(),
            Some("https://github.com/acme/widgets/pull/42")
        );
        assert!(view.ticket_url.is_none());
        assert_eq!(view.linked_by, ACTOR);
        assert!(!view.linked_at.is_empty());
    }

    #[tokio::test]
    async fn ticket_only_round_trip_succeeds() {
        let bundle = RemediationTrackingBundle::build();
        let view = bundle
            .tracking
            .link(TENANT, FINDING, ACTOR, ticket_only_request())
            .await
            .expect("ticket-only link ok");
        assert!(view.pr_url.is_none());
        assert_eq!(
            view.ticket_url.as_deref(),
            Some("https://acme.atlassian.net/browse/SEC-91")
        );
    }

    #[tokio::test]
    async fn second_link_upserts_in_place() {
        let bundle = RemediationTrackingBundle::build();
        bundle
            .tracking
            .link(TENANT, FINDING, ACTOR, pr_only_request())
            .await
            .expect("first link ok");
        // Second link with a different URL replaces the first.
        let req2 = RemediationLinkRequest {
            pr_url: Some("https://gitlab.com/acme/widgets/-/merge_requests/7".into()),
            ticket_url: None,
            comment: Some("rebased".into()),
        };
        let view2 = bundle
            .tracking
            .link(TENANT, FINDING, ACTOR, req2)
            .await
            .expect("upsert ok");
        assert_eq!(
            view2.pr_url.as_deref(),
            Some("https://gitlab.com/acme/widgets/-/merge_requests/7")
        );
        // And unlink succeeds — the second view is present in the store.
        bundle
            .tracking
            .unlink(TENANT, FINDING)
            .await
            .expect("unlink ok");
    }

    #[tokio::test]
    async fn unlink_missing_returns_not_found() {
        let bundle = RemediationTrackingBundle::build();
        let err = bundle
            .tracking
            .unlink(TENANT, FINDING)
            .await
            .expect_err("must be NotFound");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn malformed_tenant_id_is_invalid() {
        let bundle = RemediationTrackingBundle::build();
        let err = bundle
            .tracking
            .link("not-a-uuid", FINDING, ACTOR, pr_only_request())
            .await
            .expect_err("must be Invalid");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn cross_tenant_lookup_is_isolated() {
        let bundle = RemediationTrackingBundle::build();
        let other_tenant = "02020202-0202-0202-0202-020202020202";
        bundle
            .tracking
            .link(TENANT, FINDING, ACTOR, pr_only_request())
            .await
            .expect("first tenant link ok");
        // Unlink under a different tenant must NOT see the first link.
        let err = bundle
            .tracking
            .unlink(other_tenant, FINDING)
            .await
            .expect_err("cross-tenant unlink must fail");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    /// Durability proof against a real Postgres: link → re-link (upsert) →
    /// *fresh store (restart-equivalent)* → the link survived (unlink finds
    /// it) → a second unlink returns NotFound.
    ///
    /// Gated on `TEST_DATABASE_URL` (silent no-op in CI; workspace live-DB
    /// fixture convention).
    #[tokio::test]
    async fn pg_remediation_link_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        // A unique finding id per run keeps the test independent of leftovers.
        let finding = uuid::Uuid::new_v4().to_string();

        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let store = PgRemediationTracking {
                pool,
                stmt_timeout_ms: 15_000,
            };
            let v1 = store
                .link(TENANT, &finding, ACTOR, pr_only_request())
                .await
                .expect("link");
            assert!(v1.pr_url.is_some());
            // Re-link upserts in place (one row per finding).
            store
                .link(TENANT, &finding, ACTOR, ticket_only_request())
                .await
                .expect("re-link upsert");
        }

        // Fresh store == a fresh process. In-memory state would be gone here.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let store = PgRemediationTracking {
                pool,
                stmt_timeout_ms: 15_000,
            };
            // The link survived the restart — unlink finds and removes it.
            store
                .unlink(TENANT, &finding)
                .await
                .expect("link survived restart");
            // Second unlink: gone.
            let err = store
                .unlink(TENANT, &finding)
                .await
                .expect_err("second unlink must be NotFound");
            assert!(matches!(err, Phase3PortError::NotFound));
        }
    }
}
