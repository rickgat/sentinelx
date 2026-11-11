//! P1-014 — per-tenant risk-model tuning adapter.
//!
//! Wires [`sx_risk::tenant_tuning::TenantRiskTuningService`] (the
//! orchestrator that owns the store, recompute queue, and audit sink)
//! behind the [`RiskTuningPort`] the API layer depends on.
//!
//! The current build instantiates the service against the in-memory
//! reference adapters shipped by `sx-risk` (the same three trait
//! objects the unit tests exercise). The Postgres-backed store and
//! Redis-backed recompute queue land in a follow-up pass; the trait
//! seams are designed so swapping them in is an `Arc::new(...)` change
//! at this composition root and nothing else.
//!
//! ## Audit
//!
//! The wrapped service drives the audit sink **after** the override is
//! persisted, so a failed write never produces a phantom diff. The
//! controller passes the bearer-less sub-claim (`AccessClaims::sub`) as
//! the audit actor — never the raw `Authorization` header.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::{RiskTuningPort, RiskTuningPortError};
use sx_api::view::risk_tuning_view::{EffectiveRiskConfigView, TenantRiskConfigView};
use sx_config::schema::risk_weights::RiskWeightsConfig;
use sx_config::schema::tenant_risk::{RiskThresholdsConfig, TenantRiskOverride};
use sx_risk::tenant_tuning::{
    in_memory_service, InMemoryAuditSink, InMemoryRecomputeQueue, InMemoryTuningStore,
    RecomputeQueue, TenantRiskTuningService, TenantTuningStore, TuningAuditSink,
};
use sx_risk::RiskError;

/// Build the in-memory-backed adapter. `defaults_weights` are the
/// process-wide composite weights captured at boot (typically from
/// `settings.risk.weights`); `defaults_thresholds` is the platform
/// score-band vector defined in `sentinelx_default()`.
///
/// The three in-memory handles are returned alongside the trait object
/// so the binary's smoke tests can inspect what landed in storage / on
/// the queue / in the audit log.
#[allow(dead_code)] // exposed for future smoke tests + the binary main wiring
pub(crate) fn build(
    defaults_weights: RiskWeightsConfig,
    defaults_thresholds: RiskThresholdsConfig,
) -> RiskTuningBundle {
    let (service, store, queue, audit) = in_memory_service(defaults_weights, defaults_thresholds);
    let port: Arc<dyn RiskTuningPort> = Arc::new(RiskTuningAdapter { inner: service });
    RiskTuningBundle {
        port,
        store,
        queue,
        audit,
    }
}

/// Build the durable Postgres-backed risk-tuning port. Selected by the
/// composition root when the DB is enabled, so per-tenant risk-model
/// overrides survive a restart instead of living in a throwaway map.
///
/// Only the override *store* is persisted; the recompute queue is an
/// ephemeral work signal (a Redis-backed queue is the eventual home — kept
/// in-memory here) and the audit sink stays in-memory (CRUD events also flow
/// to the platform audit log via the controller).
pub(crate) fn build_pg(
    pool: PgPool,
    stmt_timeout_ms: u64,
    defaults_weights: RiskWeightsConfig,
    defaults_thresholds: RiskThresholdsConfig,
) -> Arc<dyn RiskTuningPort> {
    let store: Arc<dyn TenantTuningStore> = Arc::new(PgTuningStore {
        pool,
        stmt_timeout_ms,
    });
    let recompute: Arc<dyn RecomputeQueue> = Arc::new(InMemoryRecomputeQueue::new());
    let audit: Arc<dyn TuningAuditSink> = Arc::new(InMemoryAuditSink::new());
    let service = TenantRiskTuningService::new(
        store,
        recompute,
        audit,
        defaults_weights,
        defaults_thresholds,
    );
    Arc::new(RiskTuningAdapter { inner: service })
}

/// Postgres-backed [`TenantTuningStore`] — the per-tenant risk-model override
/// (optional composite-weight + score-band dials). Stored as JSONB keyed by
/// `tenant_id`; a missing row reads back as `TenantRiskOverride::empty()`,
/// matching the in-memory store (a tenant with no override inherits the
/// platform defaults). Keyed by the tenant id alone with no cross-tenant
/// query, so no tenant RLS is needed.
struct PgTuningStore {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgTuningStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTuningStore").finish_non_exhaustive()
    }
}

impl PgTuningStore {
    fn err(e: impl std::fmt::Display) -> RiskError {
        RiskError::internal(format!("risk tuning store: {e}"))
    }

    async fn begin(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, RiskError> {
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
impl TenantTuningStore for PgTuningStore {
    async fn get(&self, tenant_id: &str) -> Result<TenantRiskOverride, RiskError> {
        let mut tx = self.begin().await?;
        let row = sqlx::query("SELECT override_ FROM risk_tuning_overrides WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        match row {
            Some(r) => Ok(r
                .try_get::<Json<TenantRiskOverride>, _>("override_")
                .map(|j| j.0)
                .map_err(Self::err)?),
            None => Ok(TenantRiskOverride::empty()),
        }
    }

    async fn put(&self, tenant_id: &str, override_: TenantRiskOverride) -> Result<(), RiskError> {
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO risk_tuning_overrides (tenant_id, override_, updated_at) \
             VALUES ($1, $2, now()) \
             ON CONFLICT (tenant_id) DO UPDATE SET override_ = EXCLUDED.override_, updated_at = now()",
        )
        .bind(tenant_id)
        .bind(Json(&override_))
        .execute(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)
    }
}

/// Bundle returned by [`build`].
#[allow(dead_code)]
pub(crate) struct RiskTuningBundle {
    /// Trait-object handle the API layer mounts on `AppState.risk_tuning`.
    pub port: Arc<dyn RiskTuningPort>,
    /// In-memory store handle — useful for binary smoke tests.
    pub store: Arc<InMemoryTuningStore>,
    /// In-memory recompute queue handle — useful for binary smoke tests.
    pub queue: Arc<InMemoryRecomputeQueue>,
    /// In-memory audit sink handle — useful for binary smoke tests.
    pub audit: Arc<InMemoryAuditSink>,
}

/// Adapter object held behind the trait pointer. Cheap to clone (the
/// inner service is `Clone` via three `Arc`s).
struct RiskTuningAdapter {
    inner: TenantRiskTuningService,
}

#[async_trait]
impl RiskTuningPort for RiskTuningAdapter {
    async fn get_override(
        &self,
        tenant_id: &str,
    ) -> Result<TenantRiskConfigView, RiskTuningPortError> {
        let domain = self.inner.get_override(tenant_id).await.map_err(map_err)?;
        Ok(domain.into())
    }

    async fn put_override(
        &self,
        tenant_id: &str,
        actor: Option<String>,
        req: TenantRiskConfigView,
    ) -> Result<EffectiveRiskConfigView, RiskTuningPortError> {
        let override_ = req.into();
        let eff = self
            .inner
            .put_override(tenant_id, override_, actor)
            .await
            .map_err(map_err)?;
        Ok(eff.into())
    }

    async fn get_effective(
        &self,
        tenant_id: &str,
    ) -> Result<EffectiveRiskConfigView, RiskTuningPortError> {
        let eff = self.inner.get_effective(tenant_id).await.map_err(map_err)?;
        Ok(eff.into())
    }

    fn defaults(&self) -> EffectiveRiskConfigView {
        self.inner.defaults_effective().into()
    }
}

fn map_err(e: RiskError) -> RiskTuningPortError {
    match e {
        RiskError::Config(m) | RiskError::InvalidInput(m) => RiskTuningPortError::Invalid(m),
        RiskError::Provider(m) => RiskTuningPortError::Dependency(m),
        RiskError::Internal(m) => RiskTuningPortError::Internal(m),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    fn defaults() -> (RiskWeightsConfig, RiskThresholdsConfig) {
        (
            RiskWeightsConfig::default(),
            RiskThresholdsConfig::sentinelx_default(),
        )
    }

    #[tokio::test]
    async fn defaults_returned_when_no_override() {
        let (w, t) = defaults();
        let bundle = build(w, t);
        let eff = bundle.port.get_effective("tenant-a").await.unwrap();
        assert_eq!(eff.weights.w_severity, w.w_severity);
        assert_eq!(eff.thresholds.crit, t.crit);
    }

    #[tokio::test]
    async fn put_then_get_round_trip() {
        let (w, t) = defaults();
        let bundle = build(w, t);
        let req = TenantRiskConfigView {
            weights: Some(sx_api::view::risk_tuning_view::RiskWeightsView {
                w_severity: 0.10,
                w_exploit: 0.10,
                w_exposure: 0.10,
                w_criticality: 0.50,
                w_business_impact: 0.10,
                w_chain: 0.10,
            }),
            thresholds: None,
        };
        let eff = bundle
            .port
            .put_override("tenant-a", Some("alice".into()), req)
            .await
            .unwrap();
        // Weights match the override; thresholds inherited.
        assert!((eff.weights.w_criticality - 0.50).abs() < 1e-9);
        assert_eq!(eff.thresholds.crit, t.crit);

        // Read-back via the port surfaces the same sparse override.
        let back = bundle.port.get_override("tenant-a").await.unwrap();
        assert!(back.weights.is_some());
        assert!(back.thresholds.is_none());

        // Recompute was enqueued, audit recorded.
        assert_eq!(bundle.queue.snapshot().await.len(), 1);
        assert_eq!(bundle.audit.events().await.len(), 1);
    }

    #[tokio::test]
    async fn invalid_payload_maps_to_invalid_variant() {
        let (w, t) = defaults();
        let bundle = build(w, t);
        let req = TenantRiskConfigView {
            // Sum out of band — service rejects, adapter maps to Invalid.
            weights: Some(sx_api::view::risk_tuning_view::RiskWeightsView {
                w_severity: 0.50,
                w_exploit: 0.50,
                w_exposure: 0.10,
                w_criticality: 0.10,
                w_business_impact: 0.10,
                w_chain: 0.20,
            }),
            thresholds: None,
        };
        let err = bundle
            .port
            .put_override("tenant-a", None, req)
            .await
            .expect_err("invalid weights must be rejected");
        assert!(matches!(err, RiskTuningPortError::Invalid(_)));
        // No persistence, no audit, no recompute on failed write.
        assert!(bundle.store.snapshot().await.is_empty());
        assert!(bundle.queue.snapshot().await.is_empty());
        assert!(bundle.audit.events().await.is_empty());
    }

    #[tokio::test]
    async fn empty_tenant_id_is_invalid() {
        let (w, t) = defaults();
        let bundle = build(w, t);
        let err = bundle.port.get_override("").await.unwrap_err();
        assert!(matches!(err, RiskTuningPortError::Invalid(_)));
    }

    /// Durability proof against a real Postgres: a non-empty override is
    /// persisted → *fresh store (restart-equivalent)* → it survives, while a
    /// never-written tenant reads back as empty (inherits defaults).
    ///
    /// Gated on `TEST_DATABASE_URL` (silent no-op in CI; workspace live-DB
    /// fixture convention). The store operates on the `TenantTuningStore`
    /// seam directly (no validation — that lives in the service).
    #[tokio::test]
    async fn pg_risk_tuning_override_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = uuid::Uuid::new_v4().to_string();
        let other = uuid::Uuid::new_v4().to_string();
        let override_ = TenantRiskOverride {
            weights: None,
            thresholds: Some(RiskThresholdsConfig::sentinelx_default()),
        };

        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let store = PgTuningStore {
                pool,
                stmt_timeout_ms: 15_000,
            };
            store.put(&tenant, override_).await.expect("put");
        }

        // Fresh store == a fresh process. In-memory state would be gone.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let store = PgTuningStore {
                pool,
                stmt_timeout_ms: 15_000,
            };
            let got = store.get(&tenant).await.expect("get after restart");
            assert!(got.thresholds.is_some(), "override survived restart");
            assert!(got.weights.is_none());
            // A never-written tenant inherits defaults (empty override).
            let missing = store.get(&other).await.expect("get missing");
            assert!(missing.is_empty(), "unwritten tenant reads back empty");
        }
    }
}
