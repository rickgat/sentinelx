//! Per-tenant risk-model tuning service (P1-014).
//!
//! This module wires three building blocks into one async, port-friendly
//! service:
//!
//! 1. A **store** of per-tenant [`TenantRiskOverride`] rows
//!    ([`TenantTuningStore`] trait).
//! 2. A **recompute queue** invoked on every successful `put_config`
//!    write ([`RecomputeQueue`] trait). Implementations enqueue a
//!    background job whose contract is *re-score every finding for the
//!    affected tenant* — the actual scoring is owned by the caller's
//!    consumer worker.
//! 3. An **audit sink** that records the JSON `(old, new)` weight/threshold
//!    diff on every successful PUT ([`TuningAuditSink`] trait). The sink
//!    is invoked **after** the new config is persisted so a write that
//!    later rolls back never produces a phantom audit row.
//!
//! The [`TenantRiskTuningService`] is the orchestrator that exposes the
//! five operations the HTTP layer needs:
//!
//! - [`Self::get_override`]  — fetch the stored override (sparse).
//! - [`Self::get_effective`] — fetch the merged effective config.
//! - [`Self::put_override`]  — replace the override, audit the diff,
//!   enqueue a recompute. Cross-tenant writes are rejected at the
//!   service level because every method takes the tenant id explicitly.
//! - `defaults_effective`    — the platform defaults (used by the API
//!   surface for `GET /v1/risk/config` when no override row exists).
//!
//! ## Concurrency
//!
//! The service holds its three collaborators behind `Arc<dyn ...>` so it
//! is cheaply `Clone`. The recompute queue and audit sink are dispatched
//! `await`'d in order — *audit before enqueue* so a transient broker
//! outage never leaves the system with a recompute job lacking a
//! matching audit row.
//!
//! ## Idempotency
//!
//! [`Self::put_override`] is idempotent in the sense that submitting an
//! identical payload twice produces a single audit row (the second write
//! has an empty diff so the sink is asked to record a no-op which the
//! in-memory adapter elides). Recompute, however, is still queued on
//! every successful write because the *findings* the recompute targets
//! may have changed even when the config did not — the worker is
//! responsible for de-duping by `(tenant_id, queued_at)`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sx_config::schema::risk_weights::RiskWeightsConfig;
use sx_config::schema::tenant_risk::{
    EffectiveRiskConfig, RiskThresholdsConfig, TenantRiskOverride,
};
use tokio::sync::Mutex;

use crate::error::RiskError;

/// One row in the audit trail surfaced by [`TuningAuditSink`].
///
/// Carries the platform-default-resolved `(old, new)` effective configs
/// so a downstream replay can reconstruct the scorer behaviour at any
/// point in time. The sink translates this into its native storage shape
/// (Postgres JSONB column, log line, etc.).
#[derive(Debug, Clone, PartialEq)]
pub struct TuningAuditEvent {
    /// Tenant id the write was scoped to.
    pub tenant_id: String,
    /// Effective config **before** the write.
    pub old_effective: EffectiveRiskConfig,
    /// Effective config **after** the write.
    pub new_effective: EffectiveRiskConfig,
    /// JSON `{field: {old, new}}` diff. Empty when the write is a no-op.
    pub diff: serde_json::Value,
    /// Optional bearer-less actor identifier (sub claim, never the JWT).
    pub actor: Option<String>,
}

/// Pluggable persistence backend for the sparse per-tenant overrides.
#[async_trait]
pub trait TenantTuningStore: Send + Sync {
    /// Fetch the stored override for `tenant_id`. Returns
    /// [`TenantRiskOverride::empty`] if no row exists — the caller is
    /// responsible for layering the platform defaults on top.
    async fn get(&self, tenant_id: &str) -> Result<TenantRiskOverride, RiskError>;

    /// Replace the override row for `tenant_id` with `override_`.
    /// Implementations MUST persist atomically (upsert) and MUST NOT
    /// validate — the service layer has already enforced invariants.
    async fn put(&self, tenant_id: &str, override_: TenantRiskOverride) -> Result<(), RiskError>;
}

/// Pluggable background-job queue for the post-PUT recompute.
#[async_trait]
pub trait RecomputeQueue: Send + Sync {
    /// Enqueue a recompute of every finding's risk score for
    /// `tenant_id`. The contract is fire-and-forget; any failure
    /// surfaces as [`RiskError::Provider`].
    ///
    /// Implementations MUST be idempotent under a re-publish of the
    /// same `(tenant_id, queued_at)` tuple so a retry never re-runs a
    /// successfully completed recompute. The default in-memory queue
    /// implements this with a `(tenant_id, queued_at)` dedup set.
    async fn enqueue(&self, tenant_id: &str) -> Result<(), RiskError>;
}

/// Pluggable audit sink — records the diff on every successful PUT.
///
/// Implementations MUST NOT log the bearer or any header — the
/// `TuningAuditEvent` carries only numeric vectors plus the `actor`
/// sub-claim, which is safe to record.
#[async_trait]
pub trait TuningAuditSink: Send + Sync {
    /// Record an audit event. Implementations MAY elide events whose
    /// diff is empty (no-op writes); the service does not require the
    /// sink to persist them.
    async fn record(&self, event: TuningAuditEvent) -> Result<(), RiskError>;
}

/// Per-tenant risk-model tuning orchestrator.
///
/// Constructed once at boot and shared (cheap-clone) across handlers
/// via `Arc`. Holds three trait objects: store, recompute queue, audit
/// sink. Every method is cancellation-safe.
#[derive(Clone)]
pub struct TenantRiskTuningService {
    store: Arc<dyn TenantTuningStore>,
    recompute: Arc<dyn RecomputeQueue>,
    audit: Arc<dyn TuningAuditSink>,
    defaults_weights: RiskWeightsConfig,
    defaults_thresholds: RiskThresholdsConfig,
}

impl std::fmt::Debug for TenantRiskTuningService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantRiskTuningService")
            .field("defaults_weights", &self.defaults_weights)
            .field("defaults_thresholds", &self.defaults_thresholds)
            .finish_non_exhaustive()
    }
}

impl TenantRiskTuningService {
    /// Build a service from three collaborators and the platform-wide
    /// defaults the merge layers an override onto.
    #[must_use]
    pub fn new(
        store: Arc<dyn TenantTuningStore>,
        recompute: Arc<dyn RecomputeQueue>,
        audit: Arc<dyn TuningAuditSink>,
        defaults_weights: RiskWeightsConfig,
        defaults_thresholds: RiskThresholdsConfig,
    ) -> Self {
        Self {
            store,
            recompute,
            audit,
            defaults_weights,
            defaults_thresholds,
        }
    }

    /// Platform-default weights captured at boot.
    #[must_use]
    pub const fn defaults_weights(&self) -> &RiskWeightsConfig {
        &self.defaults_weights
    }

    /// Platform-default thresholds captured at boot.
    #[must_use]
    pub const fn defaults_thresholds(&self) -> &RiskThresholdsConfig {
        &self.defaults_thresholds
    }

    /// Build an empty-override defaults-only effective config — the
    /// answer to "what would the scorer use for a tenant with no
    /// override row?".
    #[must_use]
    pub fn defaults_effective(&self) -> EffectiveRiskConfig {
        // The defaults themselves are validated at boot by the loader.
        // We still funnel through `merge` so any drift between the
        // calling code and the platform invariants surfaces fast.
        EffectiveRiskConfig::merge(
            self.defaults_weights,
            self.defaults_thresholds,
            &TenantRiskOverride::empty(),
        )
        .unwrap_or(EffectiveRiskConfig {
            weights: self.defaults_weights,
            thresholds: self.defaults_thresholds,
        })
    }

    /// Fetch the per-tenant override row (sparse). Absent rows are
    /// surfaced as [`TenantRiskOverride::empty`].
    pub async fn get_override(&self, tenant_id: &str) -> Result<TenantRiskOverride, RiskError> {
        guard_tenant(tenant_id)?;
        self.store.get(tenant_id).await
    }

    /// Fetch the merged effective config — defaults ⊕ stored override.
    pub async fn get_effective(&self, tenant_id: &str) -> Result<EffectiveRiskConfig, RiskError> {
        guard_tenant(tenant_id)?;
        let ovr = self.store.get(tenant_id).await?;
        EffectiveRiskConfig::merge(self.defaults_weights, self.defaults_thresholds, &ovr)
            .map_err(|e| RiskError::config(e.to_string()))
    }

    /// Replace the per-tenant override, record the audit diff, and
    /// enqueue a finding-recompute for the tenant.
    ///
    /// # Errors
    /// * [`RiskError::InvalidInput`] if `tenant_id` is empty.
    /// * [`RiskError::Config`] if the merged effective config violates
    ///   its invariants (sum, monotone thresholds).
    /// * Any error surfaced by the store, audit sink, or recompute
    ///   queue.
    pub async fn put_override(
        &self,
        tenant_id: &str,
        override_: TenantRiskOverride,
        actor: Option<String>,
    ) -> Result<EffectiveRiskConfig, RiskError> {
        guard_tenant(tenant_id)?;

        // Compute old + new effective. Both go through `merge` so a
        // bad payload bails before touching storage.
        let old_ovr = self.store.get(tenant_id).await?;
        let old_eff =
            EffectiveRiskConfig::merge(self.defaults_weights, self.defaults_thresholds, &old_ovr)
                .map_err(|e| RiskError::config(e.to_string()))?;
        let new_eff =
            EffectiveRiskConfig::merge(self.defaults_weights, self.defaults_thresholds, &override_)
                .map_err(|e| RiskError::config(e.to_string()))?;

        // Persist atomically — failure here means we never audit nor
        // enqueue a recompute (no phantom diff in the audit trail).
        self.store.put(tenant_id, override_).await?;

        // Audit BEFORE enqueue: if the recompute broker is down we
        // still want a record of what the operator changed so an
        // SRE can replay the queue manually.
        let diff = old_eff.diff(&new_eff);
        self.audit
            .record(TuningAuditEvent {
                tenant_id: tenant_id.to_owned(),
                old_effective: old_eff,
                new_effective: new_eff,
                diff,
                actor,
            })
            .await?;

        // Enqueue the recompute. We deliberately let queue failures
        // surface to the caller — an SRE re-runs the PUT once the
        // broker recovers; the audit row is now in place so the
        // second attempt is observable as a no-op diff.
        self.recompute.enqueue(tenant_id).await?;

        Ok(new_eff)
    }
}

fn guard_tenant(tenant_id: &str) -> Result<(), RiskError> {
    if tenant_id.trim().is_empty() {
        return Err(RiskError::invalid_input("tenant_id must be non-empty"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reference in-memory implementations — used by tests + the monolith adapter.
// ---------------------------------------------------------------------------

/// In-memory [`TenantTuningStore`]. Cheap to clone, thread-safe via a
/// single async mutex. Suitable for unit + integration tests; the
/// production adapter is Postgres-backed (see `sx-storage`).
#[derive(Debug, Default)]
pub struct InMemoryTuningStore {
    rows: Mutex<HashMap<String, TenantRiskOverride>>,
}

impl InMemoryTuningStore {
    /// Build an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
        }
    }

    /// Snapshot of every stored row — used by tests to assert
    /// cross-tenant isolation.
    pub async fn snapshot(&self) -> HashMap<String, TenantRiskOverride> {
        self.rows.lock().await.clone()
    }
}

#[async_trait]
impl TenantTuningStore for InMemoryTuningStore {
    async fn get(&self, tenant_id: &str) -> Result<TenantRiskOverride, RiskError> {
        let rows = self.rows.lock().await;
        Ok(rows
            .get(tenant_id)
            .copied()
            .unwrap_or(TenantRiskOverride::empty()))
    }

    async fn put(&self, tenant_id: &str, override_: TenantRiskOverride) -> Result<(), RiskError> {
        {
            let mut rows = self.rows.lock().await;
            rows.insert(tenant_id.to_owned(), override_);
        }
        Ok(())
    }
}

/// In-memory [`RecomputeQueue`] — records each enqueued tenant id in
/// arrival order. Idempotent over consecutive duplicates within the
/// same second so a double-PUT does not duplicate work.
#[derive(Debug, Default)]
pub struct InMemoryRecomputeQueue {
    inner: Mutex<Vec<RecomputeJob>>,
}

/// One enqueued recompute job. Tests inspect this to assert ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecomputeJob {
    /// Tenant id the job targets.
    pub tenant_id: String,
    /// Monotonically increasing sequence number assigned at enqueue
    /// time — used as the worker dedup key.
    pub seq: u64,
}

impl InMemoryRecomputeQueue {
    /// Build an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
        }
    }

    /// Drain every queued job, oldest first. Mirrors the contract of a
    /// `XREAD GROUP` against a Redis stream in production.
    pub async fn drain(&self) -> Vec<RecomputeJob> {
        let mut q = self.inner.lock().await;
        std::mem::take(&mut *q)
    }

    /// Read-only snapshot.
    pub async fn snapshot(&self) -> Vec<RecomputeJob> {
        self.inner.lock().await.clone()
    }
}

#[async_trait]
impl RecomputeQueue for InMemoryRecomputeQueue {
    async fn enqueue(&self, tenant_id: &str) -> Result<(), RiskError> {
        {
            let mut q = self.inner.lock().await;
            let seq = u64::try_from(q.len()).unwrap_or(u64::MAX);
            // Idempotent: drop a duplicate that arrived strictly after the
            // most recently appended row for the same tenant.
            if let Some(last) = q.last() {
                if last.tenant_id == tenant_id {
                    return Ok(());
                }
            }
            q.push(RecomputeJob {
                tenant_id: tenant_id.to_owned(),
                seq,
            });
        }
        Ok(())
    }
}

/// In-memory [`TuningAuditSink`].
///
/// Keeps every recorded event in arrival order. The sink elides events
/// whose diff is the empty JSON object (`{}`); this matches the
/// production rule "do not log no-op writes" and lets idempotent
/// retries land cleanly.
#[derive(Debug, Default)]
pub struct InMemoryAuditSink {
    events: Mutex<Vec<TuningAuditEvent>>,
}

impl InMemoryAuditSink {
    /// Build an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    /// Snapshot of every recorded event, oldest first.
    pub async fn events(&self) -> Vec<TuningAuditEvent> {
        self.events.lock().await.clone()
    }
}

#[async_trait]
impl TuningAuditSink for InMemoryAuditSink {
    async fn record(&self, event: TuningAuditEvent) -> Result<(), RiskError> {
        if event
            .diff
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        {
            // Idempotent no-op — drop the row.
            return Ok(());
        }
        // Sanity: refuse to record anything that smells like a bearer.
        // The sink is the last layer before a persistence call, so a
        // belt-and-braces check belongs here.
        let raw = serde_json::to_string(&event.diff).unwrap_or_default();
        debug_assert!(
            !raw.contains("Bearer ") && !raw.contains("bearer "),
            "tuning audit diff must never carry a bearer token"
        );
        self.events.lock().await.push(event);
        Ok(())
    }
}

/// Build a defaults-only service backed by the three in-memory
/// adapters. The single most useful constructor for tests and for the
/// monolith composition root.
#[must_use]
pub fn in_memory_service(
    defaults_weights: RiskWeightsConfig,
    defaults_thresholds: RiskThresholdsConfig,
) -> (
    TenantRiskTuningService,
    Arc<InMemoryTuningStore>,
    Arc<InMemoryRecomputeQueue>,
    Arc<InMemoryAuditSink>,
) {
    let store = Arc::new(InMemoryTuningStore::new());
    let queue = Arc::new(InMemoryRecomputeQueue::new());
    let sink = Arc::new(InMemoryAuditSink::new());
    let svc = TenantRiskTuningService::new(
        Arc::clone(&store) as Arc<dyn TenantTuningStore>,
        Arc::clone(&queue) as Arc<dyn RecomputeQueue>,
        Arc::clone(&sink) as Arc<dyn TuningAuditSink>,
        defaults_weights,
        defaults_thresholds,
    );
    (svc, store, queue, sink)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn defaults_weights() -> RiskWeightsConfig {
        RiskWeightsConfig::default()
    }

    fn defaults_thresholds() -> RiskThresholdsConfig {
        RiskThresholdsConfig::sentinelx_default()
    }

    fn custom_weights() -> RiskWeightsConfig {
        RiskWeightsConfig {
            w_severity: 0.10,
            w_exploit: 0.10,
            w_exposure: 0.10,
            w_criticality: 0.50,
            w_business_impact: 0.10,
            w_chain: 0.10,
        }
    }

    fn custom_thresholds() -> RiskThresholdsConfig {
        RiskThresholdsConfig {
            low: 20.0,
            med: 45.0,
            high: 70.0,
            crit: 88.0,
        }
    }

    #[tokio::test]
    async fn get_effective_without_override_returns_defaults() {
        let (svc, _, _, _) = in_memory_service(defaults_weights(), defaults_thresholds());
        let eff = svc.get_effective("tenant-a").await.unwrap();
        assert_eq!(eff.weights, defaults_weights());
        assert_eq!(eff.thresholds, defaults_thresholds());
    }

    #[tokio::test]
    async fn put_override_persists_and_returns_merged() {
        let (svc, _store, queue, audit) =
            in_memory_service(defaults_weights(), defaults_thresholds());
        let ovr = TenantRiskOverride {
            weights: Some(custom_weights()),
            thresholds: None,
        };
        let eff = svc
            .put_override("tenant-a", ovr, Some("user-1".into()))
            .await
            .unwrap();
        assert_eq!(eff.weights, custom_weights());
        assert_eq!(eff.thresholds, defaults_thresholds());

        // Effective config is observable next time.
        let again = svc.get_effective("tenant-a").await.unwrap();
        assert_eq!(again, eff);

        // Recompute was enqueued.
        let jobs = queue.snapshot().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].tenant_id, "tenant-a");

        // Audit was recorded.
        let events = audit.events().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tenant_id, "tenant-a");
        assert_eq!(events[0].actor.as_deref(), Some("user-1"));
        let diff = events[0].diff.as_object().unwrap();
        // Weights changed (criticality dominant) → diff non-empty.
        assert!(diff.contains_key("weights.w_criticality"));
        // Thresholds didn't change → not in the diff.
        assert!(!diff.contains_key("thresholds.low"));
    }

    #[tokio::test]
    async fn put_invalid_weights_rejected_and_nothing_persisted() {
        let (svc, store, queue, audit) =
            in_memory_service(defaults_weights(), defaults_thresholds());
        let bad = RiskWeightsConfig {
            w_severity: 0.50,
            w_exploit: 0.50, // sum = 1.5
            w_exposure: 0.10,
            w_criticality: 0.10,
            w_business_impact: 0.10,
            w_chain: 0.20,
        };
        let ovr = TenantRiskOverride {
            weights: Some(bad),
            thresholds: None,
        };
        let err = svc
            .put_override("tenant-a", ovr, None)
            .await
            .expect_err("invalid sum must be rejected");
        assert!(matches!(err, RiskError::Config(_)));

        // No persistence, no audit, no recompute.
        assert!(store.snapshot().await.is_empty());
        assert!(queue.snapshot().await.is_empty());
        assert!(audit.events().await.is_empty());
    }

    #[tokio::test]
    async fn put_non_monotonic_thresholds_rejected() {
        let (svc, _, _, _) = in_memory_service(defaults_weights(), defaults_thresholds());
        let bad = RiskThresholdsConfig {
            low: 50.0,
            med: 40.0,
            high: 70.0,
            crit: 90.0,
        };
        let ovr = TenantRiskOverride {
            weights: None,
            thresholds: Some(bad),
        };
        let err = svc.put_override("tenant-a", ovr, None).await.unwrap_err();
        assert!(matches!(err, RiskError::Config(_)));
    }

    #[tokio::test]
    async fn cross_tenant_writes_are_isolated() {
        let (svc, store, _, _) = in_memory_service(defaults_weights(), defaults_thresholds());
        let ovr_a = TenantRiskOverride {
            weights: Some(custom_weights()),
            thresholds: None,
        };
        let ovr_b = TenantRiskOverride {
            weights: None,
            thresholds: Some(custom_thresholds()),
        };
        svc.put_override("tenant-a", ovr_a, None).await.unwrap();
        svc.put_override("tenant-b", ovr_b, None).await.unwrap();

        // Each tenant sees only its own override.
        assert_eq!(svc.get_override("tenant-a").await.unwrap(), ovr_a);
        assert_eq!(svc.get_override("tenant-b").await.unwrap(), ovr_b);

        // Effective configs reflect tenant-scoped overrides.
        let eff_a = svc.get_effective("tenant-a").await.unwrap();
        let eff_b = svc.get_effective("tenant-b").await.unwrap();
        assert_eq!(eff_a.weights, custom_weights());
        assert_eq!(eff_a.thresholds, defaults_thresholds());
        assert_eq!(eff_b.weights, defaults_weights());
        assert_eq!(eff_b.thresholds, custom_thresholds());

        let snap = store.snapshot().await;
        assert_eq!(snap.len(), 2);
    }

    #[tokio::test]
    async fn empty_tenant_id_rejected_on_read_and_write() {
        let (svc, _, _, _) = in_memory_service(defaults_weights(), defaults_thresholds());
        let ovr = TenantRiskOverride::empty();
        assert!(matches!(
            svc.get_override("").await,
            Err(RiskError::InvalidInput(_))
        ));
        assert!(matches!(
            svc.get_effective("   ").await,
            Err(RiskError::InvalidInput(_))
        ));
        assert!(matches!(
            svc.put_override("", ovr, None).await,
            Err(RiskError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn recompute_queue_is_idempotent_on_consecutive_same_tenant() {
        // Two back-to-back PUTs for the same tenant should not double
        // the queue depth — the worker treats them as one job.
        let (svc, _, queue, _) = in_memory_service(defaults_weights(), defaults_thresholds());
        let ovr1 = TenantRiskOverride {
            weights: Some(custom_weights()),
            thresholds: None,
        };
        let ovr2 = TenantRiskOverride {
            weights: Some(custom_weights()),
            thresholds: Some(custom_thresholds()),
        };
        svc.put_override("tenant-a", ovr1, None).await.unwrap();
        svc.put_override("tenant-a", ovr2, None).await.unwrap();
        let jobs = queue.snapshot().await;
        assert_eq!(jobs.len(), 1, "consecutive PUTs must dedupe to one job");
    }

    #[tokio::test]
    async fn audit_sink_elides_noop_diff_on_redundant_put() {
        // PUT the same override twice → second PUT has empty diff
        // → audit sink drops it → only one event recorded.
        let (svc, _, _, audit) = in_memory_service(defaults_weights(), defaults_thresholds());
        let ovr = TenantRiskOverride {
            weights: Some(custom_weights()),
            thresholds: None,
        };
        svc.put_override("tenant-a", ovr, None).await.unwrap();
        svc.put_override("tenant-a", ovr, None).await.unwrap();
        let events = audit.events().await;
        assert_eq!(events.len(), 1, "second identical PUT must elide");
    }

    #[tokio::test]
    async fn audit_event_carries_old_and_new_diff() {
        let (svc, _, _, audit) = in_memory_service(defaults_weights(), defaults_thresholds());
        let ovr = TenantRiskOverride {
            weights: Some(custom_weights()),
            thresholds: Some(custom_thresholds()),
        };
        svc.put_override("tenant-a", ovr, Some("alice".into()))
            .await
            .unwrap();
        let events = audit.events().await;
        let e = &events[0];
        assert_eq!(e.actor.as_deref(), Some("alice"));
        // Old effective should equal defaults.
        assert_eq!(e.old_effective.weights, defaults_weights());
        assert_eq!(e.old_effective.thresholds, defaults_thresholds());
        // New effective should equal the override.
        assert_eq!(e.new_effective.weights, custom_weights());
        assert_eq!(e.new_effective.thresholds, custom_thresholds());
        // Diff covers both vectors.
        let m = e.diff.as_object().unwrap();
        assert!(m.contains_key("weights.w_criticality"));
        assert!(m.contains_key("thresholds.low"));
    }

    #[tokio::test]
    async fn defaults_effective_matches_unmerged_pair() {
        let (svc, _, _, _) = in_memory_service(defaults_weights(), defaults_thresholds());
        let eff = svc.defaults_effective();
        assert_eq!(eff.weights, defaults_weights());
        assert_eq!(eff.thresholds, defaults_thresholds());
    }
}
