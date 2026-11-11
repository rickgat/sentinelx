//! Admin endpoints + audit hooks for chaos engineering.
//!
//! Two HTTP surfaces are exposed:
//!
//! * `GET /v1/chaos/config` — return the current snapshot.
//! * `PUT /v1/chaos/config` — replace the configuration; admin RBAC +
//!   non-prod env gate enforced by the caller. Every PUT emits an
//!   [`ChaosAuditRecord`] via the supplied sink.
//!
//! The crate is HTTP-transport-agnostic: the embedded axum surfaces are
//! gated behind the `axum` types but the call sites in `sx-api` simply
//! call [`ChaosAdminService::get`] / [`ChaosAdminService::put`].

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::model::{ChaosConfig, ChaosError, ENV_APP_ENV, PROD_ENV_VALUE};
use crate::registry::{read_env, SharedChaosRegistry};

/// Audit-record metadata captured for each PUT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosAuditRecord {
    /// Tenant id (when the caller is tenant-scoped) or `"global"`.
    pub tenant_id: String,
    /// Authenticated actor (user id / svc id).
    pub actor: String,
    /// Previous configuration.
    pub previous: ChaosConfig,
    /// New configuration.
    pub next: ChaosConfig,
    /// ISO-8601 UTC timestamp.
    pub timestamp: String,
}

/// Receive-side for audit records emitted by [`ChaosAdminService::put`].
#[async_trait]
pub trait ChaosAuditSink: Send + Sync + std::fmt::Debug {
    /// Persist a single audit record. Implementations should be
    /// best-effort; transient errors are logged but **not** propagated
    /// to the caller so chaos configuration changes succeed even if the
    /// audit store is degraded.
    async fn record(&self, entry: ChaosAuditRecord);
}

/// In-memory audit sink — used in tests + as a default while the real
/// `sx-audit` adapter is wired in by the composition root.
#[derive(Debug, Default)]
pub struct InMemoryChaosAuditSink {
    inner: std::sync::Mutex<Vec<ChaosAuditRecord>>,
}

impl InMemoryChaosAuditSink {
    /// Construct an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded entries.
    #[must_use]
    pub fn entries(&self) -> Vec<ChaosAuditRecord> {
        match self.inner.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }
}

#[async_trait]
impl ChaosAuditSink for InMemoryChaosAuditSink {
    async fn record(&self, entry: ChaosAuditRecord) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.push(entry);
    }
}

/// Application service backing the admin surface.
#[derive(Debug, Clone)]
pub struct ChaosAdminService {
    registry: SharedChaosRegistry,
    audit: Arc<dyn ChaosAuditSink>,
}

impl ChaosAdminService {
    /// Construct from a shared registry + audit sink.
    #[must_use]
    pub fn new(registry: SharedChaosRegistry, audit: Arc<dyn ChaosAuditSink>) -> Self {
        Self { registry, audit }
    }

    /// Snapshot the current configuration. Read-only, no audit emitted.
    #[must_use]
    pub fn get(&self) -> ChaosConfig {
        self.registry.snapshot()
    }

    /// Replace the configuration.
    ///
    /// * Refuses when `APP_ENV=production` regardless of caller.
    /// * Validates fractions.
    /// * Emits an audit record carrying the before/after snapshots.
    ///
    /// # Errors
    ///
    /// See [`ChaosError`].
    pub async fn put(
        &self,
        tenant_id: &str,
        actor: &str,
        new: ChaosConfig,
    ) -> Result<ChaosConfig, ChaosError> {
        let app_env = read_env(ENV_APP_ENV).unwrap_or_default();
        if app_env.eq_ignore_ascii_case(PROD_ENV_VALUE) {
            return Err(ChaosError::ProductionRefused { env: app_env });
        }
        let previous = self.registry.replace(new.clone())?;
        let record = ChaosAuditRecord {
            tenant_id: tenant_id.to_owned(),
            actor: actor.to_owned(),
            previous,
            next: new.clone(),
            timestamp: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        };
        self.audit.record(record).await;
        Ok(new)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    // The test mutex is intentionally held across `await` so the env
    // mutations in `put_in_prod_is_refused` / `put_records_audit_entry`
    // don't race with the parallel test runner. The held futures only
    // touch process-local state — no IO — so the await is safe.
    clippy::await_holding_lock
)]
mod tests {
    use super::*;
    use crate::model::{ErrorRateConfig, LatencyConfig};
    use crate::registry::ChaosRegistry;

    fn svc_with_sink() -> (ChaosAdminService, Arc<InMemoryChaosAuditSink>) {
        let reg = Arc::new(ChaosRegistry::disabled());
        let sink = Arc::new(InMemoryChaosAuditSink::new());
        let svc = ChaosAdminService::new(reg, sink.clone());
        (svc, sink)
    }

    use crate::registry::{remove_env, set_env};

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn put_in_prod_is_refused() {
        let _g = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = read_env(ENV_APP_ENV);
        set_env(ENV_APP_ENV, "production");
        let (svc, _) = svc_with_sink();
        let err = svc
            .put("global", "alice", ChaosConfig::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ChaosError::ProductionRefused { .. }));
        match prev {
            Some(v) => set_env(ENV_APP_ENV, &v),
            None => remove_env(ENV_APP_ENV),
        }
    }

    #[tokio::test]
    async fn put_records_audit_entry() {
        let _g = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = read_env(ENV_APP_ENV);
        set_env(ENV_APP_ENV, "staging");
        let (svc, sink) = svc_with_sink();
        let new_cfg = ChaosConfig {
            enabled: true,
            latency: LatencyConfig {
                fraction: 0.1_f64,
                p50_ms: 5,
                p99_ms: 50,
            },
            error_rate: ErrorRateConfig { fraction: 0.0_f64 },
            ..ChaosConfig::default()
        };
        svc.put("global", "alice", new_cfg.clone()).await.unwrap();
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        let first = entries.first().expect("at least one entry");
        assert_eq!(first.actor, "alice");
        assert!(first.next.enabled);
        match prev {
            Some(v) => set_env(ENV_APP_ENV, &v),
            None => remove_env(ENV_APP_ENV),
        }
    }

    #[tokio::test]
    async fn invalid_fraction_returns_error() {
        let _g = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = read_env(ENV_APP_ENV);
        set_env(ENV_APP_ENV, "dev");
        let (svc, _) = svc_with_sink();
        let bad = ChaosConfig {
            error_rate: ErrorRateConfig { fraction: 1.5_f64 },
            ..ChaosConfig::default()
        };
        let err = svc.put("global", "alice", bad).await.unwrap_err();
        assert!(matches!(err, ChaosError::InvalidFraction { .. }));
        match prev {
            Some(v) => set_env(ENV_APP_ENV, &v),
            None => remove_env(ENV_APP_ENV),
        }
    }
}
