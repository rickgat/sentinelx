//! Repository-side chaos wrappers.
//!
//! Adapters that own a `Pool<Postgres>` or `redis::Client` are expected to
//! call [`ChaosRepoGuard::check`] before every external call. When the
//! shared registry decides to fail, the guard returns
//! [`ChaosRepoFault`] which the adapter maps onto its own error type.
//!
//! Note: we deliberately do not pull `sqlx` or `redis` into `sx-chaos`'s
//! direct dependencies — instead the wrapper is generic over the wrapped
//! handle. This keeps the crate dependency footprint small AND lets
//! callers wrap *any* dependency (`vector` DB, `graph` DB, etc.) through
//! the same machinery.

use std::sync::Arc;

use crate::model::{ChaosInjector, ChaosOutcome, DependencyKind, DependencyOutcome};
use crate::registry::SharedChaosRegistry;

/// Returned by [`ChaosRepoGuard::check`] when chaos was injected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaosRepoFault {
    /// Which dependency was affected.
    pub kind: DependencyKind,
    /// How the failure manifests.
    pub outcome: DependencyOutcome,
}

/// Generic wrapper around a dependency handle (e.g. `Pool<Postgres>` or
/// `redis::Client`) that consults the chaos registry before each call.
#[derive(Debug, Clone)]
pub struct ChaosRepoGuard<T> {
    inner: T,
    registry: SharedChaosRegistry,
    target: DependencyKind,
}

impl<T> ChaosRepoGuard<T>
where
    T: Send + Sync,
{
    /// Wrap a dependency handle.
    pub const fn new(inner: T, registry: SharedChaosRegistry, target: DependencyKind) -> Self {
        Self {
            inner,
            registry,
            target,
        }
    }

    /// Inspect the wrapped handle without consulting chaos. Useful for
    /// read-only metadata calls (pool size, idle counts) that should
    /// never be subject to chaos.
    pub const fn inner(&self) -> &T {
        &self.inner
    }

    /// Consume the wrapper, returning the raw handle.
    #[allow(clippy::missing_const_for_fn)]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Consult the chaos registry before performing a dependency call.
    ///
    /// Returns `Ok(&T)` when the call should proceed normally,
    /// `Err(ChaosRepoFault { .. })` when chaos was injected. The caller
    /// is responsible for translating the fault onto its own error type
    /// (typically a `503` for `Unavailable` and a `504` for `Timeout`).
    pub async fn check(&self) -> Result<&T, ChaosRepoFault> {
        match self.registry.inject_dependency(self.target).await {
            ChaosOutcome::Dependency { kind, outcome } => Err(ChaosRepoFault { kind, outcome }),
            _ => Ok(&self.inner),
        }
    }
}

/// Standalone dependency probe.
///
/// Helper for sites that hold the registry but no concrete handle —
/// e.g. an HTTP route reaching an external API. The function returns
/// `Ok(())` or `Err(ChaosRepoFault)` mirroring [`ChaosRepoGuard::check`].
pub async fn check_dependency(
    registry: &Arc<crate::registry::ChaosRegistry>,
    target: DependencyKind,
) -> Result<(), ChaosRepoFault> {
    match registry.inject_dependency(target).await {
        ChaosOutcome::Dependency { kind, outcome } => Err(ChaosRepoFault { kind, outcome }),
        _ => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::{ChaosConfig, DependencyConfig};
    use crate::registry::ChaosRegistry;
    use crate::sampler::deterministic_sampler;

    fn fired_cfg(kind: DependencyKind, outcome: DependencyOutcome) -> ChaosConfig {
        ChaosConfig {
            enabled: true,
            dependency: DependencyConfig {
                fraction: 1.0,
                kind,
                outcome,
            },
            ..ChaosConfig::default()
        }
    }

    #[tokio::test]
    async fn guard_passes_through_when_no_chaos() {
        let reg = Arc::new(ChaosRegistry::disabled());
        let guard = ChaosRepoGuard::new("conn", reg, DependencyKind::Db);
        let got = guard.check().await.unwrap();
        assert_eq!(*got, "conn");
    }

    #[tokio::test]
    async fn db_dependency_unavailable_returns_fault() {
        let reg = Arc::new(ChaosRegistry::with_sampler(
            fired_cfg(DependencyKind::Db, DependencyOutcome::Unavailable),
            deterministic_sampler(vec![0.0]),
        ));
        let guard = ChaosRepoGuard::new("conn", reg, DependencyKind::Db);
        let err = guard.check().await.unwrap_err();
        assert_eq!(err.kind, DependencyKind::Db);
        assert_eq!(err.outcome, DependencyOutcome::Unavailable);
    }

    #[tokio::test]
    async fn redis_kind_mismatch_passes_through() {
        let reg = Arc::new(ChaosRegistry::with_sampler(
            fired_cfg(DependencyKind::Db, DependencyOutcome::Unavailable),
            deterministic_sampler(vec![0.0]),
        ));
        let guard = ChaosRepoGuard::new("conn", reg, DependencyKind::Redis);
        let got = guard.check().await.unwrap();
        assert_eq!(*got, "conn");
    }

    #[tokio::test]
    async fn external_check_dependency_returns_timeout() {
        let reg = Arc::new(ChaosRegistry::with_sampler(
            fired_cfg(DependencyKind::External, DependencyOutcome::Timeout),
            deterministic_sampler(vec![0.0]),
        ));
        let err = check_dependency(&reg, DependencyKind::External)
            .await
            .unwrap_err();
        assert_eq!(err.outcome, DependencyOutcome::Timeout);
    }
}
