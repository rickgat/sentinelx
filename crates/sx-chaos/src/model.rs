//! Domain types for the chaos engineering hooks (P2-012).

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Env var that globally gates chaos. Must be `"1"` to enable. Default off.
pub const ENV_CHAOS_ENABLED: &str = "SX_CHAOS_ENABLED";
/// Env var fraction (0.0..=1.0) for [`ChaosKind::Latency`].
pub const ENV_CHAOS_LATENCY_FRACTION: &str = "SX_CHAOS_LATENCY_FRACTION";
/// Env var fraction (0.0..=1.0) for [`ChaosKind::ErrorRate`].
pub const ENV_CHAOS_ERROR_RATE_FRACTION: &str = "SX_CHAOS_ERROR_RATE_FRACTION";
/// Env var fraction (0.0..=1.0) for [`ChaosKind::Dependency`].
pub const ENV_CHAOS_DEPENDENCY_FRACTION: &str = "SX_CHAOS_DEPENDENCY_FRACTION";

/// Deployment env var: when set to [`PROD_ENV_VALUE`] all chaos is refused.
pub const ENV_APP_ENV: &str = "APP_ENV";
/// Value of [`ENV_APP_ENV`] that disables chaos unconditionally.
pub const PROD_ENV_VALUE: &str = "production";

/// All known kinds — used as label values for metrics + config payloads.
///
/// Variants are exposed as machine-readable lower-snake strings via
/// [`KindName::as_str`]. Adding a new kind here requires extending the
/// registry, metrics, and admin payload in tandem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KindName {
    /// Latency injection.
    Latency,
    /// Synthetic error responses.
    ErrorRate,
    /// Dependency unavailability / timeout.
    Dependency,
}

impl KindName {
    /// Stable string form for metrics labels and admin payloads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Latency => "latency",
            Self::ErrorRate => "error_rate",
            Self::Dependency => "dependency",
        }
    }

    /// Iterate all kinds — handy for admin payload defaulting.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Latency, Self::ErrorRate, Self::Dependency]
    }
}

impl fmt::Display for KindName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which backing dependency a [`ChaosKind::Dependency`] fault targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Postgres / sqlx pool.
    Db,
    /// Redis client.
    Redis,
    /// External outbound HTTP call.
    External,
}

impl DependencyKind {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Db => "db",
            Self::Redis => "redis",
            Self::External => "external",
        }
    }
}

impl fmt::Display for DependencyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a dependency fault manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyOutcome {
    /// Dependency is reported as unavailable (e.g. surfaced as `503`).
    Unavailable,
    /// Dependency is reported as timed-out (e.g. surfaced as `504`).
    Timeout,
}

impl DependencyOutcome {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
        }
    }
}

impl fmt::Display for DependencyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Concrete fault variants that an [`ChaosInjector`] may emit.
#[derive(Debug, Clone, PartialEq)]
pub enum ChaosKind {
    /// Sleep `p50_ms` (or `p99_ms` for the tail) before passing through.
    Latency {
        /// Median latency injected, in milliseconds.
        p50_ms: u64,
        /// 99th-percentile latency injected, in milliseconds.
        p99_ms: u64,
    },
    /// Return a synthetic error.
    ErrorRate {
        /// Probability (0.0..=1.0) of emitting the synthetic error.
        fraction: f64,
    },
    /// Mark a backing dependency as failed.
    Dependency {
        /// Which dependency is affected.
        kind: DependencyKind,
        /// How the failure manifests.
        outcome: DependencyOutcome,
    },
}

impl ChaosKind {
    /// Project to the metric-label form.
    #[must_use]
    pub const fn name(&self) -> KindName {
        match self {
            Self::Latency { .. } => KindName::Latency,
            Self::ErrorRate { .. } => KindName::ErrorRate,
            Self::Dependency { .. } => KindName::Dependency,
        }
    }
}

/// What the injector decided to do on a single decision point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChaosOutcome {
    /// No fault injected — pass through.
    Pass,
    /// Latency was injected (and the sleep already awaited).
    Latency {
        /// How long the injector slept, in milliseconds.
        slept_ms: u64,
    },
    /// Error response should be returned by the caller.
    Error,
    /// Dependency reported as failed.
    Dependency {
        /// Affected dependency.
        kind: DependencyKind,
        /// Manifestation.
        outcome: DependencyOutcome,
    },
}

impl ChaosOutcome {
    /// Stable label string for metrics + tracing.
    #[must_use]
    pub const fn metric_outcome(&self) -> &'static str {
        match self {
            Self::Pass => crate::OUTCOME_PASS,
            Self::Latency { .. } => crate::OUTCOME_LATENCY,
            Self::Error => crate::OUTCOME_ERROR,
            Self::Dependency { outcome, .. } => match outcome {
                DependencyOutcome::Unavailable => crate::OUTCOME_DEPENDENCY_UNAVAILABLE,
                DependencyOutcome::Timeout => crate::OUTCOME_DEPENDENCY_TIMEOUT,
            },
        }
    }
}

/// Per-kind configuration backing the [`ChaosRegistry`](crate::ChaosRegistry).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChaosConfig {
    /// Master switch — all chaos is bypassed when `false`.
    pub enabled: bool,
    /// Latency-fault settings (always present; disabled by `fraction == 0.0`).
    pub latency: LatencyConfig,
    /// Error-rate-fault settings.
    pub error_rate: ErrorRateConfig,
    /// Dependency-fault settings.
    pub dependency: DependencyConfig,
}

/// Latency-fault configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatencyConfig {
    /// Activation probability (0.0..=1.0); 0.0 disables.
    pub fraction: f64,
    /// Median sleep injected when activated.
    pub p50_ms: u64,
    /// Tail (p99) sleep injected when activated (~5% of activations).
    pub p99_ms: u64,
}

impl Default for LatencyConfig {
    fn default() -> Self {
        Self {
            fraction: 0.0,
            p50_ms: 50,
            p99_ms: 500,
        }
    }
}

/// Error-rate-fault configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorRateConfig {
    /// Probability that a single decision returns an error.
    pub fraction: f64,
}

impl Default for ErrorRateConfig {
    fn default() -> Self {
        Self { fraction: 0.0_f64 }
    }
}

/// Dependency-fault configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyConfig {
    /// Probability that a dependency call is failed.
    pub fraction: f64,
    /// Which backing dependency this targets.
    pub kind: DependencyKind,
    /// Manifestation (unavailable / timeout).
    pub outcome: DependencyOutcome,
}

impl Default for DependencyConfig {
    fn default() -> Self {
        Self {
            fraction: 0.0,
            kind: DependencyKind::Db,
            outcome: DependencyOutcome::Unavailable,
        }
    }
}

/// Error returned by the registry / admin surface.
#[derive(Debug, Error)]
pub enum ChaosError {
    /// Refused because the deployment is production.
    #[error("chaos engineering is disabled in production (APP_ENV={env})")]
    ProductionRefused {
        /// Echoed `APP_ENV` value for diagnostics.
        env: String,
    },
    /// A supplied fraction is outside `0.0..=1.0`.
    #[error("invalid fraction {fraction} for kind {kind} (must be 0.0..=1.0)")]
    InvalidFraction {
        /// Offending kind label.
        kind: &'static str,
        /// Offending value.
        fraction: f64,
    },
}

/// Trait implemented by chaos injectors. The registry implements this.
#[async_trait]
pub trait ChaosInjector: Send + Sync + std::fmt::Debug {
    /// Decide whether to inject a fault on the HTTP middleware path.
    ///
    /// For [`ChaosKind::Latency`] outcomes the implementation will have
    /// already slept for the appropriate duration before returning.
    async fn inject_http(&self) -> ChaosOutcome;

    /// Decide whether to inject a fault on a dependency call.
    ///
    /// Pass [`DependencyKind`] for the surface being called; the
    /// implementation returns [`ChaosOutcome::Dependency`] when the
    /// configured kind matches AND the sampler fires.
    async fn inject_dependency(&self, target: DependencyKind) -> ChaosOutcome;

    /// Current configuration snapshot.
    fn config(&self) -> ChaosConfig;
}
