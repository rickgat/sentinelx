//! The shared chaos registry.
//!
//! Owns a [`Mutex`]-wrapped [`ChaosConfig`] plus a sampler. The registry
//! is the lone [`ChaosInjector`] implementation and is shared across the
//! HTTP middleware, repository wrappers, and the admin endpoints.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::metrics::record_injection;
use crate::model::{
    ChaosConfig, ChaosError, ChaosInjector, ChaosOutcome, DependencyConfig, DependencyKind,
    DependencyOutcome, ErrorRateConfig, KindName, LatencyConfig, ENV_APP_ENV,
    ENV_CHAOS_DEPENDENCY_FRACTION, ENV_CHAOS_ENABLED, ENV_CHAOS_ERROR_RATE_FRACTION,
    ENV_CHAOS_LATENCY_FRACTION, PROD_ENV_VALUE,
};
use crate::sampler::{Sampler, ThreadRngSampler};

/// Reference-counted handle to the registry — convenient for sharing across
/// layers without juggling lifetimes.
pub type SharedChaosRegistry = Arc<ChaosRegistry>;

/// Shared chaos state.
pub struct ChaosRegistry {
    /// Current [`ChaosConfig`]; mutated by the admin endpoint.
    inner: Mutex<ChaosConfig>,
    /// Pluggable sampler.
    sampler: Box<dyn Sampler>,
}

impl fmt::Debug for ChaosRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snap = self.snapshot();
        f.debug_struct("ChaosRegistry")
            .field("config", &snap)
            .finish_non_exhaustive()
    }
}

impl ChaosRegistry {
    /// Build a registry from an explicit [`ChaosConfig`] and sampler.
    #[must_use]
    pub fn with_sampler(config: ChaosConfig, sampler: Box<dyn Sampler>) -> Self {
        Self {
            inner: Mutex::new(config),
            sampler,
        }
    }

    /// Convenience: build a registry with the thread-rng sampler.
    #[must_use]
    pub fn new(config: ChaosConfig) -> Self {
        Self::with_sampler(config, Box::new(ThreadRngSampler))
    }

    /// Disabled registry — handy as a default in tests + composition root
    /// when the operator has not opted in.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(ChaosConfig::default())
    }

    /// Load a registry from the process environment.
    ///
    /// Returns [`ChaosError::ProductionRefused`] when `APP_ENV=production`
    /// AND chaos is requested. When chaos is not enabled in the env this
    /// returns a disabled registry without touching `APP_ENV` — safe to
    /// call from any binary.
    ///
    /// # Errors
    ///
    /// See [`ChaosError`].
    pub fn from_env() -> Result<Self, ChaosError> {
        let requested = read_env(ENV_CHAOS_ENABLED).is_some_and(|v| v == "1");
        if !requested {
            return Ok(Self::disabled());
        }
        let app_env = read_env(ENV_APP_ENV).unwrap_or_default();
        if app_env.eq_ignore_ascii_case(PROD_ENV_VALUE) {
            return Err(ChaosError::ProductionRefused { env: app_env });
        }
        let latency_fraction = parse_fraction_env(ENV_CHAOS_LATENCY_FRACTION)?;
        let error_fraction = parse_fraction_env(ENV_CHAOS_ERROR_RATE_FRACTION)?;
        let dep_fraction = parse_fraction_env(ENV_CHAOS_DEPENDENCY_FRACTION)?;
        let cfg = ChaosConfig {
            enabled: true,
            latency: LatencyConfig {
                fraction: latency_fraction,
                ..LatencyConfig::default()
            },
            error_rate: ErrorRateConfig {
                fraction: error_fraction,
            },
            dependency: DependencyConfig {
                fraction: dep_fraction,
                ..DependencyConfig::default()
            },
        };
        Ok(Self::new(cfg))
    }

    /// Snapshot the current configuration (cheap clone).
    #[must_use]
    pub fn snapshot(&self) -> ChaosConfig {
        match self.inner.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Replace the configuration, returning the previous value.
    ///
    /// Validates that every fraction is finite and in `0.0..=1.0`. The
    /// production gate is **not** applied here — callers (typically the
    /// admin endpoint) should check `APP_ENV` themselves so unit tests
    /// can drive arbitrary configs in-process without env munging.
    ///
    /// # Errors
    ///
    /// Returns [`ChaosError::InvalidFraction`] when any field is out of
    /// range.
    pub fn replace(&self, new: ChaosConfig) -> Result<ChaosConfig, ChaosError> {
        check_fraction(KindName::Latency.as_str(), new.latency.fraction)?;
        check_fraction(KindName::ErrorRate.as_str(), new.error_rate.fraction)?;
        check_fraction(KindName::Dependency.as_str(), new.dependency.fraction)?;
        let prev = {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            std::mem::replace(&mut *g, new)
        };
        Ok(prev)
    }

    /// Sample the latency arm: returns `Some(slept_ms)` when injected.
    async fn maybe_inject_latency(&self) -> Option<u64> {
        let cfg = self.snapshot();
        if !cfg.enabled || cfg.latency.fraction <= 0.0 {
            return None;
        }
        let s = self.sampler.sample();
        if s < cfg.latency.fraction {
            // 5% of the time use p99, the rest use p50 — mirrors the
            // shape of a long-tail distribution closely enough for
            // chaos testing.
            let tail = self.sampler.sample();
            let ms = if tail < 0.05 {
                cfg.latency.p99_ms
            } else {
                cfg.latency.p50_ms
            };
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Some(ms)
        } else {
            None
        }
    }

    /// Sample the error-rate arm.
    fn maybe_inject_error(&self) -> bool {
        let cfg = self.snapshot();
        if !cfg.enabled || cfg.error_rate.fraction <= 0.0 {
            return false;
        }
        self.sampler.sample() < cfg.error_rate.fraction
    }

    /// Sample the dependency arm.
    fn maybe_inject_dependency(
        &self,
        target: DependencyKind,
    ) -> Option<(DependencyKind, DependencyOutcome)> {
        let cfg = self.snapshot();
        if !cfg.enabled || cfg.dependency.fraction <= 0.0 || cfg.dependency.kind != target {
            return None;
        }
        if self.sampler.sample() < cfg.dependency.fraction {
            Some((cfg.dependency.kind, cfg.dependency.outcome))
        } else {
            None
        }
    }
}

#[async_trait]
impl ChaosInjector for ChaosRegistry {
    async fn inject_http(&self) -> ChaosOutcome {
        // Latency comes first so a single request can both sleep AND
        // return an error — matches real-world tail failures.
        let latency = self.maybe_inject_latency().await;
        let outcome = match latency {
            Some(slept_ms) => ChaosOutcome::Latency { slept_ms },
            None if self.maybe_inject_error() => ChaosOutcome::Error,
            None => ChaosOutcome::Pass,
        };
        record_injection(metric_kind(&outcome), outcome.metric_outcome());
        outcome
    }

    async fn inject_dependency(&self, target: DependencyKind) -> ChaosOutcome {
        let outcome = if let Some((kind, dep_outcome)) = self.maybe_inject_dependency(target) {
            ChaosOutcome::Dependency {
                kind,
                outcome: dep_outcome,
            }
        } else {
            ChaosOutcome::Pass
        };
        record_injection(metric_kind(&outcome), outcome.metric_outcome());
        outcome
    }

    fn config(&self) -> ChaosConfig {
        self.snapshot()
    }
}

const fn metric_kind(outcome: &ChaosOutcome) -> &'static str {
    match outcome {
        ChaosOutcome::Pass => "none",
        ChaosOutcome::Latency { .. } => KindName::Latency.as_str(),
        ChaosOutcome::Error => KindName::ErrorRate.as_str(),
        ChaosOutcome::Dependency { .. } => KindName::Dependency.as_str(),
    }
}

fn parse_fraction_env(name: &str) -> Result<f64, ChaosError> {
    let Some(s) = read_env(name) else {
        return Ok(0.0_f64);
    };
    let f: f64 = s.parse().map_err(|_| ChaosError::InvalidFraction {
        kind: kind_static_label(name),
        fraction: f64::NAN,
    })?;
    check_fraction(kind_static_label(name), f)?;
    Ok(f)
}

/// Internal env helpers — the only place in the crate that touches
/// `std::env`. `disallowed_methods` blanket-forbids `std::env::var`
/// project-wide; the chaos crate is the documented exception because
/// opt-in via `SX_CHAOS_*` env vars is part of the contract in the task
/// spec.
#[allow(clippy::disallowed_methods, clippy::redundant_pub_crate)]
pub(crate) fn read_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::redundant_pub_crate)]
pub(crate) fn set_env(name: &str, value: &str) {
    std::env::set_var(name, value);
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::redundant_pub_crate)]
pub(crate) fn remove_env(name: &str) {
    std::env::remove_var(name);
}

fn check_fraction(kind: &'static str, f: f64) -> Result<(), ChaosError> {
    if !f.is_finite() || !(0.0..=1.0).contains(&f) {
        return Err(ChaosError::InvalidFraction { kind, fraction: f });
    }
    Ok(())
}

const fn kind_static_label(env: &str) -> &'static str {
    // Match the env-var name to one of the well-known kinds for the error
    // message. We use byte-eq to stay const.
    if str_eq(env, ENV_CHAOS_LATENCY_FRACTION) {
        KindName::Latency.as_str()
    } else if str_eq(env, ENV_CHAOS_ERROR_RATE_FRACTION) {
        KindName::ErrorRate.as_str()
    } else if str_eq(env, ENV_CHAOS_DEPENDENCY_FRACTION) {
        KindName::Dependency.as_str()
    } else {
        "unknown"
    }
}

#[allow(clippy::indexing_slicing)]
const fn str_eq(a: &str, b: &str) -> bool {
    let aa = a.as_bytes();
    let bb = b.as_bytes();
    if aa.len() != bb.len() {
        return false;
    }
    let mut i = 0;
    while i < aa.len() {
        if aa[i] != bb[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;
    use crate::sampler::deterministic_sampler;

    fn enabled_cfg() -> ChaosConfig {
        ChaosConfig {
            enabled: true,
            latency: LatencyConfig {
                fraction: 0.5,
                p50_ms: 10,
                p99_ms: 20,
            },
            error_rate: ErrorRateConfig { fraction: 0.5 },
            dependency: DependencyConfig {
                fraction: 0.5,
                kind: DependencyKind::Db,
                outcome: DependencyOutcome::Unavailable,
            },
        }
    }

    #[tokio::test]
    async fn disabled_registry_never_injects() {
        let reg = ChaosRegistry::disabled();
        for _ in 0..32_u32 {
            assert_eq!(reg.inject_http().await, ChaosOutcome::Pass);
            assert_eq!(
                reg.inject_dependency(DependencyKind::Db).await,
                ChaosOutcome::Pass
            );
        }
    }

    #[tokio::test]
    async fn replace_validates_fractions() {
        let reg = ChaosRegistry::disabled();
        let mut bad = ChaosConfig::default();
        bad.latency.fraction = 1.5;
        let err = reg.replace(bad).unwrap_err();
        assert!(matches!(err, ChaosError::InvalidFraction { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn latency_arm_sleeps_when_sampler_below_fraction() {
        // 0.1 < 0.5 -> latency arm fires. 0.99 > 0.05 -> p50_ms path.
        let sampler = deterministic_sampler(vec![0.1, 0.99]);
        let reg = ChaosRegistry::with_sampler(enabled_cfg(), sampler);
        let start = tokio::time::Instant::now();
        let outcome = reg.inject_http().await;
        let elapsed = start.elapsed();
        assert!(matches!(outcome, ChaosOutcome::Latency { slept_ms: 10 }));
        assert!(elapsed >= Duration::from_millis(10));
    }

    #[tokio::test]
    async fn error_arm_fires_when_above_latency_threshold() {
        // First sample 0.9 (>0.5) skips latency; second 0.1 (<0.5) fires error.
        let sampler = deterministic_sampler(vec![0.9, 0.1]);
        let reg = ChaosRegistry::with_sampler(enabled_cfg(), sampler);
        let outcome = reg.inject_http().await;
        assert_eq!(outcome, ChaosOutcome::Error);
    }

    #[tokio::test]
    async fn dependency_arm_returns_for_matching_kind() {
        let sampler = deterministic_sampler(vec![0.1]);
        let reg = ChaosRegistry::with_sampler(enabled_cfg(), sampler);
        let outcome = reg.inject_dependency(DependencyKind::Db).await;
        assert!(matches!(outcome, ChaosOutcome::Dependency { .. }));
    }

    #[tokio::test]
    async fn dependency_arm_ignores_mismatched_kind() {
        let sampler = deterministic_sampler(vec![0.0]);
        let reg = ChaosRegistry::with_sampler(enabled_cfg(), sampler);
        let outcome = reg.inject_dependency(DependencyKind::Redis).await;
        assert_eq!(outcome, ChaosOutcome::Pass);
    }

    #[tokio::test]
    async fn fraction_sampling_statistically_close() {
        // Use the error-rate arm so each iteration consumes exactly one
        // sample from the deterministic sequence. 100 samples alternate
        // 0.4 (< 0.5, fires) and 0.6 (>= 0.5, skipped).
        let pattern: Vec<f64> = (0..100_u32)
            .map(|i| if i % 2 == 0 { 0.4_f64 } else { 0.6_f64 })
            .collect();
        let sampler = deterministic_sampler(pattern);
        let cfg = ChaosConfig {
            enabled: true,
            error_rate: ErrorRateConfig { fraction: 0.5 },
            ..ChaosConfig::default()
        };
        let reg = ChaosRegistry::with_sampler(cfg, sampler);
        let mut hits = 0_u32;
        for _ in 0..100_u32 {
            if matches!(reg.inject_http().await, ChaosOutcome::Error) {
                hits += 1;
            }
        }
        assert_eq!(hits, 50, "expected 50/100 injections, got {hits}");
    }

    // Env tests touch process-wide state; we serialize via a Mutex so
    // parallel tests don't race. The Mutex is poisoned-safe.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn from_env_disabled_when_flag_missing() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = read_env(ENV_CHAOS_ENABLED);
        remove_env(ENV_CHAOS_ENABLED);
        let reg = ChaosRegistry::from_env().unwrap();
        assert!(!reg.snapshot().enabled);
        if let Some(v) = prev {
            set_env(ENV_CHAOS_ENABLED, &v);
        }
    }

    #[test]
    fn from_env_refuses_production() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_enabled = read_env(ENV_CHAOS_ENABLED);
        let prev_app = read_env(ENV_APP_ENV);
        set_env(ENV_CHAOS_ENABLED, "1");
        set_env(ENV_APP_ENV, "production");
        let result = ChaosRegistry::from_env();
        assert!(matches!(result, Err(ChaosError::ProductionRefused { .. })));
        match prev_enabled {
            Some(v) => set_env(ENV_CHAOS_ENABLED, &v),
            None => remove_env(ENV_CHAOS_ENABLED),
        }
        match prev_app {
            Some(v) => set_env(ENV_APP_ENV, &v),
            None => remove_env(ENV_APP_ENV),
        }
    }
}
