//! Anti-abuse detector configuration.
//!
//! Mirrors the runtime [`AntiAbuseConfig`] inside
//! `sx-api/src/middleware/anti_abuse.rs`. The middleware ships with
//! defensible defaults; production overrides arrive through this struct
//! after the YAML/env loader has assembled the global [`crate::Settings`].
//!
//! ## Disabled by default
//!
//! The middleware is **not** registered in the router yet, so the schema
//! ships with `enabled: false`. A freshly cloned checkout therefore boots
//! without engaging the detector. Operators flip `enabled: true` once they
//! have wired the layer into the authenticated subrouter.
//!
//! ## Field semantics
//!
//! All windows are expressed in **seconds** (not [`std::time::Duration`])
//! because the figment `Env` provider only emits string-typed scalars.
//! Conversion to `Duration` happens at the
//! `From<sx_config::AntiAbuseConfig> for sx_api::middleware::anti_abuse::AntiAbuseConfig`
//! boundary.
//!
//! ## Invariants
//!
//! When `enabled: true`, every numeric threshold MUST be strictly positive.
//! A zero window would either disable a detector silently (which is what
//! the `enabled` flag is for) or, worse, cause a divide-by-zero in the
//! rate-anomaly median calculation. Rejecting zero at load time keeps the
//! failure mode loud and early.

use serde::Deserialize;
use validator::Validate;

/// Default replay window in seconds (5 minutes). Matches the runtime
/// `AntiAbuseConfig::default().replay_window`.
const fn default_replay_window_secs() -> u64 {
    5 * 60
}

/// Default rate sample window in seconds (60 seconds). Matches the runtime
/// `AntiAbuseConfig::default().rate_window`.
const fn default_rate_window_secs() -> u64 {
    60
}

/// Default rate-anomaly multiplier (`3.0`). Matches the runtime
/// `AntiAbuseConfig::default().rate_anomaly_multiplier`.
const fn default_rate_anomaly_multiplier() -> f64 {
    3.0
}

/// Default minimum sample count before the rate detector will flag (`4`).
/// Matches the runtime `AntiAbuseConfig::default().rate_min_samples`.
const fn default_rate_min_samples() -> u32 {
    4
}

/// Default user-agent diversity window in seconds (10 minutes). Matches the
/// runtime `AntiAbuseConfig::default().agent_window`.
const fn default_agent_window_secs() -> u64 {
    10 * 60
}

/// Default distinct-UA threshold per IP (`5`). Matches the runtime
/// `AntiAbuseConfig::default().agent_threshold`.
const fn default_agent_threshold() -> u32 {
    5
}

/// Tunable thresholds for the anti-abuse detector middleware.
///
/// Every field has a documented default that matches the in-process
/// `AntiAbuseConfig` so a YAML file omitting all fields produces a
/// detector behaviourally identical to `AntiAbuseConfig::default()`.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct AntiAbuseConfig {
    /// Whether the detector is engaged at all. When `false`, every
    /// detector path is a no-op; useful for local development and
    /// emergency disablement via config push.
    pub enabled: bool,

    /// Sliding window (seconds) over which a `jti` is considered
    /// "recently seen" by the replay detector.
    #[serde(default = "default_replay_window_secs")]
    pub replay_window_secs: u64,

    /// Per-IP rate sample window (seconds) used by the rate-anomaly
    /// detector.
    #[serde(default = "default_rate_window_secs")]
    pub rate_window_secs: u64,

    /// Multiplier applied to the rolling median IP rate to decide
    /// whether a single IP is anomalous.
    #[serde(default = "default_rate_anomaly_multiplier")]
    pub rate_anomaly_multiplier: f64,

    /// Minimum number of requests an IP must contribute in
    /// `rate_window_secs` before the anomaly detector is willing to
    /// flag it.
    #[serde(default = "default_rate_min_samples")]
    pub rate_min_samples: u32,

    /// Sliding window (seconds) over which distinct user agents per IP
    /// are counted by the agent-rotation detector.
    #[serde(default = "default_agent_window_secs")]
    pub agent_window_secs: u64,

    /// Maximum number of distinct user agents per IP within
    /// `agent_window_secs` before the detector flags `AgentRotation`.
    #[serde(default = "default_agent_threshold")]
    pub agent_threshold: u32,
}

impl Default for AntiAbuseConfig {
    fn default() -> Self {
        Self {
            // Disabled by default — the middleware is not registered in
            // the router yet. Operators flip this to `true` once the
            // router builder wraps the authenticated subrouter with
            // `AntiAbuseLayer`.
            enabled: false,
            replay_window_secs: default_replay_window_secs(),
            rate_window_secs: default_rate_window_secs(),
            rate_anomaly_multiplier: default_rate_anomaly_multiplier(),
            rate_min_samples: default_rate_min_samples(),
            agent_window_secs: default_agent_window_secs(),
            agent_threshold: default_agent_threshold(),
        }
    }
}

impl AntiAbuseConfig {
    /// Cross-field invariants checked by the loader.
    ///
    /// Disabled configs always pass. Enabled configs enforce that every
    /// numeric threshold is strictly positive and that
    /// `rate_anomaly_multiplier` is finite and greater than 1.0 (anything
    /// less than 1.0 would flag the median itself).
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.replay_window_secs == 0 {
            return Err(crate::ConfigError::invalid(
                "anti_abuse.replay_window_secs",
                "must be greater than zero when enabled",
            ));
        }
        if self.rate_window_secs == 0 {
            return Err(crate::ConfigError::invalid(
                "anti_abuse.rate_window_secs",
                "must be greater than zero when enabled",
            ));
        }
        if !self.rate_anomaly_multiplier.is_finite() || self.rate_anomaly_multiplier <= 1.0 {
            return Err(crate::ConfigError::invalid(
                "anti_abuse.rate_anomaly_multiplier",
                "must be a finite number strictly greater than 1.0",
            ));
        }
        if self.rate_min_samples == 0 {
            return Err(crate::ConfigError::invalid(
                "anti_abuse.rate_min_samples",
                "must be greater than zero when enabled",
            ));
        }
        if self.agent_window_secs == 0 {
            return Err(crate::ConfigError::invalid(
                "anti_abuse.agent_window_secs",
                "must be greater than zero when enabled",
            ));
        }
        if self.agent_threshold == 0 {
            return Err(crate::ConfigError::invalid(
                "anti_abuse.agent_threshold",
                "must be greater than zero when enabled",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::AntiAbuseConfig;

    fn enabled() -> AntiAbuseConfig {
        AntiAbuseConfig {
            enabled: true,
            ..AntiAbuseConfig::default()
        }
    }

    #[test]
    fn default_is_disabled_and_passes_invariants() {
        let cfg = AntiAbuseConfig::default();
        assert!(!cfg.enabled, "shipped disabled by default");
        cfg.check_invariants()
            .expect("disabled config must always pass");
    }

    #[test]
    fn defaults_match_middleware_runtime_values() {
        // These numbers are the SAME numbers as the in-process
        // AntiAbuseConfig::default() inside sx-api. If a future change
        // diverges them, that change should also update this test.
        let cfg = AntiAbuseConfig::default();
        assert_eq!(cfg.replay_window_secs, 5 * 60);
        assert_eq!(cfg.rate_window_secs, 60);
        assert!((cfg.rate_anomaly_multiplier - 3.0).abs() < f64::EPSILON);
        assert_eq!(cfg.rate_min_samples, 4);
        assert_eq!(cfg.agent_window_secs, 10 * 60);
        assert_eq!(cfg.agent_threshold, 5);
    }

    #[test]
    fn enabled_rejects_zero_replay_window() {
        let mut cfg = enabled();
        cfg.replay_window_secs = 0;
        let err = cfg
            .check_invariants()
            .expect_err("zero replay window must be rejected");
        assert!(
            matches!(
                err,
                crate::ConfigError::InvalidValue { ref key, .. }
                if key == "anti_abuse.replay_window_secs"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_rejects_zero_rate_window() {
        let mut cfg = enabled();
        cfg.rate_window_secs = 0;
        let err = cfg
            .check_invariants()
            .expect_err("zero rate window must be rejected");
        assert!(
            matches!(
                err,
                crate::ConfigError::InvalidValue { ref key, .. }
                if key == "anti_abuse.rate_window_secs"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_rejects_zero_rate_min_samples() {
        let mut cfg = enabled();
        cfg.rate_min_samples = 0;
        let err = cfg
            .check_invariants()
            .expect_err("zero rate_min_samples must be rejected");
        assert!(
            matches!(
                err,
                crate::ConfigError::InvalidValue { ref key, .. }
                if key == "anti_abuse.rate_min_samples"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_rejects_zero_agent_window() {
        let mut cfg = enabled();
        cfg.agent_window_secs = 0;
        let err = cfg
            .check_invariants()
            .expect_err("zero agent window must be rejected");
        assert!(
            matches!(
                err,
                crate::ConfigError::InvalidValue { ref key, .. }
                if key == "anti_abuse.agent_window_secs"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_rejects_zero_agent_threshold() {
        let mut cfg = enabled();
        cfg.agent_threshold = 0;
        let err = cfg
            .check_invariants()
            .expect_err("zero agent_threshold must be rejected");
        assert!(
            matches!(
                err,
                crate::ConfigError::InvalidValue { ref key, .. }
                if key == "anti_abuse.agent_threshold"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_rejects_non_finite_multiplier() {
        let mut cfg = enabled();
        cfg.rate_anomaly_multiplier = f64::NAN;
        let err = cfg
            .check_invariants()
            .expect_err("NaN multiplier must be rejected");
        assert!(
            matches!(
                err,
                crate::ConfigError::InvalidValue { ref key, .. }
                if key == "anti_abuse.rate_anomaly_multiplier"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_rejects_multiplier_at_or_below_one() {
        let mut cfg = enabled();
        cfg.rate_anomaly_multiplier = 1.0;
        let err = cfg
            .check_invariants()
            .expect_err("multiplier 1.0 must be rejected");
        assert!(
            matches!(
                err,
                crate::ConfigError::InvalidValue { ref key, .. }
                if key == "anti_abuse.rate_anomaly_multiplier"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn disabled_config_skips_all_invariants() {
        let cfg = AntiAbuseConfig {
            enabled: false,
            replay_window_secs: 0,
            rate_window_secs: 0,
            rate_anomaly_multiplier: 0.0,
            rate_min_samples: 0,
            agent_window_secs: 0,
            agent_threshold: 0,
        };
        cfg.check_invariants()
            .expect("disabled config must skip every threshold check");
    }

    #[test]
    fn enabled_with_valid_thresholds_passes() {
        enabled()
            .check_invariants()
            .expect("default-derived enabled config must pass");
    }
}
