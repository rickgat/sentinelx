//! Per-tenant RBA configuration.
//!
//! Every tenant carries one [`RbaConfig`] holding:
//!
//! * Two thresholds: `allow_threshold` and `block_threshold`. Scores
//!   strictly below `allow_threshold` allow; scores at or above
//!   `block_threshold` block; everything between forces step-up MFA.
//! * One [`RbaWeights`] bundle dictating how each signal contributes
//!   to the composite score.
//! * One [`crate::signals::business_hours::BusinessHours`] window.
//!
//! Defaults match the acceptance criteria in
//! `docs/SECURITY_GAP_REMEDIATION_TASKS.md`:
//!
//! * `allow_threshold = 30`
//! * `block_threshold = 70`
//! * Weights sum to 1.0 across the three MVP signals (IP geo,
//!   velocity, time-of-day).
//!
//! Changes to thresholds / weights through the admin endpoint go
//! through [`RbaConfig::validate`] so an operator cannot install
//! degenerate values.

use serde::{Deserialize, Serialize};

use crate::signals::business_hours::BusinessHours;

/// Default allow threshold — anything strictly under this score is
/// allowed without friction.
pub const DEFAULT_ALLOW_THRESHOLD: i32 = 30;

/// Default block threshold — anything at or above this score is
/// hard-blocked and an alert is raised.
pub const DEFAULT_BLOCK_THRESHOLD: i32 = 70;

/// Minimum legal threshold value (0 disables the bucket).
pub const MIN_THRESHOLD: i32 = 0;
/// Maximum legal threshold value (100 disables the bucket).
pub const MAX_THRESHOLD: i32 = 100;

/// Per-signal weights. Each component is `0.0..=1.0`; the sum is
/// expected to be ~1.0 (we tolerate `[0.99, 1.01]` like the existing
/// risk-weights migration) so callers can express "ignore this signal"
/// by setting its weight to 0.
///
/// HIGH-001 introduced four additional signals (device fingerprint,
/// MFA recency, prior success rate, impossible travel). The legacy
/// three weights were rebalanced so the new ones sum to `0.55`;
/// per-tenant overrides via the P1-014 risk-tuning path can dial
/// individual signals up or down as long as `validate()` remains green.
///
/// Runtime toggles for each signal live on [`RbaFeatureFlags`] — flip
/// `enable_*` to `false` to skip the signal entirely (it is then NOT
/// included in the weighted average, even if its weight is non-zero).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RbaWeights {
    /// Weight applied to the IP-geo contribution.
    pub w_ip_geo: f64,
    /// Weight applied to the velocity contribution.
    pub w_velocity: f64,
    /// Weight applied to the business-hours contribution.
    pub w_business_hours: f64,
    /// Weight applied to the device-fingerprint contribution (HIGH-001).
    #[serde(default = "default_w_device_fp")]
    pub w_device_fp: f64,
    /// Weight applied to the MFA-recency contribution (HIGH-001).
    #[serde(default = "default_w_mfa_recent")]
    pub w_mfa_recent: f64,
    /// Weight applied to the 7-day success-rate contribution (HIGH-001).
    #[serde(default = "default_w_success_rate")]
    pub w_success_rate: f64,
    /// Weight applied to the impossible-travel contribution (HIGH-001).
    #[serde(default = "default_w_impossible_travel")]
    pub w_impossible_travel: f64,
}

fn default_w_device_fp() -> f64 {
    0.15
}
fn default_w_mfa_recent() -> f64 {
    0.10
}
fn default_w_success_rate() -> f64 {
    0.05
}
fn default_w_impossible_travel() -> f64 {
    0.15
}

impl Default for RbaWeights {
    fn default() -> Self {
        Self {
            w_ip_geo: 0.25,
            w_velocity: 0.20,
            w_business_hours: 0.10,
            w_device_fp: default_w_device_fp(),
            w_mfa_recent: default_w_mfa_recent(),
            w_success_rate: default_w_success_rate(),
            w_impossible_travel: default_w_impossible_travel(),
        }
    }
}

impl RbaWeights {
    /// Total weight across every signal.
    #[must_use]
    pub fn sum(&self) -> f64 {
        self.w_ip_geo
            + self.w_velocity
            + self.w_business_hours
            + self.w_device_fp
            + self.w_mfa_recent
            + self.w_success_rate
            + self.w_impossible_travel
    }
}

/// Runtime feature-flag bundle for the RBA signals.
///
/// Each [`crate::signals::RiskSignal`] consults its toggle before
/// contributing to the composite score. A signal whose flag is `false`
/// is excluded from the weighted average entirely (its weight is NOT
/// silently rebalanced — the remaining signals divide by the reduced
/// sum) and its sub-score still lands in the audit row tagged as
/// `disabled: true` so the SOC can correlate.
///
/// Defaults enable every signal — a brand-new tenant gets the full
/// enrichment surface. Operators can dial individual signals off
/// (`enable_impossible_travel = false`, say, while a noisy GeoIP feed
/// is being investigated) without forcing a config-table migration.
// 7 bool toggles is the natural surface for the per-signal enrichment
// switches (HIGH-001). A state-machine / bitmask refactor would just
// hide the same information behind a less debuggable API.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RbaFeatureFlags {
    /// IP-geo signal toggle.
    #[serde(default = "default_true")]
    pub enable_ip_geo: bool,
    /// Velocity signal toggle.
    #[serde(default = "default_true")]
    pub enable_velocity: bool,
    /// Business-hours signal toggle.
    #[serde(default = "default_true")]
    pub enable_business_hours: bool,
    /// Device-fingerprint signal toggle (HIGH-001).
    #[serde(default = "default_true")]
    pub enable_device_fp: bool,
    /// MFA-recency signal toggle (HIGH-001).
    #[serde(default = "default_true")]
    pub enable_mfa_recent: bool,
    /// 7-day success-rate signal toggle (HIGH-001).
    #[serde(default = "default_true")]
    pub enable_success_rate: bool,
    /// Impossible-travel signal toggle (HIGH-001).
    #[serde(default = "default_true")]
    pub enable_impossible_travel: bool,
}

fn default_true() -> bool {
    true
}

impl Default for RbaFeatureFlags {
    fn default() -> Self {
        Self {
            enable_ip_geo: true,
            enable_velocity: true,
            enable_business_hours: true,
            enable_device_fp: true,
            enable_mfa_recent: true,
            enable_success_rate: true,
            enable_impossible_travel: true,
        }
    }
}

impl RbaFeatureFlags {
    /// Convenience: turn EVERY signal off. Useful in unit tests that
    /// want to assert the scorer falls back to "baseline" when nothing
    /// is enabled.
    #[must_use]
    pub fn all_off() -> Self {
        Self {
            enable_ip_geo: false,
            enable_velocity: false,
            enable_business_hours: false,
            enable_device_fp: false,
            enable_mfa_recent: false,
            enable_success_rate: false,
            enable_impossible_travel: false,
        }
    }
}

/// Errors raised while validating a configuration update.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RbaConfigError {
    /// A threshold was outside the legal `[0, 100]` range.
    #[error("threshold out of range: {field}={value}")]
    ThresholdOutOfRange {
        /// `allow_threshold` or `block_threshold`.
        field: &'static str,
        /// Value supplied.
        value: i32,
    },
    /// `allow_threshold >= block_threshold` would collapse the
    /// step-up bucket.
    #[error("allow_threshold ({allow}) must be < block_threshold ({block})")]
    InvertedThresholds {
        /// Supplied allow value.
        allow: i32,
        /// Supplied block value.
        block: i32,
    },
    /// A weight was negative.
    #[error("weight {field} must be >= 0 (got {value})")]
    NegativeWeight {
        /// Which weight.
        field: &'static str,
        /// Value supplied.
        value: f64,
    },
    /// The weights did not sum to approximately 1.0.
    #[error("weights must sum to ~1.0 (got {sum})")]
    WeightSumOutOfRange {
        /// Actual sum.
        sum: f64,
    },
    /// The business-hours window was invalid.
    #[error("business hours invalid: {0}")]
    BusinessHours(String),
}

/// Per-tenant configuration bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RbaConfig {
    /// Scores strictly below this allow without friction.
    pub allow_threshold: i32,
    /// Scores at or above this block hard.
    pub block_threshold: i32,
    /// Per-signal weights.
    pub weights: RbaWeights,
    /// Per-signal runtime toggles. Defaults to "everything enabled".
    #[serde(default)]
    pub feature_flags: RbaFeatureFlags,
    /// Business-hours window.
    pub business_hours: BusinessHours,
}

impl Default for RbaConfig {
    fn default() -> Self {
        Self {
            allow_threshold: DEFAULT_ALLOW_THRESHOLD,
            block_threshold: DEFAULT_BLOCK_THRESHOLD,
            weights: RbaWeights::default(),
            feature_flags: RbaFeatureFlags::default(),
            business_hours: BusinessHours::default(),
        }
    }
}

impl RbaConfig {
    /// Validate every field. Returns `Ok(())` if the config is safe to
    /// install.
    pub fn validate(&self) -> Result<(), RbaConfigError> {
        for (field, value) in [
            ("allow_threshold", self.allow_threshold),
            ("block_threshold", self.block_threshold),
        ] {
            if !(MIN_THRESHOLD..=MAX_THRESHOLD).contains(&value) {
                return Err(RbaConfigError::ThresholdOutOfRange { field, value });
            }
        }
        if self.allow_threshold >= self.block_threshold {
            return Err(RbaConfigError::InvertedThresholds {
                allow: self.allow_threshold,
                block: self.block_threshold,
            });
        }
        for (field, value) in [
            ("w_ip_geo", self.weights.w_ip_geo),
            ("w_velocity", self.weights.w_velocity),
            ("w_business_hours", self.weights.w_business_hours),
            ("w_device_fp", self.weights.w_device_fp),
            ("w_mfa_recent", self.weights.w_mfa_recent),
            ("w_success_rate", self.weights.w_success_rate),
            ("w_impossible_travel", self.weights.w_impossible_travel),
        ] {
            if value < 0.0 {
                return Err(RbaConfigError::NegativeWeight { field, value });
            }
        }
        let sum = self.weights.sum();
        if !(0.99..=1.01).contains(&sum) {
            return Err(RbaConfigError::WeightSumOutOfRange { sum });
        }
        self.business_hours
            .validate()
            .map_err(|e| RbaConfigError::BusinessHours(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        RbaConfig::default()
            .validate()
            .expect("defaults must validate");
    }

    #[test]
    fn defaults_match_acceptance_criteria() {
        let c = RbaConfig::default();
        assert_eq!(c.allow_threshold, 30);
        assert_eq!(c.block_threshold, 70);
        let s = c.weights.sum();
        assert!((s - 1.0).abs() < 1e-9, "weights must sum to 1.0, got {s}");
        // HIGH-001: per-signal weights frozen to the acceptance criteria.
        assert!((c.weights.w_ip_geo - 0.25).abs() < 1e-9);
        assert!((c.weights.w_velocity - 0.20).abs() < 1e-9);
        assert!((c.weights.w_business_hours - 0.10).abs() < 1e-9);
        assert!((c.weights.w_device_fp - 0.15).abs() < 1e-9);
        assert!((c.weights.w_mfa_recent - 0.10).abs() < 1e-9);
        assert!((c.weights.w_success_rate - 0.05).abs() < 1e-9);
        assert!((c.weights.w_impossible_travel - 0.15).abs() < 1e-9);
        // HIGH-001: feature flags default to all-on.
        assert!(c.feature_flags.enable_impossible_travel);
        assert!(c.feature_flags.enable_device_fp);
        assert!(c.feature_flags.enable_mfa_recent);
    }

    #[test]
    fn inverted_thresholds_rejected() {
        let c = RbaConfig {
            allow_threshold: 80,
            block_threshold: 50,
            ..Default::default()
        };
        assert!(matches!(
            c.validate().unwrap_err(),
            RbaConfigError::InvertedThresholds { .. }
        ));
    }

    #[test]
    fn out_of_range_threshold_rejected() {
        let c = RbaConfig {
            allow_threshold: -1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate().unwrap_err(),
            RbaConfigError::ThresholdOutOfRange { .. }
        ));
        let c = RbaConfig {
            block_threshold: 200,
            ..Default::default()
        };
        assert!(matches!(
            c.validate().unwrap_err(),
            RbaConfigError::ThresholdOutOfRange { .. }
        ));
    }

    #[test]
    fn negative_weight_rejected() {
        let c = RbaConfig {
            weights: RbaWeights {
                w_ip_geo: -0.1,
                w_velocity: 0.6,
                w_business_hours: 0.5,
                w_device_fp: 0.0,
                w_mfa_recent: 0.0,
                w_success_rate: 0.0,
                w_impossible_travel: 0.0,
            },
            ..Default::default()
        };
        assert!(matches!(
            c.validate().unwrap_err(),
            RbaConfigError::NegativeWeight { .. }
        ));
    }

    #[test]
    fn bad_weight_sum_rejected() {
        let c = RbaConfig {
            weights: RbaWeights {
                w_ip_geo: 0.1,
                w_velocity: 0.1,
                w_business_hours: 0.1,
                w_device_fp: 0.1,
                w_mfa_recent: 0.1,
                w_success_rate: 0.1,
                w_impossible_travel: 0.1,
            },
            ..Default::default()
        };
        assert!(matches!(
            c.validate().unwrap_err(),
            RbaConfigError::WeightSumOutOfRange { .. }
        ));
    }

    #[test]
    fn feature_flags_default_to_all_on() {
        let f = RbaFeatureFlags::default();
        assert!(f.enable_ip_geo);
        assert!(f.enable_velocity);
        assert!(f.enable_business_hours);
        assert!(f.enable_device_fp);
        assert!(f.enable_mfa_recent);
        assert!(f.enable_success_rate);
        assert!(f.enable_impossible_travel);
    }

    #[test]
    fn feature_flags_all_off_disables_every_signal() {
        let f = RbaFeatureFlags::all_off();
        assert!(!f.enable_ip_geo);
        assert!(!f.enable_velocity);
        assert!(!f.enable_business_hours);
        assert!(!f.enable_device_fp);
        assert!(!f.enable_mfa_recent);
        assert!(!f.enable_success_rate);
        assert!(!f.enable_impossible_travel);
    }

    #[test]
    fn feature_flags_round_trip_via_serde() {
        let cfg = RbaConfig {
            feature_flags: RbaFeatureFlags {
                enable_impossible_travel: false,
                ..RbaFeatureFlags::default()
            },
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).expect("serialise");
        let round: RbaConfig = serde_json::from_str(&json).expect("deserialise");
        assert!(!round.feature_flags.enable_impossible_travel);
        assert!(round.feature_flags.enable_ip_geo);
    }

    #[test]
    fn business_hours_validated() {
        let c = RbaConfig {
            business_hours: BusinessHours {
                tz: "UTC".into(),
                start_hour: 20,
                end_hour: 9,
            },
            ..Default::default()
        };
        assert!(matches!(
            c.validate().unwrap_err(),
            RbaConfigError::BusinessHours(_)
        ));
    }
}
