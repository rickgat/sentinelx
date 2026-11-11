//! Per-tenant risk-model tuning configuration (P1-014).
//!
//! `RiskConfig::weights` ([`crate::schema::risk::CompositeWeights`]) and
//! [`crate::schema::risk_weights::RiskWeightsConfig`] carry the
//! **process-wide** defaults for the composite scoring formula. P1-014
//! introduces a per-tenant **sparse override** of:
//!
//! - the six composite weights (`w_severity` … `w_chain`), and
//! - the four score-band thresholds that classify a `0..=100` composite
//!   into a [`sx_core::value_object::severity::Severity`].
//!
//! ## Sparse merge
//!
//! `TenantRiskOverride` is intentionally `Option`-heavy: each field is
//! independent and any subset can be omitted, which lets an operator
//! tweak a single dial without specifying every other knob. The
//! "effective" config is computed by [`EffectiveRiskConfig::merge`]
//! which layers the override on top of the platform defaults — present
//! fields win, absent fields inherit.
//!
//! ## Invariants
//!
//! When the operator supplies weights they MUST sum to `1.0 ± 0.01`
//! (same window as [`crate::schema::risk_weights::RiskWeightsConfig`]).
//! When the operator supplies thresholds they MUST be:
//!
//! 1. each finite and in `[0.0, 100.0]`, and
//! 2. strictly monotonic ascending — `low < med < high < crit`.
//!
//! Both invariants are validated **on the override** before merge so
//! that a partially-tuned tenant is never able to install a vector that
//! the global scorer would reject.

use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::schema::risk_weights::RiskWeightsConfig;

/// Score-band thresholds (P1-014).
///
/// Four inclusive lower-bounds, all in `[0.0, 100.0]`, that classify a
/// composite score into a [`sx_core::value_object::severity::Severity`]:
///
/// - `score < low`           → `Info`,
/// - `low  <= score < med`   → `Low`,
/// - `med  <= score < high`  → `Medium`,
/// - `high <= score < crit`  → `High`,
/// - `crit <= score`         → `Critical`.
///
/// The four values MUST be strictly monotonic ascending so the buckets
/// do not overlap.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct RiskThresholdsConfig {
    /// Inclusive lower bound for the `Low` band.
    #[validate(range(min = 0.0, max = 100.0))]
    pub low: f64,
    /// Inclusive lower bound for the `Medium` band.
    #[validate(range(min = 0.0, max = 100.0))]
    pub med: f64,
    /// Inclusive lower bound for the `High` band.
    #[validate(range(min = 0.0, max = 100.0))]
    pub high: f64,
    /// Inclusive lower bound for the `Critical` band.
    #[validate(range(min = 0.0, max = 100.0))]
    pub crit: f64,
}

impl RiskThresholdsConfig {
    /// Platform default thresholds, matching the example
    /// `sentinelx.example.yaml`.
    #[must_use]
    pub const fn sentinelx_default() -> Self {
        Self {
            low: 25.0,
            med: 50.0,
            high: 75.0,
            crit: 90.0,
        }
    }

    /// Cross-field invariant: every threshold finite, in `[0, 100]`,
    /// and strictly monotonic ascending.
    pub fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        for (name, v) in [
            ("low", self.low),
            ("med", self.med),
            ("high", self.high),
            ("crit", self.crit),
        ] {
            if !v.is_finite() {
                return Err(crate::ConfigError::invalid(
                    format!("risk_thresholds.{name}"),
                    "must be a finite number",
                ));
            }
            if !(0.0..=100.0).contains(&v) {
                return Err(crate::ConfigError::invalid(
                    format!("risk_thresholds.{name}"),
                    "must be in [0.0, 100.0]",
                ));
            }
        }
        if !(self.low < self.med && self.med < self.high && self.high < self.crit) {
            return Err(crate::ConfigError::invalid(
                "risk_thresholds",
                "thresholds must be strictly monotonic ascending: low < med < high < crit",
            ));
        }
        Ok(())
    }
}

impl Default for RiskThresholdsConfig {
    fn default() -> Self {
        Self::sentinelx_default()
    }
}

/// Per-tenant **sparse** override of the platform composite risk model.
///
/// Every field is independently `Option`-typed so the operator can tune
/// a single dial without restating every default. Absent fields inherit
/// from the platform-wide defaults at merge time
/// ([`EffectiveRiskConfig::merge`]).
///
/// When `weights` is present the override's six fields MUST satisfy the
/// `1.0 ± 0.01` invariant exactly like a process-wide
/// [`RiskWeightsConfig`]. When `thresholds` is present they MUST be
/// finite, in `[0, 100]`, and strictly monotonic ascending.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize, Validate, Default)]
#[serde(deny_unknown_fields)]
pub struct TenantRiskOverride {
    /// Optional per-tenant composite weights override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub weights: Option<RiskWeightsConfig>,

    /// Optional per-tenant score-band threshold override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub thresholds: Option<RiskThresholdsConfig>,
}

impl TenantRiskOverride {
    /// An empty override — every field absent, every dial inherits the
    /// platform default. This is the row stored for a freshly-created
    /// tenant.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            weights: None,
            thresholds: None,
        }
    }

    /// `true` when the override touches **no** dials at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.weights.is_none() && self.thresholds.is_none()
    }

    /// Cross-field invariants. Called on the override **before** the
    /// merge so that a tenant cannot install a vector the global scorer
    /// would reject.
    pub fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if let Some(w) = &self.weights {
            w.check_invariants()?;
        }
        if let Some(t) = &self.thresholds {
            t.check_invariants()?;
        }
        Ok(())
    }
}

/// **Effective** risk configuration after merging an override into the
/// platform defaults. Always concrete — no optional fields.
///
/// This is the shape the scorer consumes once the per-tenant tuning has
/// been resolved. Construction always goes through
/// [`Self::merge`], which enforces both the per-field invariants and the
/// cross-field invariants on the resulting object.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveRiskConfig {
    /// Effective composite weights (six fields, sum in `1.0 ± 0.01`).
    pub weights: RiskWeightsConfig,
    /// Effective score-band thresholds (`low < med < high < crit`).
    pub thresholds: RiskThresholdsConfig,
}

impl EffectiveRiskConfig {
    /// Layer a [`TenantRiskOverride`] on top of the platform defaults.
    ///
    /// Present fields on the override win; absent fields inherit the
    /// default. The resulting [`EffectiveRiskConfig`] is validated
    /// (`check_invariants` on weights and thresholds) so the caller can
    /// substitute the returned struct into the scorer with confidence.
    ///
    /// # Errors
    /// * [`crate::ConfigError::InvalidValue`] if the merged weights or
    ///   thresholds fail their invariants.
    pub fn merge(
        defaults_weights: RiskWeightsConfig,
        defaults_thresholds: RiskThresholdsConfig,
        override_: &TenantRiskOverride,
    ) -> Result<Self, crate::ConfigError> {
        // Validate the override **first** so an obviously bad payload
        // never leaks into the merged config.
        override_.check_invariants()?;

        let effective = Self {
            weights: override_.weights.unwrap_or(defaults_weights),
            thresholds: override_.thresholds.unwrap_or(defaults_thresholds),
        };
        effective.weights.check_invariants()?;
        effective.thresholds.check_invariants()?;
        Ok(effective)
    }

    /// Pretty-print a structured diff against another effective config
    /// — used by the audit layer to record what changed. Returns a
    /// JSON-compatible map of `field -> {"old": …, "new": …}` entries
    /// for every weight or threshold that differs by more than `1e-9`.
    ///
    /// The diff is **never** the bearer or any secret; it is the
    /// numeric vectors only.
    #[must_use]
    pub fn diff(&self, other: &Self) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        let pairs: [(&str, f64, f64); 10] = [
            (
                "weights.w_severity",
                self.weights.w_severity,
                other.weights.w_severity,
            ),
            (
                "weights.w_exploit",
                self.weights.w_exploit,
                other.weights.w_exploit,
            ),
            (
                "weights.w_exposure",
                self.weights.w_exposure,
                other.weights.w_exposure,
            ),
            (
                "weights.w_criticality",
                self.weights.w_criticality,
                other.weights.w_criticality,
            ),
            (
                "weights.w_business_impact",
                self.weights.w_business_impact,
                other.weights.w_business_impact,
            ),
            (
                "weights.w_chain",
                self.weights.w_chain,
                other.weights.w_chain,
            ),
            ("thresholds.low", self.thresholds.low, other.thresholds.low),
            ("thresholds.med", self.thresholds.med, other.thresholds.med),
            (
                "thresholds.high",
                self.thresholds.high,
                other.thresholds.high,
            ),
            (
                "thresholds.crit",
                self.thresholds.crit,
                other.thresholds.crit,
            ),
        ];
        for (k, old, new) in pairs {
            if (old - new).abs() > 1e-9 {
                out.insert(k.to_owned(), serde_json::json!({"old": old, "new": new}));
            }
        }
        serde_json::Value::Object(out)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    fn balanced_weights() -> RiskWeightsConfig {
        RiskWeightsConfig {
            w_severity: 0.25,
            w_exploit: 0.20,
            w_exposure: 0.15,
            w_criticality: 0.20,
            w_business_impact: 0.15,
            w_chain: 0.05,
        }
    }

    fn default_thresholds() -> RiskThresholdsConfig {
        RiskThresholdsConfig::sentinelx_default()
    }

    #[test]
    fn empty_override_inherits_all_defaults() {
        let eff = EffectiveRiskConfig::merge(
            balanced_weights(),
            default_thresholds(),
            &TenantRiskOverride::empty(),
        )
        .unwrap();
        assert_eq!(eff.weights, balanced_weights());
        assert_eq!(eff.thresholds, default_thresholds());
    }

    #[test]
    fn weights_only_override_keeps_default_thresholds() {
        let custom = RiskWeightsConfig {
            w_severity: 0.10,
            w_exploit: 0.10,
            w_exposure: 0.10,
            w_criticality: 0.50,
            w_business_impact: 0.10,
            w_chain: 0.10,
        };
        let ovr = TenantRiskOverride {
            weights: Some(custom),
            thresholds: None,
        };
        let eff =
            EffectiveRiskConfig::merge(balanced_weights(), default_thresholds(), &ovr).unwrap();
        assert_eq!(eff.weights, custom);
        assert_eq!(eff.thresholds, default_thresholds()); // inherited
    }

    #[test]
    fn thresholds_only_override_keeps_default_weights() {
        let custom = RiskThresholdsConfig {
            low: 10.0,
            med: 30.0,
            high: 60.0,
            crit: 85.0,
        };
        let ovr = TenantRiskOverride {
            weights: None,
            thresholds: Some(custom),
        };
        let eff =
            EffectiveRiskConfig::merge(balanced_weights(), default_thresholds(), &ovr).unwrap();
        assert_eq!(eff.weights, balanced_weights()); // inherited
        assert_eq!(eff.thresholds, custom);
    }

    #[test]
    fn invalid_weights_rejected_at_merge() {
        let bad = RiskWeightsConfig {
            w_severity: 0.50,
            w_exploit: 0.50, // sum = 1.5, outside [0.99, 1.01]
            w_exposure: 0.10,
            w_criticality: 0.10,
            w_business_impact: 0.10,
            w_chain: 0.20,
        };
        let ovr = TenantRiskOverride {
            weights: Some(bad),
            thresholds: None,
        };
        let err = EffectiveRiskConfig::merge(balanced_weights(), default_thresholds(), &ovr)
            .expect_err("out-of-band sum must be rejected");
        assert!(matches!(err, crate::ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn non_monotonic_thresholds_rejected() {
        let bad = RiskThresholdsConfig {
            low: 50.0,
            med: 40.0, // less than low — violates strict-monotone
            high: 70.0,
            crit: 90.0,
        };
        let ovr = TenantRiskOverride {
            weights: None,
            thresholds: Some(bad),
        };
        let err = EffectiveRiskConfig::merge(balanced_weights(), default_thresholds(), &ovr)
            .expect_err("non-monotonic thresholds must be rejected");
        assert!(matches!(err, crate::ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn equal_thresholds_rejected_strict_monotone() {
        let bad = RiskThresholdsConfig {
            low: 25.0,
            med: 25.0, // equal — strict-monotone forbids ties
            high: 75.0,
            crit: 90.0,
        };
        let err = bad
            .check_invariants()
            .expect_err("equal thresholds must be rejected by strict monotone");
        assert!(matches!(err, crate::ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn out_of_range_threshold_rejected() {
        let bad = RiskThresholdsConfig {
            low: -1.0, // below 0
            med: 30.0,
            high: 60.0,
            crit: 90.0,
        };
        assert!(bad.check_invariants().is_err());

        let bad2 = RiskThresholdsConfig {
            low: 10.0,
            med: 30.0,
            high: 60.0,
            crit: 100.5, // above 100
        };
        assert!(bad2.check_invariants().is_err());
    }

    #[test]
    fn diff_skips_unchanged_fields() {
        let a = EffectiveRiskConfig {
            weights: balanced_weights(),
            thresholds: default_thresholds(),
        };
        let mut b = a;
        b.weights.w_severity = 0.30; // changed
        b.weights.w_exploit = 0.15; // changed (keeps sum stable)
        b.thresholds.crit = 95.0; // changed
        let d = a.diff(&b);
        let map = d.as_object().unwrap();
        assert!(map.contains_key("weights.w_severity"));
        assert!(map.contains_key("weights.w_exploit"));
        assert!(map.contains_key("thresholds.crit"));
        assert!(!map.contains_key("weights.w_chain"));
        assert!(!map.contains_key("thresholds.low"));
    }

    #[test]
    fn diff_empty_for_equal_configs() {
        let a = EffectiveRiskConfig {
            weights: balanced_weights(),
            thresholds: default_thresholds(),
        };
        let d = a.diff(&a);
        assert!(d.as_object().unwrap().is_empty());
    }

    #[test]
    fn override_serde_round_trip_omits_absent_fields() {
        let ovr = TenantRiskOverride {
            weights: Some(balanced_weights()),
            thresholds: None,
        };
        let s = serde_json::to_string(&ovr).unwrap();
        // `thresholds` absent on the wire because skip_serializing_if.
        assert!(
            !s.contains("thresholds"),
            "wire form should omit absent thresholds: {s}"
        );
        let back: TenantRiskOverride = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ovr);
    }

    #[test]
    fn override_serde_deny_unknown_fields() {
        let bad = r#"{"weights": null, "thresholds": null, "ghost": 1}"#;
        assert!(serde_json::from_str::<TenantRiskOverride>(bad).is_err());
    }

    #[test]
    fn weights_sum_bounds_re_exported_constants() {
        // Confirm we re-use the same window as the platform-wide config.
        use crate::schema::risk_weights::{WEIGHTS_SUM_MAX, WEIGHTS_SUM_MIN};
        assert!((WEIGHTS_SUM_MIN - 0.99).abs() < 1e-9);
        assert!((WEIGHTS_SUM_MAX - 1.01).abs() < 1e-9);
    }
}
