//! Per-tenant composite risk-weight configuration (P1-014).
//!
//! `RiskConfig::weights` ([`crate::schema::risk::CompositeWeights`]) carries
//! the **process-wide** composite weights that are pinned at boot. P1-014
//! introduces a per-tenant override of the same six weights that can be
//! tuned at runtime by a platform operator (and, eventually, persisted in
//! the `tenant_risk_weights` table guarded by Row-Level Security).
//!
//! This module defines the strongly-typed configuration / value-object
//! [`RiskWeightsConfig`] shipped from `sx-config` and reused by `sx-risk`
//! and `sx-storage`. The struct intentionally mirrors `CompositeWeights`
//! field-for-field (same `w_*` prefix, same units) so the two are trivially
//! convertible, but enforces an additional **sum-in-band** invariant that
//! the cross-cutting weights deliberately leave open: a per-tenant weight
//! vector MUST sum to `1.0 ± 0.01` so the resulting composite stays in the
//! same `0.0..=100.0` plane as the platform-wide formula.
//!
//! The `±0.01` tolerance is required to accommodate ordinary `f64`
//! rounding error when an operator types out six three-decimal weights in
//! YAML. The matching SQL `CHECK` constraint
//! (`weights_sum_in_range`) on the `tenant_risk_weights` table uses the
//! exact same `[0.99, 1.01]` window so the validator and the database
//! cannot disagree.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Inclusive lower bound on the sum of the six per-tenant weights.
pub const WEIGHTS_SUM_MIN: f64 = 0.99;

/// Inclusive upper bound on the sum of the six per-tenant weights.
pub const WEIGHTS_SUM_MAX: f64 = 1.01;

/// Per-tenant composite risk-scoring weights.
///
/// Mirrors [`crate::schema::risk::CompositeWeights`] one-for-one so a
/// `RiskWeightsConfig` can be substituted for the process-wide weights
/// inside the scorer. Each field is a non-negative finite `f64`; the sum
/// MUST sit in `[WEIGHTS_SUM_MIN, WEIGHTS_SUM_MAX]` (i.e. `1.0 ± 0.01`)
/// so the composite score stays bounded to the published `0.0..=100.0`
/// plane.
///
/// The validator allows `±0.01` of rounding tolerance so that an operator
/// can supply six three-decimal weights in YAML without tripping the
/// invariant on the last bit of `f64` precision.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct RiskWeightsConfig {
    /// Weight on CVSS severity.
    #[validate(range(min = 0.0))]
    pub w_severity: f64,

    /// Weight on EPSS exploit-likelihood.
    #[validate(range(min = 0.0))]
    pub w_exploit: f64,

    /// Weight on internet-facing exposure.
    #[validate(range(min = 0.0))]
    pub w_exposure: f64,

    /// Weight on asset criticality.
    #[validate(range(min = 0.0))]
    pub w_criticality: f64,

    /// Weight on business impact (revenue / compliance).
    #[validate(range(min = 0.0))]
    pub w_business_impact: f64,

    /// Weight on attack-chain reachability.
    #[validate(range(min = 0.0))]
    pub w_chain: f64,
}

impl RiskWeightsConfig {
    /// Sum of all six weights.
    #[must_use]
    pub fn sum(&self) -> f64 {
        self.w_severity
            + self.w_exploit
            + self.w_exposure
            + self.w_criticality
            + self.w_business_impact
            + self.w_chain
    }

    /// Cross-field invariant: every field finite, non-negative, and the
    /// sum within `[WEIGHTS_SUM_MIN, WEIGHTS_SUM_MAX]`.
    ///
    /// Called by the loader after the per-field `Validate` derive has
    /// already confirmed each `w_*` is `>= 0.0`.
    pub fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        for (name, v) in [
            ("w_severity", self.w_severity),
            ("w_exploit", self.w_exploit),
            ("w_exposure", self.w_exposure),
            ("w_criticality", self.w_criticality),
            ("w_business_impact", self.w_business_impact),
            ("w_chain", self.w_chain),
        ] {
            if !v.is_finite() {
                return Err(crate::ConfigError::invalid(
                    format!("risk_weights.{name}"),
                    "must be a finite number",
                ));
            }
            if v < 0.0 {
                return Err(crate::ConfigError::invalid(
                    format!("risk_weights.{name}"),
                    "must be >= 0",
                ));
            }
        }
        let sum = self.sum();
        if !sum.is_finite() {
            return Err(crate::ConfigError::invalid(
                "risk_weights",
                "weight sum must be a finite number",
            ));
        }
        if !(WEIGHTS_SUM_MIN..=WEIGHTS_SUM_MAX).contains(&sum) {
            return Err(crate::ConfigError::invalid(
                "risk_weights",
                format!(
                    "sum of weights must be in [{WEIGHTS_SUM_MIN}, {WEIGHTS_SUM_MAX}] (1.0 \
                     +/- 0.01), got {sum}"
                ),
            ));
        }
        Ok(())
    }
}

impl Default for RiskWeightsConfig {
    /// Default per-tenant weights match the values shipped in the example
    /// `risk:` section of `sentinelx.example.yaml` (and the
    /// `RiskScoringConfig::sentinelx_default` factory in `sx-risk`),
    /// adjusted so that the per-tenant invariant `sum == 1.0` holds.
    ///
    /// The published vector — `[0.25, 0.20, 0.15, 0.20, 0.15, 0.05]` —
    /// sums to exactly `1.0` and is used both here and in the YAML
    /// example so the validator and the example file agree out of the
    /// box.
    fn default() -> Self {
        Self {
            w_severity: 0.25,
            w_exploit: 0.20,
            w_exposure: 0.15,
            w_criticality: 0.20,
            w_business_impact: 0.15,
            w_chain: 0.05,
        }
    }
}

impl From<crate::schema::risk::CompositeWeights> for RiskWeightsConfig {
    fn from(w: crate::schema::risk::CompositeWeights) -> Self {
        Self {
            w_severity: w.w_severity,
            w_exploit: w.w_exploit,
            w_exposure: w.w_exposure,
            w_criticality: w.w_criticality,
            w_business_impact: w.w_business_impact,
            w_chain: w.w_chain,
        }
    }
}

impl From<RiskWeightsConfig> for crate::schema::risk::CompositeWeights {
    fn from(w: RiskWeightsConfig) -> Self {
        Self {
            w_severity: w.w_severity,
            w_exploit: w.w_exploit,
            w_exposure: w.w_exposure,
            w_criticality: w.w_criticality,
            w_business_impact: w.w_business_impact,
            w_chain: w.w_chain,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn balanced() -> RiskWeightsConfig {
        RiskWeightsConfig {
            w_severity: 0.25,
            w_exploit: 0.20,
            w_exposure: 0.15,
            w_criticality: 0.20,
            w_business_impact: 0.15,
            w_chain: 0.05,
        }
    }

    #[test]
    fn default_satisfies_invariants() {
        let cfg = RiskWeightsConfig::default();
        cfg.check_invariants()
            .expect("default config must satisfy invariants");
        assert!((cfg.sum() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn validator_accepts_sum_exactly_one() {
        balanced()
            .check_invariants()
            .expect("sum == 1.0 must be accepted");
    }

    #[test]
    fn validator_accepts_sum_at_lower_tolerance() {
        // 0.99 sum — extreme but inside the band.
        let cfg = RiskWeightsConfig {
            w_severity: 0.20,
            w_exploit: 0.20,
            w_exposure: 0.15,
            w_criticality: 0.20,
            w_business_impact: 0.19,
            w_chain: 0.05,
        };
        assert!((cfg.sum() - 0.99).abs() < 1e-9);
        cfg.check_invariants()
            .expect("sum == 0.99 must be accepted");
    }

    #[test]
    fn validator_accepts_sum_at_upper_tolerance() {
        // 1.01 sum — extreme but inside the band.
        let cfg = RiskWeightsConfig {
            w_severity: 0.26,
            w_exploit: 0.20,
            w_exposure: 0.15,
            w_criticality: 0.20,
            w_business_impact: 0.15,
            w_chain: 0.05,
        };
        assert!((cfg.sum() - 1.01).abs() < 1e-9);
        cfg.check_invariants()
            .expect("sum == 1.01 must be accepted");
    }

    #[test]
    fn validator_rejects_sum_too_low() {
        // 0.8 sum — well below the lower tolerance.
        let cfg = RiskWeightsConfig {
            w_severity: 0.20,
            w_exploit: 0.15,
            w_exposure: 0.10,
            w_criticality: 0.15,
            w_business_impact: 0.15,
            w_chain: 0.05,
        };
        assert!((cfg.sum() - 0.8).abs() < 1e-9);
        let err = cfg
            .check_invariants()
            .expect_err("sum = 0.8 must be rejected");
        match err {
            crate::ConfigError::InvalidValue { key, reason } => {
                assert_eq!(key, "risk_weights");
                assert!(
                    reason.contains("sum of weights"),
                    "reason should mention sum, got: {reason}"
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn validator_rejects_sum_too_high() {
        // 1.5 sum — well above the upper tolerance.
        let cfg = RiskWeightsConfig {
            w_severity: 0.30,
            w_exploit: 0.25,
            w_exposure: 0.20,
            w_criticality: 0.30,
            w_business_impact: 0.30,
            w_chain: 0.15,
        };
        assert!((cfg.sum() - 1.5).abs() < 1e-9);
        let err = cfg
            .check_invariants()
            .expect_err("sum = 1.5 must be rejected");
        assert!(matches!(err, crate::ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn validator_rejects_negative_weight() {
        let cfg = RiskWeightsConfig {
            w_severity: -0.10,
            w_exploit: 0.30,
            w_exposure: 0.15,
            w_criticality: 0.25,
            w_business_impact: 0.25,
            w_chain: 0.15,
        };
        let err = cfg
            .check_invariants()
            .expect_err("negative weight must be rejected");
        match err {
            crate::ConfigError::InvalidValue { key, .. } => {
                assert_eq!(key, "risk_weights.w_severity");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn validator_rejects_nan_weight() {
        let cfg = RiskWeightsConfig {
            w_severity: f64::NAN,
            w_exploit: 0.20,
            w_exposure: 0.15,
            w_criticality: 0.20,
            w_business_impact: 0.15,
            w_chain: 0.05,
        };
        let err = cfg
            .check_invariants()
            .expect_err("NaN weight must be rejected");
        match err {
            crate::ConfigError::InvalidValue { key, reason } => {
                assert_eq!(key, "risk_weights.w_severity");
                assert!(reason.contains("finite"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn roundtrip_with_composite_weights() {
        // RiskWeightsConfig -> CompositeWeights -> RiskWeightsConfig
        let original = balanced();
        let cw: crate::schema::risk::CompositeWeights = original.into();
        let back: RiskWeightsConfig = cw.into();
        assert!((back.w_severity - original.w_severity).abs() < 1e-12);
        assert!((back.w_exploit - original.w_exploit).abs() < 1e-12);
        assert!((back.w_exposure - original.w_exposure).abs() < 1e-12);
        assert!((back.w_criticality - original.w_criticality).abs() < 1e-12);
        assert!((back.w_business_impact - original.w_business_impact).abs() < 1e-12);
        assert!((back.w_chain - original.w_chain).abs() < 1e-12);
    }

    #[test]
    fn json_roundtrip_accepts_balanced_vector() {
        // Demonstrates the on-the-wire encoding agrees with the example
        // file `config/sentinelx.example.yaml` (JSON form, since
        // `sx-config` only ever materializes parsed values, never YAML
        // text).
        let json = r#"{
            "w_severity": 0.25,
            "w_exploit": 0.20,
            "w_exposure": 0.15,
            "w_criticality": 0.20,
            "w_business_impact": 0.15,
            "w_chain": 0.05
        }"#;
        let cfg: RiskWeightsConfig = serde_json::from_str(json).expect("json must parse");
        cfg.check_invariants()
            .expect("parsed config must satisfy invariants");
        assert!((cfg.sum() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn deny_unknown_fields_rejects_typos() {
        // `deny_unknown_fields` guards against operators typing
        // `w_busines_impact` (one `s` short) and silently using a
        // platform-side default.
        let json = r#"{
            "w_severity": 0.25,
            "w_exploit": 0.20,
            "w_exposure": 0.15,
            "w_criticality": 0.20,
            "w_busines_impact": 0.15,
            "w_chain": 0.05
        }"#;
        assert!(serde_json::from_str::<RiskWeightsConfig>(json).is_err());
    }
}
