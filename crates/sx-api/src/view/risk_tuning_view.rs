//! Per-tenant risk-model tuning view types (P1-014).
//!
//! Wire-side DTOs returned by `GET /v1/risk/config` and accepted by
//! `PUT /v1/risk/config`, plus the merged-effective shape returned by
//! `GET /v1/risk/config/effective`.
//!
//! The view types intentionally mirror the [`sx_config`] schema rather
//! than depending on it directly so the public API can evolve
//! independently of the config crate.

use serde::{Deserialize, Serialize};
use sx_config::schema::risk_weights::{
    WEIGHTS_SUM_MAX as CONFIG_WEIGHTS_SUM_MAX, WEIGHTS_SUM_MIN as CONFIG_WEIGHTS_SUM_MIN,
};
use sx_config::schema::tenant_risk::{
    EffectiveRiskConfig, RiskThresholdsConfig, TenantRiskOverride,
};
use validator::{Validate, ValidationError};

/// Wire form of [`sx_config::RiskWeightsConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct RiskWeightsView {
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
    /// Weight on business impact.
    #[validate(range(min = 0.0))]
    pub w_business_impact: f64,
    /// Weight on attack-chain reachability.
    #[validate(range(min = 0.0))]
    pub w_chain: f64,
}

impl RiskWeightsView {
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
}

impl From<sx_config::RiskWeightsConfig> for RiskWeightsView {
    fn from(w: sx_config::RiskWeightsConfig) -> Self {
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

impl From<RiskWeightsView> for sx_config::RiskWeightsConfig {
    fn from(w: RiskWeightsView) -> Self {
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

/// Wire form of [`sx_config::RiskThresholdsConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct RiskThresholdsView {
    /// Inclusive lower bound for `Low`.
    #[validate(range(min = 0.0, max = 100.0))]
    pub low: f64,
    /// Inclusive lower bound for `Medium`.
    #[validate(range(min = 0.0, max = 100.0))]
    pub med: f64,
    /// Inclusive lower bound for `High`.
    #[validate(range(min = 0.0, max = 100.0))]
    pub high: f64,
    /// Inclusive lower bound for `Critical`.
    #[validate(range(min = 0.0, max = 100.0))]
    pub crit: f64,
}

impl From<RiskThresholdsConfig> for RiskThresholdsView {
    fn from(t: RiskThresholdsConfig) -> Self {
        Self {
            low: t.low,
            med: t.med,
            high: t.high,
            crit: t.crit,
        }
    }
}

impl From<RiskThresholdsView> for RiskThresholdsConfig {
    fn from(t: RiskThresholdsView) -> Self {
        Self {
            low: t.low,
            med: t.med,
            high: t.high,
            crit: t.crit,
        }
    }
}

/// Wire form of [`TenantRiskOverride`] — accepted by `PUT
/// /v1/risk/config`, returned by `GET /v1/risk/config`.
///
/// Both fields are sparse: an operator may PUT a body with only
/// `weights`, only `thresholds`, or both. Absent fields inherit the
/// platform defaults at merge time.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Validate, Default)]
#[serde(deny_unknown_fields)]
#[validate(schema(function = "validate_tenant_risk_config"))]
pub struct TenantRiskConfigView {
    /// Optional per-tenant weights override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub weights: Option<RiskWeightsView>,
    /// Optional per-tenant threshold override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub thresholds: Option<RiskThresholdsView>,
}

/// Cross-field validation: weights sum within `[WEIGHTS_SUM_MIN,
/// WEIGHTS_SUM_MAX]` when present, thresholds strictly monotonic
/// ascending when present.
///
/// Returning a [`ValidationError`] surfaces the failure to the
/// `ValidatedJson` extractor which maps it to `422 Unprocessable
/// Entity`.
fn validate_tenant_risk_config(v: &TenantRiskConfigView) -> Result<(), ValidationError> {
    if let Some(w) = &v.weights {
        let sum = w.sum();
        if !sum.is_finite() {
            let mut e = ValidationError::new("weights_sum_finite");
            e.add_param("got".into(), &sum);
            return Err(e);
        }
        if !(CONFIG_WEIGHTS_SUM_MIN..=CONFIG_WEIGHTS_SUM_MAX).contains(&sum) {
            let mut e = ValidationError::new("weights_sum_band");
            e.add_param("got".into(), &sum);
            e.add_param("min".into(), &CONFIG_WEIGHTS_SUM_MIN);
            e.add_param("max".into(), &CONFIG_WEIGHTS_SUM_MAX);
            return Err(e);
        }
    }
    if let Some(t) = &v.thresholds {
        if !(t.low < t.med && t.med < t.high && t.high < t.crit) {
            let e = ValidationError::new("thresholds_monotone");
            return Err(e);
        }
    }
    Ok(())
}

impl From<TenantRiskOverride> for TenantRiskConfigView {
    fn from(o: TenantRiskOverride) -> Self {
        Self {
            weights: o.weights.map(Into::into),
            thresholds: o.thresholds.map(Into::into),
        }
    }
}

impl From<TenantRiskConfigView> for TenantRiskOverride {
    fn from(v: TenantRiskConfigView) -> Self {
        Self {
            weights: v.weights.map(Into::into),
            thresholds: v.thresholds.map(Into::into),
        }
    }
}

/// Wire form of [`EffectiveRiskConfig`] — returned by `GET
/// /v1/risk/config/effective`. Always concrete (no optional fields).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveRiskConfigView {
    /// Effective composite weights.
    pub weights: RiskWeightsView,
    /// Effective score-band thresholds.
    pub thresholds: RiskThresholdsView,
}

impl From<EffectiveRiskConfig> for EffectiveRiskConfigView {
    fn from(e: EffectiveRiskConfig) -> Self {
        Self {
            weights: e.weights.into(),
            thresholds: e.thresholds.into(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    fn balanced() -> RiskWeightsView {
        RiskWeightsView {
            w_severity: 0.25,
            w_exploit: 0.20,
            w_exposure: 0.15,
            w_criticality: 0.20,
            w_business_impact: 0.15,
            w_chain: 0.05,
        }
    }

    fn default_thresholds() -> RiskThresholdsView {
        RiskThresholdsView {
            low: 25.0,
            med: 50.0,
            high: 75.0,
            crit: 90.0,
        }
    }

    #[test]
    fn empty_override_validates_ok() {
        let v = TenantRiskConfigView::default();
        assert!(v.validate().is_ok());
    }

    #[test]
    fn balanced_override_validates_ok() {
        let v = TenantRiskConfigView {
            weights: Some(balanced()),
            thresholds: Some(default_thresholds()),
        };
        assert!(v.validate().is_ok());
    }

    #[test]
    fn sum_out_of_band_rejected() {
        let bad = RiskWeightsView {
            w_severity: 0.50,
            w_exploit: 0.50,
            w_exposure: 0.10,
            w_criticality: 0.10,
            w_business_impact: 0.10,
            w_chain: 0.20,
        };
        let v = TenantRiskConfigView {
            weights: Some(bad),
            thresholds: None,
        };
        assert!(v.validate().is_err());
    }

    #[test]
    fn non_monotone_thresholds_rejected() {
        let bad = RiskThresholdsView {
            low: 50.0,
            med: 40.0,
            high: 70.0,
            crit: 90.0,
        };
        let v = TenantRiskConfigView {
            weights: None,
            thresholds: Some(bad),
        };
        assert!(v.validate().is_err());
    }

    #[test]
    fn negative_weight_rejected() {
        let bad = RiskWeightsView {
            w_severity: -0.10,
            w_exploit: 0.30,
            w_exposure: 0.20,
            w_criticality: 0.20,
            w_business_impact: 0.20,
            w_chain: 0.20,
        };
        let v = TenantRiskConfigView {
            weights: Some(bad),
            thresholds: None,
        };
        assert!(v.validate().is_err());
    }

    #[test]
    fn out_of_range_threshold_rejected() {
        let bad = RiskThresholdsView {
            low: 25.0,
            med: 50.0,
            high: 75.0,
            crit: 101.0, // > 100
        };
        let v = TenantRiskConfigView {
            weights: None,
            thresholds: Some(bad),
        };
        assert!(v.validate().is_err());
    }

    #[test]
    fn serde_round_trip_omits_absent_fields() {
        let v = TenantRiskConfigView {
            weights: Some(balanced()),
            thresholds: None,
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(
            !s.contains("thresholds"),
            "wire form must omit absent thresholds: {s}"
        );
        let back: TenantRiskConfigView = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn deny_unknown_field_rejected() {
        let raw = r#"{"weights": null, "thresholds": null, "ghost": 1}"#;
        assert!(serde_json::from_str::<TenantRiskConfigView>(raw).is_err());
    }

    #[test]
    fn override_view_round_trips_with_domain() {
        let view = TenantRiskConfigView {
            weights: Some(balanced()),
            thresholds: Some(default_thresholds()),
        };
        let domain: TenantRiskOverride = view.into();
        let back: TenantRiskConfigView = domain.into();
        assert_eq!(view, back);
    }

    #[test]
    fn effective_view_round_trips() {
        let eff = EffectiveRiskConfig {
            weights: sx_config::RiskWeightsConfig {
                w_severity: 0.25,
                w_exploit: 0.20,
                w_exposure: 0.15,
                w_criticality: 0.20,
                w_business_impact: 0.15,
                w_chain: 0.05,
            },
            thresholds: RiskThresholdsConfig::sentinelx_default(),
        };
        let view: EffectiveRiskConfigView = eff.into();
        let s = serde_json::to_string(&view).unwrap();
        let back: EffectiveRiskConfigView = serde_json::from_str(&s).unwrap();
        assert_eq!(view, back);
    }
}
