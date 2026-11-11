//! Risk scoring configuration.
//!
//! `SentinelX` combines several signals into a single composite risk score;
//! the weights, KEV boost, and EPSS act-threshold all come from here so
//! that risk-policy changes do not require a redeploy.

use serde::Deserialize;
use validator::Validate;

/// Weights applied to each component of the composite risk score.
///
/// Weights are absolute (not required to sum to 1.0) but their sum must
/// be strictly greater than zero, otherwise the composite would always be
/// zero.
///
/// The `w_` prefix on every field is intentional: it mirrors the published
/// risk-model spec and gives auditors a stable identifier to reference.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct CompositeWeights {
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

impl CompositeWeights {
    /// Sum of all weights.
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

/// Top-level risk configuration.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct RiskConfig {
    /// Weights for each component of the composite score.
    #[validate(nested)]
    pub weights: CompositeWeights,

    /// Multiplicative boost applied when a finding is on CISA's Known
    /// Exploited Vulnerabilities (KEV) catalogue.
    #[validate(range(min = 1.0))]
    pub kev_boost_factor: f64,

    /// EPSS probability at or above which a finding is auto-elevated to
    /// "act now" priority. Must be in `[0, 1]`.
    #[validate(range(min = 0.0, max = 1.0))]
    pub epss_threshold_act: f64,
}

impl RiskConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        let sum = self.weights.sum();
        if !sum.is_finite() {
            return Err(crate::ConfigError::invalid(
                "risk.weights",
                "weight sum must be a finite number",
            ));
        }
        if sum <= 0.0 {
            return Err(crate::ConfigError::invalid(
                "risk.weights",
                "sum of weights must be > 0",
            ));
        }
        if !self.epss_threshold_act.is_finite() {
            return Err(crate::ConfigError::invalid(
                "risk.epss_threshold_act",
                "must be a finite number",
            ));
        }
        if !self.kev_boost_factor.is_finite() {
            return Err(crate::ConfigError::invalid(
                "risk.kev_boost_factor",
                "must be a finite number",
            ));
        }
        Ok(())
    }
}
