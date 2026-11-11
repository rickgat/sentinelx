//! # sx-risk
//!
//! Risk scoring engine for `SentinelX`.
//!
//! ## Responsibilities
//!
//! This crate produces two artefacts from a normalised vulnerability +
//! asset context:
//!
//! 1. a composite [`RiskScore`](crate::model::RiskScore) in `0.0..=100.0`
//!    accompanied by a per-component [`ComponentScore`](crate::model::ComponentScore)
//!    breakdown, and
//! 2. a CISA SSVC v2.0 [`SsvcDecision`](crate::model::SsvcDecision)
//!    (Act / Attend / Track / Track*).
//!
//! ## Layering
//!
//! - `model::*` — pure data types, every numeric value validated at
//!   construction; no I/O.
//! - `view::*` — JSON-friendly projections returned by the controllers.
//! - `service::*` — pure scorer + SSVC mapper + the [`EpssProvider`] and
//!   [`KevProvider`] ports.
//! - `controller::*` — async use-case orchestrators that combine the
//!   ports with the services.
//!
//! ## Configuration-driven
//!
//! Nothing is hardcoded. Weights, lookup tables, the KEV boost, the EPSS
//! act-threshold, score-bands and the SSVC rulebook all flow through
//! [`crate::model::RiskScoringConfig`], which itself wraps
//! [`sx_config::schema::risk::RiskConfig`] for the cross-cutting policy
//! fields.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod controller;
pub mod error;
pub mod model;
pub mod prelude;
pub mod service;
pub mod tenant_tuning;
pub mod view;

pub use error::RiskError;

use sx_config::schema::risk::CompositeWeights;
use sx_config::schema::risk_weights::RiskWeightsConfig;
use sx_core::value_object::severity::SeverityBands;

use crate::model::{RiskInput, RiskScoringConfig};
use crate::service::CompositeScorer;

/// Value-object mirror of [`sx_config::RiskWeightsConfig`] used by the
/// scorer at runtime.
///
/// `sx-config` owns the on-the-wire shape (with serde + validator
/// derives). `sx-risk` re-exports the same six fields here as a pure
/// value object so that callers wiring up a tenant override do not need
/// to depend on `sx-config` directly.
///
/// The conversion between [`RiskWeights`] and
/// [`sx_config::RiskWeightsConfig`] is a total, lossless field-for-field
/// copy.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct RiskWeights {
    /// Weight on CVSS severity.
    pub w_severity: f64,
    /// Weight on EPSS exploit-likelihood.
    pub w_exploit: f64,
    /// Weight on internet-facing exposure.
    pub w_exposure: f64,
    /// Weight on asset criticality.
    pub w_criticality: f64,
    /// Weight on business impact (revenue / compliance).
    pub w_business_impact: f64,
    /// Weight on attack-chain reachability.
    pub w_chain: f64,
}

impl RiskWeights {
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

impl From<RiskWeightsConfig> for RiskWeights {
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

impl From<RiskWeights> for RiskWeightsConfig {
    fn from(w: RiskWeights) -> Self {
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

impl From<CompositeWeights> for RiskWeights {
    fn from(w: CompositeWeights) -> Self {
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

impl From<RiskWeights> for CompositeWeights {
    fn from(w: RiskWeights) -> Self {
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

/// Compute the composite risk score using a caller-supplied
/// [`RiskWeights`] override (typically loaded from the
/// `tenant_risk_weights` table for the active tenant).
///
/// The platform-wide scorer's `core.weights` are temporarily replaced
/// with `weights` for the duration of the call; every other policy
/// field — KEV boost, EPSS threshold, score bands, lookup tables — is
/// inherited from `base_cfg`.
///
/// This is the "weights overload" referenced by P1-014. The existing
/// platform-default calculator (`CompositeScorer::score`) stays in
/// place for backward compatibility with callers that do not opt into
/// per-tenant overrides.
///
/// # Errors
/// * [`RiskError::Config`] if `weights` would build an invalid scorer
///   (sum non-finite or `<= 0`),
/// * any error surfaced by [`CompositeScorer::score`].
pub fn calculate_with_weights(
    base_cfg: &RiskScoringConfig,
    bands: SeverityBands,
    input: &RiskInput,
    weights: RiskWeights,
) -> Result<f64, RiskError> {
    let mut cfg = base_cfg.clone();
    cfg.core.weights = weights.into();
    let scorer = CompositeScorer::new(cfg, bands)?;
    let (score, _components) = scorer.score(input)?;
    Ok(score.value())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use sx_config::schema::risk_weights::RiskWeightsConfig;
    use sx_core::value_object::{
        criticality::AssetCriticality, cvss::CvssScore, epss::EpssScore, exposure::ExposureLevel,
    };

    use crate::model::{BusinessImpact, ChainAmplifier};

    fn bands() -> SeverityBands {
        SeverityBands::new(0.1, 4.0, 7.0, 9.0).unwrap()
    }

    fn base_cfg() -> RiskScoringConfig {
        RiskScoringConfig::sentinelx_default().unwrap()
    }

    fn input(crit: AssetCriticality) -> RiskInput {
        RiskInput::new(
            Some(CvssScore::v3_only(7.5).unwrap()),
            None,
            Some(EpssScore::new(0.3, 0.7).unwrap()),
            false,
            ExposureLevel::Internal,
            crit,
            BusinessImpact::Medium,
            ChainAmplifier::new(1.5).unwrap(),
        )
        .unwrap()
    }

    fn balanced_weights() -> RiskWeights {
        RiskWeights {
            w_severity: 0.25,
            w_exploit: 0.20,
            w_exposure: 0.15,
            w_criticality: 0.20,
            w_business_impact: 0.15,
            w_chain: 0.05,
        }
    }

    fn criticality_dominant_weights() -> RiskWeights {
        // Criticality dominates (sum still = 1.0).
        RiskWeights {
            w_severity: 0.10,
            w_exploit: 0.10,
            w_exposure: 0.10,
            w_criticality: 0.50,
            w_business_impact: 0.10,
            w_chain: 0.10,
        }
    }

    #[test]
    fn risk_weights_roundtrip_with_config() {
        let cfg: RiskWeightsConfig = balanced_weights().into();
        let back: RiskWeights = cfg.into();
        assert_eq!(balanced_weights(), back);
    }

    #[test]
    fn calculate_with_weights_matches_default_scorer_for_default_weights() {
        // Using the same weights the scorer is built with should
        // reproduce the platform-default score exactly.
        let cfg = base_cfg();
        let w: RiskWeights = cfg.core.weights.clone().into();
        let inp = input(AssetCriticality::Production);
        let default_scorer = CompositeScorer::new(cfg.clone(), bands()).unwrap();
        let (expected, _) = default_scorer.score(&inp).unwrap();
        let got = calculate_with_weights(&cfg, bands(), &inp, w).unwrap();
        assert!(
            (got - expected.value()).abs() < 1e-9,
            "got {got}, expected {}",
            expected.value()
        );
    }

    #[test]
    fn criticality_dominant_weights_rank_crown_jewel_above_dev() {
        // With criticality dominating the weight vector, swapping
        // AssetCriticality::CrownJewel for AssetCriticality::Dev must
        // produce a strictly higher score even though every other
        // input is identical.
        let cfg = base_cfg();
        let w = criticality_dominant_weights();
        let crown =
            calculate_with_weights(&cfg, bands(), &input(AssetCriticality::CrownJewel), w).unwrap();
        let dev = calculate_with_weights(&cfg, bands(), &input(AssetCriticality::Dev), w).unwrap();
        assert!(
            crown > dev,
            "criticality-dominant weights must rank crown jewel above dev: crown={crown}, \
             dev={dev}"
        );
    }

    #[test]
    fn criticality_dominant_weights_amplify_criticality_gap() {
        // The gap between a crown-jewel asset and a dev asset should be
        // wider under criticality-dominant weights than under balanced
        // weights.
        let cfg = base_cfg();
        let balanced = balanced_weights();
        let skewed = criticality_dominant_weights();

        let crown_balanced = calculate_with_weights(
            &cfg,
            bands(),
            &input(AssetCriticality::CrownJewel),
            balanced,
        )
        .unwrap();
        let dev_balanced =
            calculate_with_weights(&cfg, bands(), &input(AssetCriticality::Dev), balanced).unwrap();
        let crown_skewed =
            calculate_with_weights(&cfg, bands(), &input(AssetCriticality::CrownJewel), skewed)
                .unwrap();
        let dev_skewed =
            calculate_with_weights(&cfg, bands(), &input(AssetCriticality::Dev), skewed).unwrap();

        let balanced_gap = crown_balanced - dev_balanced;
        let skewed_gap = crown_skewed - dev_skewed;
        assert!(
            skewed_gap > balanced_gap,
            "skewed_gap {skewed_gap} should exceed balanced_gap {balanced_gap}"
        );
    }

    #[test]
    fn calculate_with_weights_rejects_all_zero_weights() {
        let cfg = base_cfg();
        let zero = RiskWeights {
            w_severity: 0.0,
            w_exploit: 0.0,
            w_exposure: 0.0,
            w_criticality: 0.0,
            w_business_impact: 0.0,
            w_chain: 0.0,
        };
        let err = calculate_with_weights(&cfg, bands(), &input(AssetCriticality::Production), zero)
            .expect_err("zero-sum weights must be rejected by the scorer");
        assert!(matches!(err, RiskError::Config(_)));
    }

    #[test]
    fn risk_weights_sum_matches_components() {
        let w = balanced_weights();
        assert!((w.sum() - 1.0).abs() < 1e-9);
    }
}
