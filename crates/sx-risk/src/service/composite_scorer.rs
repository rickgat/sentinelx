//! Pure composite scoring service.
//!
//! Implements the weighted formula documented at the crate root:
//!
//! ```text
//! score = w_severity        * normalize(severity_to_score(severity))
//!       + w_exploit         * normalize(exploit_score(epss, kev))
//!       + w_exposure        * normalize(exposure_score(level))
//!       + w_criticality     * normalize(criticality_score(level))
//!       + w_business_impact * normalize(business_score(business_impact))
//!       + w_chain           * normalize(chain_score(chain_amplifier))
//! ```
//!
//! Each `normalize(x)` divides `x` by the sum of the weights so the final
//! score is bounded to `0.0..=100.0`. All weights / lookups come from
//! [`crate::model::RiskScoringConfig`]; **nothing** is hardcoded here.

use sx_core::value_object::severity::{Severity, SeverityBands};

use crate::error::RiskError;
use crate::model::{ComponentScore, RiskInput, RiskScore, RiskScoringConfig};

/// Pure, deterministic composite scorer.
#[derive(Debug, Clone)]
pub struct CompositeScorer {
    cfg: RiskScoringConfig,
    severity_bands: SeverityBands,
    weight_sum: f64,
}

impl CompositeScorer {
    /// Construct and validate.
    ///
    /// `severity_bands` is used to translate a CVSS envelope into a
    /// [`Severity`] when one is present on the input. It is supplied
    /// separately because the canonical band table lives in `sx-core`.
    pub fn new(cfg: RiskScoringConfig, severity_bands: SeverityBands) -> Result<Self, RiskError> {
        cfg.validate()?;
        let weight_sum = cfg.core.weights.sum();
        if weight_sum <= 0.0 || !weight_sum.is_finite() {
            return Err(RiskError::config("weight sum must be > 0 and finite"));
        }
        Ok(Self {
            cfg,
            severity_bands,
            weight_sum,
        })
    }

    /// Borrow the underlying configuration.
    #[must_use]
    pub const fn config(&self) -> &RiskScoringConfig {
        &self.cfg
    }

    /// Compute the composite score and per-component breakdown.
    ///
    /// The function is **pure** — identical inputs always produce
    /// identical outputs.
    pub fn score(&self, input: &RiskInput) -> Result<(RiskScore, ComponentScore), RiskError> {
        let severity = input.effective_severity(self.severity_bands)?;
        let severity_raw = self.severity_raw(severity);
        let exploit_raw = self.exploit_raw(input)?;
        let exposure_raw = self.exposure_raw(input)?;
        let criticality_raw = self.criticality_raw(input)?;
        let business_raw = self.business_raw(input)?;
        let chain_raw = self.chain_raw(input);

        // Each component is bounded to 0..=10 (or 0..=100 for chain — we
        // rescale below). Multiplying by the weight and dividing by the
        // sum of weights produces a per-component contribution in
        // 0..=(10 * w_i / sum_w). The final composite is then scaled by
        // *10* so the engine emits a 0..=100 range.
        //
        // Equivalently: each `normalize(raw)` returns `raw * 10 / sum_w`,
        // so the per-component contribution is `w_i * raw * 10 / sum_w`.
        // For the chain component, whose `raw` is already 0..=100, we
        // divide by 10 first so the same scaling applies.
        let w = &self.cfg.core.weights;
        let scale = 10.0 / self.weight_sum;

        let severity_part = w.w_severity * severity_raw * scale;
        let exploit_part = w.w_exploit * exploit_raw * scale;
        let exposure_part = w.w_exposure * exposure_raw * scale;
        let criticality_part = w.w_criticality * criticality_raw * scale;
        let business_part = w.w_business_impact * business_raw * scale;
        // chain_raw is 0..=100; bring it onto the 0..=10 plane first.
        let chain_part = w.w_chain * (chain_raw / 10.0) * scale;

        let total = severity_part
            + exploit_part
            + exposure_part
            + criticality_part
            + business_part
            + chain_part;

        // Defensive clamp: floating-point arithmetic on inputs at the
        // boundary may produce a `100.000000000001`-style value.
        let total = total.clamp(0.0, 100.0);
        let score = RiskScore::new(total)?;
        let components = ComponentScore {
            severity_part,
            exploit_part,
            exposure_part,
            criticality_part,
            business_part,
            chain_part,
        };
        Ok((score, components))
    }

    fn severity_raw(&self, sev: Severity) -> f64 {
        self.cfg.severity_band_scores.get(sev)
    }

    fn exploit_raw(&self, input: &RiskInput) -> Result<f64, RiskError> {
        // EPSS probability is 0..=1. Multiplied by 10 it sits on the same
        // 0..=10 plane as the other raw components. KEV applies a
        // multiplicative boost from config.
        let prob = input
            .epss
            .as_ref()
            .map_or(0.0, |score| f64::from(score.probability));
        let base = (prob * 10.0).clamp(0.0, 10.0);
        let boosted = if input.kev {
            base * self.cfg.core.kev_boost_factor
        } else {
            base
        };
        if !boosted.is_finite() {
            return Err(RiskError::internal(
                "exploit_score produced a non-finite value",
            ));
        }
        Ok(boosted.clamp(0.0, 10.0))
    }

    fn exposure_raw(&self, input: &RiskInput) -> Result<f64, RiskError> {
        self.cfg
            .exposure_scores
            .get(&input.exposure)
            .copied()
            .ok_or_else(|| {
                RiskError::config(format!(
                    "exposure_scores missing entry for {}",
                    input.exposure
                ))
            })
    }

    fn criticality_raw(&self, input: &RiskInput) -> Result<f64, RiskError> {
        self.cfg
            .criticality_scores
            .get(&input.criticality)
            .copied()
            .ok_or_else(|| {
                RiskError::config(format!(
                    "criticality_scores missing entry for {}",
                    input.criticality
                ))
            })
    }

    fn business_raw(&self, input: &RiskInput) -> Result<f64, RiskError> {
        self.cfg
            .business_impact_scores
            .get(&input.business_impact)
            .copied()
            .ok_or_else(|| {
                RiskError::config(format!(
                    "business_impact_scores missing entry for {:?}",
                    input.business_impact
                ))
            })
    }

    fn chain_raw(&self, input: &RiskInput) -> f64 {
        self.cfg
            .chain_amplifier_band
            .map(input.chain_amplifier.value())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use sx_config::schema::risk::{CompositeWeights, RiskConfig};
    use sx_core::value_object::{
        criticality::AssetCriticality, cvss::CvssScore, epss::EpssScore, exposure::ExposureLevel,
        severity::SeverityBands,
    };

    use crate::model::{BusinessImpact, ChainAmplifier};

    fn nist_bands() -> SeverityBands {
        SeverityBands::new(0.1, 4.0, 7.0, 9.0).unwrap()
    }

    fn default_scorer() -> CompositeScorer {
        let cfg = RiskScoringConfig::sentinelx_default().unwrap();
        CompositeScorer::new(cfg, nist_bands()).unwrap()
    }

    fn baseline_input() -> RiskInput {
        RiskInput::new(
            Some(CvssScore::v3_only(9.8).unwrap()),
            None,
            Some(EpssScore::new(0.9, 0.99).unwrap()),
            true,
            ExposureLevel::Internet,
            AssetCriticality::CrownJewel,
            BusinessImpact::Critical,
            ChainAmplifier::new(2.0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn worst_case_inputs_yield_max_score() {
        let scorer = default_scorer();
        let (score, _) = scorer.score(&baseline_input()).unwrap();
        // With KEV boost applied to a max-probability EPSS the exploit
        // component is clamped at 10.0; every other component is also
        // its max value, so the score should be 100.
        assert!(
            (score.value() - 100.0).abs() < 1e-6,
            "got {}",
            score.value()
        );
    }

    #[test]
    fn no_signal_inputs_yield_zero_ish_score() {
        let scorer = default_scorer();
        let input = RiskInput::new(
            None,
            Some(Severity::Info),
            None,
            false,
            ExposureLevel::Isolated,
            AssetCriticality::Dev,
            BusinessImpact::None,
            ChainAmplifier::new(1.0).unwrap(),
        )
        .unwrap();
        let (score, _) = scorer.score(&input).unwrap();
        // Severity=Info -> 0; EPSS=None -> 0; Isolated -> 0; Dev -> 1.0;
        // BusinessImpact::None -> 0; chain -> 0. Only Dev contributes.
        // The expected raw is 1.0, weighted by 0.15 / 1.00 * 10 = 1.5.
        assert!((score.value() - 1.5).abs() < 1e-6, "got {}", score.value());
    }

    #[test]
    fn exact_known_good_uniform_weights() {
        // Uniform weights so the maths is auditable by hand.
        let weights = CompositeWeights {
            w_severity: 1.0,
            w_exploit: 1.0,
            w_exposure: 1.0,
            w_criticality: 1.0,
            w_business_impact: 1.0,
            w_chain: 1.0,
        };
        let core = RiskConfig {
            weights,
            kev_boost_factor: 1.0, // No boost so the maths is clean.
            epss_threshold_act: 0.5,
        };
        let mut cfg = RiskScoringConfig::sentinelx_default().unwrap();
        cfg.core = core;
        let scorer = CompositeScorer::new(cfg, nist_bands()).unwrap();
        // CVSS 7.5 -> Severity::High -> raw 8.0
        // EPSS 0.3 -> raw 3.0 (no KEV)
        // Exposure::Internal -> raw 5.0
        // Criticality::Production -> raw 8.0
        // BusinessImpact::Medium -> raw 5.0
        // ChainAmplifier 1.5 -> raw 50 -> 5.0 on the 0..=10 plane
        // Sum of raws = 34.0
        // scale = 10 / sum_weights = 10/6 ≈ 1.6667
        // score = sum(raw_i * 1 * 10/6) = 34 * 10/6 ≈ 56.6667
        let input = RiskInput::new(
            Some(CvssScore::v3_only(7.5).unwrap()),
            None,
            Some(EpssScore::new(0.3, 0.7).unwrap()),
            false,
            ExposureLevel::Internal,
            AssetCriticality::Production,
            BusinessImpact::Medium,
            ChainAmplifier::new(1.5).unwrap(),
        )
        .unwrap();
        let (score, comp) = scorer.score(&input).unwrap();
        let expected = 34.0 * 10.0 / 6.0;
        assert!(
            (score.value() - expected).abs() < 1e-6,
            "got {}, expected {expected}",
            score.value(),
        );
        // Sum of components recovers the composite.
        assert!((comp.total() - score.value()).abs() < 1e-6);
    }

    #[test]
    fn kev_strictly_boosts_score() {
        let scorer = default_scorer();
        let base = RiskInput::new(
            Some(CvssScore::v3_only(5.0).unwrap()),
            None,
            Some(EpssScore::new(0.4, 0.7).unwrap()),
            false,
            ExposureLevel::Internal,
            AssetCriticality::Production,
            BusinessImpact::Medium,
            ChainAmplifier::identity(),
        )
        .unwrap();
        let mut with_kev = base.clone();
        with_kev.kev = true;
        let (no_kev, _) = scorer.score(&base).unwrap();
        let (kev, _) = scorer.score(&with_kev).unwrap();
        assert!(
            kev.value() > no_kev.value(),
            "KEV must boost: no_kev={} kev={}",
            no_kev.value(),
            kev.value(),
        );
    }

    #[test]
    fn rejects_zero_weights() {
        let weights = CompositeWeights {
            w_severity: 0.0,
            w_exploit: 0.0,
            w_exposure: 0.0,
            w_criticality: 0.0,
            w_business_impact: 0.0,
            w_chain: 0.0,
        };
        let core = RiskConfig {
            weights,
            kev_boost_factor: 1.0,
            epss_threshold_act: 0.5,
        };
        let mut cfg = RiskScoringConfig::sentinelx_default().unwrap();
        cfg.core = core;
        assert!(CompositeScorer::new(cfg, nist_bands()).is_err());
    }

    #[test]
    fn deterministic() {
        let scorer = default_scorer();
        let input = baseline_input();
        let (a, _) = scorer.score(&input).unwrap();
        let (b, _) = scorer.score(&input).unwrap();
        assert_eq!(a, b);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn monotonic_in_cvss(
            cvss_a in 0.0f32..=10.0,
            delta in 0.0f32..=10.0,
        ) {
            let scorer = default_scorer();
            let cvss_b = (cvss_a + delta).min(10.0);
            let make = |c: f32| RiskInput::new(
                Some(CvssScore::v3_only(c).unwrap()),
                None,
                Some(EpssScore::new(0.5, 0.5).unwrap()),
                false,
                ExposureLevel::Internal,
                AssetCriticality::Production,
                BusinessImpact::Medium,
                ChainAmplifier::identity(),
            ).unwrap();
            let (sa, _) = scorer.score(&make(cvss_a)).unwrap();
            let (sb, _) = scorer.score(&make(cvss_b)).unwrap();
            // Severity moves in steps so we assert non-decreasing.
            prop_assert!(sb.value() >= sa.value() - 1e-9);
        }

        #[test]
        fn monotonic_in_epss(
            p_a in 0.0f32..=1.0,
            delta in 0.0f32..=1.0,
        ) {
            let scorer = default_scorer();
            let p_b = (p_a + delta).min(1.0);
            let make = |p: f32| RiskInput::new(
                Some(CvssScore::v3_only(7.0).unwrap()),
                None,
                Some(EpssScore::new(p, p).unwrap()),
                false,
                ExposureLevel::Internal,
                AssetCriticality::Production,
                BusinessImpact::Medium,
                ChainAmplifier::identity(),
            ).unwrap();
            let (sa, _) = scorer.score(&make(p_a)).unwrap();
            let (sb, _) = scorer.score(&make(p_b)).unwrap();
            prop_assert!(sb.value() >= sa.value() - 1e-9);
        }

        #[test]
        fn monotonic_in_chain_amplifier(
            a_lo in 1.0f64..=2.0,
            delta in 0.0f64..=1.0,
        ) {
            let scorer = default_scorer();
            let a_hi = (a_lo + delta).min(2.0);
            let make = |a: f64| RiskInput::new(
                Some(CvssScore::v3_only(7.0).unwrap()),
                None,
                Some(EpssScore::new(0.5, 0.5).unwrap()),
                false,
                ExposureLevel::Internal,
                AssetCriticality::Production,
                BusinessImpact::Medium,
                ChainAmplifier::new(a).unwrap(),
            ).unwrap();
            let (sa, _) = scorer.score(&make(a_lo)).unwrap();
            let (sb, _) = scorer.score(&make(a_hi)).unwrap();
            prop_assert!(sb.value() >= sa.value() - 1e-9);
        }
    }
}
