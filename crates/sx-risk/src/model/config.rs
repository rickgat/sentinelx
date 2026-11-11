//! Extended risk-scoring configuration owned by `sx-risk`.
//!
//! `sx_config::RiskConfig` carries the cross-cutting policy fields shared
//! with other crates (composite weights, KEV boost, EPSS act-threshold).
//! `sx-risk` additionally needs:
//!
//! - the numeric **severity band scores** (Info … Critical → 0–10),
//! - the numeric **exposure score lookup** (Unknown … Internet),
//! - the numeric **criticality score lookup** (Unknown … `CrownJewel`),
//! - the linear band used to map `chain_amplifier` into a 0–100 number,
//! - score-band thresholds for translating the composite score back into a
//!   [`sx_core::value_object::severity::Severity`].
//! - the SSVC v2 decision rulebook (which can be overridden by callers).
//!
//! All of these are **configuration**, not constants — they ship with no
//! hardcoded defaults at the workspace level. Tests in this crate construct
//! a `RiskScoringConfig::sentinelx_default()` factory which packages
//! commonly-used policy values; this is the only place a "default" exists,
//! and it is built from explicit named constructors so the values are
//! still auditable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sx_config::schema::risk::RiskConfig;
use sx_core::value_object::{
    criticality::AssetCriticality, exposure::ExposureLevel, severity::Severity,
};

use crate::error::RiskError;
use crate::model::ssvc::{
    AutomatableImpact, Exploitation, HumanImpact, MissionImpact, SsvcDecision, SsvcExposure,
};

/// Per-severity numeric score used to build the `severity_part` of the
/// composite. Values are expected to live in `0.0..=10.0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityBandScores(BTreeMap<Severity, f64>);

impl SeverityBandScores {
    /// Build and validate the table.
    pub fn new(map: BTreeMap<Severity, f64>) -> Result<Self, RiskError> {
        for (sev, v) in &map {
            if !v.is_finite() || !(0.0..=10.0).contains(v) {
                return Err(RiskError::config(format!(
                    "severity_band_scores[{sev}] must be finite in 0.0..=10.0, got {v}",
                )));
            }
        }
        for sev in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            if !map.contains_key(&sev) {
                return Err(RiskError::config(format!(
                    "severity_band_scores is missing entry for {sev}",
                )));
            }
        }
        // Monotonicity: Info <= Low <= Medium <= High <= Critical.
        let order = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        for w in order.windows(2) {
            #[allow(clippy::indexing_slicing)] // windows(2) guarantees w.len() == 2
            let (a, b) = (w[0], w[1]);
            #[allow(clippy::indexing_slicing)]
            let (va, vb) = (map[&a], map[&b]);
            if va > vb {
                return Err(RiskError::config(format!(
                    "severity_band_scores must be monotonic non-decreasing: {a}={va} > {b}={vb}",
                )));
            }
        }
        Ok(Self(map))
    }

    /// Lookup the numeric score for `sev`. Guaranteed to succeed because
    /// [`Self::new`] verified every variant is present.
    #[must_use]
    pub fn get(&self, sev: Severity) -> f64 {
        self.0.get(&sev).copied().unwrap_or(0.0)
    }

    /// Borrow the inner map (read-only).
    #[must_use]
    pub const fn as_map(&self) -> &BTreeMap<Severity, f64> {
        &self.0
    }
}

/// Inclusive lower bounds for translating a composite score (0..=100) back
/// into a [`Severity`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct ScoreBand {
    /// Inclusive lower bound for [`Severity::Low`].
    pub low_min: f64,
    /// Inclusive lower bound for [`Severity::Medium`].
    pub medium_min: f64,
    /// Inclusive lower bound for [`Severity::High`].
    pub high_min: f64,
    /// Inclusive lower bound for [`Severity::Critical`].
    pub critical_min: f64,
}

impl ScoreBand {
    /// Build and validate band thresholds. All values must lie in
    /// `0.0..=100.0` and be monotonically non-decreasing.
    pub fn new(
        low_min: f64,
        medium_min: f64,
        high_min: f64,
        critical_min: f64,
    ) -> Result<Self, RiskError> {
        for (name, v) in [
            ("low_min", low_min),
            ("medium_min", medium_min),
            ("high_min", high_min),
            ("critical_min", critical_min),
        ] {
            if !v.is_finite() || !(0.0..=100.0).contains(&v) {
                return Err(RiskError::config(format!(
                    "score_band.{name} must be finite in 0.0..=100.0, got {v}",
                )));
            }
        }
        if !(low_min <= medium_min && medium_min <= high_min && high_min <= critical_min) {
            return Err(RiskError::config(
                "score_band thresholds must be monotonic non-decreasing",
            ));
        }
        Ok(Self {
            low_min,
            medium_min,
            high_min,
            critical_min,
        })
    }

    /// Map a 0..=100 composite score into a [`Severity`].
    #[must_use]
    pub fn classify(&self, score: f64) -> Severity {
        if score >= self.critical_min {
            Severity::Critical
        } else if score >= self.high_min {
            Severity::High
        } else if score >= self.medium_min {
            Severity::Medium
        } else if score >= self.low_min {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

/// Linear band used to map `chain_amplifier` into a 0..=100 contribution.
///
/// Any amplifier `a < lower` is clamped to `0.0`; any `a > upper` is
/// clamped to `100.0`. Inside the band the contribution is linear.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ChainAmplifierBand {
    /// Lower bound of the band; amplifier values below this yield `0.0`.
    pub lower: f64,
    /// Upper bound of the band; amplifier values above this yield `100.0`.
    pub upper: f64,
}

impl ChainAmplifierBand {
    /// Build and validate the band. `lower` must be strictly less than `upper`.
    pub fn new(lower: f64, upper: f64) -> Result<Self, RiskError> {
        if !lower.is_finite() || !upper.is_finite() {
            return Err(RiskError::config(
                "chain_amplifier_band bounds must be finite",
            ));
        }
        if lower >= upper {
            return Err(RiskError::config(
                "chain_amplifier_band: lower must be < upper",
            ));
        }
        Ok(Self { lower, upper })
    }

    /// Linearly map `amplifier` into `0.0..=100.0`.
    #[must_use]
    pub fn map(&self, amplifier: f64) -> f64 {
        if amplifier <= self.lower {
            0.0
        } else if amplifier >= self.upper {
            100.0
        } else {
            // safe: upper > lower by construction
            let frac = (amplifier - self.lower) / (self.upper - self.lower);
            frac * 100.0
        }
    }
}

/// CISA SSVC v2 decision rulebook.
///
/// The default rulebook implements the published CISA SSVC for Coordinator
/// Stakeholders. Callers can override it via configuration without
/// touching code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsvcRulebook {
    /// Decision rules as tuples — first match wins. Encoded as a flat
    /// table so that it round-trips cleanly through YAML/JSON.
    pub rules: Vec<SsvcRule>,
    /// Decision used when no rule matches (should never happen with the
    /// CISA default rulebook because it is total, but a safety net).
    pub fallback: SsvcDecision,
}

/// A single SSVC decision rule. `None` means "wildcard".
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SsvcRule {
    /// Match condition on [`Exploitation`].
    pub exploitation: Option<Exploitation>,
    /// Match condition on [`SsvcExposure`].
    pub exposure: Option<SsvcExposure>,
    /// Match condition on [`AutomatableImpact`].
    pub automatable: Option<AutomatableImpact>,
    /// Match condition on [`MissionImpact`].
    pub mission_impact: Option<MissionImpact>,
    /// Match condition on [`HumanImpact`].
    pub human_impact: Option<HumanImpact>,
    /// Decision to emit when all match conditions are satisfied.
    pub decision: SsvcDecision,
}

impl SsvcRulebook {
    /// Construct the CISA SSVC v2.0 default for Coordinator Stakeholders.
    ///
    /// Source: <https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf>
    /// The encoding below is a faithful — but admittedly compact — rendering
    /// of the published decision tree. Tests pin the cardinal cases.
    #[must_use]
    #[allow(clippy::too_many_lines)] // verbatim CISA decision table
    pub fn cisa_v2_default() -> Self {
        use AutomatableImpact::{No, Yes};
        use Exploitation::{Active, None as NoneExp, Poc};
        use HumanImpact::{High as HHigh, Low as HLow, Medium as HMedium};
        use MissionImpact::{High as MHigh, Low as MLow, Medium as MMedium};
        use SsvcDecision::{Act, Attend, Track, TrackStar};
        use SsvcExposure::{Controlled, Open, Small};

        let rules: Vec<SsvcRule> = vec![
            // ── Exploitation = Active ────────────────────────────────
            rule(Some(Active), Some(Open), Some(Yes), None, Some(HHigh), Act),
            rule(Some(Active), Some(Open), Some(Yes), Some(MHigh), None, Act),
            rule(
                Some(Active),
                Some(Open),
                Some(Yes),
                Some(MMedium),
                None,
                Attend,
            ),
            rule(
                Some(Active),
                Some(Open),
                Some(Yes),
                Some(MLow),
                None,
                Attend,
            ),
            rule(Some(Active), Some(Open), Some(No), Some(MHigh), None, Act),
            rule(
                Some(Active),
                Some(Open),
                Some(No),
                Some(MMedium),
                None,
                Attend,
            ),
            rule(Some(Active), Some(Open), Some(No), Some(MLow), None, Track),
            rule(
                Some(Active),
                Some(Controlled),
                Some(Yes),
                Some(MHigh),
                None,
                Act,
            ),
            rule(
                Some(Active),
                Some(Controlled),
                Some(Yes),
                Some(MMedium),
                None,
                Attend,
            ),
            rule(
                Some(Active),
                Some(Controlled),
                Some(Yes),
                Some(MLow),
                None,
                Track,
            ),
            rule(
                Some(Active),
                Some(Controlled),
                Some(No),
                Some(MHigh),
                None,
                Attend,
            ),
            rule(
                Some(Active),
                Some(Controlled),
                Some(No),
                Some(MMedium),
                None,
                Track,
            ),
            rule(
                Some(Active),
                Some(Controlled),
                Some(No),
                Some(MLow),
                None,
                Track,
            ),
            rule(
                Some(Active),
                Some(Small),
                Some(Yes),
                Some(MHigh),
                None,
                Attend,
            ),
            rule(
                Some(Active),
                Some(Small),
                Some(Yes),
                Some(MMedium),
                None,
                Track,
            ),
            rule(
                Some(Active),
                Some(Small),
                Some(Yes),
                Some(MLow),
                None,
                Track,
            ),
            rule(Some(Active), Some(Small), Some(No), None, None, Track),
            // ── Exploitation = PoC ───────────────────────────────────
            rule(Some(Poc), Some(Open), Some(Yes), Some(MHigh), None, Attend),
            rule(
                Some(Poc),
                Some(Open),
                Some(Yes),
                Some(MMedium),
                None,
                Attend,
            ),
            rule(Some(Poc), Some(Open), Some(Yes), Some(MLow), None, Track),
            rule(Some(Poc), Some(Open), Some(No), Some(MHigh), None, Attend),
            rule(Some(Poc), Some(Open), Some(No), Some(MMedium), None, Track),
            rule(Some(Poc), Some(Open), Some(No), Some(MLow), None, Track),
            rule(
                Some(Poc),
                Some(Controlled),
                Some(Yes),
                Some(MHigh),
                None,
                Attend,
            ),
            rule(
                Some(Poc),
                Some(Controlled),
                Some(Yes),
                Some(MMedium),
                None,
                Track,
            ),
            rule(
                Some(Poc),
                Some(Controlled),
                Some(Yes),
                Some(MLow),
                None,
                Track,
            ),
            rule(Some(Poc), Some(Controlled), Some(No), None, None, Track),
            rule(Some(Poc), Some(Small), None, None, Some(HHigh), TrackStar),
            rule(Some(Poc), Some(Small), None, None, Some(HMedium), Track),
            rule(Some(Poc), Some(Small), None, None, Some(HLow), Track),
            rule(Some(Poc), Some(Small), None, None, None, Track),
            // ── Exploitation = None ──────────────────────────────────
            rule(
                Some(NoneExp),
                Some(Open),
                Some(Yes),
                Some(MHigh),
                None,
                Attend,
            ),
            rule(
                Some(NoneExp),
                Some(Open),
                Some(Yes),
                Some(MMedium),
                None,
                Track,
            ),
            rule(
                Some(NoneExp),
                Some(Open),
                Some(Yes),
                Some(MLow),
                None,
                Track,
            ),
            rule(
                Some(NoneExp),
                Some(Open),
                Some(No),
                None,
                Some(HHigh),
                TrackStar,
            ),
            rule(Some(NoneExp), Some(Open), Some(No), None, None, Track),
            rule(
                Some(NoneExp),
                Some(Controlled),
                None,
                None,
                Some(HHigh),
                TrackStar,
            ),
            rule(Some(NoneExp), Some(Controlled), None, None, None, Track),
            rule(Some(NoneExp), Some(Small), None, None, None, Track),
        ];

        Self {
            rules,
            fallback: Track,
        }
    }
}

#[allow(clippy::too_many_arguments)]
const fn rule(
    exploitation: Option<Exploitation>,
    exposure: Option<SsvcExposure>,
    automatable: Option<AutomatableImpact>,
    mission_impact: Option<MissionImpact>,
    human_impact: Option<HumanImpact>,
    decision: SsvcDecision,
) -> SsvcRule {
    SsvcRule {
        exploitation,
        exposure,
        automatable,
        mission_impact,
        human_impact,
        decision,
    }
}

/// Configuration container consumed by [`crate::service::CompositeScorer`].
///
/// Combines the shared cross-cutting [`sx_config::schema::risk::RiskConfig`]
/// (weights + KEV boost + EPSS act-threshold) with the lookup tables and
/// rulebook that are specific to the scoring engine itself.
#[derive(Debug, Clone)]
pub struct RiskScoringConfig {
    /// Cross-cutting policy fields shared with other crates.
    pub core: RiskConfig,
    /// Per-[`Severity`] numeric score used in the composite.
    pub severity_band_scores: SeverityBandScores,
    /// Per-[`ExposureLevel`] numeric score used in the composite.
    pub exposure_scores: BTreeMap<ExposureLevel, f64>,
    /// Per-[`AssetCriticality`] numeric score used in the composite.
    pub criticality_scores: BTreeMap<AssetCriticality, f64>,
    /// Per-[`BusinessImpactBand`](crate::model::BusinessImpact) score.
    ///
    /// Keyed by a discrete label so the table round-trips through YAML.
    pub business_impact_scores: BTreeMap<BusinessImpactKey, f64>,
    /// Linear band used to project `chain_amplifier` into 0..=100.
    pub chain_amplifier_band: ChainAmplifierBand,
    /// Bands used to translate the composite score into a [`Severity`].
    pub score_band: ScoreBand,
    /// SSVC v2 rulebook.
    pub ssvc_rulebook: SsvcRulebook,
}

/// Discrete key for the [`RiskScoringConfig::business_impact_scores`] table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusinessImpactKey {
    /// No measurable business impact.
    None,
    /// Limited monetary or operational impact.
    Low,
    /// Moderate revenue or compliance impact.
    Medium,
    /// Major revenue, reputation or compliance impact.
    High,
    /// Existential / regulatory-shutdown grade impact.
    Critical,
}

impl RiskScoringConfig {
    /// Validate the assembled configuration.
    pub fn validate(&self) -> Result<(), RiskError> {
        // Re-check the cross-cutting weights too — `sx_config` enforces this
        // at load time, but we cannot assume the caller went through that
        // path (tests can construct a `RiskConfig` directly).
        let sum = self.core.weights.sum();
        if !sum.is_finite() {
            return Err(RiskError::config("weights sum must be a finite number"));
        }
        if sum <= 0.0 {
            return Err(RiskError::config("sum of weights must be > 0"));
        }
        if !self.core.kev_boost_factor.is_finite() || self.core.kev_boost_factor < 1.0 {
            return Err(RiskError::config(
                "kev_boost_factor must be a finite number >= 1.0",
            ));
        }
        if !self.core.epss_threshold_act.is_finite()
            || !(0.0..=1.0).contains(&self.core.epss_threshold_act)
        {
            return Err(RiskError::config(
                "epss_threshold_act must be finite in 0.0..=1.0",
            ));
        }

        // Lookup tables must cover every enum variant.
        for level in [
            ExposureLevel::Unknown,
            ExposureLevel::Isolated,
            ExposureLevel::Internal,
            ExposureLevel::Internet,
        ] {
            let v = self.exposure_scores.get(&level).copied().ok_or_else(|| {
                RiskError::config(format!("exposure_scores missing entry for {level}"))
            })?;
            if !v.is_finite() || !(0.0..=10.0).contains(&v) {
                return Err(RiskError::config(format!(
                    "exposure_scores[{level}] must be finite in 0.0..=10.0, got {v}",
                )));
            }
        }
        for crit in [
            AssetCriticality::Unknown,
            AssetCriticality::Dev,
            AssetCriticality::Staging,
            AssetCriticality::Production,
            AssetCriticality::CrownJewel,
        ] {
            let v = self.criticality_scores.get(&crit).copied().ok_or_else(|| {
                RiskError::config(format!("criticality_scores missing entry for {crit}"))
            })?;
            if !v.is_finite() || !(0.0..=10.0).contains(&v) {
                return Err(RiskError::config(format!(
                    "criticality_scores[{crit}] must be finite in 0.0..=10.0, got {v}",
                )));
            }
        }
        for key in [
            BusinessImpactKey::None,
            BusinessImpactKey::Low,
            BusinessImpactKey::Medium,
            BusinessImpactKey::High,
            BusinessImpactKey::Critical,
        ] {
            let v = self
                .business_impact_scores
                .get(&key)
                .copied()
                .ok_or_else(|| {
                    RiskError::config(format!("business_impact_scores missing entry for {key:?}",))
                })?;
            if !v.is_finite() || !(0.0..=10.0).contains(&v) {
                return Err(RiskError::config(format!(
                    "business_impact_scores[{key:?}] must be finite in 0.0..=10.0, got {v}",
                )));
            }
        }
        Ok(())
    }

    /// `SentinelX` policy preset — intended for development, examples, and as
    /// the seed for tests. Production deployments are expected to override
    /// every field via the YAML / env configuration loader.
    pub fn sentinelx_default() -> Result<Self, RiskError> {
        let weights = sx_config::schema::risk::CompositeWeights {
            w_severity: 0.30,
            w_exploit: 0.25,
            w_exposure: 0.15,
            w_criticality: 0.15,
            w_business_impact: 0.10,
            w_chain: 0.05,
        };
        let core = RiskConfig {
            weights,
            kev_boost_factor: 1.25,
            epss_threshold_act: 0.50,
        };
        let mut sev = BTreeMap::new();
        sev.insert(Severity::Info, 0.0);
        sev.insert(Severity::Low, 2.0);
        sev.insert(Severity::Medium, 5.0);
        sev.insert(Severity::High, 8.0);
        sev.insert(Severity::Critical, 10.0);
        let severity_band_scores = SeverityBandScores::new(sev)?;

        let mut exposure_scores = BTreeMap::new();
        exposure_scores.insert(ExposureLevel::Unknown, 3.0);
        exposure_scores.insert(ExposureLevel::Isolated, 0.0);
        exposure_scores.insert(ExposureLevel::Internal, 5.0);
        exposure_scores.insert(ExposureLevel::Internet, 10.0);

        let mut criticality_scores = BTreeMap::new();
        criticality_scores.insert(AssetCriticality::Unknown, 3.0);
        criticality_scores.insert(AssetCriticality::Dev, 1.0);
        criticality_scores.insert(AssetCriticality::Staging, 4.0);
        criticality_scores.insert(AssetCriticality::Production, 8.0);
        criticality_scores.insert(AssetCriticality::CrownJewel, 10.0);

        let mut business_impact_scores = BTreeMap::new();
        business_impact_scores.insert(BusinessImpactKey::None, 0.0);
        business_impact_scores.insert(BusinessImpactKey::Low, 2.5);
        business_impact_scores.insert(BusinessImpactKey::Medium, 5.0);
        business_impact_scores.insert(BusinessImpactKey::High, 7.5);
        business_impact_scores.insert(BusinessImpactKey::Critical, 10.0);

        let chain_amplifier_band = ChainAmplifierBand::new(1.0, 2.0)?;
        let score_band = ScoreBand::new(10.0, 30.0, 60.0, 85.0)?;

        let cfg = Self {
            core,
            severity_band_scores,
            exposure_scores,
            criticality_scores,
            business_impact_scores,
            chain_amplifier_band,
            score_band,
            ssvc_rulebook: SsvcRulebook::cisa_v2_default(),
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn severity_band_scores_must_cover_all_variants() {
        let mut m = BTreeMap::new();
        m.insert(Severity::Info, 0.0);
        m.insert(Severity::Low, 2.0);
        m.insert(Severity::Medium, 5.0);
        m.insert(Severity::High, 8.0);
        // Missing Critical
        assert!(SeverityBandScores::new(m).is_err());
    }

    #[test]
    fn severity_band_scores_must_be_monotonic() {
        let mut m = BTreeMap::new();
        m.insert(Severity::Info, 0.0);
        m.insert(Severity::Low, 5.0);
        m.insert(Severity::Medium, 2.0); // out of order
        m.insert(Severity::High, 8.0);
        m.insert(Severity::Critical, 10.0);
        assert!(SeverityBandScores::new(m).is_err());
    }

    #[test]
    fn score_band_classifies_correctly() {
        let band = ScoreBand::new(10.0, 30.0, 60.0, 85.0).unwrap();
        assert_eq!(band.classify(0.0), Severity::Info);
        assert_eq!(band.classify(9.99), Severity::Info);
        assert_eq!(band.classify(10.0), Severity::Low);
        assert_eq!(band.classify(29.99), Severity::Low);
        assert_eq!(band.classify(30.0), Severity::Medium);
        assert_eq!(band.classify(60.0), Severity::High);
        assert_eq!(band.classify(85.0), Severity::Critical);
        assert_eq!(band.classify(100.0), Severity::Critical);
    }

    #[test]
    fn chain_amplifier_band_clamps() {
        let band = ChainAmplifierBand::new(1.0, 2.0).unwrap();
        assert!((band.map(0.5) - 0.0).abs() < 1e-9);
        assert!((band.map(1.0) - 0.0).abs() < 1e-9);
        assert!((band.map(1.5) - 50.0).abs() < 1e-9);
        assert!((band.map(2.0) - 100.0).abs() < 1e-9);
        assert!((band.map(3.0) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn chain_amplifier_band_rejects_inverted() {
        assert!(ChainAmplifierBand::new(2.0, 1.0).is_err());
        assert!(ChainAmplifierBand::new(1.0, 1.0).is_err());
    }

    #[test]
    fn sentinelx_default_is_valid() {
        let cfg = RiskScoringConfig::sentinelx_default().unwrap();
        cfg.validate().unwrap();
    }
}
