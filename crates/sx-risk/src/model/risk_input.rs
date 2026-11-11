//! Inputs to the composite risk scorer.

use serde::{Deserialize, Serialize};
use sx_core::value_object::{
    criticality::AssetCriticality, cvss::CvssScore, epss::EpssScore, exposure::ExposureLevel,
    severity::Severity,
};

use crate::error::RiskError;
use crate::model::config::BusinessImpactKey;

/// Business impact classification chosen by the engagement owner.
pub type BusinessImpact = BusinessImpactKey;

/// Attack-chain reachability amplifier — a scalar in `[1.0, 2.0]` supplied
/// by the caller (typically the attack-graph engine).
///
/// `1.0` means "no amplification"; `2.0` is the maximum the band accepts.
/// Values outside the band are clamped by
/// [`crate::model::ChainAmplifierBand::map`] but rejected at construction
/// so that bad upstream data fails loudly.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainAmplifier(f64);

impl ChainAmplifier {
    /// Build and validate. Returns [`RiskError::InvalidInput`] when the
    /// value is non-finite or outside `[1.0, 2.0]`.
    pub fn new(value: f64) -> Result<Self, RiskError> {
        if !value.is_finite() {
            return Err(RiskError::invalid_input(
                "chain_amplifier must be a finite number",
            ));
        }
        if !(1.0..=2.0).contains(&value) {
            return Err(RiskError::invalid_input(format!(
                "chain_amplifier must be in 1.0..=2.0, got {value}",
            )));
        }
        Ok(Self(value))
    }

    /// Identity amplifier (`1.0`) — no chain boost.
    #[must_use]
    pub const fn identity() -> Self {
        Self(1.0)
    }

    /// Borrow the inner value.
    #[must_use]
    pub const fn value(self) -> f64 {
        self.0
    }
}

impl Default for ChainAmplifier {
    fn default() -> Self {
        Self::identity()
    }
}

/// Composite scoring input.
///
/// All numeric ranges are validated by the value-object constructors
/// (`CvssScore`, `EpssScore`, `ChainAmplifier`). The combination of
/// `cvss + severity_hint` lets callers pass either the CVSS envelope or
/// a pre-computed [`Severity`] when the envelope is unavailable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskInput {
    /// Optional CVSS envelope. When present, the v4 base is preferred,
    /// falling back to v3.
    pub cvss: Option<CvssScore>,
    /// Pre-computed [`Severity`] used when `cvss` is `None`.
    pub severity_hint: Option<Severity>,
    /// EPSS exploit-likelihood score, if known.
    pub epss: Option<EpssScore>,
    /// Whether the underlying CVE is on the CISA KEV catalogue.
    pub kev: bool,
    /// Asset exposure level.
    pub exposure: ExposureLevel,
    /// Asset criticality.
    pub criticality: AssetCriticality,
    /// Business impact band.
    pub business_impact: BusinessImpact,
    /// Attack-chain amplifier in `[1.0, 2.0]`.
    pub chain_amplifier: ChainAmplifier,
}

impl RiskInput {
    /// Constructor that enforces "must have a severity signal": either
    /// `cvss` or `severity_hint` must be `Some`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cvss: Option<CvssScore>,
        severity_hint: Option<Severity>,
        epss: Option<EpssScore>,
        kev: bool,
        exposure: ExposureLevel,
        criticality: AssetCriticality,
        business_impact: BusinessImpact,
        chain_amplifier: ChainAmplifier,
    ) -> Result<Self, RiskError> {
        if cvss.is_none() && severity_hint.is_none() {
            return Err(RiskError::invalid_input(
                "RiskInput requires at least one of cvss or severity_hint",
            ));
        }
        Ok(Self {
            cvss,
            severity_hint,
            epss,
            kev,
            exposure,
            criticality,
            business_impact,
            chain_amplifier,
        })
    }

    /// Effective [`Severity`] for this input.
    ///
    /// When a CVSS envelope is present its primary score is used together
    /// with the supplied severity bands. Otherwise the supplied
    /// `severity_hint` is returned. When neither is present (which
    /// [`Self::new`] disallows) a [`RiskError::InvalidInput`] is returned.
    #[allow(clippy::option_if_let_else)] // the if-chain is the clearest form here
    pub fn effective_severity(
        &self,
        bands: sx_core::value_object::severity::SeverityBands,
    ) -> Result<Severity, RiskError> {
        if let Some(cvss) = &self.cvss {
            Severity::from_cvss(cvss.primary(), bands)
                .map_err(|e| RiskError::invalid_input(e.to_string()))
        } else if let Some(s) = self.severity_hint {
            Ok(s)
        } else {
            Err(RiskError::invalid_input(
                "RiskInput has neither cvss nor severity_hint",
            ))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn chain_amplifier_rejects_below_one() {
        assert!(ChainAmplifier::new(0.99).is_err());
    }

    #[test]
    fn chain_amplifier_rejects_above_two() {
        assert!(ChainAmplifier::new(2.0001).is_err());
    }

    #[test]
    fn chain_amplifier_accepts_bounds() {
        assert!(ChainAmplifier::new(1.0).is_ok());
        assert!(ChainAmplifier::new(2.0).is_ok());
    }

    #[test]
    fn chain_amplifier_rejects_nan() {
        assert!(ChainAmplifier::new(f64::NAN).is_err());
        assert!(ChainAmplifier::new(f64::INFINITY).is_err());
    }

    #[test]
    fn risk_input_requires_severity_signal() {
        let r = RiskInput::new(
            None,
            None,
            None,
            false,
            ExposureLevel::Internet,
            AssetCriticality::Production,
            BusinessImpact::Medium,
            ChainAmplifier::identity(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn risk_input_with_cvss_is_valid() {
        let cvss = CvssScore::v3_only(7.5).unwrap();
        let r = RiskInput::new(
            Some(cvss),
            None,
            None,
            false,
            ExposureLevel::Internet,
            AssetCriticality::Production,
            BusinessImpact::Medium,
            ChainAmplifier::identity(),
        );
        assert!(r.is_ok());
    }
}
