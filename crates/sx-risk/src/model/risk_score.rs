//! The composite [`RiskScore`] — a validated `f64` in `0.0..=100.0`.

use serde::{Deserialize, Serialize};
use sx_core::value_object::severity::Severity;

use crate::error::RiskError;
use crate::model::config::ScoreBand;

/// Normalized risk score in `0.0..=100.0`.
///
/// Construction validates the value; once held it is guaranteed finite and
/// in range.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RiskScore(f64);

impl RiskScore {
    /// Build and validate.
    pub fn new(value: f64) -> Result<Self, RiskError> {
        if !value.is_finite() {
            return Err(RiskError::internal(
                "risk score computation produced a non-finite value",
            ));
        }
        let clamped = value.clamp(0.0, 100.0);
        // We accept a tiny tolerance for floating-point drift past the
        // bounds before clamping but treat large excursions as a bug.
        if (value - clamped).abs() > 1e-6 {
            return Err(RiskError::internal(format!(
                "risk score out of range: {value}",
            )));
        }
        Ok(Self(clamped))
    }

    /// Borrow the inner value.
    #[must_use]
    pub const fn value(self) -> f64 {
        self.0
    }

    /// Map this score back into a [`Severity`] using the supplied bands.
    #[must_use]
    pub fn severity(self, band: ScoreBand) -> Severity {
        band.classify(self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bounds() {
        assert!(RiskScore::new(0.0).is_ok());
        assert!(RiskScore::new(100.0).is_ok());
    }

    #[test]
    fn rejects_nan_inf() {
        assert!(RiskScore::new(f64::NAN).is_err());
        assert!(RiskScore::new(f64::INFINITY).is_err());
    }

    #[test]
    fn rejects_grossly_out_of_range() {
        assert!(RiskScore::new(-1.0).is_err());
        assert!(RiskScore::new(200.0).is_err());
    }

    #[test]
    fn classifies_via_band() {
        let band = ScoreBand::new(10.0, 30.0, 60.0, 85.0).unwrap();
        let s = RiskScore::new(90.0).unwrap();
        assert_eq!(s.severity(band), Severity::Critical);
        let s = RiskScore::new(0.0).unwrap();
        assert_eq!(s.severity(band), Severity::Info);
    }
}
