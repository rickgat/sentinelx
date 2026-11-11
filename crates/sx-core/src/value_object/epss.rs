//! EPSS (Exploit Prediction Scoring System) value object.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// An EPSS score: probability of in-the-wild exploitation in the next 30 days.
///
/// `probability` is in the closed range `0.0..=1.0`.
/// `percentile` is in the closed range `0.0..=1.0` — the score's rank
/// among all known CVEs, where `1.0` is the most likely to be exploited.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EpssScore {
    /// Modelled exploitation probability `0.0..=1.0`.
    pub probability: f32,
    /// Percentile rank `0.0..=1.0`.
    pub percentile: f32,
}

impl EpssScore {
    /// Construct and validate an [`EpssScore`].
    pub fn new(probability: f32, percentile: f32) -> Result<Self, DomainError> {
        check_unit("probability", probability)?;
        check_unit("percentile", percentile)?;
        Ok(Self {
            probability,
            percentile,
        })
    }
}

fn check_unit(label: &str, v: f32) -> Result<(), DomainError> {
    if !v.is_finite() || !(0.0..=1.0).contains(&v) {
        return Err(DomainError::invalid(format!(
            "epss {label} must be finite in 0.0..=1.0, got {v}",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bounds() {
        assert!(EpssScore::new(0.0, 0.0).is_ok());
        assert!(EpssScore::new(1.0, 1.0).is_ok());
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(EpssScore::new(-0.1, 0.5).is_err());
        assert!(EpssScore::new(1.1, 0.5).is_err());
        assert!(EpssScore::new(0.5, -0.01).is_err());
        assert!(EpssScore::new(0.5, 1.01).is_err());
        assert!(EpssScore::new(f32::NAN, 0.5).is_err());
    }
}
