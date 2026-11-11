//! CVSS score value object — v3 and/or v4, validated to `0.0..=10.0`.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// A CVSS score envelope holding optional v3 and v4 base scores.
///
/// At least one of `v3` or `v4` MUST be present. Each present score is
/// validated to be a finite value in `0.0..=10.0`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CvssScore {
    /// CVSS v3 base score, if available.
    pub v3: Option<f32>,
    /// CVSS v4 base score, if available.
    pub v4: Option<f32>,
}

impl CvssScore {
    /// Construct and validate a [`CvssScore`].
    pub fn new(v3: Option<f32>, v4: Option<f32>) -> Result<Self, DomainError> {
        if v3.is_none() && v4.is_none() {
            return Err(DomainError::invariant(
                "CvssScore must carry at least one of v3 or v4",
            ));
        }
        if let Some(score) = v3 {
            validate(score, "v3")?;
        }
        if let Some(score) = v4 {
            validate(score, "v4")?;
        }
        Ok(Self { v3, v4 })
    }

    /// Convenience: a CVSS envelope carrying only a v3 score.
    pub fn v3_only(v: f32) -> Result<Self, DomainError> {
        Self::new(Some(v), None)
    }

    /// Convenience: a CVSS envelope carrying only a v4 score.
    pub fn v4_only(v: f32) -> Result<Self, DomainError> {
        Self::new(None, Some(v))
    }

    /// The score to use for severity classification: prefer v4 when present,
    /// otherwise fall back to v3.
    #[must_use]
    pub const fn primary(&self) -> f32 {
        match (self.v4, self.v3) {
            (Some(v), _) | (None, Some(v)) => v,
            (None, None) => 0.0,
        }
    }
}

fn validate(score: f32, label: &str) -> Result<(), DomainError> {
    if !score.is_finite() || !(0.0..=10.0).contains(&score) {
        return Err(DomainError::invalid(format!(
            "cvss {label} must be finite in 0.0..=10.0, got {score}",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn requires_at_least_one_score() {
        assert!(CvssScore::new(None, None).is_err());
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(CvssScore::v3_only(-0.1).is_err());
        assert!(CvssScore::v3_only(10.1).is_err());
        assert!(CvssScore::v4_only(f32::INFINITY).is_err());
        assert!(CvssScore::v4_only(f32::NAN).is_err());
    }

    #[test]
    fn primary_prefers_v4() {
        let s = CvssScore::new(Some(7.5), Some(8.2)).unwrap();
        assert!((s.primary() - 8.2).abs() < 1e-6);
    }

    #[test]
    fn primary_falls_back_to_v3() {
        let s = CvssScore::v3_only(7.5).unwrap();
        assert!((s.primary() - 7.5).abs() < 1e-6);
    }
}
