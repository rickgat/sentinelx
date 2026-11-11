//! Confidence score `0.0..=1.0` for inferred / heuristic results.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// A normalized confidence value in `0.0..=1.0`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "f32", into = "f32")]
pub struct ConfidenceScore(f32);

impl ConfidenceScore {
    /// Construct and validate.
    pub fn new(v: f32) -> Result<Self, DomainError> {
        if !v.is_finite() || !(0.0..=1.0).contains(&v) {
            return Err(DomainError::invalid(format!(
                "confidence must be finite in 0.0..=1.0, got {v}",
            )));
        }
        Ok(Self(v))
    }

    /// The raw value.
    #[must_use]
    pub const fn value(self) -> f32 {
        self.0
    }
}

impl TryFrom<f32> for ConfidenceScore {
    type Error = DomainError;

    fn try_from(value: f32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ConfidenceScore> for f32 {
    fn from(c: ConfidenceScore) -> Self {
        c.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bounds() {
        assert!(ConfidenceScore::new(0.0).is_ok());
        assert!(ConfidenceScore::new(1.0).is_ok());
        assert!(ConfidenceScore::new(0.5).is_ok());
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(ConfidenceScore::new(-0.1).is_err());
        assert!(ConfidenceScore::new(1.01).is_err());
        assert!(ConfidenceScore::new(f32::NAN).is_err());
    }
}
