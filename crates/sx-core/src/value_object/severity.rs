//! Severity classification and the band table that maps CVSS → [`Severity`].

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// Severity buckets for findings.
///
/// Ordering is `Info < Low < Medium < High < Critical` — derive `Ord`
/// gives this directly because the discriminants are declared in ascending
/// order. Tests pin the ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational only — no action required.
    Info,
    /// Low impact.
    Low,
    /// Medium impact.
    Medium,
    /// High impact.
    High,
    /// Critical impact — escalate immediately.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// Inclusive lower bounds for mapping a CVSS base score to a [`Severity`].
///
/// **Bands are configuration**, not domain constants. Callers (typically
/// the config layer) construct a [`SeverityBands`] table and pass it to
/// [`Severity::from_cvss`]. The crate intentionally ships no default
/// table so that policy stays explicit.
///
/// Each `*_min` field is the inclusive lower bound of that band. A score
/// strictly below `low_min` maps to [`Severity::Info`].
///
/// Invariants enforced at construction:
/// - all fields in range `0.0..=10.0`
/// - `low_min <= medium_min <= high_min <= critical_min`
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct SeverityBands {
    /// Inclusive lower bound for [`Severity::Low`].
    pub low_min: f32,
    /// Inclusive lower bound for [`Severity::Medium`].
    pub medium_min: f32,
    /// Inclusive lower bound for [`Severity::High`].
    pub high_min: f32,
    /// Inclusive lower bound for [`Severity::Critical`].
    pub critical_min: f32,
}

impl SeverityBands {
    /// Build and validate a band table.
    pub fn new(
        low_min: f32,
        medium_min: f32,
        high_min: f32,
        critical_min: f32,
    ) -> Result<Self, DomainError> {
        for (name, v) in [
            ("low_min", low_min),
            ("medium_min", medium_min),
            ("high_min", high_min),
            ("critical_min", critical_min),
        ] {
            if !v.is_finite() || !(0.0..=10.0).contains(&v) {
                return Err(DomainError::invalid(format!(
                    "severity band {name} must be in 0.0..=10.0, got {v}",
                )));
            }
        }
        if !(low_min <= medium_min && medium_min <= high_min && high_min <= critical_min) {
            return Err(DomainError::invariant(
                "severity bands must be monotonically non-decreasing",
            ));
        }
        Ok(Self {
            low_min,
            medium_min,
            high_min,
            critical_min,
        })
    }
}

impl Severity {
    /// Map a CVSS base score into a [`Severity`] using the supplied bands.
    ///
    /// Returns [`DomainError::InvalidValue`] if `score` is NaN or outside
    /// `0.0..=10.0`.
    pub fn from_cvss(score: f32, bands: SeverityBands) -> Result<Self, DomainError> {
        if !score.is_finite() || !(0.0..=10.0).contains(&score) {
            return Err(DomainError::invalid(format!(
                "cvss score must be in 0.0..=10.0, got {score}",
            )));
        }
        let s = if score >= bands.critical_min {
            Self::Critical
        } else if score >= bands.high_min {
            Self::High
        } else if score >= bands.medium_min {
            Self::Medium
        } else if score >= bands.low_min {
            Self::Low
        } else {
            Self::Info
        };
        Ok(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn bands() -> SeverityBands {
        // NIST-style bands, supplied by tests only.
        SeverityBands::new(0.1, 4.0, 7.0, 9.0).unwrap()
    }

    #[test]
    fn ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[rstest]
    #[case(0.0, Severity::Info)]
    #[case(0.1, Severity::Low)]
    #[case(3.9, Severity::Low)]
    #[case(4.0, Severity::Medium)]
    #[case(6.9, Severity::Medium)]
    #[case(7.0, Severity::High)]
    #[case(8.9, Severity::High)]
    #[case(9.0, Severity::Critical)]
    #[case(10.0, Severity::Critical)]
    fn from_cvss_maps_correctly(#[case] score: f32, #[case] expected: Severity) {
        let s = Severity::from_cvss(score, bands()).unwrap();
        assert_eq!(s, expected);
    }

    #[test]
    fn rejects_out_of_range_cvss() {
        assert!(Severity::from_cvss(-0.1, bands()).is_err());
        assert!(Severity::from_cvss(10.1, bands()).is_err());
        assert!(Severity::from_cvss(f32::NAN, bands()).is_err());
    }

    #[test]
    fn rejects_non_monotonic_bands() {
        assert!(SeverityBands::new(4.0, 2.0, 7.0, 9.0).is_err());
    }

    #[test]
    fn rejects_band_out_of_range() {
        assert!(SeverityBands::new(0.1, 4.0, 7.0, 11.0).is_err());
        assert!(SeverityBands::new(-0.1, 4.0, 7.0, 9.0).is_err());
    }

    #[test]
    fn display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
    }
}
