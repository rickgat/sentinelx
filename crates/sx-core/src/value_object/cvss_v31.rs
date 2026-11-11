//! CVSS v3.1 base metrics — vector, base score, qualitative severity rating.
//!
//! Distinct from [`crate::value_object::cvss::CvssScore`], which is a
//! lightweight envelope carrying only numeric base scores for v3 and/or v4
//! and is used by the legacy CVE ingestion pipeline. This struct is the
//! richer payload required by enterprise compliance pipelines (SARIF
//! export, NIST 800-53 evidence, PCI ROC):
//!
//! - the full CVSS v3.1 base vector (so auditors can independently
//!   verify the score), and
//! - the qualitative rating string the CVSS v3.1 spec defines for the
//!   base score band (`None|Low|Medium|High|Critical`).
//!
//! Validation enforces the `0.0..=10.0` base-score range and a permissive
//! check on the vector prefix; we deliberately do NOT re-implement the
//! full CVSS calculator — callers either pull the score from the upstream
//! reference (NVD, vendor advisory) or look it up from an authoritative
//! table.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// Qualitative severity rating for a CVSS v3.1 base score, per the
/// CVSS v3.1 specification §5 ("Qualitative Severity Rating Scale").
///
/// Bands are fixed by the spec and are NOT the same as
/// [`crate::value_object::severity::SeverityBands`] (which is a tunable
/// internal policy). Use [`CvssV31::rating_from_score`] to derive the
/// rating from a base score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CvssV31Rating {
    /// `0.0`
    None,
    /// `0.1..=3.9`
    Low,
    /// `4.0..=6.9`
    Medium,
    /// `7.0..=8.9`
    High,
    /// `9.0..=10.0`
    Critical,
}

impl CvssV31Rating {
    /// Lower-case string form. Useful when emitting to log fields.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// CVSS v3.1 base metric payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CvssV31 {
    /// Full CVSS v3.1 base vector, e.g.
    /// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`. The vector is
    /// stored as the canonical string form so auditors can copy/paste
    /// into the FIRST.org calculator without re-encoding.
    pub vector: String,
    /// Base score in `0.0..=10.0`, derived from the metric vector. Rounded
    /// per the CVSS v3.1 spec — callers should use the value published by
    /// the authoritative source rather than recomputing locally.
    pub base_score: f64,
    /// Qualitative rating bucket for the base score.
    pub severity: CvssV31Rating,
}

impl CvssV31 {
    /// Build a new CVSS v3.1 payload, validating the vector prefix, the
    /// score range, and the score↔rating consistency.
    pub fn new(
        vector: impl Into<String>,
        base_score: f64,
        severity: CvssV31Rating,
    ) -> Result<Self, DomainError> {
        let vector = vector.into();
        validate_vector(&vector)?;
        validate_score(base_score)?;
        let expected = Self::rating_from_score(base_score)?;
        if expected != severity {
            return Err(DomainError::invariant(format!(
                "CVSS rating {} disagrees with base_score {base_score} (expected {})",
                severity.as_str(),
                expected.as_str(),
            )));
        }
        Ok(Self {
            vector,
            base_score,
            severity,
        })
    }

    /// Build the payload with the rating auto-derived from the score.
    pub fn from_vector_and_score(
        vector: impl Into<String>,
        base_score: f64,
    ) -> Result<Self, DomainError> {
        let severity = Self::rating_from_score(base_score)?;
        Self::new(vector, base_score, severity)
    }

    /// Map a CVSS v3.1 base score to its qualitative rating per the CVSS
    /// v3.1 specification §5.
    pub fn rating_from_score(score: f64) -> Result<CvssV31Rating, DomainError> {
        validate_score(score)?;
        let r = if score == 0.0 {
            CvssV31Rating::None
        } else if score < 4.0 {
            CvssV31Rating::Low
        } else if score < 7.0 {
            CvssV31Rating::Medium
        } else if score < 9.0 {
            CvssV31Rating::High
        } else {
            CvssV31Rating::Critical
        };
        Ok(r)
    }
}

fn validate_vector(vector: &str) -> Result<(), DomainError> {
    if !vector.starts_with("CVSS:3.1/") {
        return Err(DomainError::invalid(format!(
            "cvss v3.1 vector must start with 'CVSS:3.1/', got {vector:?}",
        )));
    }
    // Permissive sanity: every metric segment is `KEY:VALUE` separated
    // by `/`. We do not exhaustively validate the metric alphabet —
    // FIRST.org maintains the canonical grammar.
    for seg in vector.trim_start_matches("CVSS:3.1/").split('/') {
        if seg.is_empty() {
            continue;
        }
        if !seg.contains(':') {
            return Err(DomainError::invalid(format!(
                "cvss v3.1 vector segment {seg:?} is not KEY:VALUE",
            )));
        }
    }
    Ok(())
}

fn validate_score(score: f64) -> Result<(), DomainError> {
    if !score.is_finite() || !(0.0..=10.0).contains(&score) {
        return Err(DomainError::invalid(format!(
            "cvss v3.1 base_score must be finite in 0.0..=10.0, got {score}",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_prefix() {
        let r = CvssV31::from_vector_and_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5);
        assert!(matches!(r, Err(DomainError::InvalidValue(_))));
    }

    #[test]
    fn rejects_out_of_range_score() {
        let r =
            CvssV31::from_vector_and_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 11.0);
        assert!(matches!(r, Err(DomainError::InvalidValue(_))));
    }

    #[test]
    fn rejects_nan_score() {
        let r = CvssV31::from_vector_and_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            f64::NAN,
        );
        assert!(matches!(r, Err(DomainError::InvalidValue(_))));
    }

    #[test]
    fn rejects_rating_score_mismatch() {
        let r = CvssV31::new(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            7.5,
            CvssV31Rating::Critical,
        );
        assert!(matches!(r, Err(DomainError::InvariantViolation(_))));
    }

    #[test]
    fn auto_rating_high() {
        let c = CvssV31::from_vector_and_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5)
            .unwrap();
        assert_eq!(c.severity, CvssV31Rating::High);
        assert!((c.base_score - 7.5).abs() < f64::EPSILON);
    }

    #[test]
    fn band_boundaries() {
        assert_eq!(
            CvssV31::rating_from_score(0.0).unwrap(),
            CvssV31Rating::None,
        );
        assert_eq!(CvssV31::rating_from_score(0.1).unwrap(), CvssV31Rating::Low,);
        assert_eq!(CvssV31::rating_from_score(3.9).unwrap(), CvssV31Rating::Low,);
        assert_eq!(
            CvssV31::rating_from_score(4.0).unwrap(),
            CvssV31Rating::Medium,
        );
        assert_eq!(
            CvssV31::rating_from_score(6.9).unwrap(),
            CvssV31Rating::Medium,
        );
        assert_eq!(
            CvssV31::rating_from_score(7.0).unwrap(),
            CvssV31Rating::High,
        );
        assert_eq!(
            CvssV31::rating_from_score(8.9).unwrap(),
            CvssV31Rating::High,
        );
        assert_eq!(
            CvssV31::rating_from_score(9.0).unwrap(),
            CvssV31Rating::Critical,
        );
        assert_eq!(
            CvssV31::rating_from_score(10.0).unwrap(),
            CvssV31Rating::Critical,
        );
    }
}
