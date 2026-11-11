//! Remediation-advisories DTOs.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/remediation/advisories` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct RemediationAdvisoriesRequestView {
    /// CVE identifier in the canonical `CVE-YYYY-NNNN+` form.
    #[validate(custom(function = "validate_cve_id"))]
    pub cve_id: String,
}

/// Single advisory record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdvisoryView {
    /// Issuing vendor (e.g. `microsoft`, `red_hat`, `canonical`).
    pub vendor: String,
    /// Vendor-side advisory identifier (e.g. `MSRC-CVE-2024-XXXX`).
    pub advisory_id: String,
    /// References (URLs, tracker ids) attached to the advisory.
    pub references: Vec<String>,
}

/// `POST /v1/remediation/advisories` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationAdvisoriesResponseView {
    /// Zero-or-more advisories matched for the input CVE.
    pub advisories: Vec<AdvisoryView>,
}

/// Validate that `value` matches `^CVE-\d{4}-\d{4,}$`.
fn validate_cve_id(value: &str) -> Result<(), validator::ValidationError> {
    if is_canonical_cve(value) {
        Ok(())
    } else {
        Err(validator::ValidationError::new("invalid_cve_id"))
    }
}

/// Pure-function CVE id check (no regex dep).
fn is_canonical_cve(s: &str) -> bool {
    let mut parts = s.split('-');
    let Some(prefix) = parts.next() else {
        return false;
    };
    let Some(year) = parts.next() else {
        return false;
    };
    let Some(seq) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if prefix != "CVE" {
        return false;
    }
    if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if seq.len() < 4 || !seq.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_cve() {
        let r = RemediationAdvisoriesRequestView {
            cve_id: "CVE-2024-12345".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn rejects_lowercase_cve() {
        let r = RemediationAdvisoriesRequestView {
            cve_id: "cve-2024-12345".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_short_sequence() {
        let r = RemediationAdvisoriesRequestView {
            cve_id: "CVE-2024-123".into(),
        };
        assert!(r.validate().is_err());
    }
}
