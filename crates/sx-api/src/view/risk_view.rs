//! Risk-calculation DTOs.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Risk-calculation request body.
#[derive(Debug, Deserialize, Validate)]
pub struct CalculateRiskRequest {
    /// Engagement uuid (scopes the calculation).
    #[validate(length(min = 1))]
    pub engagement_id: String,
    /// Optional asset uuid filter.
    pub asset_id: Option<String>,
    /// Optional CVE identifier driving the real intel pipeline.
    ///
    /// When `None` the adapter falls back to a deterministic Phase-0
    /// synthetic CVE (kept so existing smoke tests continue to pass).
    /// When `Some`, the value MUST match the canonical CVE pattern
    /// `^CVE-\d{4}-\d{4,}$` — uppercase only.
    #[validate(custom(function = "validate_cve_id"))]
    pub cve_id: Option<String>,
}

/// Risk-calculation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalculateRiskView {
    /// Echo of the engagement uuid.
    pub engagement_id: String,
    /// Composite risk score, 0.0–100.0.
    pub composite_score: f64,
    /// Per-component breakdown.
    pub components: RiskBreakdownView,
}

/// Per-component scores making up `composite_score`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskBreakdownView {
    /// CVSS factor (0.0–10.0).
    pub cvss: f64,
    /// EPSS factor (0.0–1.0).
    pub epss: f64,
    /// Exposure factor (0.0–1.0).
    pub exposure: f64,
    /// Asset criticality factor (0.0–1.0).
    pub criticality: f64,
}

/// Request body for `POST /v1/risk/engagement/{engagement_id}`.
///
/// Drives the per-engagement aggregate flow that iterates over every
/// finding in the tenant's scope, looks up each CVE, and folds the
/// per-finding scores into a single breakdown.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CalculateEngagementRiskRequest {
    /// When `true`, findings with no `cve_id` are still counted in
    /// `total_findings`. They are NEVER counted in `scored`, since the
    /// composite scorer needs a CVE to resolve EPSS / KEV / CVSS.
    pub include_unscored: bool,
    /// Size of the `top` vector in the response.
    ///
    /// Constrained to `1..=200` to bound response payload size.
    #[validate(range(min = 1, max = 200))]
    pub top_n: u32,
}

/// Aggregate risk for an engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementRiskBreakdownView {
    /// Echo of the engagement uuid.
    pub engagement_id: String,
    /// Total findings considered (controlled by `include_unscored`).
    pub total_findings: u32,
    /// Number of findings whose CVE was successfully scored.
    pub scored: u32,
    /// Highest composite score across all scored findings (0.0 when none).
    pub max_score: f64,
    /// Arithmetic mean of composite scores across scored findings
    /// (0.0 when `scored == 0`).
    pub average_score: f64,
    /// Histogram of severities across scored findings.
    pub severity_counts: SeverityCounts,
    /// The top-N highest-scoring findings, ordered by descending score.
    pub top: Vec<FindingRisk>,
}

/// Histogram of severity buckets across an engagement's scored findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    /// Number of findings classified Critical.
    pub critical: u32,
    /// Number of findings classified High.
    pub high: u32,
    /// Number of findings classified Medium.
    pub medium: u32,
    /// Number of findings classified Low.
    pub low: u32,
    /// Number of findings classified Info / None.
    pub info: u32,
}

/// Per-finding risk projection used in the engagement aggregate response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRisk {
    /// Finding uuid.
    pub finding_id: String,
    /// Optional CVE id that drove the score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    /// Composite score (0.0–100.0).
    pub score: f64,
    /// Severity bucket as a lower-case string
    /// (`critical | high | medium | low | info`).
    pub severity: String,
}

/// Validate that `value` matches the canonical CVE pattern
/// `^CVE-\d{4}-\d{4,}$`.
///
/// The implementation walks the string by hand (no regex dependency) so
/// the API crate keeps its dep footprint minimal.
fn validate_cve_id(value: &str) -> Result<(), validator::ValidationError> {
    if is_canonical_cve(value) {
        Ok(())
    } else {
        Err(validator::ValidationError::new("invalid_cve_id"))
    }
}

/// `true` iff `s` matches `^CVE-\d{4}-\d{4,}$` — uppercase prefix only.
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn calculate_risk_request_validates_engagement_id() {
        let r = CalculateRiskRequest {
            engagement_id: String::new(),
            asset_id: None,
            cve_id: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn calculate_risk_request_accepts_valid_cve_id() {
        for s in ["CVE-2024-12345", "CVE-1999-0001", "CVE-2024-1234567890"] {
            let r = CalculateRiskRequest {
                engagement_id: "eng-1".into(),
                asset_id: None,
                cve_id: Some(s.into()),
            };
            assert!(r.validate().is_ok(), "should accept {s}");
        }
    }

    #[test]
    fn calculate_risk_request_rejects_malformed_cve_id() {
        for s in [
            "cve-2024-12345",
            "CVE-24-12345",
            "CVE-2024-123",
            "CVE--12345",
            "XVE-2024-12345",
            "CVE-2024-12345-1",
            "CVE-2024-ABCDE",
            "",
        ] {
            let r = CalculateRiskRequest {
                engagement_id: "eng-1".into(),
                asset_id: None,
                cve_id: Some(s.into()),
            };
            assert!(r.validate().is_err(), "should reject {s}");
        }
    }

    #[test]
    fn calculate_risk_request_accepts_absent_cve_id() {
        let r = CalculateRiskRequest {
            engagement_id: "eng-1".into(),
            asset_id: None,
            cve_id: None,
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn engagement_risk_request_accepts_default_params() {
        // The documented default — top_n = 5, include_unscored = false —
        // must always pass validation.
        let r = CalculateEngagementRiskRequest {
            include_unscored: false,
            top_n: 5,
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn engagement_risk_request_rejects_out_of_range_top_n() {
        for n in [0u32, 201, 1_000] {
            let r = CalculateEngagementRiskRequest {
                include_unscored: false,
                top_n: n,
            };
            assert!(r.validate().is_err(), "should reject top_n = {n}");
        }
    }
}
