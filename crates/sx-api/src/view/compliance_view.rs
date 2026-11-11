//! Compliance DTOs.
//!
//! Used by both `GET /v1/compliance/frameworks/{framework}` (list controls
//! in a framework) and `POST /v1/compliance/map` (map a finding category
//! to implicated controls).

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Compliance control projection.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlView {
    /// Control identifier (e.g. `AC-2`, `A.9.2.1`).
    pub id: String,
    /// Owning framework (e.g. `nist_800_53`, `iso_27001`).
    pub framework: String,
    /// Human-readable title.
    pub title: String,
    /// Control family (e.g. `AC`, `Access Control`).
    pub family: String,
}

/// `POST /v1/compliance/map` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ComplianceMapRequestView {
    /// Finding uuid being mapped (used for echoing only).
    #[validate(length(min = 1))]
    pub finding_id: String,
    /// Finding category (must parse to a `FindingCategory` code).
    #[validate(custom(function = "validate_category"))]
    pub category: String,
    /// Finding severity (`info`, `low`, `medium`, `high`, `critical`).
    #[validate(custom(function = "validate_severity"))]
    pub severity: String,
}

/// `POST /v1/compliance/map` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComplianceMapResponseView {
    /// Echo of the input finding uuid.
    pub finding_id: String,
    /// Controls implicated by the finding's category, in framework order.
    pub controls: Vec<ControlView>,
}

/// `GET /v1/compliance/frameworks/{framework}` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComplianceFrameworkResponseView {
    /// Framework identifier echoed from the URL.
    pub framework: String,
    /// Controls in the framework, in catalog order.
    pub controls: Vec<ControlView>,
}

/// Validate that `value` is a known [`FindingCategory`] code.
///
/// We re-implement the match inline rather than depend on
/// [`sx_compliance::FindingCategory::from_str`] so the view crate does not
/// inherit the compliance crate's error types just to compile.
///
/// [`FindingCategory`]: sx_compliance::FindingCategory
fn validate_category(value: &str) -> Result<(), validator::ValidationError> {
    match value {
        "authentication"
        | "authorization"
        | "encryption_at_rest"
        | "encryption_in_transit"
        | "logging"
        | "vulnerability_management"
        | "network_segmentation"
        | "backup_recovery"
        | "secrets_management"
        | "configuration_drift"
        | "incident_response" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_category")),
    }
}

/// Validate that `value` is one of the canonical severities.
fn validate_severity(value: &str) -> Result<(), validator::ValidationError> {
    match value {
        "info" | "low" | "medium" | "high" | "critical" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_severity")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_all_categories() {
        for c in [
            "authentication",
            "authorization",
            "encryption_at_rest",
            "encryption_in_transit",
            "logging",
            "vulnerability_management",
            "network_segmentation",
            "backup_recovery",
            "secrets_management",
            "configuration_drift",
            "incident_response",
        ] {
            let r = ComplianceMapRequestView {
                finding_id: "f-1".into(),
                category: c.into(),
                severity: "low".into(),
            };
            assert!(r.validate().is_ok(), "should accept {c}");
        }
    }

    #[test]
    fn rejects_bad_category() {
        let r = ComplianceMapRequestView {
            finding_id: "f-1".into(),
            category: "yolo".into(),
            severity: "low".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_bad_severity() {
        let r = ComplianceMapRequestView {
            finding_id: "f-1".into(),
            category: "logging".into(),
            severity: "fatal".into(),
        };
        assert!(r.validate().is_err());
    }
}
