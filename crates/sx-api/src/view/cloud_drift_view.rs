//! Cloud-drift DTOs (wire shape only).
//!
//! Wire types backing the four `/v1/cloud/drift/*` endpoints:
//!
//! - `POST /v1/cloud/drift/upload-baseline`  → [`UploadBaselineRequest`] / [`UploadBaselineResponse`]
//! - `GET  /v1/cloud/drift/baselines`         → [`ListBaselinesResponse`]
//! - `POST /v1/cloud/drift/scan`              → [`DriftScanRequest`] / [`DriftScanResponse`]
//! - `GET  /v1/cloud/drift`                   → [`DriftListResponse`]
//!
//! Baseline payloads cross the wire as base64-encoded strings — this
//! keeps the HTTP body homogeneous JSON (no multipart parser in
//! sx-api), respects the configured body limit, and means the same
//! payload can be replayed deterministically from the audit trail.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Hard upper bound on the decoded baseline payload size. Matches the
/// 20 MB cap mandated by P2-004.
pub const BASELINE_MAX_DECODED_BYTES: usize = 20 * 1024 * 1024;

/// `POST /v1/cloud/drift/upload-baseline` request body.
///
/// `payload` is the raw IaC document, base64-encoded so the API surface
/// remains pure JSON.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct UploadBaselineRequest {
    /// Display name shown in the dashboard listing.
    #[validate(length(min = 1, max = 256))]
    pub name: String,

    /// Wire format identifier — `"terraform_json"` or
    /// `"cloudformation_yaml"`. Validated at the controller boundary.
    #[validate(length(min = 1, max = 32))]
    pub format: String,

    /// Base64-encoded baseline document. The decoded length is enforced
    /// against [`BASELINE_MAX_DECODED_BYTES`] inside the controller
    /// (validator alone cannot reason about decoded byte length).
    #[validate(length(min = 4, max = 32_000_000))]
    pub payload: String,
}

/// `POST /v1/cloud/drift/upload-baseline` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UploadBaselineResponse {
    /// Newly minted baseline id (uuid).
    pub id: String,
    /// Echoed display name.
    pub name: String,
    /// Echoed format identifier.
    pub format: String,
    /// Count of supported resources the parser recognised.
    pub resource_count: u32,
}

/// One baseline summary surfaced from `GET /v1/cloud/drift/baselines`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BaselineSummaryView {
    /// Baseline uuid.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Format identifier.
    pub format: String,
    /// Count of supported resources.
    pub resource_count: u32,
}

/// `GET /v1/cloud/drift/baselines` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListBaselinesResponse {
    /// Baselines ordered by name (ASC).
    pub items: Vec<BaselineSummaryView>,
}

/// `POST /v1/cloud/drift/scan` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct DriftScanRequest {
    /// Engagement to scope the live inventory pull to. Required so the
    /// adapter can choose which connectors fan out.
    #[validate(length(min = 1))]
    pub engagement_id: String,

    /// Baseline to diff against. When omitted, the adapter falls back
    /// to the most recently uploaded baseline for the tenant. (P2-004
    /// MVP: required; we surface as `Option` for forward-compat.)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub baseline_id: Option<String>,
}

/// One drift observation surfaced on the wire.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DriftEntryView {
    /// Canonical upstream resource identifier (ARN for AWS).
    pub resource_id: String,
    /// IaC-style resource type.
    pub resource_type: String,
    /// Attribute path that differs (or `<missing>` / `<unmanaged>`).
    pub attribute: String,
    /// Value from the baseline document.
    pub baseline_value: serde_json::Value,
    /// Value observed on the live cloud surface.
    pub live_value: serde_json::Value,
    /// Severity hint (`low` / `medium` / `high` / `critical`).
    pub severity: String,
}

/// `POST /v1/cloud/drift/scan` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DriftScanResponse {
    /// Baseline id the scan was run against.
    pub baseline_id: String,
    /// Drift entries detected on this scan, newest-severity-first.
    pub entries: Vec<DriftEntryView>,
}

/// `GET /v1/cloud/drift` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DriftListResponse {
    /// Drift entries currently recorded for the caller's tenant,
    /// newest-severity-first.
    pub items: Vec<DriftEntryView>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_baseline_request_validates_minimum_payload() {
        let r = UploadBaselineRequest {
            name: "main".into(),
            format: "terraform_json".into(),
            payload: "AAAA".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn upload_baseline_request_rejects_empty_name() {
        let r = UploadBaselineRequest {
            name: String::new(),
            format: "terraform_json".into(),
            payload: "AAAA".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn upload_baseline_request_rejects_short_payload() {
        let r = UploadBaselineRequest {
            name: "n".into(),
            format: "terraform_json".into(),
            payload: "AA".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn drift_scan_request_round_trips_optional_baseline() {
        let r = DriftScanRequest {
            engagement_id: "00000000-0000-0000-0000-000000000001".into(),
            baseline_id: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("baseline_id"));
    }
}
