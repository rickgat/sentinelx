//! P1-004 — HTTP DTOs for the automated compliance evidence collector.
//!
//! The three endpoints under `/v1/compliance/evidence` reuse the JSON
//! envelope; the per-request shapes here mirror the application-layer
//! DTOs in `sx_compliance::p1_004::api` while staying decoupled from
//! the upstream module so a future schema change in the compliance
//! crate cannot silently break the wire format.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/compliance/evidence/collect` request body.
///
/// Both bounds are optional — when omitted the application defaults to
/// the last 7 days (`period_end = now()`, `period_start = now() - 7d`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, Validate)]
pub struct CollectEvidenceRequestView {
    /// RFC 3339 start of the audit period.
    #[serde(default)]
    pub period_start: Option<String>,
    /// RFC 3339 end of the audit period.
    #[serde(default)]
    pub period_end: Option<String>,
}

/// `POST /v1/compliance/evidence/collect` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CollectEvidenceResponseView {
    /// Identifier of the run created.
    pub run_id: String,
    /// WORM key the bundle was written to.
    pub bundle_key: String,
    /// Lowercase hex SHA-256 of the bundle bytes.
    pub bundle_sha256: String,
    /// Number of evidence files included in the bundle.
    pub files: u32,
}

/// One row in [`ListBundlesResponseView`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BundleSummaryView {
    /// Run id.
    pub run_id: String,
    /// WORM key.
    pub bundle_key: String,
    /// Lowercase hex SHA-256.
    pub bundle_sha256: String,
    /// RFC 3339 start timestamp.
    pub started_at: String,
    /// RFC 3339 finish timestamp; absent for in-flight runs.
    pub finished_at: Option<String>,
}

/// `GET /v1/compliance/evidence/bundles` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListBundlesResponseView {
    /// Bundles for the requesting tenant, newest first.
    pub bundles: Vec<BundleSummaryView>,
}

/// `GET /v1/compliance/evidence/bundles/{id}/download` response body.
///
/// Returns the metadata + a short-lived pre-signed download URL rather
/// than streaming bytes through the gateway so the audit log records
/// *who* asked for *which* bundle. The MVP's in-memory adapter returns
/// an `s3://`-style placeholder; the production binding will substitute
/// an `aws-sdk-s3` pre-signed URL.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DownloadBundleResponseView {
    /// Run id.
    pub run_id: String,
    /// WORM key.
    pub bundle_key: String,
    /// Lowercase hex SHA-256.
    pub bundle_sha256: String,
    /// Pre-signed URL valid for `expires_in_seconds`.
    pub presigned_url: String,
    /// Lifetime of the pre-signed URL in seconds.
    pub expires_in_seconds: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_request_defaults_to_empty_window() {
        let req = CollectEvidenceRequestView::default();
        assert!(req.period_start.is_none());
        assert!(req.period_end.is_none());
        let s = serde_json::to_string(&req).unwrap();
        let back: CollectEvidenceRequestView = serde_json::from_str(&s).unwrap();
        assert_eq!(back.period_start, req.period_start);
        assert_eq!(back.period_end, req.period_end);
    }

    #[test]
    fn list_response_serialises_full_summary() {
        let r = ListBundlesResponseView {
            bundles: vec![BundleSummaryView {
                run_id: "00000000-0000-0000-0000-000000000001".into(),
                bundle_key: "tenant/A/bundles/x.zip".into(),
                bundle_sha256: "deadbeef".into(),
                started_at: "2026-06-12T00:00:00Z".into(),
                finished_at: Some("2026-06-12T00:00:30Z".into()),
            }],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("deadbeef"));
        assert!(s.contains("tenant/A/bundles/x.zip"));
    }
}
