//! HTTP DTOs for the P1-004 endpoints.
//!
//! The shape is intentionally small + serde-friendly so `sx-api` can
//! re-export these directly and the OpenAPI doc generation can pick
//! them up without a translator.
//!
//! The three endpoints — all per-tenant — are:
//!
//! * `POST /v1/compliance/evidence/collect`
//!   * In:  [`CollectEvidenceRequest`] (optional `period_start` /
//!     `period_end` override; otherwise defaults to "last 7 days").
//!   * Out: [`CollectEvidenceResponse`] with the new `run_id` and the
//!     S3 key the bundle was uploaded to.
//! * `GET /v1/compliance/evidence/bundles`
//!   * Out: [`ListBundlesResponse`] (per-tenant scoped).
//! * `GET /v1/compliance/evidence/bundles/{id}/download`
//!   * Out: [`DownloadBundleResponse`] — pre-signed URL + sha256 + key.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Request body for `POST /v1/compliance/evidence/collect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectEvidenceRequest {
    /// Optional start of the audit period the bundle should cover.
    /// Defaults to `period_end - 7d` if not supplied.
    #[serde(default)]
    pub period_start: Option<OffsetDateTime>,
    /// Optional end of the audit period. Defaults to `now()`.
    #[serde(default)]
    pub period_end: Option<OffsetDateTime>,
}

/// Response body for `POST /v1/compliance/evidence/collect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectEvidenceResponse {
    /// Identifier of the run created.
    pub run_id: Uuid,
    /// WORM key the bundle was written to.
    pub bundle_key: String,
    /// Lowercase hex SHA-256 of the bundle bytes.
    pub bundle_sha256: String,
    /// Number of files included in the bundle.
    pub files: u32,
}

/// Summary projection of one bundle for the list endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSummary {
    /// Run id.
    pub run_id: Uuid,
    /// WORM key.
    pub bundle_key: String,
    /// Lowercase hex SHA-256.
    pub bundle_sha256: String,
    /// When the run started.
    pub started_at: OffsetDateTime,
    /// When the run finished.
    pub finished_at: Option<OffsetDateTime>,
}

/// Response body for `GET /v1/compliance/evidence/bundles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListBundlesResponse {
    /// Bundles for the requesting tenant, newest first.
    pub bundles: Vec<BundleSummary>,
}

/// Response body for `GET /v1/compliance/evidence/bundles/{id}/download`.
///
/// We return the metadata + a short-lived pre-signed download URL
/// rather than streaming bytes through the gateway so the audit log
/// records *who* asked for *which* bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadBundleResponse {
    /// Run id.
    pub run_id: Uuid,
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn collect_request_defaults_round_trip() {
        let req = CollectEvidenceRequest {
            period_start: None,
            period_end: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: CollectEvidenceRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn list_response_serialises_bundle_metadata() {
        let r = ListBundlesResponse {
            bundles: vec![BundleSummary {
                run_id: Uuid::nil(),
                bundle_key: "tenant/A/bundles/x.zip".into(),
                bundle_sha256: "deadbeef".into(),
                started_at: datetime!(2026-06-12 00:00:00 UTC),
                finished_at: Some(datetime!(2026-06-12 00:01:00 UTC)),
            }],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("tenant/A/bundles/x.zip"));
        assert!(s.contains("deadbeef"));
    }
}
