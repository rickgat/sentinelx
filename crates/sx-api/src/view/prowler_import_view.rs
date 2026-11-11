//! Prowler-import DTOs — backs `POST /v1/discovery/prowler/import` (P1-009).
//!
//! Wire shapes mirror [`sx_discovery::prowler_import::ImportProwlerOutput`]
//! but stay decoupled so the API contract can evolve independently of the
//! domain model. The endpoint is multipart (file upload) and returns the
//! per-import metrics envelope the dashboard renders in the CSPM history
//! table.

use serde::{Deserialize, Serialize};

/// Response body for `POST /v1/discovery/prowler/import`.
///
/// Shape is "accepted-async": the import currently executes synchronously
/// inside the request budget, but the 202-style `id` field is preserved so
/// the upcoming background-worker swap-in is a pure adapter change rather
/// than a wire-shape break.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProwlerImportResponse {
    /// Stable id for this import — useful for cross-referencing the audit
    /// log row.
    pub id: String,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// Hex-encoded SHA-256 of the uploaded payload.
    pub upload_digest: String,
    /// Original upload size in bytes.
    pub upload_bytes: u64,
    /// Total parsed findings (post-status-filter, pre-dedupe).
    pub parsed: u32,
    /// Findings actually written to the multicloud table.
    pub written: u32,
    /// Cross-tenant rejections.
    pub rejected_cross_tenant: u32,
    /// In-batch duplicates suppressed.
    pub deduplicated: u32,
    /// KEV uplifts applied (i.e. severity bumped one tier).
    pub kev_uplifts_applied: u32,
    /// Unmapped Prowler check-ids encountered (still persisted under a
    /// `cspm.<provider>.unmapped.*` id).
    pub unmapped_check_ids: u32,
    /// RFC 3339 timestamp the import was accepted.
    pub accepted_at: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn response_serialises_with_snake_case_keys() {
        let v = ProwlerImportResponse {
            id: "imp".into(),
            tenant_id: "tnt".into(),
            upload_digest: "deadbeef".into(),
            upload_bytes: 4096,
            parsed: 12,
            written: 11,
            rejected_cross_tenant: 0,
            deduplicated: 1,
            kev_uplifts_applied: 2,
            unmapped_check_ids: 0,
            accepted_at: "2027-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"upload_digest\""));
        assert!(json.contains("\"kev_uplifts_applied\":2"));
        assert!(json.contains("\"rejected_cross_tenant\":0"));
    }

    #[test]
    fn response_round_trips() {
        let v = ProwlerImportResponse {
            id: "imp".into(),
            tenant_id: "tnt".into(),
            upload_digest: "x".into(),
            upload_bytes: 1,
            parsed: 1,
            written: 1,
            rejected_cross_tenant: 0,
            deduplicated: 0,
            kev_uplifts_applied: 0,
            unmapped_check_ids: 0,
            accepted_at: "2027-01-01T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: ProwlerImportResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }
}
