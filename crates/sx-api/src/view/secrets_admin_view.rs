//! DTOs for per-tenant DEK rotation admin endpoints (CRIT-003).
//!
//! Two endpoints, both gated by the `admin:secrets` permission:
//!
//! - `POST /v1/admin/secrets/rotate-dek` — start (or resume) a rotation
//!   for `tenant_id`. The handler delegates to
//!   [`crate::port::DekRotationAdminPort::rotate_dek`].
//! - `GET  /v1/admin/secrets/rotation-progress` — report the latest
//!   checkpoint for `tenant_id`. Delegates to
//!   [`crate::port::DekRotationAdminPort::rotation_progress`].
//!
//! ## Wire shape
//!
//! ```json
//! // POST /v1/admin/secrets/rotate-dek
//! { "tenant_id": "0192...", "target_version": 4 }
//!
//! // GET  /v1/admin/secrets/rotation-progress?tenant_id=0192...
//! {
//!   "data": {
//!     "tenant_id": "0192...",
//!     "target_dek_version": 4,
//!     "status": "in_progress",
//!     "processed_rows": 12340,
//!     "total_rows": 50000,
//!     "started_at": "2026-06-15T00:00:00Z",
//!     "last_checkpoint_at": "2026-06-15T00:01:23Z",
//!     "last_error": null
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/admin/secrets/rotate-dek` request body.
///
/// `tenant_id` is the UUID of the tenant whose DEK to rotate.
/// `target_version` is optional — when absent the adapter auto-bumps
/// to `current + 1`.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, PartialEq, Eq)]
pub struct RotateDekRequest {
    /// Tenant whose DEK to rotate. UUID rendered as a string.
    #[validate(length(min = 1, max = 64))]
    pub tenant_id: String,
    /// Optional explicit target version. When `None` the adapter
    /// auto-computes the next available version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<u32>,
}

/// `GET /v1/admin/secrets/rotation-progress` query string.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Validate)]
pub struct RotationProgressQuery {
    /// Tenant id to inspect. UUID rendered as a string.
    #[validate(length(min = 1, max = 64))]
    pub tenant_id: String,
}

/// Wire projection of a [`sx_secrets::dek_rotation::RotationCheckpoint`].
///
/// Note the deliberate omission of any KMS-side material. The
/// `last_error` field is the pre-redacted operator-facing message; the
/// adapter guarantees it never contains ciphertext or plaintext bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationProgressView {
    /// Tenant the rotation belongs to.
    pub tenant_id: String,
    /// Target DEK version every row will be re-encrypted to.
    pub target_dek_version: u32,
    /// Lifecycle status as a stable lower-snake string.
    pub status: String,
    /// Rows successfully re-encrypted so far.
    pub processed_rows: u64,
    /// Best-effort row count snapshot taken at job start.
    pub total_rows: u64,
    /// Wall-clock job start time, RFC 3339.
    pub started_at: String,
    /// Wall-clock stamp of the most recent successful checkpoint write,
    /// RFC 3339.
    pub last_checkpoint_at: String,
    /// Operator-facing redacted error message on `failed`. `None`
    /// otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// `POST /v1/admin/secrets/rotate-dek` response body. Mirrors the
/// `GET …/rotation-progress` projection so the caller sees the
/// initial checkpoint without an extra round-trip.
pub type RotateDekResponse = RotationProgressView;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rotate_dek_request_round_trips() {
        let req = RotateDekRequest {
            tenant_id: "0192aaaa-bbbb-cccc-dddd-eeeeffffffff".into(),
            target_version: Some(3),
        };
        let s = serde_json::to_string(&req).unwrap();
        let parsed: RotateDekRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn rotate_dek_request_omits_target_version_when_none() {
        let req = RotateDekRequest {
            tenant_id: "tenant".into(),
            target_version: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(!s.contains("target_version"), "must be omitted when None");
    }

    #[test]
    fn progress_view_round_trips() {
        let v = RotationProgressView {
            tenant_id: "t".into(),
            target_dek_version: 2,
            status: "completed".into(),
            processed_rows: 10,
            total_rows: 10,
            started_at: "2026-06-15T00:00:00Z".into(),
            last_checkpoint_at: "2026-06-15T00:01:00Z".into(),
            last_error: None,
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("last_error"));
        let parsed: RotationProgressView = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, v);
    }
}
