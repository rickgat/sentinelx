//! External audit-chain anchoring DTOs (P1-015).
//!
//! These views back the two anchoring endpoints exposed by
//! [`crate::controller::audit_anchor`]:
//!
//! - `GET /v1/audit/anchors` — paginated list of the tenant's anchor
//!   runs, newest-first. RBAC: `audit:read`.
//! - `POST /v1/audit/anchors/verify/{run_id}` — re-verify a persisted
//!   anchor run against the operator-pinned per-tenant CA cert. RBAC:
//!   `audit:read`.
//!
//! ## Wire shape
//!
//! ```json
//! // GET /v1/audit/anchors
//! {
//!   "data": {
//!     "items": [
//!       {
//!         "run_id": "0192…",
//!         "merkle_root": "<64-char hex>",
//!         "tsa_serial": "0x000000ab",
//!         "tsa_gen_time": "2026-06-14T00:00:00Z",
//!         "anchored_at": "2026-06-14T00:00:01Z",
//!         "payload_size_bytes": 1024
//!       }
//!     ],
//!     "has_more": false
//!   },
//!   "meta": {"...": "..."}
//! }
//! ```
//!
//! The raw TSA reply blob (`payload_bytes`) is **never** exposed on the
//! wire — we surface only its length so callers can sanity-check size
//! without ever seeing the bytes. The verify endpoint loads the blob
//! server-side.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Default page size for [`AuditAnchorListQuery::effective_limit`].
pub const DEFAULT_ANCHOR_LIMIT: u32 = 50;

/// Hard cap on [`AuditAnchorListQuery::effective_limit`]. Anchors run at
/// most a few times per hour per tenant, so a 500-row page covers more
/// than a week of history in a single response.
pub const MAX_ANCHOR_LIMIT: u32 = 500;

/// Wire projection of one `audit_anchor_runs` row.
///
/// Note the deliberate omission of `payload_bytes` — see the module-level
/// docs for the rationale. `payload_size_bytes` is exposed in its place
/// so operators can see the blob is non-empty and roughly the right
/// size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorRunView {
    /// UUID v4 of the run.
    pub run_id: String,
    /// Hex (lowercase) SHA-256 Merkle root the TSA signed.
    pub merkle_root: String,
    /// TSA-issued serial number (opaque to the caller).
    pub tsa_serial: String,
    /// `genTime` from the TSA reply, RFC 3339.
    pub tsa_gen_time: String,
    /// Server-side wall-clock time the row was persisted, RFC 3339.
    pub anchored_at: String,
    /// Length of the persisted TSA reply blob in bytes.
    ///
    /// Deliberately surfaces the length only — the verbatim bytes never
    /// leave the server (the engineering bar is "NEVER log raw TS bytes"
    /// and the wire surface follows the same rule).
    pub payload_size_bytes: u64,
}

/// `GET /v1/audit/anchors` query string.
#[derive(Debug, Clone, Default, Deserialize, Serialize, Validate)]
pub struct AuditAnchorListQuery {
    /// Page size, defaults to [`DEFAULT_ANCHOR_LIMIT`]; capped at
    /// [`MAX_ANCHOR_LIMIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(range(min = 1, max = 500))]
    pub limit: Option<u32>,
}

impl AuditAnchorListQuery {
    /// Effective page size: defaults to [`DEFAULT_ANCHOR_LIMIT`] when
    /// missing, capped to [`MAX_ANCHOR_LIMIT`].
    #[must_use]
    pub fn effective_limit(&self) -> u32 {
        self.limit
            .unwrap_or(DEFAULT_ANCHOR_LIMIT)
            .min(MAX_ANCHOR_LIMIT)
    }
}

/// `GET /v1/audit/anchors` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditAnchorListResponse {
    /// Anchor runs, newest-first.
    pub items: Vec<AuditAnchorRunView>,
    /// `true` when more rows exist past the returned page.
    pub has_more: bool,
}

/// `POST /v1/audit/anchors/verify/{run_id}` response body.
///
/// Returns the extracted serial / genTime / Merkle root on success. On
/// verification failure the controller returns a 422 with the verifier's
/// message embedded in the standard error envelope, and the in-process
/// CRITICAL sink fires — the row's signature is no longer trustworthy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditAnchorVerifyResponse {
    /// Run id that was re-verified.
    pub run_id: String,
    /// TSA-issued serial (echoed back from the persisted token).
    pub tsa_serial: String,
    /// `genTime` from the persisted token, RFC 3339.
    pub tsa_gen_time: String,
    /// Hex (lowercase) Merkle root the TSA signed.
    pub merkle_root: String,
    /// Always `true` — the endpoint either succeeds or surfaces a 4xx.
    pub verified: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn list_query_caps_limit() {
        let q = AuditAnchorListQuery {
            limit: Some(10_000),
        };
        assert_eq!(q.effective_limit(), MAX_ANCHOR_LIMIT);
    }

    #[test]
    fn list_query_default_limit() {
        let q = AuditAnchorListQuery::default();
        assert_eq!(q.effective_limit(), DEFAULT_ANCHOR_LIMIT);
    }

    #[test]
    fn run_view_serialises_without_payload_bytes() {
        let v = AuditAnchorRunView {
            run_id: "r".into(),
            merkle_root: "ab".into(),
            tsa_serial: "0x1".into(),
            tsa_gen_time: "2026-01-01T00:00:00Z".into(),
            anchored_at: "2026-01-01T00:00:01Z".into(),
            payload_size_bytes: 42,
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("payload_bytes"), "raw bytes must not appear");
        assert!(s.contains("payload_size_bytes"));
    }
}
