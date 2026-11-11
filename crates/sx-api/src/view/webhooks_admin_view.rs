//! DTOs for the per-tenant webhook signing-key admin endpoint (MED-003).
//!
//! One endpoint, gated by the `admin:webhooks` permission:
//!
//! - `POST /v1/admin/webhooks/keys/rotate` — force-rotate the
//!   tenant's outbound webhook signing key right now. The handler
//!   delegates to
//!   [`crate::port::WebhookKeyRotationAdminPort::force_rotate`].
//!
//! ## Wire shape
//!
//! ```json
//! // POST /v1/admin/webhooks/keys/rotate
//! { "tenant_id": "0192...-aaaa" }
//!
//! // 200 OK
//! {
//!   "data": {
//!     "tenant_id": "0192...-aaaa",
//!     "new_kid": "kid_a1b2c3d4",
//!     "previous_kid": "kid_99887766",
//!     "previous_retire_at": "2026-06-22T00:00:00Z",
//!     "minted_at": "2026-06-15T00:00:00Z"
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/admin/webhooks/keys/rotate` request body.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, PartialEq, Eq)]
pub struct RotateWebhookKeyRequest {
    /// Tenant whose signing key to rotate. UUID string.
    #[validate(length(min = 1, max = 64))]
    pub tenant_id: String,
}

/// Wire projection of a successful rotation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotateWebhookKeyResponse {
    /// Tenant the rotation applied to.
    pub tenant_id: String,
    /// Freshly minted kid (header value).
    pub new_kid: String,
    /// Previous active kid, if any (omitted when this was the first
    /// rotation for the tenant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_kid: Option<String>,
    /// Wall-clock RFC-3339 stamp at which the previous kid will be
    /// retired (omitted when there was no previous kid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_retire_at: Option<String>,
    /// Wall-clock RFC-3339 stamp when the new kid was minted (server
    /// clock).
    pub minted_at: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let req = RotateWebhookKeyRequest {
            tenant_id: "0192aaaa-bbbb-cccc-dddd-eeeeffffffff".into(),
        };
        let s = serde_json::to_string(&req).unwrap();
        let parsed: RotateWebhookKeyRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn response_omits_previous_when_first_rotation() {
        let resp = RotateWebhookKeyResponse {
            tenant_id: "t".into(),
            new_kid: "kid_aa".into(),
            previous_kid: None,
            previous_retire_at: None,
            minted_at: "2026-06-15T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(!s.contains("previous_kid"));
        assert!(!s.contains("previous_retire_at"));
    }

    #[test]
    fn response_includes_previous_when_present() {
        let resp = RotateWebhookKeyResponse {
            tenant_id: "t".into(),
            new_kid: "kid_new".into(),
            previous_kid: Some("kid_old".into()),
            previous_retire_at: Some("2026-06-22T00:00:00Z".into()),
            minted_at: "2026-06-15T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("kid_old"));
        assert!(s.contains("2026-06-22"));
    }
}
