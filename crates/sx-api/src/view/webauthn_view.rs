//! FIDO2 / `WebAuthn` MFA DTOs (P1-002).
//!
//! Backs the four `/v1/auth/mfa/webauthn/{register,login}/{start,finish}`
//! endpoints. The wire format closely follows the W3C `WebAuthn` JSON
//! serialisation so a vanilla browser SDK can hand the request directly
//! to `navigator.credentials.{create,get}` and pipe the response right
//! back to the server.
//!
//! ## Why so many `serde_json::Value`s?
//!
//! `webauthn-rs`'s on-the-wire types (`CreationChallengeResponse`,
//! `RegisterPublicKeyCredential`, etc.) are stable but big, and the API
//! crate intentionally does not depend on `webauthn-rs`. We pass them
//! through as opaque JSON so the storage/state layer below the trait
//! object can deserialise them however it wants. The HTTP boundary
//! still validates that the envelope shape (top-level `challenge` etc.)
//! is well-formed via [`validator::Validate`] before forwarding.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/auth/mfa/webauthn/register/start` request body.
///
/// Triggered by an authenticated user from the UI; the caller's tenant
/// id and user id come from the bearer claim, NOT this DTO.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RegisterStartRequest {
    /// Optional user-visible label that will be stored on the credential
    /// row once the ceremony completes. Surfaced in the management UI
    /// (`/v1/auth/mfa/webauthn/credentials`) to help users distinguish
    /// "YubiKey 5" from "MacBook Touch ID" at a glance.
    #[validate(length(min = 1, max = 64))]
    pub label: Option<String>,
}

/// `POST /v1/auth/mfa/webauthn/register/start` response.
///
/// `challenge` is the raw `CreationChallengeResponse` JSON the browser
/// hands to `navigator.credentials.create`. `state_id` is the opaque
/// handle the client returns in `register/finish` so the server can
/// look up the matching `PasskeyRegistration` state without trusting
/// any client-supplied identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// Opaque server-side state handle (UUID v4) — short TTL.
    pub state_id: String,
    /// Raw `CreationChallengeResponse` JSON — pass straight to the browser.
    pub challenge: serde_json::Value,
}

/// `POST /v1/auth/mfa/webauthn/register/finish` request body.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterFinishRequest {
    /// `state_id` returned by `register/start`.
    pub state_id: String,
    /// Raw `RegisterPublicKeyCredential` JSON the browser produced.
    pub response: serde_json::Value,
}

/// `POST /v1/auth/mfa/webauthn/register/finish` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFinishResponse {
    /// Base64url-encoded credential id that the server just persisted.
    /// Echoed back to the client so the management UI can map the new
    /// credential to a freshly-rendered row without an extra round-trip.
    pub cred_id: String,
}

/// `POST /v1/auth/mfa/webauthn/login/start` request body.
///
/// `email` is required because login/start happens **before** the user
/// is authenticated — there is no bearer claim to read the user id
/// from. Tenant id is derived from the email lookup.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct LoginStartRequest {
    /// Lower-cased email of the account being logged in.
    #[validate(email)]
    pub email: String,
}

/// `POST /v1/auth/mfa/webauthn/login/start` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// Opaque server-side state handle (UUID v4) — short TTL.
    pub state_id: String,
    /// Raw `RequestChallengeResponse` JSON the browser hands to
    /// `navigator.credentials.get`.
    pub challenge: serde_json::Value,
}

/// `POST /v1/auth/mfa/webauthn/login/finish` request body.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginFinishRequest {
    /// `state_id` returned by `login/start`.
    pub state_id: String,
    /// Raw `PublicKeyCredential` JSON the browser produced.
    pub response: serde_json::Value,
}

/// `POST /v1/auth/mfa/webauthn/login/finish` response — a fresh access
/// token bound to the passkey that satisfied the assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishResponse {
    /// Bearer access token; carries the `cred_id` claim.
    pub access_token: String,
    /// Refresh token (also carries `cred_id`).
    pub refresh_token: String,
    /// Lifetime of the access token in seconds.
    pub expires_in: u64,
    /// Base64url-encoded credential id of the passkey that authenticated.
    pub cred_id: String,
}

// ---------------------------------------------------------------------------
// HIGH-002 — AAGUID policy + MDS3 management surface
// ---------------------------------------------------------------------------

/// `PUT /v1/iam/webauthn/aaguid-policy/{aaguid}` request body.
///
/// Wire shape mirrors `sx_iam::model::webauthn::AaguidAction`. `reason`
/// is required and capped at 256 chars by validator.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PutAaguidPolicyRequest {
    /// Either `"allow"` or `"block"`. Anything else is rejected at
    /// validation time.
    #[validate(length(min = 1, max = 16))]
    pub action: String,
    /// Operator-supplied reason. Recorded on the audit log and
    /// surfaced in the management UI tooltip.
    #[validate(length(min = 1, max = 256))]
    pub reason: String,
}

/// One row in the AAGUID policy list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AaguidPolicyView {
    /// 16-byte AAGUID, encoded as the canonical UUID string.
    pub aaguid: String,
    /// `"allow"` or `"block"`.
    pub action: String,
    /// Operator-supplied reason.
    pub reason: String,
    /// UUID of the operator who set the row.
    pub set_by: String,
    /// RFC 3339 / ISO-8601 timestamp.
    pub set_at: String,
}

/// `GET /v1/iam/webauthn/aaguid-policy` response — list of rows for the
/// caller's tenant. The presence of any `allow` row puts the tenant in
/// allowlist-only mode (`allowlist_mode = true`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AaguidPolicyListResponse {
    /// All policy rows for the tenant, oldest-first.
    pub rows: Vec<AaguidPolicyView>,
    /// True iff at least one `allow` row exists — convenience flag
    /// surfaced so the dashboard does not need to re-derive it.
    pub allowlist_mode: bool,
}

/// `GET /v1/iam/webauthn/mds-status` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdsStatusView {
    /// Last successful refresh time (RFC 3339), or `null` if never.
    pub last_refresh: Option<String>,
    /// Total entry count in the cache.
    pub total_entries: u64,
    /// Lower-case hex SHA-256 fingerprint of the pinned MDS root cert.
    pub root_cert_fingerprint: String,
    /// True iff the cache is older than the configured tolerance window.
    pub is_stale: bool,
}

/// One credential row in the per-user credential listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCredentialView {
    /// Base64url-encoded credential id.
    pub cred_id: String,
    /// Optional user-set label.
    pub label: Option<String>,
    /// AAGUID as canonical UUID string. `null` if the authenticator
    /// did not return one (U2F-style devices).
    pub aaguid: Option<String>,
    /// Authenticator name from the MDS cache (`null` if not present).
    pub authenticator_name: Option<String>,
    /// FIDO certification level from MDS (`null` if not present).
    pub certification_level: Option<String>,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Last-used timestamp (RFC 3339), or `null`.
    pub last_used_at: Option<String>,
}

/// `GET /v1/iam/webauthn/credentials` response — every active
/// credential for the authenticated user enriched with MDS metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialListResponse {
    /// All active credentials, oldest-first.
    pub credentials: Vec<UserCredentialView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn register_start_validates_label_length() {
        let bad = RegisterStartRequest {
            label: Some(String::new()),
        };
        assert!(bad.validate().is_err());
        let ok = RegisterStartRequest {
            label: Some("yubikey-5".to_owned()),
        };
        assert!(ok.validate().is_ok());
        let absent = RegisterStartRequest { label: None };
        assert!(absent.validate().is_ok());
    }

    #[test]
    fn login_start_rejects_invalid_email() {
        let bad = LoginStartRequest {
            email: "not-an-email".to_owned(),
        };
        assert!(bad.validate().is_err());
        let ok = LoginStartRequest {
            email: "alice@example.com".to_owned(),
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn put_aaguid_policy_validates_action_and_reason_lengths() {
        let bad_empty_reason = PutAaguidPolicyRequest {
            action: "allow".into(),
            reason: String::new(),
        };
        assert!(bad_empty_reason.validate().is_err());
        let too_long_reason = PutAaguidPolicyRequest {
            action: "block".into(),
            reason: "x".repeat(257),
        };
        assert!(too_long_reason.validate().is_err());
        let ok = PutAaguidPolicyRequest {
            action: "block".into(),
            reason: "RP-001".into(),
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn aaguid_policy_view_round_trips() {
        let v = AaguidPolicyView {
            aaguid: "00000000-0000-0000-0000-000000000001".into(),
            action: "allow".into(),
            reason: "approved".into(),
            set_by: "00000000-0000-0000-0000-000000000099".into(),
            set_at: "1970-01-01T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: AaguidPolicyView = serde_json::from_str(&s).unwrap();
        assert_eq!(back.aaguid, v.aaguid);
        assert_eq!(back.action, v.action);
    }

    #[test]
    fn mds_status_view_round_trips() {
        let v = MdsStatusView {
            last_refresh: Some("2026-06-14T00:00:00Z".into()),
            total_entries: 142,
            root_cert_fingerprint: "abc".into(),
            is_stale: false,
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: MdsStatusView = serde_json::from_str(&s).unwrap();
        assert_eq!(back.total_entries, 142);
        assert!(!back.is_stale);
    }

    #[test]
    fn login_finish_response_round_trips_through_serde() {
        let r = LoginFinishResponse {
            access_token: "abc".into(),
            refresh_token: "def".into(),
            expires_in: 900,
            cred_id: "Y3JlZA".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: LoginFinishResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cred_id, "Y3JlZA");
        assert_eq!(back.expires_in, 900);
    }
}
