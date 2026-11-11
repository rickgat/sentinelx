//! Wire DTOs for OIDC confidential-client endpoints (MED-004).
//!
//! These types live exclusively on the HTTP boundary; the domain types
//! [`sx_iam::model::oidc_client::OidcClient`] never appear in JSON.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request body of `POST /v1/oauth/token` with `grant_type=client_credentials`.
///
/// The fields are name-matched to OAuth2 / RFC 7521 form parameters; the
/// API accepts both `application/json` and
/// `application/x-www-form-urlencoded`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Validate)]
pub struct OAuthTokenRequest {
    /// MUST be `"client_credentials"` — other grants are rejected on the
    /// MED-004 token endpoint.
    #[validate(length(min = 1, max = 64))]
    pub grant_type: String,
    /// MUST be the JWT-bearer URN.
    #[validate(length(min = 1, max = 256))]
    pub client_assertion_type: String,
    /// The signed JWT.
    #[validate(length(min = 1, max = 8192))]
    pub client_assertion: String,
    /// Optional `scope` claim — currently echoed back as-is, not used
    /// for permission gating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 512))]
    pub scope: Option<String>,
}

/// Successful `POST /v1/oauth/token` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthTokenResponse {
    /// The bearer access token.
    pub access_token: String,
    /// `"Bearer"`.
    pub token_type: String,
    /// Seconds until the token's `exp`.
    pub expires_in: u64,
    /// Optional scope echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// `"rotate-now"` when the client authenticated with the previous
    /// (grace-window) secret. Absent otherwise — silence means "live
    /// secret used".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Response body of `POST /v1/admin/oidc/clients/{client_id}/rotate-secret`.
///
/// The plaintext `new_secret` is surfaced exactly once. Subsequent
/// reads never expose it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotateClientSecretResponse {
    /// The customer-facing client identifier (echoed for confirmation).
    pub client_id: String,
    /// Freshly generated secret. URL-safe base64.
    pub new_secret: String,
    /// Wall-clock the previous secret stops being accepted (RFC 3339).
    pub previous_expires_at: String,
    /// Wall-clock of this rotation (RFC 3339).
    pub rotated_at: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn token_request_roundtrips_json() {
        let body = OAuthTokenRequest {
            grant_type: "client_credentials".into(),
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            client_assertion: "header.payload.sig".into(),
            scope: Some("read".into()),
        };
        let s = serde_json::to_string(&body).unwrap();
        let back: OAuthTokenRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn token_response_omits_optional_fields() {
        let body = OAuthTokenResponse {
            access_token: "tok".into(),
            token_type: "Bearer".into(),
            expires_in: 900,
            scope: None,
            warning: None,
        };
        let s = serde_json::to_string(&body).unwrap();
        assert!(!s.contains("scope"));
        assert!(!s.contains("warning"));
    }

    #[test]
    fn rotate_response_carries_new_secret_field() {
        let r = RotateClientSecretResponse {
            client_id: "acme".into(),
            new_secret: "fresh".into(),
            previous_expires_at: "2030-01-08T00:00:00Z".into(),
            rotated_at: "2030-01-01T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("new_secret"));
        assert!(s.contains("acme"));
    }
}
