//! JWT claim set carried inside every access / refresh token.
//!
//! `AccessClaims` is what we sign on the way out and what we deserialize
//! and validate on the way in. Field names match the JWT registered
//! claim spec where possible (`sub`, `iss`, `aud`, `exp`, `nbf`, `iat`,
//! `jti`).

use serde::{Deserialize, Serialize};

use crate::domain::Permission;

/// The classification of a token — access vs refresh.
///
/// Encoded into the JWT body as the `typ` claim so that a refresh token
/// stolen and replayed at an access-only endpoint will be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Short-lived access token.
    Access,
    /// Long-lived refresh token.
    Refresh,
}

/// Body of every JWT issued by this crate.
///
/// `sub`, `tenant_id`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `sid` are
/// required. Roles are duplicated alongside permissions for ergonomic
/// reasons (callers often want to display the role name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Subject — the user id (uuid string).
    pub sub: String,
    /// Tenant id (uuid string).
    pub tenant_id: String,
    /// Issuer — verified against `JwtConfig.issuer`.
    pub iss: String,
    /// Audience — verified against `JwtConfig.audience`.
    pub aud: String,
    /// Issued-at, seconds since epoch.
    pub iat: i64,
    /// Not-before, seconds since epoch.
    pub nbf: i64,
    /// Expiry, seconds since epoch.
    pub exp: i64,
    /// JWT id — opaque, unique per token, used for revocation lookup.
    pub jti: String,
    /// Session id — links the token to a [`crate::model::Session`].
    pub sid: String,
    /// Token classification.
    #[serde(rename = "typ")]
    pub token_type: TokenType,
    /// Role names assigned to the user (denormalised for display).
    #[serde(default)]
    pub roles: Vec<String>,
    /// Permission grants (`resource:action`) carried in the token.
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// Credential binding — when present, this access token was issued
    /// against a successful FIDO2 / `WebAuthn` assertion and the value is
    /// the base64url-encoded credential id (`cred_id`) of the passkey
    /// that satisfied the MFA factor. Downstream services can require a
    /// non-empty `cred_id` on sensitive operations to guarantee the
    /// session is bound to a hardware-backed authenticator (P1-002).
    ///
    /// Absent (serialised as omitted) for password / OIDC / TOTP-only
    /// sessions to keep wire compatibility with pre-WebAuthn tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_id: Option<String>,
}

impl AccessClaims {
    /// Whether the claims have a non-empty subject and tenant.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !self.sub.is_empty() && !self.tenant_id.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_requires_sub_and_tenant() {
        let c = AccessClaims {
            sub: "u".into(),
            tenant_id: "t".into(),
            iss: "i".into(),
            aud: "a".into(),
            iat: 0,
            nbf: 0,
            exp: 0,
            jti: "j".into(),
            sid: "s".into(),
            token_type: TokenType::Access,
            roles: vec![],
            permissions: vec![],
            cred_id: None,
        };
        assert!(c.is_well_formed());
    }

    #[test]
    fn cred_id_round_trips_through_serde() {
        let c = AccessClaims {
            sub: "u".into(),
            tenant_id: "t".into(),
            iss: "i".into(),
            aud: "a".into(),
            iat: 0,
            nbf: 0,
            exp: 0,
            jti: "j".into(),
            sid: "s".into(),
            token_type: TokenType::Access,
            roles: vec![],
            permissions: vec![],
            cred_id: Some("dGVzdC1jcmVk".into()),
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains("\"cred_id\":\"dGVzdC1jcmVk\""));
        let parsed: AccessClaims = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.cred_id, Some("dGVzdC1jcmVk".into()));
    }

    #[test]
    fn cred_id_absent_is_omitted_on_serialise() {
        let c = AccessClaims {
            sub: "u".into(),
            tenant_id: "t".into(),
            iss: "i".into(),
            aud: "a".into(),
            iat: 0,
            nbf: 0,
            exp: 0,
            jti: "j".into(),
            sid: "s".into(),
            token_type: TokenType::Access,
            roles: vec![],
            permissions: vec![],
            cred_id: None,
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(
            !s.contains("cred_id"),
            "absent cred_id must be skipped, got: {s}"
        );
    }

    #[test]
    fn token_type_serialises_snake_case() {
        let s = serde_json::to_string(&TokenType::Access).unwrap();
        assert_eq!(s, "\"access\"");
        let s = serde_json::to_string(&TokenType::Refresh).unwrap();
        assert_eq!(s, "\"refresh\"");
    }
}
