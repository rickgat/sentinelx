//! Authentication-related request/response DTOs.
//!
//! These are wire-stability shims: keeping the shapes here means the public
//! schema does not move when the underlying `sx-iam` use-case DTOs evolve.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// Login request body.
///
/// The password is wrapped in [`SecretString`] so that any accidental
/// `Debug` log will print `***` rather than the plaintext.
#[derive(Deserialize, Validate)]
pub struct LoginView {
    /// Tenant id (uuid) the user belongs to.
    #[validate(length(min = 1))]
    pub tenant_id: String,
    /// Email — must be a syntactically valid address.
    #[validate(email)]
    pub email: String,
    /// Plaintext password — never logged, never echoed back.
    #[serde(deserialize_with = "deserialize_secret")]
    pub password: SecretString,
}

impl std::fmt::Debug for LoginView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginView")
            .field("tenant_id", &self.tenant_id)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .finish()
    }
}

fn deserialize_secret<'de, D>(de: D) -> Result<SecretString, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(de)?;
    Ok(SecretString::from(s))
}

impl LoginView {
    /// Borrow the plaintext password — callers must not log the result.
    pub fn password(&self) -> &str {
        self.password.expose_secret()
    }
}

/// Refresh-token request body.
#[derive(Debug, Deserialize, Validate)]
pub struct RefreshView {
    /// The refresh JWT.
    #[validate(length(min = 1))]
    pub refresh_token: String,
}

/// Token-pair response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenView {
    /// Short-lived access JWT.
    pub access_token: String,
    /// Long-lived refresh JWT.
    pub refresh_token: String,
    /// Seconds until `access_token` expires.
    pub expires_in: i64,
    /// Token type — always `Bearer`.
    pub token_type: String,
}

impl TokenView {
    /// Build a new bearer token view.
    pub fn bearer(access: impl Into<String>, refresh: impl Into<String>, expires_in: i64) -> Self {
        Self {
            access_token: access.into(),
            refresh_token: refresh.into(),
            expires_in,
            token_type: "Bearer".to_owned(),
        }
    }
}

/// OIDC exchange request body.
///
/// The dashboard hands the IdP-issued `id_token` to
/// `POST /v1/auth/oidc/exchange`; the API verifies the token against the
/// configured JWKS and returns the standard [`TokenView`] response.
///
/// The `id_token` field is wrapped as a plain `String` because OIDC tokens
/// must be sent verbatim and the API logs them at TRACE-or-below only.
#[derive(Debug, Deserialize, Validate)]
pub struct OidcExchangeRequest {
    /// The OIDC `id_token` returned by the IdP after a successful login.
    #[validate(length(min = 1))]
    pub id_token: String,
}

/// Logout request body.
#[derive(Debug, Deserialize, Validate)]
pub struct LogoutView {
    /// Refresh token to revoke (or `None` to revoke the current session
    /// indicated by the bearer access token).
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn login_view_password_redacted_in_debug() {
        let v = LoginView {
            tenant_id: "t".into(),
            email: "a@b.test".into(),
            password: SecretString::from("hunter2".to_owned()),
        };
        let s = format!("{v:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("hunter2"));
    }

    #[test]
    fn token_view_round_trip() {
        let t = TokenView::bearer("at", "rt", 900);
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["access_token"], "at");
        assert_eq!(v["refresh_token"], "rt");
        assert_eq!(v["expires_in"], 900);
        assert_eq!(v["token_type"], "Bearer");
    }

    #[test]
    fn login_view_deserialises() {
        let json = serde_json::json!({
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "email": "a@b.test",
            "password": "hunter2",
        });
        let v: LoginView = serde_json::from_value(json).unwrap();
        assert_eq!(v.password(), "hunter2");
        assert!(v.validate().is_ok());
    }
}
