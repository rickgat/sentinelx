//! Customer-facing authentication DTOs — signup, email verification,
//! and password reset.
//!
//! These DTOs back the four **public** (unauthenticated) endpoints under
//! `/v1/auth/*` that customers use to self-service their account:
//!
//! - `POST /v1/auth/signup`            → [`SignupRequest`]
//! - `POST /v1/auth/verify-email`      → [`VerifyEmailRequest`]
//! - `POST /v1/auth/forgot-password`   → [`ForgotPasswordRequest`]
//! - `POST /v1/auth/reset-password`    → [`ResetPasswordRequest`]
//!
//! All four responses share the same minimal [`OkView`] shape so the
//! controllers can stay uniform.
//!
//! ## Secret hygiene
//!
//! Every plaintext password is wrapped in [`secrecy::SecretString`] so
//! that any accidental `Debug` log will print `<redacted>` rather than the
//! plaintext. Tokens (`verify-email`, `reset-password`) are
//! cryptographically random opaque strings — the API surface validates
//! length only and never logs them.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/auth/signup` request body.
///
/// Creates a brand-new customer-facing user in `tenant_id` with
/// `is_active = false`. The adapter responds with a verification token
/// out-of-band (email in production; logged token id in dev). The
/// account stays inactive until [`VerifyEmailRequest`] is exchanged.
#[derive(Deserialize, Validate)]
pub struct SignupRequest {
    /// Tenant uuid the new user belongs to.
    #[validate(custom(function = "validate_uuid"))]
    pub tenant_id: String,
    /// Login email — RFC-5322-ish validation via the `validator` crate.
    #[validate(email)]
    pub email: String,
    /// Plaintext password (8..=200 chars) — hashed before storage.
    #[serde(deserialize_with = "deserialize_secret")]
    pub password: SecretString,
}

impl std::fmt::Debug for SignupRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupRequest")
            .field("tenant_id", &self.tenant_id)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl SignupRequest {
    /// Borrow the plaintext password. Callers MUST NOT log the result.
    pub fn password(&self) -> &str {
        self.password.expose_secret()
    }

    /// Standalone password-length check used by the controller because
    /// `serde(deserialize_with)` bypasses the derive's `#[validate]` on
    /// the secret field. Length bounds mirror the admin-provisioning
    /// surface (`crates/sx-api/src/view/admin_view.rs`).
    pub fn validate_password(&self) -> Result<(), validator::ValidationError> {
        let len = self.password.expose_secret().len();
        if (8..=200).contains(&len) {
            Ok(())
        } else {
            Err(validator::ValidationError::new("password_length"))
        }
    }
}

/// `POST /v1/auth/verify-email` request body.
///
/// Carries the opaque token previously handed to the user out-of-band.
/// The adapter looks the token up, marks the user `is_active = true`,
/// and deletes the token so it cannot be replayed.
#[derive(Debug, Deserialize, Validate)]
pub struct VerifyEmailRequest {
    /// Verification token. Adapter-generated; only the length bound is
    /// enforced on the wire.
    #[validate(length(min = 8, max = 128))]
    pub token: String,
}

/// `POST /v1/auth/forgot-password` request body.
///
/// Always returns [`OkView`] regardless of whether the email exists —
/// the response never reveals account presence. The adapter mints a
/// reset token and (in production) emails it to the user.
#[derive(Debug, Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    /// Tenant the user belongs to (uuid).
    #[validate(custom(function = "validate_uuid"))]
    pub tenant_id: String,
    /// Account email.
    #[validate(email)]
    pub email: String,
}

/// `POST /v1/auth/reset-password` request body.
///
/// Exchanges a reset token for a new password hash. The token is
/// consumed (deleted) on success regardless of subsequent authentication
/// outcome.
#[derive(Deserialize, Validate)]
pub struct ResetPasswordRequest {
    /// Reset token from a prior [`ForgotPasswordRequest`].
    #[validate(length(min = 8, max = 128))]
    pub token: String,
    /// Replacement plaintext password (8..=200 chars).
    #[serde(deserialize_with = "deserialize_secret")]
    pub new_password: SecretString,
}

impl std::fmt::Debug for ResetPasswordRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetPasswordRequest")
            .field("token", &"<redacted>")
            .field("new_password", &"<redacted>")
            .finish()
    }
}

impl ResetPasswordRequest {
    /// Borrow the plaintext new password. Callers MUST NOT log it.
    pub fn new_password(&self) -> &str {
        self.new_password.expose_secret()
    }

    /// Same length policy as [`SignupRequest::validate_password`].
    pub fn validate_password(&self) -> Result<(), validator::ValidationError> {
        let len = self.new_password.expose_secret().len();
        if (8..=200).contains(&len) {
            Ok(())
        } else {
            Err(validator::ValidationError::new("password_length"))
        }
    }
}

/// Uniform success projection for every customer-auth endpoint.
///
/// The shape is deliberately empty — these endpoints never reveal
/// account existence, token validity, or any side-channel a caller
/// could probe to enumerate accounts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OkView {
    /// Always `true` on success; absent on the error envelope.
    pub ok: bool,
}

impl OkView {
    /// Convenience constructor.
    pub const fn ok() -> Self {
        Self { ok: true }
    }
}

/// Pull a `SecretString` out of a JSON string field.
///
/// Used by the `#[serde(deserialize_with)]` annotations on the password
/// fields above to keep the plaintext in a `SecretString` from the
/// instant it leaves the JSON parser.
fn deserialize_secret<'de, D>(de: D) -> Result<SecretString, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(de)?;
    Ok(SecretString::from(s))
}

/// Validate that `value` is a canonical UUID string.
fn validate_uuid(value: &str) -> Result<(), validator::ValidationError> {
    uuid::Uuid::parse_str(value).map_err(|_| validator::ValidationError::new("invalid_uuid"))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn valid_uuid() -> String {
        "11111111-1111-1111-1111-111111111111".to_string()
    }

    #[test]
    fn signup_redacts_password_in_debug() {
        let r = SignupRequest {
            tenant_id: valid_uuid(),
            email: "a@b.test".into(),
            password: SecretString::from("hunter2-correct".to_owned()),
        };
        let s = format!("{r:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("hunter2-correct"));
    }

    #[test]
    fn reset_password_redacts_token_and_password_in_debug() {
        let r = ResetPasswordRequest {
            token: "tok_should_not_leak".into(),
            new_password: SecretString::from("hunter2-correct".to_owned()),
        };
        let s = format!("{r:?}");
        assert!(!s.contains("tok_should_not_leak"));
        assert!(!s.contains("hunter2-correct"));
        assert!(s.contains("<redacted>"));
    }

    #[test]
    fn signup_deserialises_and_validates() {
        let json = serde_json::json!({
            "tenant_id": valid_uuid(),
            "email": "a@b.test",
            "password": "hunter2-correct",
        });
        let r: SignupRequest = serde_json::from_value(json).expect("deserialise");
        assert_eq!(r.password(), "hunter2-correct");
        assert!(r.validate().is_ok());
        assert!(r.validate_password().is_ok());
    }

    #[test]
    fn signup_rejects_invalid_email() {
        let json = serde_json::json!({
            "tenant_id": valid_uuid(),
            "email": "not-an-email",
            "password": "hunter2-correct",
        });
        let r: SignupRequest = serde_json::from_value(json).expect("deserialise");
        assert!(r.validate().is_err());
    }

    #[test]
    fn signup_rejects_invalid_tenant() {
        let json = serde_json::json!({
            "tenant_id": "not-a-uuid",
            "email": "a@b.test",
            "password": "hunter2-correct",
        });
        let r: SignupRequest = serde_json::from_value(json).expect("deserialise");
        assert!(r.validate().is_err());
    }

    #[test]
    fn signup_rejects_short_password() {
        let r = SignupRequest {
            tenant_id: valid_uuid(),
            email: "a@b.test".into(),
            password: SecretString::from("short".to_owned()),
        };
        assert!(r.validate_password().is_err());
    }

    #[test]
    fn reset_rejects_short_password() {
        let r = ResetPasswordRequest {
            token: "valid-token-len".into(),
            new_password: SecretString::from("x".to_owned()),
        };
        assert!(r.validate_password().is_err());
    }

    #[test]
    fn verify_email_rejects_short_token() {
        let r = VerifyEmailRequest {
            token: "abc".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn forgot_password_rejects_invalid_email() {
        let r = ForgotPasswordRequest {
            tenant_id: valid_uuid(),
            email: "not-an-email".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn ok_view_serialises() {
        let v = serde_json::to_value(OkView::ok()).expect("serialise");
        assert_eq!(v["ok"], true);
    }
}
