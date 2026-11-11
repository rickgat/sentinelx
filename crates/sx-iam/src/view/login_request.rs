//! HTTP-layer DTO for the login endpoint.

use secrecy::SecretString;
use serde::Deserialize;
use validator::Validate;

/// Payload accepted by `POST /v1/auth/login`.
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    /// Tenant slug or UUID — adapter chooses.
    #[validate(length(min = 1, max = 128))]
    pub tenant: String,

    /// Login email (validator enforces email shape).
    #[validate(email)]
    pub email: String,

    /// Plaintext password. Wrapped in [`SecretString`] so it does not
    /// appear in the [`std::fmt::Debug`] output of this struct.
    pub password: SecretString,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn password_redacts_in_debug() {
        let r = LoginRequest {
            tenant: "acme".into(),
            email: "a@b.io".into(),
            password: SecretString::from("hunter2".to_string()),
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("hunter2"));
    }

    #[test]
    fn validates_email() {
        let bad = LoginRequest {
            tenant: "acme".into(),
            email: "not-an-email".into(),
            password: SecretString::from("x".to_string()),
        };
        assert!(bad.validate().is_err());
    }
}
