//! `IamError` — the canonical error type for the sx-iam crate.
//!
//! Variants are intentionally coarse-grained: at the boundary an HTTP layer
//! must not be able to distinguish "user does not exist" from "password
//! mismatch" or it would leak account-existence to an attacker. Both map
//! to [`IamError::InvalidCredentials`].
//!
//! All variants are safe to log via `Display` (no secrets, no plaintext
//! passwords, no token material).

use thiserror::Error;

/// Public error surface of the sx-iam crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IamError {
    /// Credentials did not authenticate (wrong password OR no such user).
    ///
    /// Deliberately ambiguous — see module docs.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Login attempts exceeded the configured threshold.
    #[error("account locked")]
    AccountLocked,

    /// Bearer token presented past its `exp` claim.
    #[error("token expired")]
    TokenExpired,

    /// Bearer token failed signature, header, claim, or format validation.
    ///
    /// Deliberately coarse — the upstream caller does not need to know
    /// *which* validation failed, only that the token is unusable.
    #[error("invalid token")]
    InvalidToken,

    /// Authenticated principal lacks the permission required by the use case.
    #[error("forbidden: missing permission {required}")]
    Forbidden {
        /// The `resource:action` string that was required.
        required: String,
    },

    /// Programmer error or unexpected library failure.
    #[error("internal: {0}")]
    Internal(String),

    /// Adapter (database, cache, ...) reported a transport failure.
    #[error("repository: {0}")]
    Repository(String),

    /// Configuration value is missing or invalid at run time.
    #[error("config: {0}")]
    Config(String),

    /// An entity with the same uniqueness key already exists.
    ///
    /// Used by write-side use cases (e.g. user provisioning) when a
    /// repository rejects an insert because of a unique-constraint
    /// collision such as `(tenant_id, email)`.
    #[error("conflict: {0}")]
    Conflict(String),
}

impl IamError {
    /// Convenience constructor for [`IamError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Convenience constructor for [`IamError::Repository`].
    #[must_use]
    pub fn repository(msg: impl Into<String>) -> Self {
        Self::Repository(msg.into())
    }

    /// Convenience constructor for [`IamError::Config`].
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Convenience constructor for [`IamError::Forbidden`].
    #[must_use]
    pub fn forbidden(required: impl Into<String>) -> Self {
        Self::Forbidden {
            required: required.into(),
        }
    }

    /// Convenience constructor for [`IamError::Conflict`].
    #[must_use]
    pub fn conflict(entity: impl Into<String>) -> Self {
        Self::Conflict(entity.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::IamError;

    #[test]
    fn invalid_credentials_does_not_leak() {
        // The Display representation must never disclose which side failed.
        let e = IamError::InvalidCredentials;
        let msg = e.to_string();
        assert!(!msg.contains("user"));
        assert!(!msg.contains("password"));
    }

    #[test]
    fn forbidden_renders_required_permission() {
        let e = IamError::forbidden("engagement:read");
        assert_eq!(
            e.to_string(),
            "forbidden: missing permission engagement:read"
        );
    }

    #[test]
    fn token_expired_distinct_from_invalid() {
        assert_ne!(IamError::TokenExpired, IamError::InvalidToken);
    }

    #[test]
    fn constructors_classify_correctly() {
        assert!(matches!(IamError::internal("x"), IamError::Internal(_)));
        assert!(matches!(IamError::repository("x"), IamError::Repository(_)));
        assert!(matches!(IamError::config("x"), IamError::Config(_)));
    }
}
