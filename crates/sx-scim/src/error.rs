//! SCIM-layer error type.
//!
//! [`ScimError`] is the canonical error returned from the filter parser,
//! the provisioner, and the adapter. Every variant is safe to `Display`
//! and never carries secrets or PII.

use thiserror::Error;

/// Public error surface of the `sx-scim` crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScimError {
    /// Filter expression failed to parse (bad operator, unterminated string,
    /// unsupported attribute path, etc.).
    #[error("invalid filter: {0}")]
    InvalidFilter(String),

    /// Resource (User / Group) not found.
    #[error("resource not found")]
    NotFound,

    /// Resource already exists (duplicate `userName` / external id).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Request was syntactically valid but business validation failed
    /// (missing required attribute, invalid email, …).
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Bearer token rejected by the adapter.
    #[error("unauthorised")]
    Unauthorised,

    /// Bearer token authenticated but its scope grant does not cover
    /// the requested operation (MED-005). The associated string is the
    /// missing scope's wire form (e.g. `scim:users:write`) so the
    /// caller can fix the token without trial-and-error.
    #[error("forbidden: missing scope {0}")]
    Forbidden(String),

    /// Bearer token has expired (past `expires_at`) or has been retired
    /// past its grace window after rotation (MED-005). Distinct from
    /// [`Self::Unauthorised`] so the controller can surface a 401 with
    /// the more actionable detail "token expired".
    #[error("expired: {0}")]
    Expired(String),

    /// Programmer error or unexpected library failure.
    #[error("internal: {0}")]
    Internal(String),
}

impl ScimError {
    /// Convenience constructor for [`ScimError::InvalidFilter`].
    #[must_use]
    pub fn invalid_filter(msg: impl Into<String>) -> Self {
        Self::InvalidFilter(msg.into())
    }

    /// Convenience constructor for [`ScimError::InvalidRequest`].
    #[must_use]
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::InvalidRequest(msg.into())
    }

    /// Convenience constructor for [`ScimError::Conflict`].
    #[must_use]
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }

    /// Convenience constructor for [`ScimError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Convenience constructor for [`ScimError::Forbidden`] — the
    /// associated string MUST be the canonical wire form of the
    /// missing scope (e.g. `scim:users:write`).
    #[must_use]
    pub fn forbidden(missing_scope: impl Into<String>) -> Self {
        Self::Forbidden(missing_scope.into())
    }

    /// Convenience constructor for [`ScimError::Expired`].
    #[must_use]
    pub fn expired(reason: impl Into<String>) -> Self {
        Self::Expired(reason.into())
    }
}

#[cfg(test)]
mod tests {
    use super::ScimError;

    #[test]
    fn display_variants() {
        assert_eq!(
            ScimError::invalid_filter("bad").to_string(),
            "invalid filter: bad",
        );
        assert_eq!(
            ScimError::invalid_request("no userName").to_string(),
            "invalid request: no userName",
        );
        assert_eq!(ScimError::NotFound.to_string(), "resource not found");
        assert_eq!(ScimError::conflict("dup").to_string(), "conflict: dup",);
        assert_eq!(ScimError::Unauthorised.to_string(), "unauthorised");
        assert_eq!(ScimError::internal("boom").to_string(), "internal: boom",);
        assert_eq!(
            ScimError::forbidden("scim:users:write").to_string(),
            "forbidden: missing scope scim:users:write",
        );
        assert_eq!(
            ScimError::expired("rotated past grace").to_string(),
            "expired: rotated past grace",
        );
    }
}
