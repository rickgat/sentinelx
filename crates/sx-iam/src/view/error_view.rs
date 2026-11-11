//! HTTP-layer DTO mapping from [`crate::IamError`].

use serde::Serialize;

use crate::IamError;

/// JSON error body returned by the HTTP layer for any `IamError`.
///
/// Deliberately compact — only `code` and `message` are exposed. Internal
/// details (`Repository`, `Internal`, `Config`) are collapsed into a
/// single opaque `"error"` code so the API surface cannot be used as an
/// oracle for backend errors.
#[derive(Debug, Serialize)]
pub struct IamErrorResponse {
    /// Stable, machine-readable code.
    pub code: &'static str,
    /// Human-readable message safe to surface to the caller.
    pub message: String,
}

impl From<&IamError> for IamErrorResponse {
    fn from(e: &IamError) -> Self {
        match e {
            IamError::InvalidCredentials => Self {
                code: "invalid_credentials",
                message: e.to_string(),
            },
            IamError::AccountLocked => Self {
                code: "account_locked",
                message: e.to_string(),
            },
            IamError::TokenExpired => Self {
                code: "token_expired",
                message: e.to_string(),
            },
            IamError::InvalidToken => Self {
                code: "invalid_token",
                message: e.to_string(),
            },
            IamError::Forbidden { .. } => Self {
                code: "forbidden",
                message: e.to_string(),
            },
            IamError::Conflict(_) => Self {
                code: "conflict",
                message: e.to_string(),
            },
            IamError::Internal(_) | IamError::Repository(_) | IamError::Config(_) => Self {
                code: "error",
                message: "internal error".to_owned(),
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_collapse() {
        let v: IamErrorResponse = (&IamError::Internal("dbpool gone".into())).into();
        assert_eq!(v.code, "error");
        assert_eq!(v.message, "internal error");
        assert!(!v.message.contains("dbpool"));
    }

    #[test]
    fn invalid_credentials_classified() {
        let v: IamErrorResponse = (&IamError::InvalidCredentials).into();
        assert_eq!(v.code, "invalid_credentials");
    }

    #[test]
    fn forbidden_carries_message() {
        let v: IamErrorResponse = (&IamError::forbidden("x:y")).into();
        assert_eq!(v.code, "forbidden");
        assert!(v.message.contains("x:y"));
    }
}
