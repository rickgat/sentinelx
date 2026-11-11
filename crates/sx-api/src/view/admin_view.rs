//! Admin-only DTOs — request/response bodies for operator-driven user
//! provisioning (`POST /v1/admin/users`).
//!
//! All identifiers are kept as plain strings on the wire so the API crate
//! never has to depend on the concrete newtypes in `sx-iam`. The custom
//! `validate_uuid` validator pins the tenant id to a canonical UUID
//! before the adapter ever sees it.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/admin/users` request body.
///
/// The caller MUST be authenticated and carry the `admin:users`
/// permission. Empty role lists are rejected at the validator boundary —
/// a user with zero roles cannot do anything useful and is almost
/// certainly a mistake on the caller's side.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct CreateUserRequestView {
    /// Tenant the new user belongs to (uuid string).
    #[validate(custom(function = "validate_uuid"))]
    pub tenant_id: String,
    /// Login email. Lower-cased by the adapter before persistence.
    #[validate(email)]
    pub email: String,
    /// Plaintext password — hashed by the adapter, never logged.
    #[validate(length(min = 8, max = 200))]
    pub password: String,
    /// Role names to grant. Must be non-empty; unknown names are dropped
    /// silently by the adapter so the wire shape never leaks which names
    /// are supported.
    #[validate(length(min = 1, max = 32))]
    pub roles: Vec<String>,
}

/// `POST /v1/admin/users` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserResponseView {
    /// Newly minted user uuid.
    pub id: String,
    /// Tenant the user belongs to.
    pub tenant_id: String,
    /// Normalised (lower-cased) email.
    pub email: String,
    /// Role names granted to the user, echoed verbatim from the request.
    pub roles: Vec<String>,
    /// RFC 3339 timestamp recorded at request time.
    pub created_at: String,
}

/// Narrow projection of a user used by the dashboard list view.
///
/// Backs `GET /v1/admin/users`. Carries only the columns the list UI
/// renders — the full role list is summarised by count rather than
/// embedded so the list response stays small at scale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminUserSummaryView {
    /// User uuid.
    pub id: String,
    /// Tenant uuid the user belongs to.
    pub tenant_id: String,
    /// Normalised (lower-cased) email.
    pub email: String,
    /// Whether the user is active (i.e. the password reset / email
    /// verification flow has not flipped them off).
    pub is_active: bool,
    /// Number of roles granted to the user.
    pub role_count: u32,
    /// RFC 3339 timestamp recorded at request time.
    pub created_at: String,
}

/// Narrow projection of a registered push device.
///
/// Backs `GET /v1/notifications/devices`. The raw `device_token` is
/// intentionally NEVER projected — only the stable id, platform, and
/// registration timestamp are exposed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceSummaryView {
    /// Stable device id (uuid v4 minted at registration).
    pub id: String,
    /// Tenant uuid the device belongs to.
    pub tenant_id: String,
    /// Owning user uuid.
    pub user_id: String,
    /// Platform discriminator (`ios` / `android`).
    pub platform: String,
    /// RFC 3339 timestamp the device was registered at.
    pub registered_at: String,
}

/// Validate that `value` is a canonical UUID string.
fn validate_uuid(value: &str) -> Result<(), validator::ValidationError> {
    uuid::Uuid::parse_str(value).map_err(|_| validator::ValidationError::new("invalid_uuid"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_uuid() -> String {
        "00000000-0000-0000-0000-000000000001".to_string()
    }

    #[test]
    fn accepts_valid_request() {
        let r = CreateUserRequestView {
            tenant_id: valid_uuid(),
            email: "admin@example.com".into(),
            password: "hunter2-correct-horse".into(),
            roles: vec!["admin".into()],
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn rejects_short_password() {
        let r = CreateUserRequestView {
            tenant_id: valid_uuid(),
            email: "admin@example.com".into(),
            password: "short".into(),
            roles: vec!["admin".into()],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_invalid_email() {
        let r = CreateUserRequestView {
            tenant_id: valid_uuid(),
            email: "not-an-email".into(),
            password: "hunter2-correct-horse".into(),
            roles: vec!["admin".into()],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_zero_roles() {
        let r = CreateUserRequestView {
            tenant_id: valid_uuid(),
            email: "admin@example.com".into(),
            password: "hunter2-correct-horse".into(),
            roles: vec![],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_invalid_uuid() {
        let r = CreateUserRequestView {
            tenant_id: "not-a-uuid".into(),
            email: "admin@example.com".into(),
            password: "hunter2-correct-horse".into(),
            roles: vec!["admin".into()],
        };
        assert!(r.validate().is_err());
    }
}
