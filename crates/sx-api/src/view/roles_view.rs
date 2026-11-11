//! Role-administration DTOs — request/response bodies for the four
//! `/v1/admin/roles` + `/v1/admin/users/{user_id}/roles` endpoints.
//!
//! Identifiers are kept as plain strings on the wire so the API crate
//! never has to depend on the concrete newtypes in `sx-iam` /
//! `sx-core`. The custom validators enforce the **shape** rules at the
//! HTTP boundary — every other semantic check (duplicate name, unknown
//! permission token, …) lives in the adapter.
//!
//! ## Wire shapes
//!
//! - `GET    /v1/admin/roles` → `ListRolesResponseView`
//! - `POST   /v1/admin/roles` body `CreateRoleRequest` → `RoleView`
//! - `DELETE /v1/admin/roles/{role_id}` → no body
//! - `POST   /v1/admin/users/{user_id}/roles` body `AssignRolesRequest` → `AssignRolesResponseView`

use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

/// `POST /v1/admin/roles` request body.
///
/// `name` is a non-empty lowercase slug (letters / digits / `-` / `_`),
/// bounded at 64 bytes to mirror the domain `Role` validator. Empty
/// permission lists are rejected — a role with zero permissions cannot
/// grant access to anything and is almost certainly a caller mistake.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct CreateRoleRequestView {
    /// Human-readable role name. Must be a lowercase slug.
    #[validate(length(min = 1, max = 64), custom(function = "validate_role_name"))]
    pub name: String,
    /// Permission tokens in `resource:action` form. Each entry must
    /// parse, individually validated. Duplicates are tolerated — the
    /// adapter de-duplicates before persisting.
    #[validate(
        length(min = 1, max = 64),
        custom(function = "validate_permission_list")
    )]
    pub permissions: Vec<String>,
}

/// `POST /v1/admin/users/{user_id}/roles` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct AssignRolesRequestView {
    /// Role ids (uuid strings) to assign to the user. Must be non-empty.
    /// Each entry is parsed as a uuid by the validator.
    #[validate(length(min = 1, max = 32), custom(function = "validate_uuid_list"))]
    pub role_ids: Vec<String>,
}

/// On-wire projection of a single role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleView {
    /// Role uuid string.
    pub id: String,
    /// Owning tenant uuid string.
    pub tenant_id: String,
    /// Human-readable role name.
    pub name: String,
    /// Granted permissions in `resource:action` form.
    pub permissions: Vec<String>,
    /// RFC 3339 timestamp recorded at creation time.
    pub created_at: String,
}

/// `GET /v1/admin/roles` response body.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListRolesResponseView {
    /// Roles bound to the caller's tenant. Order is unspecified.
    pub roles: Vec<RoleView>,
}

/// `POST /v1/admin/users/{user_id}/roles` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignRolesResponseView {
    /// Target user uuid string echoed from the URL.
    pub user_id: String,
    /// Role uuid strings now bound to the user.
    pub role_ids: Vec<String>,
    /// RFC 3339 timestamp of the assignment.
    pub assigned_at: String,
}

/// Validate that `value` is a non-empty lowercase slug.
fn validate_role_name(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("empty_role_name"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(ValidationError::new("invalid_role_name"));
    }
    Ok(())
}

/// Validate that every entry in `values` parses as `resource:action`.
fn validate_permission_list(values: &[String]) -> Result<(), ValidationError> {
    for v in values {
        if !is_valid_permission_token(v) {
            return Err(ValidationError::new("invalid_permission"));
        }
    }
    Ok(())
}

/// Validate that every entry in `values` parses as a canonical uuid.
fn validate_uuid_list(values: &[String]) -> Result<(), ValidationError> {
    for v in values {
        if uuid::Uuid::parse_str(v).is_err() {
            return Err(ValidationError::new("invalid_uuid"));
        }
    }
    Ok(())
}

/// Lightweight syntactic check for `resource:action`. Mirrors the
/// canonical validator in `sx_core::entity::permission::Permission` so
/// the HTTP layer can reject malformed tokens before the adapter ever
/// sees them.
fn is_valid_permission_token(s: &str) -> bool {
    let Some((resource, action)) = s.split_once(':') else {
        return false;
    };
    !resource.is_empty()
        && !action.is_empty()
        && resource.len() <= 64
        && action.len() <= 64
        && resource
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '*')
        && action
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_uuid() -> String {
        "00000000-0000-0000-0000-000000000001".to_string()
    }

    #[test]
    fn accepts_valid_create_role_request() {
        let r = CreateRoleRequestView {
            name: "auditor".into(),
            permissions: vec!["findings:read".into(), "engagements:read".into()],
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn rejects_empty_role_name() {
        let r = CreateRoleRequestView {
            name: String::new(),
            permissions: vec!["findings:read".into()],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_uppercase_role_name() {
        let r = CreateRoleRequestView {
            name: "Auditor".into(),
            permissions: vec!["findings:read".into()],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_zero_permissions() {
        let r = CreateRoleRequestView {
            name: "auditor".into(),
            permissions: vec![],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_malformed_permission_token() {
        let r = CreateRoleRequestView {
            name: "auditor".into(),
            permissions: vec!["no-colon-here".into()],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn accepts_wildcard_permission_tokens() {
        let r = CreateRoleRequestView {
            name: "super".into(),
            permissions: vec!["*:*".into(), "admin:*".into()],
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn rejects_role_name_exceeding_64_bytes() {
        let r = CreateRoleRequestView {
            name: "a".repeat(65),
            permissions: vec!["findings:read".into()],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn accepts_valid_assign_request() {
        let r = AssignRolesRequestView {
            role_ids: vec![valid_uuid()],
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn rejects_empty_role_id_list() {
        let r = AssignRolesRequestView { role_ids: vec![] };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_invalid_uuid_in_assign() {
        let r = AssignRolesRequestView {
            role_ids: vec!["not-a-uuid".into()],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn permission_token_predicate_handles_edge_cases() {
        assert!(is_valid_permission_token("findings:read"));
        assert!(is_valid_permission_token("admin:*"));
        assert!(is_valid_permission_token("*:*"));
        assert!(!is_valid_permission_token(":read"));
        assert!(!is_valid_permission_token("findings:"));
        assert!(!is_valid_permission_token("Findings:Read"));
        assert!(!is_valid_permission_token(""));
        assert!(!is_valid_permission_token("plain"));
    }

    #[test]
    fn role_view_round_trips_json() {
        let v = RoleView {
            id: valid_uuid(),
            tenant_id: valid_uuid(),
            name: "auditor".into(),
            permissions: vec!["findings:read".into()],
            created_at: "1970-01-01T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: RoleView = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }
}
