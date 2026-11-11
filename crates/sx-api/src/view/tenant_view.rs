//! Tenant-administration DTOs — request bodies for the three
//! `/v1/admin/tenants` write endpoints.
//!
//! The read-only projection [`crate::port::TenantSummaryView`] is
//! re-used as the response body so callers always observe the same wire
//! shape that `GET /v1/tenants/me` produces.
//!
//! ## Wire shapes
//!
//! - `POST   /v1/admin/tenants` body `CreateTenantRequest` -> `TenantSummaryView`
//! - `PATCH  /v1/admin/tenants/{id}` body `UpdateTenantRequest` -> `TenantSummaryView`
//! - `DELETE /v1/admin/tenants/{id}` -> no body
//!
//! ## Validation rules
//!
//! - `slug` MUST be `[a-z0-9-_]{1,64}` (lowercase ASCII letters / digits /
//!   `-` / `_`). The check is performed character-by-character so the API
//!   crate keeps zero regex dependencies (mirrors the equivalent rule in
//!   [`crate::view::roles_view`]).
//! - `name` MUST be 1..=200 UTF-8 chars. No further shape check — the
//!   field is intended to be human-readable and contains arbitrary
//!   printable text.
//! - On update, both fields are optional; the adapter preserves whatever
//!   was not supplied.

use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

/// `POST /v1/admin/tenants` request body.
///
/// `slug` must match `[a-z0-9-_]{1,64}`; `name` must be 1..=200 chars.
/// Slug uniqueness is enforced at the adapter (an existing slug surfaces
/// as [`crate::port::EngagementPortError::Conflict`]).
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct CreateTenantRequest {
    /// URL-safe slug — must match `[a-z0-9-_]{1,64}`.
    #[validate(length(min = 1, max = 64), custom(function = "validate_tenant_slug"))]
    pub slug: String,
    /// Human-readable display name. Bounded at 1..=200 chars.
    #[validate(length(min = 1, max = 200))]
    pub name: String,
}

/// `PATCH /v1/admin/tenants/{id}` request body.
///
/// Every field is optional; the adapter preserves whatever is not
/// supplied. Slug is **intentionally not patchable** here — slugs feature
/// in URLs and tenant slug rotation is a separate operation (out of scope
/// for this controller).
#[derive(Debug, Clone, Deserialize, Serialize, Validate, Default)]
pub struct UpdateTenantRequest {
    /// New display name (1..=200 chars) when present.
    #[validate(length(min = 1, max = 200))]
    pub name: Option<String>,
    /// New active flag when present.
    pub is_active: Option<bool>,
}

/// Validate that `value` matches `[a-z0-9-_]{1,64}`.
///
/// The length bound is enforced separately by the `#[validate(length)]`
/// attribute on the field; this validator only enforces the character
/// set.
fn validate_tenant_slug(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("empty_slug"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(ValidationError::new("invalid_slug"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_accepts_canonical_slug() {
        let r = CreateTenantRequest {
            slug: "acme-corp_01".into(),
            name: "Acme Corp".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn create_request_rejects_uppercase_slug() {
        let r = CreateTenantRequest {
            slug: "AcmeCorp".into(),
            name: "Acme Corp".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_slug_with_space() {
        let r = CreateTenantRequest {
            slug: "acme corp".into(),
            name: "Acme Corp".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_slug_with_dot() {
        let r = CreateTenantRequest {
            slug: "acme.corp".into(),
            name: "Acme Corp".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_empty_slug() {
        let r = CreateTenantRequest {
            slug: String::new(),
            name: "Acme Corp".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_oversized_slug() {
        let r = CreateTenantRequest {
            slug: "a".repeat(65),
            name: "Acme Corp".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_empty_name() {
        let r = CreateTenantRequest {
            slug: "acme".into(),
            name: String::new(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_oversized_name() {
        let r = CreateTenantRequest {
            slug: "acme".into(),
            name: "x".repeat(201),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn update_request_all_none_is_valid() {
        let r = UpdateTenantRequest::default();
        assert!(r.validate().is_ok());
    }

    #[test]
    fn update_request_rejects_empty_name() {
        let r = UpdateTenantRequest {
            name: Some(String::new()),
            is_active: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn update_request_accepts_is_active_only() {
        let r = UpdateTenantRequest {
            name: None,
            is_active: Some(false),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn slug_boundary_64_chars_accepted() {
        let r = CreateTenantRequest {
            slug: "a".repeat(64),
            name: "Acme".into(),
        };
        assert!(r.validate().is_ok());
    }
}
