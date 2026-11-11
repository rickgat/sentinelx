//! SCIM 2.0 view DTOs (RFC 7644 wire format).
//!
//! The on-the-wire shapes mostly come straight from the `sx-scim` crate
//! (which already does the camelCase + schemas-array work per RFC 7643);
//! this module adds:
//!
//! - the [`ListResponseView`] envelope SCIM uses instead of the
//!   SentinelX `ApiResponse` envelope,
//! - the [`ScimErrorView`] envelope SCIM clients (Okta, AAD) expect,
//! - the [`ScimTokenView`] / [`CreateScimTokenRequest`] / etc. shapes for
//!   the per-tenant SCIM-token admin surface.

use serde::{Deserialize, Serialize};
use sx_scim::schema::{ERROR_SCHEMA, LIST_RESPONSE_SCHEMA};
use validator::Validate;

pub use sx_scim::schema::group::{GroupMember, ScimGroup};
pub use sx_scim::schema::meta::Meta as ScimMeta;
pub use sx_scim::schema::user::{Email as ScimEmail, Name as ScimName, ScimUser};

/// Content-Type SCIM endpoints must emit (RFC 7644 §3.1).
pub const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// SCIM list-response envelope (RFC 7644 §3.4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponseView<T> {
    /// MUST contain `urn:ietf:params:scim:api:messages:2.0:ListResponse`.
    pub schemas: Vec<String>,
    /// Total resources matching the filter, across all pages.
    pub total_results: usize,
    /// 1-based index of the first resource on this page.
    pub start_index: usize,
    /// Resources on this page.
    pub items_per_page: usize,
    /// Resources on this page.
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T> ListResponseView<T> {
    /// Build a SCIM ListResponse envelope.
    pub fn new(total: usize, start_index: usize, items_per_page: usize, resources: Vec<T>) -> Self {
        Self {
            schemas: vec![LIST_RESPONSE_SCHEMA.to_owned()],
            total_results: total,
            start_index,
            items_per_page,
            resources,
        }
    }
}

/// SCIM error envelope (RFC 7644 §3.12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimErrorView {
    /// MUST contain `urn:ietf:params:scim:api:messages:2.0:Error`.
    pub schemas: Vec<String>,
    /// Stringified HTTP status code.
    pub status: String,
    /// Optional SCIM-specific reason code (e.g. `invalidFilter`, `uniqueness`).
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "scimType")]
    pub scim_type: Option<String>,
    /// Human-readable detail.
    pub detail: String,
}

impl ScimErrorView {
    /// Build a SCIM error body.
    pub fn new(status: u16, scim_type: Option<&str>, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec![ERROR_SCHEMA.to_owned()],
            status: status.to_string(),
            scim_type: scim_type.map(str::to_owned),
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// SCIM token admin surface (`GET/POST/DELETE /v1/admin/scim/tokens`)
// ---------------------------------------------------------------------------

/// Token row projection — surfaced via `GET /v1/admin/scim/tokens`.
///
/// Carries every operationally-useful field except the plaintext value
/// (which is returned exactly once at mint time and never re-emitted).
/// `status` is computed at read time from `revoked_at` / `retired_at` /
/// `expires_at` — see [`ScimTokenStatus`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimTokenView {
    /// Token uuid.
    pub id: String,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// Human-readable label.
    pub name: String,
    /// Granted scopes in canonical wire form
    /// (e.g. `["scim:users:read", "scim:users:write"]`).
    /// Empty list means default-deny — the token authenticates but
    /// authorises nothing.
    pub scopes: Vec<String>,
    /// Lifecycle status — `active`, `grace` (post-rotation, both
    /// tokens valid), `revoked`, or `expired`.
    pub status: ScimTokenStatus,
    /// RFC 3339 mint time.
    pub created_at: String,
    /// RFC 3339 timestamp when the token first became authoritative
    /// (typically identical to `created_at`).
    pub activated_at: String,
    /// RFC 3339 expiry — `created_at + cadence`.
    pub expires_at: String,
    /// RFC 3339 timestamp set on rotation: marks the *end* of the
    /// grace window during which the old token still authenticates.
    /// `None` until the token is rotated.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub retired_at: Option<String>,
    /// RFC 3339 timestamp when the token was explicitly revoked.
    /// `None` until revocation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revoked_at: Option<String>,
    /// RFC 3339 timestamp of last successful use; `None` if never used.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_used_at: Option<String>,
}

/// Lifecycle phase of a SCIM token (MED-005).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScimTokenStatus {
    /// Token mints normally and is the live, authoritative credential.
    Active,
    /// Token has been rotated. It is still valid until
    /// `retired_at` (now + grace window), after which it returns 401.
    Grace,
    /// Token was explicitly revoked. Returns 401 immediately.
    Revoked,
    /// Token aged past `expires_at` (or past `retired_at` after a
    /// rotation). Returns 401.
    Expired,
}

/// `POST /v1/admin/scim/tokens` request body (MED-005).
///
/// `name` keeps the existing P0-005 wire field for back-compat.
/// `scopes` MUST be non-empty (default-deny on missing scope).
/// `ttl_days` overrides the default 90-day rotation cadence.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateScimTokenRequest {
    /// Human-readable label (e.g. "Okta production").
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    /// Granted scopes in canonical wire form. MUST be non-empty.
    #[validate(length(min = 1, max = 16))]
    pub scopes: Vec<String>,
    /// Optional TTL override (1..=365 days). Defaults to the
    /// configured rotation cadence (90 days).
    #[validate(range(min = 1, max = 365))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_days: Option<u32>,
}

/// `POST /v1/admin/scim/tokens` response body.
///
/// The plaintext token is returned ONCE, immediately after mint. The DB
/// only stores its SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScimTokenResponse {
    /// Token projection.
    pub token: ScimTokenView,
    /// Plaintext bearer value — must be saved by the operator immediately.
    pub plaintext: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_response_includes_schemas_uri() {
        let env = ListResponseView::<ScimUser>::new(0, 1, 0, vec![]);
        let j = serde_json::to_value(&env).unwrap();
        assert_eq!(j["schemas"][0], LIST_RESPONSE_SCHEMA);
        assert_eq!(j["totalResults"], 0);
        assert_eq!(j["startIndex"], 1);
        assert_eq!(j["itemsPerPage"], 0);
        assert!(j["Resources"].is_array());
    }

    #[test]
    fn scim_error_includes_error_schema_and_status() {
        let e = ScimErrorView::new(404, Some("uniqueness"), "not found");
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["schemas"][0], ERROR_SCHEMA);
        assert_eq!(j["status"], "404");
        assert_eq!(j["scimType"], "uniqueness");
        assert_eq!(j["detail"], "not found");
    }

    #[test]
    fn scim_error_omits_scim_type_when_absent() {
        let e = ScimErrorView::new(500, None, "boom");
        let s = serde_json::to_string(&e).unwrap();
        assert!(!s.contains("scimType"));
    }

    #[test]
    fn create_token_request_rejects_empty_name() {
        let r = CreateScimTokenRequest {
            name: String::new(),
            scopes: vec!["scim:users:read".into()],
            ttl_days: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_token_request_accepts_valid_name() {
        let r = CreateScimTokenRequest {
            name: "okta-prod".into(),
            scopes: vec!["scim:users:read".into(), "scim:users:write".into()],
            ttl_days: None,
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn create_token_request_rejects_empty_scopes() {
        let r = CreateScimTokenRequest {
            name: "okta-prod".into(),
            scopes: vec![],
            ttl_days: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_token_request_rejects_out_of_range_ttl() {
        let r = CreateScimTokenRequest {
            name: "okta-prod".into(),
            scopes: vec!["scim:users:read".into()],
            ttl_days: Some(0),
        };
        assert!(r.validate().is_err());
        let r2 = CreateScimTokenRequest {
            name: "okta-prod".into(),
            scopes: vec!["scim:users:read".into()],
            ttl_days: Some(366),
        };
        assert!(r2.validate().is_err());
    }

    #[test]
    fn token_status_round_trips_via_serde() {
        let v = serde_json::to_value(ScimTokenStatus::Grace).unwrap();
        assert_eq!(v, serde_json::json!("grace"));
        let back: ScimTokenStatus = serde_json::from_value(serde_json::json!("expired")).unwrap();
        assert_eq!(back, ScimTokenStatus::Expired);
    }
}
