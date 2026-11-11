//! Engagement-resource DTOs.
//!
//! Mirrors the (still-evolving) sibling crate's `view::engagement` module
//! so the HTTP shape is stable.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Create-engagement request body.
#[derive(Debug, Deserialize, Validate)]
pub struct CreateEngagementView {
    /// Human-readable engagement name.
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    /// Free-text description.
    #[validate(length(max = 4_000))]
    pub description: Option<String>,
    /// Allow-listed scopes (CIDR / FQDN / URL). Each entry is validated by
    /// the engagement use case downstream.
    #[validate(length(min = 1, max = 1_000))]
    pub scopes: Vec<String>,
}

/// Engagement projection on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementView {
    /// Engagement uuid.
    pub id: String,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Free-text description.
    pub description: Option<String>,
    /// Authorised scopes.
    pub scopes: Vec<String>,
    /// State machine state (e.g. `draft`, `active`, `closed`).
    pub status: String,
    /// RFC 3339 UTC creation timestamp.
    pub created_at: String,
    /// RFC 3339 UTC last update timestamp.
    pub updated_at: String,
}

/// Patch-engagement request body.
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateEngagementView {
    /// New name (optional).
    #[validate(length(min = 1, max = 200))]
    pub name: Option<String>,
    /// New description (optional).
    #[validate(length(max = 4_000))]
    pub description: Option<String>,
    /// New status (optional).
    pub status: Option<String>,
}

/// Abort-engagement request body.
///
/// Carries an operator-supplied reason for aborting the engagement. The
/// reason is bounded so the audit log row has a sensible upper bound.
#[derive(Debug, Deserialize, Validate)]
pub struct EngagementAbortRequest {
    /// Human-readable abort reason. Bounded `1..=2000` chars to keep audit
    /// rows finite while still allowing operators to paste a small
    /// justification.
    #[validate(length(min = 1, max = 2_000))]
    pub reason: String,
}

/// Clone-engagement request body.
///
/// `POST /v1/engagements/{id}/clone` creates a fresh `Draft` engagement
/// that inherits its scope + window-duration from the source. The
/// operator may override the display name; otherwise the adapter mints
/// `"{source.name} (clone)"`.
///
/// `new_name` is bounded `1..=200` chars when present, matching the
/// equivalent ceiling on [`CreateEngagementView::name`] so the cloned
/// engagement never carries a wider name than a freshly-created one.
#[derive(Debug, Default, Deserialize, Validate)]
pub struct CloneEngagementRequest {
    /// Optional override for the cloned engagement's display name. When
    /// omitted the adapter defaults to `"{source.name} (clone)"`.
    #[validate(length(min = 1, max = 200))]
    pub new_name: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn create_engagement_requires_at_least_one_scope() {
        let v = CreateEngagementView {
            name: "ok".into(),
            description: None,
            scopes: vec![],
        };
        assert!(v.validate().is_err());
    }

    #[test]
    fn engagement_view_serialises() {
        let e = EngagementView {
            id: "id".into(),
            tenant_id: "t".into(),
            name: "n".into(),
            description: None,
            scopes: vec!["10.0.0.0/24".into()],
            status: "draft".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["status"], "draft");
    }

    #[test]
    fn abort_request_rejects_empty_reason() {
        let r = EngagementAbortRequest {
            reason: String::new(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn abort_request_rejects_overlong_reason() {
        let r = EngagementAbortRequest {
            reason: "x".repeat(2_001),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn abort_request_accepts_two_thousand_chars() {
        let r = EngagementAbortRequest {
            reason: "x".repeat(2_000),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn clone_request_default_is_none() {
        let r = CloneEngagementRequest::default();
        assert!(r.new_name.is_none());
        assert!(r.validate().is_ok());
    }

    #[test]
    fn clone_request_accepts_short_name() {
        let r = CloneEngagementRequest {
            new_name: Some("renamed".into()),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn clone_request_rejects_empty_name() {
        let r = CloneEngagementRequest {
            new_name: Some(String::new()),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn clone_request_rejects_overlong_name() {
        let r = CloneEngagementRequest {
            new_name: Some("x".repeat(201)),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn clone_request_accepts_two_hundred_chars() {
        let r = CloneEngagementRequest {
            new_name: Some("x".repeat(200)),
        };
        assert!(r.validate().is_ok());
    }
}
