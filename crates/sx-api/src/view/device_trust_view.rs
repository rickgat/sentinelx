//! Device-trust DTOs — request/response shapes for the
//! `/v1/device-trust/*` HTTP surface.
//!
//! The wire shapes are intentionally thin projections over the canonical
//! [`sx_device_trust`] types so the storage layer and the controllers
//! share one schema. The View types add `serde` `rename_all` rules and
//! `validator::Validate` impls so the HTTP layer can reject obviously
//! malformed payloads before they reach the port.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use validator::Validate;

use sx_device_trust::policy::{PosturePolicy, PostureRule};
use sx_device_trust::posture::PostureClaims;
use sx_device_trust::service::{DeviceTrustStatus, PostureSnapshot};

/// `GET /v1/device-trust/policy` response and `PUT /v1/device-trust/policy`
/// request body — the canonical [`PosturePolicy`] shape.
///
/// `Validate` is implemented to keep `os_allow_list` / `os_block_list` /
/// `edr_vendor_allow_list` entries bounded so a malicious operator
/// cannot blow up storage by uploading a megabyte of strings.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, PartialEq, Eq)]
pub struct PosturePolicyView {
    /// OS family allow-list. Empty = any OS accepted.
    #[serde(default)]
    #[validate(length(max = 64))]
    pub os_allow_list: Vec<String>,
    /// OS family block-list (takes precedence over the allow-list).
    #[serde(default)]
    #[validate(length(max = 64))]
    pub os_block_list: Vec<String>,
    /// Minimum dotted-integer OS versions, keyed by OS family.
    #[serde(default)]
    pub minimum_os_versions: BTreeMap<String, String>,
    /// EDR vendor allow-list. Empty = any vendor accepted.
    #[serde(default)]
    #[validate(length(max = 32))]
    pub edr_vendor_allow_list: Vec<String>,
    /// Maximum acceptable `screen_lock_minutes` value. `None` = no upper
    /// bound check.
    #[serde(default)]
    pub max_screen_lock_minutes: Option<u32>,
    /// Active rules.
    #[serde(default)]
    pub rules: Vec<PostureRule>,
}

impl From<PosturePolicy> for PosturePolicyView {
    fn from(p: PosturePolicy) -> Self {
        Self {
            os_allow_list: p.os_allow_list,
            os_block_list: p.os_block_list,
            minimum_os_versions: p.minimum_os_versions,
            edr_vendor_allow_list: p.edr_vendor_allow_list,
            max_screen_lock_minutes: p.max_screen_lock_minutes,
            rules: p.rules,
        }
    }
}

impl From<PosturePolicyView> for PosturePolicy {
    fn from(v: PosturePolicyView) -> Self {
        Self {
            os_allow_list: v.os_allow_list,
            os_block_list: v.os_block_list,
            minimum_os_versions: v.minimum_os_versions,
            edr_vendor_allow_list: v.edr_vendor_allow_list,
            max_screen_lock_minutes: v.max_screen_lock_minutes,
            rules: v.rules,
        }
    }
}

/// One row of the `GET /v1/device-trust/sessions` table — a single
/// posture snapshot recorded by the middleware against an active
/// session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostureSessionView {
    /// Snapshot uuid.
    pub id: String,
    /// User id (bearer claim `sub`).
    pub user_id: String,
    /// Session id (bearer claim `sid`).
    pub session_id: String,
    /// Verdict (`trusted` / `untrusted` / `stale`).
    pub status: DeviceTrustStatus,
    /// Per-rule violation reasons. Empty when `status == Trusted`.
    pub reasons: Vec<String>,
    /// Subset of posture claims worth surfacing on the dashboard. The
    /// full claim set is preserved server-side but only `os_name`,
    /// `os_version`, `disk_encrypted`, `edr_present`,
    /// `edr_vendor`, and `screen_lock_minutes` make it onto the wire.
    pub claims: PostureClaimsSummary,
    /// RFC 3339 timestamp.
    pub observed_at: String,
}

/// Slim projection of [`PostureClaims`] for the dashboard table view.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PostureClaimsSummary {
    /// OS family.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_name: Option<String>,
    /// OS version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Whether the system disk is encrypted.
    pub disk_encrypted: bool,
    /// Whether an EDR agent is running.
    pub edr_present: bool,
    /// EDR vendor identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edr_vendor: Option<String>,
    /// Inactivity threshold (minutes) at which the OS engages the screen
    /// lock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen_lock_minutes: Option<u32>,
}

impl From<PostureClaims> for PostureClaimsSummary {
    fn from(c: PostureClaims) -> Self {
        Self {
            os_name: c.os_name,
            os_version: c.os_version,
            disk_encrypted: c.disk_encrypted,
            edr_present: c.edr_present,
            edr_vendor: c.edr_vendor,
            screen_lock_minutes: c.screen_lock_minutes,
        }
    }
}

impl From<PostureSnapshot> for PostureSessionView {
    fn from(s: PostureSnapshot) -> Self {
        Self {
            id: s.id,
            user_id: s.user_id,
            session_id: s.session_id,
            status: s.status,
            reasons: s.reasons,
            claims: s.claims.into(),
            observed_at: s.observed_at,
        }
    }
}

/// `GET /v1/device-trust/sessions` response body — a flat list of
/// recent session snapshots, newest-first.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListSessionsResponseView {
    /// Snapshot rows in newest-first order.
    pub items: Vec<PostureSessionView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn policy_round_trips_through_view() {
        let policy = PosturePolicy::strict_baseline();
        let view: PosturePolicyView = policy.clone().into();
        let back: PosturePolicy = view.into();
        assert_eq!(back, policy);
    }

    #[test]
    fn validate_rejects_huge_allow_list() {
        let view = PosturePolicyView {
            os_allow_list: (0..200).map(|i| format!("os-{i}")).collect(),
            ..PosturePolicyView::from(PosturePolicy::permissive())
        };
        assert!(view.validate().is_err());
    }

    #[test]
    fn permissive_view_validates() {
        let view: PosturePolicyView = PosturePolicy::permissive().into();
        assert!(view.validate().is_ok());
    }

    #[test]
    fn claims_summary_drops_extra() {
        let claims = PostureClaims {
            os_name: Some("macOS".into()),
            os_version: Some("14.5.0".into()),
            disk_encrypted: true,
            edr_present: true,
            edr_vendor: Some("CrowdStrike".into()),
            screen_lock_minutes: Some(5),
            ..PostureClaims::default()
        };
        let summary: PostureClaimsSummary = claims.into();
        assert_eq!(summary.os_name.as_deref(), Some("macOS"));
        assert!(summary.disk_encrypted);
    }

    #[test]
    fn session_view_serialises_with_camel_unchanged() {
        let snap = PostureSnapshot {
            id: "00000000-0000-0000-0000-000000000001".into(),
            user_id: "u".into(),
            session_id: "s".into(),
            status: DeviceTrustStatus::Trusted,
            claims: PostureClaims::default(),
            reasons: vec![],
            observed_at: "2026-01-01T00:00:00Z".into(),
        };
        let view: PostureSessionView = snap.into();
        let v = serde_json::to_value(view).unwrap();
        assert_eq!(v["status"], "trusted");
        assert_eq!(v["id"], "00000000-0000-0000-0000-000000000001");
    }
}
