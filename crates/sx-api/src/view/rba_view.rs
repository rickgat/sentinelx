//! Risk-Based Authentication (RBA) view layer.
//!
//! Wire shapes returned by `GET /v1/rba/decisions`, `GET /v1/rba/config`
//! and accepted by `PUT /v1/rba/config`. The view types are deliberately
//! decoupled from the in-process `sx-rba` types so the wire schema can
//! evolve independently of the engine.
//!
//! ## Why a dedicated view layer
//!
//! `sx-rba::RbaDecision` and `sx-rba::RbaConfig` are domain types — they
//! carry an in-process IPv4 address and a `BusinessHours` struct that is
//! convenient for the scorer but not what we want to expose on the wire.
//! Translating into the view types here keeps the controller thin and
//! the response shape stable.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// One row in `GET /v1/rba/decisions`.
///
/// LOW-007: the optional `signals` field carries the per-signal
/// sub-score / weight / weighted contribution breakdown the scorer
/// emitted at decision time. The field is `#[serde(skip_serializing_if
/// = "Option::is_none")]`, so existing dashboard consumers that
/// predate LOW-007 keep deserialising the legacy 8-field shape
/// unchanged. The controller only populates the field for callers
/// carrying the `admin:users` capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RbaDecisionView {
    /// Decision id (uuid).
    pub id: String,
    /// Tenant id (uuid).
    pub tenant_id: String,
    /// User id (uuid), if known at decision time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// IP address, dotted-quad.
    pub ip: String,
    /// Composite score, `0..=100`.
    pub score: i32,
    /// Action label: `allow` / `step_up_mfa` / `block`.
    pub action: String,
    /// Human-readable reason from the scorer.
    pub reason: String,
    /// ISO-8601 timestamp.
    pub decided_at: String,
    /// Per-signal contribution breakdown (LOW-007).
    ///
    /// Omitted from the wire entirely when `None` (legacy back-compat).
    /// Populated only when the caller has `admin:users` — regular
    /// operators see the composite score + reason but not the raw
    /// per-signal voting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signals: Option<Vec<SignalContributionView>>,
}

/// One per-signal breakdown row on the wire (LOW-007).
///
/// Mirrors `sx_rba::SignalContribution` field-for-field. Kept as a
/// dedicated wire DTO so the engine type and the wire schema can
/// evolve independently (e.g. the engine could add an internal field
/// without auto-leaking it through the API).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignalContributionView {
    /// Stable signal identifier (`ip_geo`, `velocity`, `business_hours`,
    /// `device_fp`, `mfa_recent`, `success_rate`, `impossible_travel`).
    pub signal: String,
    /// Raw `[0, 100]` sub-score the signal emitted.
    pub sub_score: i32,
    /// Per-tenant weight applied to `sub_score`.
    pub weight: f64,
    /// `sub_score * weight` — pre-computed for the operator.
    pub weighted: f64,
}

/// Response body for `GET /v1/rba/decisions`.
///
/// Note: `Eq` was dropped from this DTO when LOW-007 added the optional
/// `signals` field (`f64` weights cannot derive `Eq`). Equality tests
/// continue to use `PartialEq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RbaDecisionsResponse {
    /// Rows newest-first.
    pub decisions: Vec<RbaDecisionView>,
}

/// Query string for `GET /v1/rba/decisions`.
#[derive(Debug, Clone, Deserialize)]
pub struct RbaDecisionsQuery {
    /// Optional caller-supplied limit. The controller clamps this to
    /// `MAX_DECISIONS_PER_REQUEST` (see `sx_rba::service`).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Per-signal weights bundle on the wire.
///
/// HIGH-001 signals (`w_device_fp`, `w_mfa_recent`, `w_success_rate`,
/// `w_impossible_travel`) are `#[serde(default)]` so legacy clients
/// posting the pre-HIGH-001 3-weight shape continue to deserialise
/// cleanly — they implicitly assign weight `0.0` to the new signals,
/// matching the previous adapter behaviour.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Validate)]
pub struct RbaWeightsView {
    /// Weight applied to the IP-geo contribution.
    #[validate(range(min = 0.0, max = 1.0))]
    pub w_ip_geo: f64,
    /// Weight applied to the velocity contribution.
    #[validate(range(min = 0.0, max = 1.0))]
    pub w_velocity: f64,
    /// Weight applied to the business-hours contribution.
    #[validate(range(min = 0.0, max = 1.0))]
    pub w_business_hours: f64,
    /// Device-fingerprint contribution (HIGH-001).
    #[serde(default)]
    #[validate(range(min = 0.0, max = 1.0))]
    pub w_device_fp: f64,
    /// MFA-recency contribution (HIGH-001).
    #[serde(default)]
    #[validate(range(min = 0.0, max = 1.0))]
    pub w_mfa_recent: f64,
    /// 7-day success-rate contribution (HIGH-001).
    #[serde(default)]
    #[validate(range(min = 0.0, max = 1.0))]
    pub w_success_rate: f64,
    /// Impossible-travel contribution (HIGH-001).
    #[serde(default)]
    #[validate(range(min = 0.0, max = 1.0))]
    pub w_impossible_travel: f64,
}

/// Per-signal feature-flag bundle on the wire (HIGH-001).
///
/// Each defaults to `true` so legacy clients posting the pre-HIGH-001
/// `RbaConfigView` (without `feature_flags`) get the post-HIGH-001
/// default of all signals enabled.
// 7 bools mirror the lib-side `RbaFeatureFlags` (HIGH-001): one
// per enrichment signal. Keeping the wire shape flat is more
// debuggable than a bitmask refactor.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RbaFeatureFlagsView {
    #[serde(default = "default_true")]
    pub enable_ip_geo: bool,
    #[serde(default = "default_true")]
    pub enable_velocity: bool,
    #[serde(default = "default_true")]
    pub enable_business_hours: bool,
    #[serde(default = "default_true")]
    pub enable_device_fp: bool,
    #[serde(default = "default_true")]
    pub enable_mfa_recent: bool,
    #[serde(default = "default_true")]
    pub enable_success_rate: bool,
    #[serde(default = "default_true")]
    pub enable_impossible_travel: bool,
}

fn default_true() -> bool {
    true
}

impl Default for RbaFeatureFlagsView {
    fn default() -> Self {
        Self {
            enable_ip_geo: true,
            enable_velocity: true,
            enable_business_hours: true,
            enable_device_fp: true,
            enable_mfa_recent: true,
            enable_success_rate: true,
            enable_impossible_travel: true,
        }
    }
}

/// One enrolled fingerprint entry returned by
/// `GET /v1/rba/users/{user_id}/devices` (HIGH-001).
///
/// `status` is one of `known`, `revoked`, `unknown`. The wire string
/// is lowercase to match the rest of the RBA API surface (compare
/// `action: "step_up_mfa"`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownDeviceView {
    /// Opaque SHA-256-ish hash of the device fingerprint.
    pub fp_hash: String,
    /// `known` (currently enrolled), `revoked` (locked out), or
    /// `unknown` (lookup miss — only used by the engine, not the
    /// inventory endpoint).
    pub status: String,
    /// ISO-8601 timestamp of the most recent successful login from
    /// this device.
    pub last_seen_at: String,
}

/// Response body for `GET /v1/rba/users/{user_id}/devices`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownDevicesResponse {
    pub devices: Vec<KnownDeviceView>,
}

/// Wire form of an [`sx_rba::RbaConfig`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
pub struct RbaConfigView {
    /// Allow threshold (`0..=100`).
    #[validate(range(min = 0, max = 100))]
    pub allow_threshold: i32,
    /// Block threshold (`0..=100`).
    #[validate(range(min = 0, max = 100))]
    pub block_threshold: i32,
    /// Per-signal weights.
    #[validate(nested)]
    pub weights: RbaWeightsView,
    /// Per-signal feature flags (HIGH-001). Optional on the wire;
    /// legacy clients that omit it get the all-enabled default.
    #[serde(default)]
    pub feature_flags: RbaFeatureFlagsView,
    /// IANA timezone for the business-hours window.
    #[validate(length(min = 1, max = 64))]
    pub business_tz: String,
    /// Business-hours start (local hour, `0..=23`).
    #[validate(range(min = 0, max = 23))]
    pub business_hours_start: u8,
    /// Business-hours end (local hour, `0..=23`).
    #[validate(range(min = 0, max = 23))]
    pub business_hours_end: u8,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn decision_view_round_trips() {
        let d = RbaDecisionView {
            id: "00000000-0000-0000-0000-000000000001".into(),
            tenant_id: "00000000-0000-0000-0000-000000000002".into(),
            user_id: Some("00000000-0000-0000-0000-000000000003".into()),
            ip: "8.8.8.8".into(),
            score: 42,
            action: "step_up_mfa".into(),
            reason: "ip-geo signal dominant".into(),
            decided_at: "2026-06-12T10:00:00Z".into(),
            signals: None,
        };
        let raw = serde_json::to_string(&d).unwrap();
        let back: RbaDecisionView = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn decision_view_omits_signals_field_when_none() {
        // LOW-007 back-compat: legacy dashboards must not see a new
        // top-level key when the controller refused to populate the
        // breakdown (non-admin caller). `serde(skip_serializing_if =
        // "Option::is_none")` is the back-compat guarantee — pin it
        // here so a future tidy-up cannot silently break it.
        let d = RbaDecisionView {
            id: "id".into(),
            tenant_id: "t".into(),
            user_id: None,
            ip: "8.8.8.8".into(),
            score: 10,
            action: "allow".into(),
            reason: "low-risk login".into(),
            decided_at: "2026-06-12T10:00:00Z".into(),
            signals: None,
        };
        let raw = serde_json::to_string(&d).unwrap();
        assert!(
            !raw.contains("\"signals\""),
            "signals key must be omitted when None, got {raw}",
        );
    }

    #[test]
    fn decision_view_serializes_signal_breakdown_for_admin_caller() {
        // LOW-007: when populated, every contribution row carries
        // signal / sub_score / weight / weighted. The wire shape is
        // intentionally flat so it's a 1-to-1 mirror of
        // `sx_rba::SignalContribution`.
        let d = RbaDecisionView {
            id: "id".into(),
            tenant_id: "t".into(),
            user_id: None,
            ip: "8.8.8.8".into(),
            score: 42,
            action: "step_up_mfa".into(),
            reason: "ip-geo signal dominant".into(),
            decided_at: "2026-06-12T10:00:00Z".into(),
            signals: Some(vec![
                SignalContributionView {
                    signal: "ip_geo".into(),
                    sub_score: 80,
                    weight: 0.25,
                    weighted: 20.0,
                },
                SignalContributionView {
                    signal: "velocity".into(),
                    sub_score: 10,
                    weight: 0.20,
                    weighted: 2.0,
                },
            ]),
        };
        let raw = serde_json::to_string(&d).unwrap();
        assert!(
            raw.contains("\"signals\""),
            "signals must be present, got {raw}",
        );
        let back: RbaDecisionView = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, d);
        let sigs = back.signals.expect("signals must round-trip");
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].signal, "ip_geo");
        assert!((sigs[0].weighted - 20.0).abs() < 1e-9);
    }

    #[test]
    fn config_view_validates_weights_range() {
        let bad = RbaConfigView {
            allow_threshold: 30,
            block_threshold: 70,
            weights: RbaWeightsView {
                w_ip_geo: 2.0, // > 1.0 → invalid
                w_velocity: 0.4,
                w_business_hours: 0.2,
                w_device_fp: 0.0,
                w_mfa_recent: 0.0,
                w_success_rate: 0.0,
                w_impossible_travel: 0.0,
            },
            feature_flags: RbaFeatureFlagsView::default(),
            business_tz: "UTC".into(),
            business_hours_start: 9,
            business_hours_end: 18,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn config_view_validates_threshold_range() {
        let bad = RbaConfigView {
            allow_threshold: -1,
            block_threshold: 70,
            weights: RbaWeightsView {
                w_ip_geo: 0.4,
                w_velocity: 0.4,
                w_business_hours: 0.2,
                w_device_fp: 0.0,
                w_mfa_recent: 0.0,
                w_success_rate: 0.0,
                w_impossible_travel: 0.0,
            },
            feature_flags: RbaFeatureFlagsView::default(),
            business_tz: "UTC".into(),
            business_hours_start: 9,
            business_hours_end: 18,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn config_view_accepts_defaults() {
        let ok = RbaConfigView {
            allow_threshold: 30,
            block_threshold: 70,
            weights: RbaWeightsView {
                w_ip_geo: 0.4,
                w_velocity: 0.4,
                w_business_hours: 0.2,
                w_device_fp: 0.0,
                w_mfa_recent: 0.0,
                w_success_rate: 0.0,
                w_impossible_travel: 0.0,
            },
            feature_flags: RbaFeatureFlagsView::default(),
            business_tz: "UTC".into(),
            business_hours_start: 9,
            business_hours_end: 18,
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn legacy_pre_high001_payload_deserializes_with_default_high001_fields() {
        // A legacy client predating HIGH-001 posts the original 3-weight
        // payload + no feature_flags. The wire DTO must accept it and
        // default the new fields (weights=0, flags=all-on).
        let legacy_json = r#"{
            "allow_threshold": 30,
            "block_threshold": 70,
            "weights": {
                "w_ip_geo": 0.4,
                "w_velocity": 0.4,
                "w_business_hours": 0.2
            },
            "business_tz": "UTC",
            "business_hours_start": 9,
            "business_hours_end": 18
        }"#;
        let parsed: RbaConfigView = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(parsed.weights.w_device_fp, 0.0);
        assert_eq!(parsed.weights.w_mfa_recent, 0.0);
        assert_eq!(parsed.weights.w_success_rate, 0.0);
        assert_eq!(parsed.weights.w_impossible_travel, 0.0);
        assert!(parsed.feature_flags.enable_device_fp);
        assert!(parsed.feature_flags.enable_impossible_travel);
        assert!(parsed.validate().is_ok());
    }

    #[test]
    fn config_view_rejects_business_tz_empty() {
        let bad = RbaConfigView {
            allow_threshold: 30,
            block_threshold: 70,
            weights: RbaWeightsView {
                w_ip_geo: 0.4,
                w_velocity: 0.4,
                w_business_hours: 0.2,
                w_device_fp: 0.0,
                w_mfa_recent: 0.0,
                w_success_rate: 0.0,
                w_impossible_travel: 0.0,
            },
            feature_flags: RbaFeatureFlagsView::default(),
            business_tz: String::new(),
            business_hours_start: 9,
            business_hours_end: 18,
        };
        assert!(bad.validate().is_err());
    }
}
