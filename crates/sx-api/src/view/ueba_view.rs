//! UEBA (User and Entity Behavioural Analytics) view layer.
//!
//! Wire shapes returned by:
//!
//! * `GET /v1/ueba/baselines/{user_id}` — a single user's behavioural
//!   roll-up.
//! * `GET /v1/ueba/anomalies?limit=N` — the most recent detected
//!   anomalies, newest-first.
//!
//! The view types intentionally do not mirror
//! [`sx_soc::UserBehaviorBaseline`] verbatim — the on-the-wire JSON omits
//! the internal idempotency ring and renames a few fields for clarity.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `GET /v1/ueba/baselines/{user_id}` response body.
///
/// All counters are bounded; see `sx_soc::ueba::baseline::MAX_*`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UebaBaselineView {
    /// Tenant id the baseline is scoped to. `None` means a baseline that
    /// has only ever been populated by global / untenanted events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Subject of the baseline.
    pub user_id: String,
    /// Exactly 24 entries — counts indexed by UTC hour-of-day.
    pub login_hour_counts: Vec<u32>,
    /// `/16` (IPv4) or `/64` (IPv6) prefixes seen for this user with hit
    /// counts.
    pub ip_prefixes: BTreeMap<String, u32>,
    /// Distinct asset ids the user has interacted with, with hit counts.
    pub accessed_assets: BTreeMap<String, u32>,
    /// RFC 3339 timestamp of the most recent update, or `None` when the
    /// baseline has never been touched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// One attributed anomaly dimension on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UebaAnomalyDimView {
    /// Dimension label: `hour_of_day` | `source_ip_prefix` | `asset_id`.
    pub dimension: String,
    /// Per-dimension score (higher = more anomalous).
    pub score: f64,
    /// Human-readable explanation.
    pub reason: String,
}

/// One persisted UEBA anomaly row on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UebaAnomalyView {
    /// Anomaly id (UUID v4).
    pub id: String,
    /// Tenant scope. `None` means "global" (no tenant attribution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Subject of the triggering event.
    pub user_id: String,
    /// Originating event id when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Aggregate anomaly score (`max` over dimensions).
    pub score: f64,
    /// Per-dimension breakdown.
    pub dimensions: Vec<UebaAnomalyDimView>,
    /// Severity bucket: `low` / `medium` / `high` / `critical` / `info`.
    pub severity: String,
    /// RFC 3339 timestamp the anomaly was detected.
    pub detected_at: String,
}

/// `GET /v1/ueba/anomalies` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UebaAnomaliesResponse {
    /// Newest-first.
    pub anomalies: Vec<UebaAnomalyView>,
}

/// Query string for `GET /v1/ueba/anomalies?limit=N`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct UebaAnomaliesQuery {
    /// Caller-supplied cap. The controller clamps to a hard limit.
    #[serde(default)]
    pub limit: Option<u32>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn baseline_view_round_trips() {
        let mut prefixes = BTreeMap::new();
        let _ = prefixes.insert("10.0.0.0/16".to_owned(), 4);
        let v = UebaBaselineView {
            tenant_id: Some("t".into()),
            user_id: "u".into(),
            login_hour_counts: vec![0; 24],
            ip_prefixes: prefixes,
            accessed_assets: BTreeMap::new(),
            updated_at: Some("2026-06-12T00:00:00Z".into()),
        };
        let raw = serde_json::to_string(&v).unwrap();
        let back: UebaBaselineView = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn anomaly_view_round_trips() {
        let a = UebaAnomalyView {
            id: "id".into(),
            tenant_id: Some("t".into()),
            user_id: "u".into(),
            event_id: Some("e".into()),
            score: 4.0,
            dimensions: vec![UebaAnomalyDimView {
                dimension: "asset_id".into(),
                score: 4.0,
                reason: "first access to asset crown".into(),
            }],
            severity: "medium".into(),
            detected_at: "2026-06-12T00:00:00Z".into(),
        };
        let raw = serde_json::to_string(&a).unwrap();
        let back: UebaAnomalyView = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn baseline_view_omits_optional_when_absent() {
        let v = UebaBaselineView {
            tenant_id: None,
            user_id: "u".into(),
            login_hour_counts: vec![0; 24],
            ip_prefixes: BTreeMap::new(),
            accessed_assets: BTreeMap::new(),
            updated_at: None,
        };
        let raw = serde_json::to_string(&v).unwrap();
        assert!(!raw.contains("tenant_id"));
        assert!(!raw.contains("updated_at"));
    }
}
