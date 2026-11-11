//! UEBA admin (freeze-mode) wire shapes — HIGH-010.
//!
//! These DTOs back the `/v1/admin/ueba/baseline/{user_id}/{freeze,unfreeze,snapshot}`
//! surface. They intentionally mirror `sx_ueba::BaselineStateView` rather
//! than re-export it so the on-wire shape stays stable even if the
//! internal struct grows fields that should not be leaked.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Lifecycle state of a UEBA baseline on the wire. Lowercase string match
/// for `sx_ueba::BaselineState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStateCode {
    /// Cold-start: silent scorer.
    Learning,
    /// Steady-state: scorer + writer live.
    Active,
    /// Anti-poisoning hold: scorer reads snapshot, writer blocked.
    Frozen,
}

/// Snapshot DTO returned alongside the state when `Frozen`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenSnapshotView {
    /// Exactly 24 entries — counts indexed by UTC hour-of-day.
    pub login_hour_counts: Vec<u32>,
    /// `/16` (IPv4) or `/64` (IPv6) prefixes with hit counts.
    pub ip_prefixes: BTreeMap<String, u32>,
    /// Asset ids with hit counts.
    pub accessed_assets: BTreeMap<String, u32>,
    /// RFC 3339 timestamp the snapshot was taken (freeze-time).
    pub frozen_at: String,
}

/// Combined state + snapshot view returned by all three admin endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineStateView {
    /// Tenant the baseline belongs to (echoed back from the JWT claim).
    pub tenant_id: String,
    /// Subject of the baseline.
    pub user_id: String,
    /// Current lifecycle state.
    pub state: BaselineStateCode,
    /// Captured baseline counters when `state == frozen`. Omitted from
    /// the wire when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<FrozenSnapshotView>,
}

/// Request body for `POST /v1/admin/ueba/baseline/{user_id}/freeze` and
/// `unfreeze`. Both endpoints accept the same shape — the controller
/// supplies the `actor` from the caller's JWT.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FreezeRequest {
    /// Free-text operator reason (incident id, ticket reference, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn state_view_round_trips() {
        let v = BaselineStateView {
            tenant_id: "t".into(),
            user_id: "alice".into(),
            state: BaselineStateCode::Frozen,
            snapshot: Some(FrozenSnapshotView {
                login_hour_counts: vec![0; 24],
                ip_prefixes: BTreeMap::new(),
                accessed_assets: BTreeMap::new(),
                frozen_at: "2027-02-01T00:00:00Z".into(),
            }),
        };
        let raw = serde_json::to_string(&v).unwrap();
        let back: BaselineStateView = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn snapshot_omitted_when_absent() {
        let v = BaselineStateView {
            tenant_id: "t".into(),
            user_id: "alice".into(),
            state: BaselineStateCode::Active,
            snapshot: None,
        };
        let raw = serde_json::to_string(&v).unwrap();
        assert!(!raw.contains("snapshot"));
    }

    #[test]
    fn freeze_request_default_omits_reason() {
        let r = FreezeRequest::default();
        let raw = serde_json::to_string(&r).unwrap();
        assert_eq!(raw, "{}");
    }
}
