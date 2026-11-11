//! Frozen baseline snapshot.
//!
//! [`BaselineSnapshot`] is the captured shape of a [`UserBehaviorBaseline`]
//! taken at the moment an operator engages `Frozen` mode. It is
//! intentionally a plain data struct (`Clone + PartialEq + Serialize`) so
//! it can be persisted to Postgres `JSONB`, returned by the admin
//! `snapshot` endpoint, and projected onto the wire DTO without any
//! impedance-mismatch glue.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use sx_soc::ueba::baseline::UserBehaviorBaseline;

/// Captured per-user baseline at freeze-time.
///
/// All counter fields are deep-cloned from the live baseline so the
/// snapshot is decoupled from any subsequent in-memory mutation (defence-
/// in-depth: even if the live baseline is accidentally mutated while frozen,
/// the snapshot remains the scoring source of truth).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    /// Tenant the snapshot belongs to.
    pub tenant_id: Option<String>,
    /// Subject of the snapshot.
    pub user_id: String,
    /// 24-bucket login-hour-of-day histogram, indexed by UTC hour.
    pub login_hours_histogram: [u32; 24],
    /// `/16` (IPv4) or `/64` (IPv6) prefixes the user had been seen from.
    pub ip_prefixes: BTreeMap<String, u32>,
    /// Asset ids the user had been seen accessing.
    pub accessed_assets: BTreeMap<String, u32>,
    /// Wall-clock time the snapshot was taken (i.e. freeze was engaged).
    pub frozen_at: OffsetDateTime,
}

impl BaselineSnapshot {
    /// Capture `live` as a new snapshot at the supplied `frozen_at`.
    #[must_use]
    pub fn capture(live: &UserBehaviorBaseline, frozen_at: OffsetDateTime) -> Self {
        Self {
            tenant_id: live.tenant_id.clone(),
            user_id: live.user_id.clone(),
            login_hours_histogram: live.login_hours_histogram,
            ip_prefixes: live.ip_prefixes.clone(),
            accessed_assets: live.accessed_assets.clone(),
            frozen_at,
        }
    }

    /// Project the snapshot back into a live-style baseline. Useful when
    /// the scoring path expects a [`UserBehaviorBaseline`] (which is how
    /// `sx_soc::detect_anomaly` is parameterised). The returned baseline
    /// carries an empty idempotency ring — the snapshot does not need it
    /// because no folding happens while frozen.
    #[must_use]
    pub fn as_scoring_baseline(&self) -> UserBehaviorBaseline {
        UserBehaviorBaseline {
            tenant_id: self.tenant_id.clone(),
            user_id: self.user_id.clone(),
            login_hours_histogram: self.login_hours_histogram,
            ip_prefixes: self.ip_prefixes.clone(),
            accessed_assets: self.accessed_assets.clone(),
            updated_at: Some(self.frozen_at),
            recent_event_ids: std::collections::VecDeque::new(),
        }
    }

    /// Total number of login samples in the captured histogram.
    #[must_use]
    pub fn total_login_samples(&self) -> u32 {
        self.login_hours_histogram.iter().copied().sum()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn seeded() -> UserBehaviorBaseline {
        let mut b = UserBehaviorBaseline::new(Some("t-1".into()), "alice");
        b.login_hours_histogram[9] = 12;
        let _ = b.ip_prefixes.insert("10.20.0.0/16".into(), 5);
        let _ = b.accessed_assets.insert("crown".into(), 3);
        b
    }

    #[test]
    fn capture_clones_counters() {
        let live = seeded();
        let snap = BaselineSnapshot::capture(&live, datetime!(2027-02-01 0:00:00 UTC));
        assert_eq!(snap.login_hours_histogram, live.login_hours_histogram);
        assert_eq!(snap.ip_prefixes, live.ip_prefixes);
        assert_eq!(snap.accessed_assets, live.accessed_assets);
    }

    #[test]
    fn capture_is_decoupled_from_live_mutation() {
        let mut live = seeded();
        let snap = BaselineSnapshot::capture(&live, datetime!(2027-02-01 0:00:00 UTC));
        // Mutate the live baseline AFTER capture.
        live.login_hours_histogram[9] = 999;
        let _ = live.ip_prefixes.insert("10.20.0.0/16".into(), 999);
        assert_eq!(snap.login_hours_histogram[9], 12);
        assert_eq!(snap.ip_prefixes.get("10.20.0.0/16").copied(), Some(5));
    }

    #[test]
    fn as_scoring_baseline_round_trips_counters() {
        let snap = BaselineSnapshot::capture(&seeded(), datetime!(2027-02-01 0:00:00 UTC));
        let projected = snap.as_scoring_baseline();
        assert_eq!(projected.login_hours_histogram, snap.login_hours_histogram);
        assert_eq!(projected.ip_prefixes, snap.ip_prefixes);
        assert_eq!(projected.accessed_assets, snap.accessed_assets);
        assert!(projected.recent_event_ids.is_empty());
    }

    #[test]
    fn total_login_samples_sums_histogram() {
        let snap = BaselineSnapshot::capture(&seeded(), datetime!(2027-02-01 0:00:00 UTC));
        assert_eq!(snap.total_login_samples(), 12);
    }

    #[test]
    fn snapshot_serde_round_trip() {
        let snap = BaselineSnapshot::capture(&seeded(), datetime!(2027-02-01 0:00:00 UTC));
        let json = serde_json::to_string(&snap).expect("serialise");
        let back: BaselineSnapshot = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(snap, back);
    }
}
