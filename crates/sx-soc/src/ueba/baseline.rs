//! UEBA baseline model.
//!
//! [`UserBehaviorBaseline`] is the per-user roll-up the anomaly detector
//! compares fresh events against. It is intentionally a plain data struct
//! (no methods that mutate via I/O) so it can be cheaply cloned, serialised
//! into Postgres `JSONB`, or projected into HTTP DTOs.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Maximum number of distinct `/16` prefixes retained per user.
///
/// Strictly bounded so a noisy attacker cannot inflate the baseline beyond
/// a constant memory ceiling.
pub const MAX_IP_PREFIXES: usize = 100;

/// Maximum number of distinct accessed asset ids retained per user.
pub const MAX_ASSETS: usize = 100;

/// Number of recent `event_id`s remembered per user for idempotency.
pub const RECENT_EVENTS_CAPACITY: usize = 256;

/// One normalised UEBA event the baseline (and the anomaly detector)
/// consume.
///
/// The struct is deliberately flat and serde-friendly so the SOC adapter
/// can construct it from a `serde_json::Value` without needing the upstream
/// crate to depend on `sx-iam` / `sx-engagement`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UebaEvent {
    /// Tenant the event is scoped to. `None` means "global / unknown" and
    /// disables per-tenant baseline writes in the in-memory service.
    pub tenant_id: Option<String>,
    /// Subject of the event (user id / sub claim).
    pub user_id: String,
    /// Stable identifier for the event. When present, used as the
    /// idempotency key for baseline updates and as the link from anomaly
    /// → originating event row.
    pub event_id: Option<String>,
    /// Source IPv4 / IPv6 address dotted-quad / colon-hex literal.
    /// `None` means "no IP available" — the IP dimension is skipped.
    pub source_ip: Option<String>,
    /// Accessed asset id. `None` skips the asset dimension.
    pub asset_id: Option<String>,
    /// Wall-clock time the event occurred; the hour-of-day bucket is
    /// derived from this in UTC.
    pub occurred_at: OffsetDateTime,
}

impl UebaEvent {
    /// Construct a minimal event with all optional fields empty.
    #[must_use]
    pub fn new(user_id: impl Into<String>, occurred_at: OffsetDateTime) -> Self {
        Self {
            tenant_id: None,
            user_id: user_id.into(),
            event_id: None,
            source_ip: None,
            asset_id: None,
            occurred_at,
        }
    }
}

/// Per-user behavioural baseline.
///
/// Snapshots of this struct are returned from `GET /v1/ueba/baselines/{user_id}`
/// after stripping the idempotency ring. All counters are bounded; see the
/// `MAX_*` constants for the exact caps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserBehaviorBaseline {
    /// Tenant the baseline is scoped to (mirrored from the events that
    /// populated it; in-memory writes refuse to mix tenants).
    pub tenant_id: Option<String>,
    /// Subject id.
    pub user_id: String,
    /// Hour-of-day counts indexed `0..=23` (UTC). Always exactly 24 entries.
    #[serde(with = "hour_counts_serde")]
    pub login_hours_histogram: [u32; 24],
    /// Bag of `/16` prefixes seen for this user, with a hit count so the
    /// LRU-by-least-seen eviction can keep the cap stable.
    pub ip_prefixes: BTreeMap<String, u32>,
    /// Bag of accessed asset ids with hit counts.
    pub accessed_assets: BTreeMap<String, u32>,
    /// RFC 3339 timestamp of the most recent update.
    pub updated_at: Option<OffsetDateTime>,
    /// Recent event ids retained for idempotency. Not part of the wire
    /// shape — flagged `#[serde(skip)]`.
    #[serde(skip)]
    pub recent_event_ids: VecDeque<String>,
}

impl UserBehaviorBaseline {
    /// Construct an empty baseline keyed by `(tenant_id, user_id)`.
    #[must_use]
    pub fn new(tenant_id: Option<String>, user_id: impl Into<String>) -> Self {
        Self {
            tenant_id,
            user_id: user_id.into(),
            login_hours_histogram: [0; 24],
            ip_prefixes: BTreeMap::new(),
            accessed_assets: BTreeMap::new(),
            updated_at: None,
            recent_event_ids: VecDeque::with_capacity(RECENT_EVENTS_CAPACITY),
        }
    }

    /// Returns the total number of login-hour samples accumulated.
    #[must_use]
    pub fn total_login_samples(&self) -> u32 {
        self.login_hours_histogram.iter().copied().sum()
    }

    /// Sample mean of the 24 bucket counts.
    #[must_use]
    pub fn login_hour_mean(&self) -> f64 {
        let total: f64 = self
            .login_hours_histogram
            .iter()
            .copied()
            .map(f64::from)
            .sum();
        total / 24.0
    }

    /// Population standard deviation of the 24 bucket counts.
    ///
    /// Returns `0.0` when every bucket is identical (including the empty
    /// case) so the caller's z-score divisor falls back to `1.0`.
    #[must_use]
    pub fn login_hour_stddev(&self) -> f64 {
        let mean = self.login_hour_mean();
        let var: f64 = self
            .login_hours_histogram
            .iter()
            .copied()
            .map(|c| {
                let d = f64::from(c) - mean;
                d * d
            })
            .sum::<f64>()
            / 24.0;
        var.sqrt()
    }

    /// Returns `true` if the supplied `event_id` was already applied to the
    /// baseline within the recent-ids ring. The idempotency check is
    /// **read-only** — callers update the ring via
    /// [`Self::remember_event_id`] after a successful counter mutation.
    #[must_use]
    pub fn already_seen(&self, event_id: &str) -> bool {
        self.recent_event_ids.iter().any(|e| e == event_id)
    }

    /// Insert `event_id` into the recent-ids ring, evicting the oldest
    /// entry when the ring is full.
    pub fn remember_event_id(&mut self, event_id: impl Into<String>) {
        if self.recent_event_ids.len() >= RECENT_EVENTS_CAPACITY {
            let _ = self.recent_event_ids.pop_front();
        }
        self.recent_event_ids.push_back(event_id.into());
    }
}

/// Extract the canonical `/16` prefix from an IP literal.
///
/// IPv4: keep the first two dotted-quads.
/// IPv6: keep the first four hex groups, joined by `:`.
///
/// Returns `None` when the literal does not parse cleanly enough to derive
/// a stable prefix.
#[must_use]
pub fn ip_prefix_16(ip: &str) -> Option<String> {
    let ip = ip.trim();
    if ip.is_empty() {
        return None;
    }
    if let Ok(parsed) = ip.parse::<std::net::Ipv4Addr>() {
        let o = parsed.octets();
        return Some(format!("{}.{}.0.0/16", o[0], o[1]));
    }
    if let Ok(parsed) = ip.parse::<std::net::Ipv6Addr>() {
        let segs = parsed.segments();
        return Some(format!(
            "{:x}:{:x}:{:x}:{:x}::/64",
            segs[0], segs[1], segs[2], segs[3],
        ));
    }
    None
}

/// Bounded insert into `bag`. Returns `true` when the entry was **new**
/// (i.e. the prefix / asset id had never been seen before, regardless of
/// whether it was actually retained — a brand-new entry on a full bag is
/// still novel from the anomaly-detection point of view).
pub(crate) fn bag_record(bag: &mut BTreeMap<String, u32>, key: String, cap: usize) -> bool {
    if let Some(slot) = bag.get_mut(&key) {
        *slot = slot.saturating_add(1);
        return false;
    }
    if bag.len() >= cap {
        // Evict the entry with the smallest hit count (deterministic on ties
        // via BTreeMap ordering).
        if let Some((evict_key, _)) = bag
            .iter()
            .min_by_key(|(k, v)| (**v, (*k).clone()))
            .map(|(k, v)| (k.clone(), *v))
        {
            let _ = bag.remove(&evict_key);
        }
    }
    let _ = bag.insert(key, 1);
    true
}

/// Module-local serde shim so the 24-element histogram round-trips via JSON
/// arrays (which is the on-wire shape used by `ueba_baselines.login_hour_counts`).
mod hour_counts_serde {
    use serde::de::Error as _;
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S>(value: &[u32; 24], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(24))?;
        for v in value {
            seq.serialize_element(v)?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u32; 24], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u32> = serde::Deserialize::deserialize(deserializer)?;
        if v.len() != 24 {
            return Err(D::Error::custom(format!(
                "expected 24 hour buckets, got {}",
                v.len()
            )));
        }
        let mut out = [0u32; 24];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix_keeps_first_two_octets() {
        assert_eq!(ip_prefix_16("10.20.30.40"), Some("10.20.0.0/16".into()));
    }

    #[test]
    fn ipv6_prefix_keeps_first_four_segments() {
        assert_eq!(
            ip_prefix_16("2001:db8:abcd:1234::1"),
            Some("2001:db8:abcd:1234::/64".into()),
        );
    }

    #[test]
    fn unparseable_ip_returns_none() {
        assert!(ip_prefix_16("not-an-ip").is_none());
        assert!(ip_prefix_16("").is_none());
        assert!(ip_prefix_16("   ").is_none());
    }

    #[test]
    fn bag_record_is_novel_on_first_insert() {
        let mut b = BTreeMap::<String, u32>::new();
        assert!(bag_record(&mut b, "a".into(), 10));
        assert!(!bag_record(&mut b, "a".into(), 10));
        assert_eq!(b.get("a").copied(), Some(2));
    }

    #[test]
    fn bag_eviction_kicks_in_at_cap() {
        let mut b = BTreeMap::<String, u32>::new();
        for i in 0..5 {
            let _ = bag_record(&mut b, format!("k{i}"), 4);
        }
        assert!(b.len() <= 4);
    }

    #[test]
    fn histogram_round_trips_via_serde() {
        let mut base = UserBehaviorBaseline::new(Some("t".into()), "u");
        base.login_hours_histogram[3] = 5;
        let json = serde_json::to_string(&base).expect("serialise");
        let back: UserBehaviorBaseline = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back.login_hours_histogram[3], 5);
    }

    #[test]
    fn login_hour_stats_handle_empty_histogram() {
        let base = UserBehaviorBaseline::new(None, "u");
        assert!((base.login_hour_mean() - 0.0).abs() < f64::EPSILON);
        assert!((base.login_hour_stddev() - 0.0).abs() < f64::EPSILON);
        assert_eq!(base.total_login_samples(), 0);
    }

    #[test]
    fn idempotency_ring_evicts_oldest_when_full() {
        let mut base = UserBehaviorBaseline::new(None, "u");
        for i in 0..(RECENT_EVENTS_CAPACITY + 10) {
            base.remember_event_id(format!("evt-{i}"));
        }
        assert_eq!(base.recent_event_ids.len(), RECENT_EVENTS_CAPACITY);
        assert!(!base.already_seen("evt-0"));
        assert!(base.already_seen(&format!("evt-{}", RECENT_EVENTS_CAPACITY + 5)));
    }
}
