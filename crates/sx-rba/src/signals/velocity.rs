//! Login velocity counter — sliding window of recent attempts.
//!
//! The tracker holds one ring of timestamps per `(tenant_id, identity_key)`
//! pair. Each call to [`VelocityTracker::record_and_count`] appends the
//! current timestamp, prunes anything outside the configured window, and
//! returns the size of the remaining ring (i.e. the number of attempts
//! in the window, including the current one).
//!
//! ## Identity key
//!
//! The identity key is intentionally caller-defined. The login flow
//! uses the lower-cased email so brute-force attempts against the same
//! account are funnelled into one ring even when the IP changes.
//! Composite keys (e.g. `email|ip`) are equally valid.
//!
//! ## Bounded memory
//!
//! Each ring is capped at [`MAX_TIMESTAMPS_PER_RING`] entries to bound
//! memory at very high attempt rates. When the cap is reached the
//! oldest entries are evicted in-place. The cap is generously sized
//! (1024) so legitimate users never hit it — only burst attackers do.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Maximum ring length per `(tenant, identity)` pair.
pub const MAX_TIMESTAMPS_PER_RING: usize = 1024;

/// Default sliding-window size — five minutes captures both
/// rapid-fire credential-stuffing bursts and a slow drip of three or
/// four attempts.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Tracker handle. Cheap to clone (internally an `Arc`).
#[derive(Debug, Clone)]
pub struct VelocityTracker {
    rings: Arc<DashMap<String, VecDeque<Instant>>>,
    window: Duration,
}

impl Default for VelocityTracker {
    fn default() -> Self {
        Self::with_window(DEFAULT_WINDOW)
    }
}

impl VelocityTracker {
    /// Build a tracker with the given sliding window size.
    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            rings: Arc::new(DashMap::new()),
            window,
        }
    }

    /// Current sliding-window size.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Number of distinct rings currently tracked. Test-only — production
    /// callers should not rely on this for sizing decisions.
    #[must_use]
    pub fn ring_count(&self) -> usize {
        self.rings.len()
    }

    /// Record an attempt for `(tenant_id, identity)` and return the
    /// number of attempts (including the current one) that fall inside
    /// the sliding window.
    pub fn record_and_count(&self, tenant_id: &str, identity: &str) -> usize {
        self.record_and_count_at(tenant_id, identity, Instant::now())
    }

    /// Test seam — same as [`Self::record_and_count`] but takes an
    /// explicit `now` so unit tests can pin the clock without taking on
    /// a clock trait.
    pub fn record_and_count_at(&self, tenant_id: &str, identity: &str, now: Instant) -> usize {
        let key = Self::ring_key(tenant_id, identity);
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut entry = self.rings.entry(key).or_default();
        let ring = entry.value_mut();
        // Prune stale entries from the front of the deque (oldest first).
        while ring.front().is_some_and(|t| *t < cutoff) {
            let _ = ring.pop_front();
        }
        // Cap the ring before pushing.
        while ring.len() >= MAX_TIMESTAMPS_PER_RING {
            let _ = ring.pop_front();
        }
        ring.push_back(now);
        let n = ring.len();
        drop(entry);
        n
    }

    /// Inspect the current count for `(tenant_id, identity)` WITHOUT
    /// recording a new attempt. Used by the controllers' dashboard
    /// (e.g. "show me the current burst size") and by unit tests.
    #[must_use]
    pub fn count_at(&self, tenant_id: &str, identity: &str, now: Instant) -> usize {
        let key = Self::ring_key(tenant_id, identity);
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        self.rings
            .get(&key)
            .map_or(0, |r| r.value().iter().filter(|t| **t >= cutoff).count())
    }

    /// Forget every recorded attempt for `(tenant_id, identity)`. Tests
    /// only — production never wipes a ring.
    pub fn forget(&self, tenant_id: &str, identity: &str) {
        let key = Self::ring_key(tenant_id, identity);
        let _ = self.rings.remove(&key);
    }

    /// Build the internal composite key. Public-but-unstable so unit
    /// tests in this module can reach in; downstream code MUST go
    /// through `record_and_count` instead.
    fn ring_key(tenant_id: &str, identity: &str) -> String {
        // The pipe character cannot appear in a uuid or RFC-5321 local
        // part, so the join is unambiguous.
        format!("{tenant_id}|{}", identity.to_ascii_lowercase())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn count_increments_within_window() {
        let t = VelocityTracker::with_window(Duration::from_secs(60));
        let now = Instant::now();
        assert_eq!(t.record_and_count_at("ten", "a@b", now), 1);
        assert_eq!(t.record_and_count_at("ten", "a@b", now), 2);
        assert_eq!(
            t.record_and_count_at("ten", "a@b", now + Duration::from_secs(10)),
            3
        );
    }

    #[test]
    fn entries_outside_window_drop_off() {
        let t = VelocityTracker::with_window(Duration::from_secs(60));
        let now = Instant::now();
        assert_eq!(t.record_and_count_at("ten", "a@b", now), 1);
        // Move past the window: only the new entry survives.
        let later = now + Duration::from_secs(120);
        assert_eq!(t.record_and_count_at("ten", "a@b", later), 1);
    }

    #[test]
    fn distinct_identities_are_independent() {
        let t = VelocityTracker::default();
        let now = Instant::now();
        let _ = t.record_and_count_at("ten", "alice@x.test", now);
        let _ = t.record_and_count_at("ten", "alice@x.test", now);
        assert_eq!(t.record_and_count_at("ten", "bob@x.test", now), 1);
    }

    #[test]
    fn distinct_tenants_are_independent() {
        let t = VelocityTracker::default();
        let now = Instant::now();
        let _ = t.record_and_count_at("t1", "u@x.test", now);
        assert_eq!(t.record_and_count_at("t2", "u@x.test", now), 1);
    }

    #[test]
    fn identity_lookup_is_case_insensitive() {
        let t = VelocityTracker::default();
        let now = Instant::now();
        let _ = t.record_and_count_at("ten", "Alice@X.Test", now);
        // Subsequent attempt with a different casing must hit the same ring.
        assert_eq!(t.record_and_count_at("ten", "alice@x.test", now), 2);
    }

    #[test]
    fn ring_capped_at_max_entries() {
        let t = VelocityTracker::with_window(Duration::from_secs(60 * 60));
        let now = Instant::now();
        for _ in 0..(MAX_TIMESTAMPS_PER_RING + 32) {
            let _ = t.record_and_count_at("ten", "burst@x.test", now);
        }
        // After overflow the ring is exactly at the cap.
        assert_eq!(
            t.count_at("ten", "burst@x.test", now),
            MAX_TIMESTAMPS_PER_RING
        );
    }

    #[test]
    fn count_at_does_not_modify_ring() {
        let t = VelocityTracker::default();
        let now = Instant::now();
        let _ = t.record_and_count_at("ten", "x", now);
        let n1 = t.count_at("ten", "x", now);
        let n2 = t.count_at("ten", "x", now);
        assert_eq!(n1, 1);
        assert_eq!(n2, 1);
    }

    #[test]
    fn forget_clears_ring() {
        let t = VelocityTracker::default();
        let now = Instant::now();
        let _ = t.record_and_count_at("ten", "x", now);
        t.forget("ten", "x");
        assert_eq!(t.count_at("ten", "x", now), 0);
    }
}
