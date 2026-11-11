//! Prior login success-rate signal (HIGH-001).
//!
//! A 7-day rolling success rate per user. A high rate means the user
//! reliably authenticates from this baseline; a depressed rate signals
//! either credential stuffing in progress (lots of recent failures) or
//! a stale credential. Either case warrants a step-up.
//!
//! ## Bucketing
//!
//! | 7-day rate | Sub-score |
//! |------------|-----------|
//! | ≥ 95%      | 0         |
//! | 80% ‥ 94%  | 20        |
//! | 50% ‥ 79%  | 60        |
//! | < 50%      | 90        |
//!
//! When the user has fewer than [`MIN_OBSERVATIONS`] attempts in the
//! window we treat the rate as "insufficient data" and return `0`
//! rather than penalise. The 30-day passive-observation phase ensures
//! we eventually have enough data to score meaningfully; once outside
//! that phase the per-tenant baseline calibrator can bias this back if
//! the rate distribution is unusual for the tenant.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Default rolling window — 7 days.
pub const DEFAULT_WINDOW_SECS: u64 = 7 * 24 * 3_600;
/// Minimum number of observations before we score the rate. Below this
/// the sub-score is `0` (assume innocence).
pub const MIN_OBSERVATIONS: usize = 5;

/// Sub-score awarded to the ≥95% bucket.
pub const SCORE_TRUSTED: i32 = 0;
/// Sub-score awarded to the 80‥94% bucket.
pub const SCORE_NORMAL: i32 = 20;
/// Sub-score awarded to the 50‥79% bucket.
pub const SCORE_DEGRADED: i32 = 60;
/// Sub-score awarded to the < 50% bucket.
pub const SCORE_HOSTILE: i32 = 90;

/// Cap on the per-user history ring (one entry per attempt). Stops a
/// burst attacker from blowing up memory.
pub const MAX_HISTORY_ENTRIES: usize = 4_096;

/// Materialised signal handed to the scorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessRateSignal {
    /// Successful logins observed in the window.
    pub successes: u32,
    /// Total attempts (success + failure) observed in the window.
    pub attempts: u32,
}

impl SuccessRateSignal {
    /// Helper for tests + the in-memory tracker.
    #[must_use]
    pub fn new(successes: u32, attempts: u32) -> Self {
        Self {
            successes,
            attempts,
        }
    }

    /// Rate in `[0.0, 1.0]`, or `None` when there are no attempts.
    #[must_use]
    pub fn rate(self) -> Option<f64> {
        if self.attempts == 0 {
            return None;
        }
        Some(f64::from(self.successes) / f64::from(self.attempts))
    }
}

#[derive(Debug, Clone)]
struct HistoryEntry {
    at: OffsetDateTime,
    success: bool,
}

/// In-memory backing store for `rba_login_history`.
#[derive(Debug, Clone)]
pub struct LoginHistory {
    rows: Arc<DashMap<String, VecDeque<HistoryEntry>>>,
    window: Duration,
}

impl Default for LoginHistory {
    fn default() -> Self {
        Self {
            rows: Arc::new(DashMap::new()),
            window: Duration::from_secs(DEFAULT_WINDOW_SECS),
        }
    }
}

impl LoginHistory {
    /// Build a history tracker with the default 7-day window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Window size in seconds.
    #[must_use]
    pub fn window_secs(&self) -> u64 {
        self.window.as_secs()
    }

    /// Build a history tracker with a custom rolling window.
    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            rows: Arc::new(DashMap::new()),
            window,
        }
    }

    /// Record one login attempt for `(tenant, user)`.
    pub fn record(&self, tenant_id: Uuid, user_id: Uuid, success: bool, at: OffsetDateTime) {
        let key = Self::key(tenant_id, user_id);
        let mut entry = self.rows.entry(key).or_default();
        let ring = entry.value_mut();
        // Cap the ring before pushing.
        while ring.len() >= MAX_HISTORY_ENTRIES {
            let _ = ring.pop_front();
        }
        ring.push_back(HistoryEntry { at, success });
        // Drop anything that has aged out.
        let cutoff = at - self.window;
        while ring.front().is_some_and(|e| e.at < cutoff) {
            let _ = ring.pop_front();
        }
    }

    /// Compute the success-rate signal for `(tenant, user)` evaluated
    /// at `observed_at`.
    #[must_use]
    pub fn signal(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        observed_at: OffsetDateTime,
    ) -> SuccessRateSignal {
        let key = Self::key(tenant_id, user_id);
        let Some(entry) = self.rows.get(&key) else {
            return SuccessRateSignal::new(0, 0);
        };
        let cutoff = observed_at - self.window;
        let mut successes = 0u32;
        let mut attempts = 0u32;
        for e in entry.value() {
            if e.at < cutoff {
                continue;
            }
            if e.at > observed_at {
                continue;
            }
            attempts = attempts.saturating_add(1);
            if e.success {
                successes = successes.saturating_add(1);
            }
        }
        SuccessRateSignal {
            successes,
            attempts,
        }
    }

    fn key(tenant_id: Uuid, user_id: Uuid) -> String {
        format!("{tenant_id}|{user_id}")
    }
}

/// Score the success-rate signal.
#[must_use]
pub fn score(signal: SuccessRateSignal) -> i32 {
    if (signal.attempts as usize) < MIN_OBSERVATIONS {
        return SCORE_TRUSTED;
    }
    let Some(rate) = signal.rate() else {
        return SCORE_TRUSTED;
    };
    if rate >= 0.95 {
        SCORE_TRUSTED
    } else if rate >= 0.80 {
        SCORE_NORMAL
    } else if rate >= 0.50 {
        SCORE_DEGRADED
    } else {
        SCORE_HOSTILE
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn now() -> OffsetDateTime {
        datetime!(2026-06-12 12:00:00 UTC)
    }

    #[test]
    fn no_attempts_scores_trusted() {
        let s = SuccessRateSignal::new(0, 0);
        assert_eq!(score(s), SCORE_TRUSTED);
    }

    #[test]
    fn below_min_observations_scores_trusted() {
        // 0/3 is awful but we don't have enough data.
        let s = SuccessRateSignal::new(0, 3);
        assert_eq!(score(s), SCORE_TRUSTED);
    }

    #[test]
    fn trusted_band_scores_zero() {
        let s = SuccessRateSignal::new(19, 20); // 95%
        assert_eq!(score(s), SCORE_TRUSTED);
        let s = SuccessRateSignal::new(20, 20); // 100%
        assert_eq!(score(s), SCORE_TRUSTED);
    }

    #[test]
    fn normal_band_scores_twenty() {
        let s = SuccessRateSignal::new(17, 20); // 85%
        assert_eq!(score(s), SCORE_NORMAL);
    }

    #[test]
    fn degraded_band_scores_sixty() {
        let s = SuccessRateSignal::new(13, 20); // 65%
        assert_eq!(score(s), SCORE_DEGRADED);
    }

    #[test]
    fn hostile_band_scores_ninety() {
        let s = SuccessRateSignal::new(2, 20); // 10%
        assert_eq!(score(s), SCORE_HOSTILE);
    }

    #[test]
    fn history_records_and_computes_signal() {
        let h = LoginHistory::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        // 19 successes + 1 failure ⇒ 95% rate ⇒ trusted band.
        for _ in 0..19 {
            h.record(tenant, user, true, now() - Duration::from_secs(3_600));
        }
        for _ in 0..1 {
            h.record(tenant, user, false, now() - Duration::from_secs(3_600));
        }
        let s = h.signal(tenant, user, now());
        assert_eq!(s.successes, 19);
        assert_eq!(s.attempts, 20);
        assert_eq!(score(s), SCORE_TRUSTED);
    }

    #[test]
    fn history_drops_old_entries() {
        let h = LoginHistory::with_window(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        // 10 ancient failures + 1 fresh success → the failures are out.
        for _ in 0..10 {
            h.record(tenant, user, false, now() - Duration::from_secs(600));
        }
        h.record(tenant, user, true, now());
        let s = h.signal(tenant, user, now());
        assert_eq!(s.successes, 1);
        assert_eq!(s.attempts, 1);
    }

    #[test]
    fn history_is_tenant_and_user_scoped() {
        let h = LoginHistory::new();
        let t = Uuid::new_v4();
        let u1 = Uuid::new_v4();
        let u2 = Uuid::new_v4();
        for _ in 0..10 {
            h.record(t, u1, false, now());
        }
        let s = h.signal(t, u2, now());
        assert_eq!(s.attempts, 0);
    }

    #[test]
    fn history_caps_ring_size() {
        let h = LoginHistory::with_window(Duration::from_secs(60 * 60));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        for i in 0..(MAX_HISTORY_ENTRIES + 100) {
            // Stagger by 0 seconds so all entries are inside the window.
            h.record(tenant, user, i % 2 == 0, now());
        }
        let s = h.signal(tenant, user, now());
        assert!(s.attempts as usize <= MAX_HISTORY_ENTRIES);
    }
}
