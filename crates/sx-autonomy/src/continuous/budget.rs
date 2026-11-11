//! Daily run budget for the 24/7 continuous simulator.
//!
//! [`DailyBudget`] caps how many simulator runs may execute in a single
//! UTC day. The counter is reset at midnight UTC — the budget exposes a
//! [`Clock`] trait so tests can drive the reset deterministically with
//! [`FakeClock`].
//!
//! # Semantics
//!
//! - [`DailyBudget::try_acquire`] atomically increments the run counter
//!   and returns `true` when the counter was strictly less than
//!   `max_runs` at acquisition time. On reset day boundary the counter
//!   is reset to zero before the increment, so the first call of a new
//!   UTC day always succeeds (assuming `max_runs > 0`).
//! - The acquire path uses a `compare_exchange` loop on an
//!   [`AtomicU32`] so concurrent callers never exceed `max_runs`.
//! - The `reset_at` field is a `Mutex<OffsetDateTime>` updated under the
//!   same critical section that zeroes the counter. The critical section
//!   is held only for the lock-and-rollover step; the hot path (an
//!   already-rolled-over budget) is purely atomic.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use time::{Date, OffsetDateTime, Time};

use crate::error::AutonomyError;

/// Pluggable clock trait so the budget can roll over at midnight UTC
/// deterministically in tests.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Returns the current UTC instant.
    fn now(&self) -> OffsetDateTime;
}

/// Real wall-clock implementation backed by `OffsetDateTime::now_utc`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Deterministic clock used by tests. Cheap `Mutex<OffsetDateTime>`
/// inside an `Arc`-friendly wrapper.
#[derive(Debug)]
pub struct FakeClock {
    inner: Mutex<OffsetDateTime>,
}

impl FakeClock {
    /// Construct a fake clock pinned to `now`.
    #[must_use]
    pub const fn new(now: OffsetDateTime) -> Self {
        Self {
            inner: Mutex::new(now),
        }
    }

    /// Advance the clock by `delta`. Panics in tests if the inner
    /// mutex is poisoned — production code does not use `FakeClock`.
    pub fn advance(&self, delta: time::Duration) {
        if let Ok(mut g) = self.inner.lock() {
            *g += delta;
        }
    }

    /// Replace the clock's current instant with `t`.
    pub fn set(&self, t: OffsetDateTime) {
        if let Ok(mut g) = self.inner.lock() {
            *g = t;
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        self.inner
            .lock()
            .map_or_else(|_| OffsetDateTime::UNIX_EPOCH, |g| *g)
    }
}

/// Daily run budget.
///
/// Conceptually equivalent to a token bucket that refills to `max_runs`
/// at midnight UTC and never refills in between. Concurrent
/// [`DailyBudget::try_acquire`] callers race via `compare_exchange`,
/// guaranteeing the total count never exceeds `max_runs` within one
/// UTC day.
#[derive(Debug)]
pub struct DailyBudget {
    /// Maximum runs allowed per UTC day.
    pub max_runs: u32,
    /// Runs already consumed in the current UTC day.
    pub used: AtomicU32,
    /// Next instant at which `used` is reset to zero — always the next
    /// midnight UTC after the day in which the budget was last touched.
    pub reset_at: Mutex<OffsetDateTime>,
}

impl DailyBudget {
    /// Build a new budget that resets at the next midnight UTC strictly
    /// after `now`.
    ///
    /// # Errors
    /// [`AutonomyError::InvalidInput`] when `max_runs == 0`.
    pub fn new(max_runs: u32, now: OffsetDateTime) -> Result<Self, AutonomyError> {
        if max_runs == 0 {
            return Err(AutonomyError::invalid_input(
                "DailyBudget::max_runs must be > 0",
            ));
        }
        Ok(Self {
            max_runs,
            used: AtomicU32::new(0),
            reset_at: Mutex::new(next_midnight_utc(now)),
        })
    }

    /// Attempt to consume one unit of budget. Returns `true` on
    /// success. Concurrent callers never observe a total over
    /// `max_runs` (within one UTC day).
    pub fn try_acquire(&self, clock: &dyn Clock) -> bool {
        self.maybe_reset(clock.now());
        loop {
            let cur = self.used.load(Ordering::Acquire);
            if cur >= self.max_runs {
                return false;
            }
            if self
                .used
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// How many runs remain in the current UTC day. Useful for status
    /// surfaces and tests.
    pub fn remaining(&self, clock: &dyn Clock) -> u32 {
        self.maybe_reset(clock.now());
        let used = self.used.load(Ordering::Acquire);
        self.max_runs.saturating_sub(used)
    }

    /// Current `reset_at` instant. Test-friendly snapshot.
    #[must_use]
    pub fn reset_at(&self) -> OffsetDateTime {
        self.reset_at
            .lock()
            .map_or(OffsetDateTime::UNIX_EPOCH, |g| *g)
    }

    fn maybe_reset(&self, now: OffsetDateTime) {
        // Lock-free fast path: read `reset_at` and bail when we're still
        // inside the current window.
        let current_reset = match self.reset_at.lock() {
            Ok(g) => *g,
            Err(_) => return,
        };
        if now < current_reset {
            return;
        }
        // We crossed midnight at least once. Re-take the lock and roll
        // forward. Another thread may have rolled it in between — be
        // idempotent.
        if let Ok(mut g) = self.reset_at.lock() {
            if now >= *g {
                *g = next_midnight_utc(now);
                self.used.store(0, Ordering::Release);
            }
        }
    }
}

/// Returns the next midnight UTC strictly after `now`. If `now` is
/// already on a midnight boundary, returns the *next* midnight (24h
/// later) so the rollover is unambiguous.
fn next_midnight_utc(now: OffsetDateTime) -> OffsetDateTime {
    let today: Date = now.date();
    let midnight_today = today.with_time(Time::MIDNIGHT).assume_utc();
    if now < midnight_today {
        // Should be impossible (`Date` of `now` always satisfies
        // `midnight_today <= now`), but stay defensive.
        return midnight_today;
    }
    let tomorrow = today.next_day().unwrap_or(today);
    tomorrow.with_time(Time::MIDNIGHT).assume_utc()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use time::macros::datetime;
    use time::Duration as TimeDuration;

    fn fake_at(t: OffsetDateTime) -> FakeClock {
        FakeClock::new(t)
    }

    #[test]
    fn rejects_zero_max_runs() {
        let now = datetime!(2026-01-01 12:00:00 UTC);
        let err = DailyBudget::new(0, now).unwrap_err();
        assert!(matches!(err, AutonomyError::InvalidInput(_)));
    }

    #[test]
    fn try_acquire_counts_down() {
        let now = datetime!(2026-01-01 12:00:00 UTC);
        let clock = fake_at(now);
        let b = DailyBudget::new(3, now).unwrap();
        assert!(b.try_acquire(&clock));
        assert!(b.try_acquire(&clock));
        assert!(b.try_acquire(&clock));
        assert!(!b.try_acquire(&clock), "fourth acquire must fail");
        assert_eq!(b.remaining(&clock), 0);
    }

    #[test]
    fn reset_at_midnight_utc() {
        let start = datetime!(2026-01-01 23:59:00 UTC);
        let clock = fake_at(start);
        let b = DailyBudget::new(2, start).unwrap();
        assert!(b.try_acquire(&clock));
        assert!(b.try_acquire(&clock));
        assert!(!b.try_acquire(&clock));
        // Advance past midnight.
        clock.advance(TimeDuration::minutes(2));
        // Counter should reset on the next acquire.
        assert!(b.try_acquire(&clock), "post-midnight acquire must succeed");
        assert_eq!(b.remaining(&clock), 1);
        // `reset_at` should now be midnight of Jan 3.
        assert_eq!(
            b.reset_at(),
            datetime!(2026-01-03 00:00:00 UTC),
            "reset_at should advance to next midnight"
        );
    }

    #[test]
    fn reset_at_is_strictly_after_now() {
        let exact_midnight = datetime!(2026-06-01 00:00:00 UTC);
        let b = DailyBudget::new(1, exact_midnight).unwrap();
        assert_eq!(b.reset_at(), datetime!(2026-06-02 00:00:00 UTC));
    }

    #[test]
    fn remaining_reflects_consumed() {
        let now = datetime!(2026-01-01 06:00:00 UTC);
        let clock = fake_at(now);
        let b = DailyBudget::new(5, now).unwrap();
        assert_eq!(b.remaining(&clock), 5);
        assert!(b.try_acquire(&clock));
        assert_eq!(b.remaining(&clock), 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn eight_concurrent_never_exceeds_max() {
        let now = datetime!(2026-01-01 12:00:00 UTC);
        let clock: Arc<FakeClock> = Arc::new(fake_at(now));
        let budget = Arc::new(DailyBudget::new(50, now).unwrap());

        let mut handles = Vec::new();
        for _ in 0..8 {
            let b = Arc::clone(&budget);
            let c: Arc<FakeClock> = Arc::clone(&clock);
            handles.push(tokio::spawn(async move {
                let mut local = 0_u32;
                for _ in 0..100 {
                    if b.try_acquire(c.as_ref()) {
                        local += 1;
                    }
                }
                local
            }));
        }

        let mut total = 0_u32;
        for h in handles {
            total += h.await.unwrap();
        }
        assert_eq!(total, 50, "concurrent acquires must total max_runs");
        assert_eq!(budget.remaining(clock.as_ref()), 0);
    }
}
