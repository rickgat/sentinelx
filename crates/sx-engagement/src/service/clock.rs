//! Clock abstraction. Production uses [`SystemClock`]; tests use a fake.
//!
//! Time is injected via this trait so that tests are deterministic and
//! window enforcement can be exercised without sleeping.

use std::sync::{Arc, Mutex};

use time::OffsetDateTime;

/// A monotonic-enough source of "wall-clock now".
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Returns the current UTC time.
    fn now(&self) -> OffsetDateTime;
}

/// Production clock — `OffsetDateTime::now_utc()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A test clock whose returned time can be advanced or set.
///
/// Cheap to clone; the inner state is shared via `Arc<Mutex<_>>`.
#[derive(Debug, Clone)]
pub struct FakeClock {
    inner: Arc<Mutex<OffsetDateTime>>,
}

impl FakeClock {
    /// Construct a clock pinned at `at`.
    #[must_use]
    pub fn new(at: OffsetDateTime) -> Self {
        Self {
            inner: Arc::new(Mutex::new(at)),
        }
    }

    /// Overwrite the current time.
    pub fn set(&self, at: OffsetDateTime) {
        if let Ok(mut g) = self.inner.lock() {
            *g = at;
        }
    }

    /// Advance the clock by the given duration.
    pub fn advance(&self, delta: time::Duration) {
        if let Ok(mut g) = self.inner.lock() {
            *g += delta;
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        // Poisoned-lock fallback: return UNIX_EPOCH; this only happens in tests
        // and never silently returns a wrong "now" in production.
        match self.inner.lock() {
            Ok(g) => *g,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn system_clock_returns_recent_time() {
        let clk = SystemClock;
        let t1 = clk.now();
        let t2 = clk.now();
        assert!(t2 >= t1);
    }

    #[test]
    fn fake_clock_pinned_and_advances() {
        let t0 = OffsetDateTime::UNIX_EPOCH;
        let clk = FakeClock::new(t0);
        assert_eq!(clk.now(), t0);
        clk.advance(Duration::hours(1));
        assert_eq!(clk.now(), t0 + Duration::hours(1));
        clk.set(t0);
        assert_eq!(clk.now(), t0);
    }

    #[test]
    fn fake_clock_clones_share_state() {
        let t0 = OffsetDateTime::UNIX_EPOCH;
        let clk = FakeClock::new(t0);
        let clone = clk.clone();
        clk.advance(Duration::minutes(5));
        assert_eq!(clone.now(), t0 + Duration::minutes(5));
    }
}
