//! Time-source abstraction.
//!
//! Token issuance and lockout durations need a clock. The trait lets
//! tests pin "now" to a deterministic value without resorting to global
//! state.

use std::sync::Arc;

use time::OffsetDateTime;

/// Supplies the current wall-clock time.
///
/// Implementations should be cheap and infallible. The default impl,
/// [`SystemClock`], reads `OffsetDateTime::now_utc()`.
pub trait Clock: Send + Sync {
    /// Current UTC instant.
    fn now(&self) -> OffsetDateTime;

    /// Current epoch seconds (truncated).
    fn unix_seconds(&self) -> i64 {
        self.now().unix_timestamp()
    }
}

/// Production clock — delegates to the OS.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn now(&self) -> OffsetDateTime {
        (**self).now()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod fake {
    //! Test-only fake clock with mutable "now".

    use std::sync::Mutex;

    use time::OffsetDateTime;

    use super::Clock;

    /// A clock whose value is set by the test.
    #[derive(Debug)]
    pub struct FixedClock {
        now: Mutex<OffsetDateTime>,
    }

    impl FixedClock {
        /// Build a [`FixedClock`] pinned at `start`.
        #[must_use]
        pub fn new(start: OffsetDateTime) -> Self {
            Self {
                now: Mutex::new(start),
            }
        }

        /// Advance the clock by `seconds`.
        pub fn advance_secs(&self, seconds: i64) {
            let mut g = self.now.lock().expect("fake clock poisoned");
            *g += time::Duration::seconds(seconds);
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            *self.now.lock().expect("fake clock poisoned")
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::service::clock::fake::FixedClock;
    use time::macros::datetime;

    #[test]
    fn system_clock_is_monotonic_ish() {
        let a = SystemClock.unix_seconds();
        let b = SystemClock.unix_seconds();
        assert!(b >= a);
    }

    #[test]
    fn fake_clock_advances() {
        let c = FixedClock::new(datetime!(2025-01-01 00:00:00 UTC));
        let t0 = c.unix_seconds();
        c.advance_secs(60);
        assert_eq!(c.unix_seconds(), t0 + 60);
    }
}
