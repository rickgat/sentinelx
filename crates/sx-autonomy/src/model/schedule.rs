//! Cron-like schedule descriptor for the continuous validation engine.
//!
//! The engine uses a single in-process scheduler driven by
//! `tokio::time::interval`. Only the shapes a typical operations team needs
//! are exposed: a flat interval (most common in CI), an hourly mark, or a
//! daily wall-clock time.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use time::Time;

use crate::error::AutonomyError;

/// How often [`crate::service::validation_engine::ContinuousValidationEngine`]
/// dispatches a validation pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Schedule {
    /// Fire every `interval`.
    Interval {
        /// Interval between runs. Must be ≥ 1 second.
        interval_secs: u64,
    },
    /// Fire once an hour, at the configured `minute` offset (0..=59).
    Hourly {
        /// Minute offset within the hour, 0..=59.
        minute: u8,
    },
    /// Fire once a day, at the configured local-time-of-day.
    Daily {
        /// Hour, 0..=23.
        hour: u8,
        /// Minute, 0..=59.
        minute: u8,
    },
}

impl Schedule {
    /// Construct an [`Schedule::Interval`] from a `Duration`.
    pub fn from_interval(d: Duration) -> Result<Self, AutonomyError> {
        let secs = d.as_secs();
        if secs == 0 {
            return Err(AutonomyError::invalid_input(
                "schedule interval must be at least one second",
            ));
        }
        Ok(Self::Interval {
            interval_secs: secs,
        })
    }

    /// Construct an [`Schedule::Hourly`].
    pub fn hourly(minute: u8) -> Result<Self, AutonomyError> {
        if minute > 59 {
            return Err(AutonomyError::invalid_input(
                "schedule hour minute must be in 0..=59",
            ));
        }
        Ok(Self::Hourly { minute })
    }

    /// Construct a [`Schedule::Daily`] from a wall-clock `Time`.
    #[must_use]
    pub const fn daily(t: Time) -> Self {
        Self::Daily {
            hour: t.hour(),
            minute: t.minute(),
        }
    }

    /// Returns the smallest tick duration that drives this schedule
    /// correctly. For `Interval` this is the interval itself; for `Hourly`
    /// and `Daily` we expose a coarse-but-correct tick (60s) so the
    /// scheduler can re-evaluate the wall clock at minute granularity. The
    /// engine treats the in-test tick as the source of truth — tests inject
    /// `Interval { interval_secs: 1 }` to run one pass quickly.
    #[must_use]
    pub const fn tick(&self) -> Duration {
        match self {
            Self::Interval { interval_secs } => Duration::from_secs(*interval_secs),
            Self::Hourly { .. } | Self::Daily { .. } => Duration::from_secs(60),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn interval_rejects_zero() {
        assert!(Schedule::from_interval(Duration::from_secs(0)).is_err());
    }

    #[test]
    fn interval_accepts_one_second() {
        let s = Schedule::from_interval(Duration::from_secs(1)).unwrap();
        assert_eq!(s.tick(), Duration::from_secs(1));
    }

    #[test]
    fn hourly_validates_minute() {
        assert!(Schedule::hourly(60).is_err());
        assert!(Schedule::hourly(0).is_ok());
        assert!(Schedule::hourly(59).is_ok());
    }

    #[test]
    fn daily_constructs_from_time() {
        let t = Time::from_hms(3, 30, 0).unwrap();
        let s = Schedule::daily(t);
        let Schedule::Daily { hour, minute } = s else {
            panic!("expected Daily")
        };
        assert_eq!(hour, 3);
        assert_eq!(minute, 30);
    }

    #[test]
    fn coarse_tick_for_hourly_and_daily() {
        let h = Schedule::hourly(15).unwrap();
        let d = Schedule::daily(Time::from_hms(1, 0, 0).unwrap());
        assert_eq!(h.tick(), Duration::from_secs(60));
        assert_eq!(d.tick(), Duration::from_secs(60));
    }
}
