//! Per-control cadence for P1-004.
//!
//! This module is intentionally *not* a fork of
//! [`crate::collector::schedule`]: the trait-based dispatcher already
//! ships a robust `EvidenceSchedule`. Here we record cadence as
//! database-friendly metadata (cron-style `kind` discriminator + a
//! single `hour_utc` for daily/weekly variants) so an operator can
//! configure it without recompiling.

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// Frequency at which a control's evidence should be collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ScheduleKind {
    /// Default — fires once per week.
    Weekly,
    /// Fires daily.
    Daily,
    /// Fires hourly. Reserved for very cheap probes (e.g. Vault seal).
    Hourly,
    /// Disabled — operator opted out for this tenant.
    Disabled,
}

/// Concrete schedule for one control.
///
/// `hour_utc` only applies to [`ScheduleKind::Daily`] / [`ScheduleKind::Weekly`];
/// the [`ScheduleKind::Hourly`] variant ignores it. We keep the field
/// unconditionally to make the database row shape uniform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlSchedule {
    /// Frequency variant.
    pub kind: ScheduleKind,
    /// UTC hour-of-day (0..=23) at which to fire daily/weekly schedules.
    pub hour_utc: u8,
}

impl ControlSchedule {
    /// The MVP default — once a week at 04:00 UTC.
    #[must_use]
    pub const fn weekly_default() -> Self {
        Self {
            kind: ScheduleKind::Weekly,
            hour_utc: 4,
        }
    }

    /// Whether this schedule's next fire is at-or-before `now`, given
    /// the optional previous fire timestamp.
    ///
    /// Logic:
    /// - `Disabled` is never due.
    /// - `Hourly` is due once per hour (60-minute lockout from
    ///   `last_fired_at`).
    /// - `Daily` is due once per 24-hour window.
    /// - `Weekly` is due once per 7-day window.
    /// - When `last_fired_at` is `None`, any non-`Disabled` schedule is
    ///   due (cold-start).
    #[must_use]
    pub fn is_due(self, last_fired_at: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
        match (self.kind, last_fired_at) {
            (ScheduleKind::Disabled, _) => false,
            (_, None) => true,
            (ScheduleKind::Hourly, Some(prev)) => now - prev >= Duration::hours(1),
            (ScheduleKind::Daily, Some(prev)) => now - prev >= Duration::days(1),
            (ScheduleKind::Weekly, Some(prev)) => now - prev >= Duration::days(7),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn weekly_default_uses_4_utc() {
        let s = ControlSchedule::weekly_default();
        assert_eq!(s.kind, ScheduleKind::Weekly);
        assert_eq!(s.hour_utc, 4);
    }

    #[test]
    fn disabled_is_never_due() {
        let s = ControlSchedule {
            kind: ScheduleKind::Disabled,
            hour_utc: 0,
        };
        assert!(!s.is_due(None, datetime!(2026-06-12 00:00:00 UTC)));
        assert!(!s.is_due(
            Some(datetime!(2020-01-01 00:00:00 UTC)),
            datetime!(2026-06-12 00:00:00 UTC)
        ));
    }

    #[test]
    fn cold_start_is_always_due() {
        for kind in [
            ScheduleKind::Hourly,
            ScheduleKind::Daily,
            ScheduleKind::Weekly,
        ] {
            let s = ControlSchedule { kind, hour_utc: 4 };
            assert!(s.is_due(None, datetime!(2026-06-12 00:00:00 UTC)));
        }
    }

    #[test]
    fn weekly_respects_seven_day_window() {
        let s = ControlSchedule::weekly_default();
        let prev = datetime!(2026-06-05 04:00:00 UTC);
        // Five days later — not due.
        assert!(!s.is_due(Some(prev), datetime!(2026-06-10 04:00:00 UTC)));
        // Seven days later — due.
        assert!(s.is_due(Some(prev), datetime!(2026-06-12 04:00:00 UTC)));
    }

    #[test]
    fn hourly_respects_one_hour_window() {
        let s = ControlSchedule {
            kind: ScheduleKind::Hourly,
            hour_utc: 0,
        };
        let prev = datetime!(2026-06-12 00:00:00 UTC);
        assert!(!s.is_due(Some(prev), datetime!(2026-06-12 00:59:00 UTC)));
        assert!(s.is_due(Some(prev), datetime!(2026-06-12 01:00:00 UTC)));
    }
}
