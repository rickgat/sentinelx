//! Scheduling primitives for [`crate::collector::EvidenceCollector`].
//!
//! A schedule is a tiny closed-form expression of "when does this
//! collector next fire?". It deliberately avoids cron-style strings to
//! keep the catalog explicit and to keep the dispatcher trivially
//! testable: every schedule reduces to a `next_fire_at(now)` answer.

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, Time, Weekday};

/// Day-of-week marker used by [`EvidenceSchedule::Weekly`].
///
/// Mirrors [`time::Weekday`] but is `Serialize`/`Deserialize`-friendly
/// with stable lowercase names so the on-disk catalog format is
/// unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WeekdayCode {
    /// Monday.
    Monday,
    /// Tuesday.
    Tuesday,
    /// Wednesday.
    Wednesday,
    /// Thursday.
    Thursday,
    /// Friday.
    Friday,
    /// Saturday.
    Saturday,
    /// Sunday.
    Sunday,
}

impl WeekdayCode {
    /// Translate into the corresponding [`time::Weekday`].
    #[must_use]
    pub const fn into_time_weekday(self) -> Weekday {
        match self {
            Self::Monday => Weekday::Monday,
            Self::Tuesday => Weekday::Tuesday,
            Self::Wednesday => Weekday::Wednesday,
            Self::Thursday => Weekday::Thursday,
            Self::Friday => Weekday::Friday,
            Self::Saturday => Weekday::Saturday,
            Self::Sunday => Weekday::Sunday,
        }
    }

    /// Convert from a [`time::Weekday`].
    #[must_use]
    pub const fn from_time_weekday(w: Weekday) -> Self {
        match w {
            Weekday::Monday => Self::Monday,
            Weekday::Tuesday => Self::Tuesday,
            Weekday::Wednesday => Self::Wednesday,
            Weekday::Thursday => Self::Thursday,
            Weekday::Friday => Self::Friday,
            Weekday::Saturday => Self::Saturday,
            Weekday::Sunday => Self::Sunday,
        }
    }
}

/// Cadence at which an [`crate::collector::EvidenceCollector`] should
/// be invoked.
///
/// All variants use UTC to keep dispatch deterministic across
/// deployment regions; operators that want a local-time schedule
/// should translate at the catalog edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EvidenceSchedule {
    /// Fire once per week at the supplied UTC weekday + hour.
    Weekly {
        /// Day of the week to fire on.
        weekday: WeekdayCode,
        /// Hour of the day (0..=23) to fire at.
        hour_utc: u8,
    },
    /// Fire once per day at the supplied UTC hour.
    Daily {
        /// Hour of the day (0..=23) to fire at.
        hour_utc: u8,
    },
    /// Fire at the top of every UTC hour.
    Hourly,
}

impl EvidenceSchedule {
    /// Return the next instant (strictly after `now`) at which this
    /// schedule fires.
    ///
    /// All arithmetic is performed in UTC; callers translate at the
    /// presentation edge. The implementation is total: for any
    /// well-formed schedule and any input `now`, it returns a finite
    /// timestamp in the future.
    #[must_use]
    pub fn next_fire_at(self, now: OffsetDateTime) -> OffsetDateTime {
        match self {
            Self::Hourly => next_hourly(now),
            Self::Daily { hour_utc } => next_daily(now, hour_utc),
            Self::Weekly { weekday, hour_utc } => {
                next_weekly(now, weekday.into_time_weekday(), hour_utc)
            }
        }
    }

    /// Whether this schedule fires "at or before" `now` relative to
    /// the previously-supplied `last_fired_at`.
    ///
    /// Used by [`crate::collector::registry::CollectorRegistry::dispatch`]
    /// to decide whether a collector should run on the current tick:
    /// a collector with no prior firing fires whenever `now >=` the
    /// schedule's first future fire from the epoch reference, while a
    /// collector that has fired before re-fires once `now >=
    /// next_fire_at(last_fired_at)`.
    #[must_use]
    pub fn is_due(self, last_fired_at: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
        match last_fired_at {
            // First-ever dispatch: fire if `now` matches the schedule's
            // tick boundary, i.e. the prior tick has already passed.
            None => self.matches_tick(now),
            Some(last) => now >= self.next_fire_at(last),
        }
    }

    /// Return `true` if `now` falls on or after the most recent tick
    /// boundary for this schedule. Used only for the cold-start path
    /// in [`Self::is_due`]; the steady-state path is driven by
    /// `next_fire_at(last_fired_at)`.
    #[must_use]
    fn matches_tick(self, now: OffsetDateTime) -> bool {
        match self {
            Self::Hourly => true, // every hour is a tick boundary at minute 0
            Self::Daily { hour_utc } => now.hour() >= hour_utc,
            Self::Weekly { weekday, hour_utc } => {
                let target = weekday.into_time_weekday();
                // "Due" if we are on the target weekday at/after the
                // hour, or if we are past it within the same week.
                let today = now.weekday();
                if today == target {
                    now.hour() >= hour_utc
                } else {
                    days_from_monday(today) > days_from_monday(target)
                }
            }
        }
    }
}

/// Helper: days elapsed since Monday for a given weekday (Mon = 0).
const fn days_from_monday(w: Weekday) -> u8 {
    match w {
        Weekday::Monday => 0,
        Weekday::Tuesday => 1,
        Weekday::Wednesday => 2,
        Weekday::Thursday => 3,
        Weekday::Friday => 4,
        Weekday::Saturday => 5,
        Weekday::Sunday => 6,
    }
}

fn top_of_hour(t: OffsetDateTime) -> OffsetDateTime {
    // Truncate to the top of the hour (minute = second = nanosecond = 0).
    let time = Time::from_hms(t.hour(), 0, 0).unwrap_or(Time::MIDNIGHT);
    t.replace_time(time)
}

fn next_hourly(now: OffsetDateTime) -> OffsetDateTime {
    let top = top_of_hour(now);
    if top > now {
        top
    } else {
        top + Duration::hours(1)
    }
}

fn next_daily(now: OffsetDateTime, hour_utc: u8) -> OffsetDateTime {
    let target_hour = hour_utc.min(23);
    let time = Time::from_hms(target_hour, 0, 0).unwrap_or(Time::MIDNIGHT);
    let today = now.replace_time(time);
    if today > now {
        today
    } else {
        today + Duration::days(1)
    }
}

fn next_weekly(now: OffsetDateTime, weekday: Weekday, hour_utc: u8) -> OffsetDateTime {
    let target_hour = hour_utc.min(23);
    let time = Time::from_hms(target_hour, 0, 0).unwrap_or(Time::MIDNIGHT);
    let today_at_target = now.replace_time(time);
    let today_dom = days_from_monday(now.weekday());
    let target_dom = days_from_monday(weekday);
    let mut delta_days = i64::from(target_dom) - i64::from(today_dom);
    if delta_days < 0 {
        delta_days += 7;
    }
    let candidate = today_at_target + Duration::days(delta_days);
    if candidate > now {
        candidate
    } else {
        candidate + Duration::days(7)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn hourly_next_fire_jumps_to_top_of_next_hour() {
        let now = datetime!(2026-06-12 12:34:56 UTC);
        let next = EvidenceSchedule::Hourly.next_fire_at(now);
        assert_eq!(next, datetime!(2026-06-12 13:00:00 UTC));
    }

    #[test]
    fn daily_next_fire_today_when_before_target_hour() {
        let now = datetime!(2026-06-12 08:00:00 UTC);
        let next = EvidenceSchedule::Daily { hour_utc: 10 }.next_fire_at(now);
        assert_eq!(next, datetime!(2026-06-12 10:00:00 UTC));
    }

    #[test]
    fn daily_next_fire_tomorrow_when_after_target_hour() {
        let now = datetime!(2026-06-12 11:00:00 UTC);
        let next = EvidenceSchedule::Daily { hour_utc: 10 }.next_fire_at(now);
        assert_eq!(next, datetime!(2026-06-13 10:00:00 UTC));
    }

    #[test]
    fn weekly_next_fire_advances_one_full_week_when_same_day_already_passed() {
        // 2026-06-12 is a Friday.
        let now = datetime!(2026-06-12 09:00:00 UTC);
        let next = EvidenceSchedule::Weekly {
            weekday: WeekdayCode::Friday,
            hour_utc: 8,
        }
        .next_fire_at(now);
        assert_eq!(next, datetime!(2026-06-19 08:00:00 UTC));
    }

    #[test]
    fn weekly_next_fire_skips_to_future_weekday() {
        // 2026-06-12 is a Friday; next Monday is the 15th.
        let now = datetime!(2026-06-12 09:00:00 UTC);
        let next = EvidenceSchedule::Weekly {
            weekday: WeekdayCode::Monday,
            hour_utc: 6,
        }
        .next_fire_at(now);
        assert_eq!(next, datetime!(2026-06-15 06:00:00 UTC));
    }

    #[test]
    fn is_due_uses_last_fired_at_when_present() {
        let last = datetime!(2026-06-12 12:00:00 UTC);
        let sched = EvidenceSchedule::Daily { hour_utc: 12 };
        // Same day, before next tick.
        assert!(!sched.is_due(Some(last), datetime!(2026-06-12 23:00:00 UTC)));
        // Day later at exactly the next tick.
        assert!(sched.is_due(Some(last), datetime!(2026-06-13 12:00:00 UTC)));
        // Well past next tick.
        assert!(sched.is_due(Some(last), datetime!(2026-06-13 14:00:00 UTC)));
    }

    #[test]
    fn weekday_code_round_trip_via_time_weekday() {
        for code in [
            WeekdayCode::Monday,
            WeekdayCode::Tuesday,
            WeekdayCode::Wednesday,
            WeekdayCode::Thursday,
            WeekdayCode::Friday,
            WeekdayCode::Saturday,
            WeekdayCode::Sunday,
        ] {
            let round = WeekdayCode::from_time_weekday(code.into_time_weekday());
            assert_eq!(round, code);
        }
    }
}
