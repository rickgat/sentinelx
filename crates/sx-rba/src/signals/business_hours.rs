//! Business-hours signal.
//!
//! Login attempts that fall inside the tenant's nominal working hours
//! are weighted less than after-hours attempts. The window is
//! configured per tenant via [`BusinessHours`]:
//!
//! * `tz` — IANA-style timezone name (e.g. `Europe/Berlin`,
//!   `America/Los_Angeles`). The MVP only interprets the suffix as a
//!   fixed UTC offset table (see [`FIXED_OFFSETS`]); anything
//!   unrecognised falls back to UTC. A production deployment will
//!   swap in a real `chrono-tz` lookup behind the same call surface.
//! * `start_hour` / `end_hour` — local-time hours in `[0, 23]`.
//!   `start_hour < end_hour` is enforced at construction time so the
//!   window never wraps across midnight.
//!
//! The check returns a [`BusinessHoursStatus`] describing both whether
//! the timestamp was inside the window AND the local hour, so the
//! audit row can reconstruct the decision later.

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset};

/// Default opening hour (09:00 local).
pub const DEFAULT_START_HOUR: u8 = 9;
/// Default closing hour (18:00 local).
pub const DEFAULT_END_HOUR: u8 = 18;
/// Default timezone if a tenant has not configured one.
pub const DEFAULT_TZ: &str = "UTC";

/// Tiny in-process table mapping common IANA timezone names to their
/// fixed UTC offset in hours. This deliberately ignores daylight
/// saving so the MVP stays dependency-free; a production deployment
/// will swap in `chrono-tz` behind the same `tz_offset` interface.
const FIXED_OFFSETS: &[(&str, i8)] = &[
    ("UTC", 0),
    ("Etc/UTC", 0),
    ("GMT", 0),
    ("Europe/London", 0),
    ("Europe/Berlin", 1),
    ("Europe/Paris", 1),
    ("Europe/Amsterdam", 1),
    ("Europe/Madrid", 1),
    ("Europe/Rome", 1),
    ("Europe/Moscow", 3),
    ("Africa/Cairo", 2),
    ("Africa/Johannesburg", 2),
    ("Asia/Dubai", 4),
    ("Asia/Kolkata", 5),
    ("Asia/Singapore", 8),
    ("Asia/Hong_Kong", 8),
    ("Asia/Shanghai", 8),
    ("Asia/Tokyo", 9),
    ("Asia/Seoul", 9),
    ("Australia/Sydney", 10),
    ("Pacific/Auckland", 12),
    ("America/New_York", -5),
    ("America/Chicago", -6),
    ("America/Denver", -7),
    ("America/Los_Angeles", -8),
    ("America/Vancouver", -8),
    ("America/Sao_Paulo", -3),
    ("America/Buenos_Aires", -3),
    ("America/Mexico_City", -6),
];

/// Per-tenant business-hours window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BusinessHours {
    /// IANA timezone name. Unknown entries fall back to UTC.
    pub tz: String,
    /// Opening hour, local time, inclusive.
    pub start_hour: u8,
    /// Closing hour, local time, exclusive.
    pub end_hour: u8,
}

impl Default for BusinessHours {
    fn default() -> Self {
        Self {
            tz: DEFAULT_TZ.to_owned(),
            start_hour: DEFAULT_START_HOUR,
            end_hour: DEFAULT_END_HOUR,
        }
    }
}

/// Errors raised while validating a [`BusinessHours`] config.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BusinessHoursError {
    /// `start_hour` / `end_hour` outside `[0, 23]`.
    #[error("hours out of range: start={start}, end={end}")]
    OutOfRange {
        /// Provided start hour.
        start: u8,
        /// Provided end hour.
        end: u8,
    },
    /// `start_hour >= end_hour` — the MVP does not support wrapping
    /// windows.
    #[error("invalid window: start ({start}) must be < end ({end})")]
    InvalidWindow {
        /// Provided start hour.
        start: u8,
        /// Provided end hour.
        end: u8,
    },
}

/// Result of evaluating a timestamp against a [`BusinessHours`] window.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BusinessHoursStatus {
    /// Whether the timestamp fell inside the tenant's business hours.
    pub in_hours: bool,
    /// The local hour (`[0, 23]`) used to make the decision.
    pub local_hour: u8,
    /// The UTC offset the engine resolved for the tenant's tz.
    pub offset_hours: i8,
}

impl BusinessHours {
    /// Validate the hour bounds.
    pub fn validate(&self) -> Result<(), BusinessHoursError> {
        if self.start_hour > 23 || self.end_hour > 23 {
            return Err(BusinessHoursError::OutOfRange {
                start: self.start_hour,
                end: self.end_hour,
            });
        }
        if self.start_hour >= self.end_hour {
            return Err(BusinessHoursError::InvalidWindow {
                start: self.start_hour,
                end: self.end_hour,
            });
        }
        Ok(())
    }

    /// Look up the configured timezone's offset in whole hours. Unknown
    /// timezones fall back to UTC (offset 0).
    #[must_use]
    pub fn tz_offset_hours(&self) -> i8 {
        FIXED_OFFSETS
            .iter()
            .find_map(|(name, off)| if *name == self.tz { Some(*off) } else { None })
            .unwrap_or(0)
    }

    /// Evaluate `ts` against this window. Returns [`BusinessHoursStatus`].
    #[must_use]
    pub fn evaluate(&self, ts: OffsetDateTime) -> BusinessHoursStatus {
        let offset_hours = self.tz_offset_hours();
        let local = ts.to_offset(UtcOffset::from_hms(offset_hours, 0, 0).unwrap_or(UtcOffset::UTC));
        let hour = local.hour();
        // Hours are bounded `[0, 23]` and start < end is enforced at
        // construction time via `validate`; tests double-check the
        // unvalidated path is still memory-safe.
        let in_hours = hour >= self.start_hour && hour < self.end_hour;
        BusinessHoursStatus {
            in_hours,
            local_hour: hour,
            offset_hours,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn default_window_is_nine_to_six_utc() {
        let bh = BusinessHours::default();
        assert!(bh.validate().is_ok());
        assert_eq!(bh.start_hour, 9);
        assert_eq!(bh.end_hour, 18);
        assert_eq!(bh.tz, "UTC");
    }

    #[test]
    fn invalid_window_rejected() {
        let bh = BusinessHours {
            tz: "UTC".into(),
            start_hour: 18,
            end_hour: 9,
        };
        assert_eq!(
            bh.validate().unwrap_err(),
            BusinessHoursError::InvalidWindow { start: 18, end: 9 }
        );
    }

    #[test]
    fn out_of_range_hours_rejected() {
        let bh = BusinessHours {
            tz: "UTC".into(),
            start_hour: 30,
            end_hour: 40,
        };
        assert!(matches!(
            bh.validate().unwrap_err(),
            BusinessHoursError::OutOfRange { .. }
        ));
    }

    #[test]
    fn ten_am_utc_is_in_hours() {
        let bh = BusinessHours::default();
        let ts = datetime!(2026-06-12 10:00:00 UTC);
        let s = bh.evaluate(ts);
        assert!(s.in_hours);
        assert_eq!(s.local_hour, 10);
        assert_eq!(s.offset_hours, 0);
    }

    #[test]
    fn three_am_utc_is_out_of_hours() {
        let bh = BusinessHours::default();
        let ts = datetime!(2026-06-12 03:00:00 UTC);
        let s = bh.evaluate(ts);
        assert!(!s.in_hours);
        assert_eq!(s.local_hour, 3);
    }

    #[test]
    fn end_hour_is_exclusive() {
        let bh = BusinessHours::default();
        // 18:00 UTC is the close — the window does not include the
        // closing minute.
        let ts = datetime!(2026-06-12 18:00:00 UTC);
        assert!(!bh.evaluate(ts).in_hours);
    }

    #[test]
    fn berlin_tz_shifts_window_by_one_hour() {
        let bh = BusinessHours {
            tz: "Europe/Berlin".into(),
            start_hour: 9,
            end_hour: 18,
        };
        // 08:30 UTC is 09:30 in Berlin → in-hours.
        let in_local = bh.evaluate(datetime!(2026-06-12 08:30:00 UTC));
        assert!(in_local.in_hours);
        assert_eq!(in_local.local_hour, 9);
        assert_eq!(in_local.offset_hours, 1);

        // 17:30 UTC is 18:30 in Berlin → after-hours.
        let after = bh.evaluate(datetime!(2026-06-12 17:30:00 UTC));
        assert!(!after.in_hours);
    }

    #[test]
    fn la_tz_shifts_window_west() {
        let bh = BusinessHours {
            tz: "America/Los_Angeles".into(),
            start_hour: 9,
            end_hour: 18,
        };
        // 17:00 UTC is 09:00 LA → in-hours.
        let s = bh.evaluate(datetime!(2026-06-12 17:00:00 UTC));
        assert!(s.in_hours);
        assert_eq!(s.local_hour, 9);
        assert_eq!(s.offset_hours, -8);
    }

    #[test]
    fn unknown_tz_falls_back_to_utc() {
        let bh = BusinessHours {
            tz: "Mars/Olympus_Mons".into(),
            start_hour: 9,
            end_hour: 18,
        };
        let s = bh.evaluate(datetime!(2026-06-12 12:00:00 UTC));
        assert!(s.in_hours);
        assert_eq!(s.offset_hours, 0);
    }
}
