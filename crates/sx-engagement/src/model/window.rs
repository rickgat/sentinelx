//! Engagement time window.
//!
//! Inclusive on both ends. `start <= end` is enforced at construction.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::EngagementError;

/// A closed time interval `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Inclusive lower bound.
    pub start: OffsetDateTime,
    /// Inclusive upper bound.
    pub end: OffsetDateTime,
}

impl TimeWindow {
    /// Construct a validated window. Returns an error if `end < start`.
    pub fn new(start: OffsetDateTime, end: OffsetDateTime) -> Result<Self, EngagementError> {
        if end < start {
            return Err(EngagementError::invalid_input(
                "time window end precedes start",
            ));
        }
        Ok(Self { start, end })
    }

    /// Returns `true` if `now` lies within `[start, end]` inclusive.
    #[must_use]
    pub fn contains(&self, now: OffsetDateTime) -> bool {
        now >= self.start && now <= self.end
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::TimeWindow;
    use time::{Duration, OffsetDateTime};

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn contains_inclusive_at_start_and_end() {
        let start = epoch();
        let end = start + Duration::hours(1);
        let w = TimeWindow::new(start, end).unwrap();
        assert!(w.contains(start));
        assert!(w.contains(end));
        assert!(w.contains(start + Duration::minutes(30)));
    }

    #[test]
    fn contains_rejects_outside() {
        let start = epoch();
        let end = start + Duration::hours(1);
        let w = TimeWindow::new(start, end).unwrap();
        assert!(!w.contains(start - Duration::seconds(1)));
        assert!(!w.contains(end + Duration::seconds(1)));
    }

    #[test]
    fn new_rejects_inverted_range() {
        let start = epoch();
        let end = start - Duration::hours(1);
        assert!(TimeWindow::new(start, end).is_err());
    }

    #[test]
    fn new_accepts_zero_duration_window() {
        let t = epoch();
        let w = TimeWindow::new(t, t).unwrap();
        assert!(w.contains(t));
    }
}
