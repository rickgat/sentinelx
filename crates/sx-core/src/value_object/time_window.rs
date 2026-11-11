//! Engagement time window — a closed interval `[start, end]`.
//!
//! Inclusive on both ends. `start <= end` is enforced at construction so
//! every value of [`TimeWindow`] is guaranteed valid.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::DomainError;

/// A closed time interval `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Inclusive lower bound.
    pub start: OffsetDateTime,
    /// Inclusive upper bound.
    pub end: OffsetDateTime,
}

impl TimeWindow {
    /// Build a validated window.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidValue`] if `end < start`.
    pub fn new(start: OffsetDateTime, end: OffsetDateTime) -> Result<Self, DomainError> {
        if end < start {
            return Err(DomainError::invalid("time window end precedes start"));
        }
        Ok(Self { start, end })
    }

    /// `true` when `now` lies inside `[start, end]` (inclusive).
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
    fn contains_inclusive_at_both_ends() {
        let s = epoch();
        let e = s + Duration::hours(1);
        let w = TimeWindow::new(s, e).unwrap();
        assert!(w.contains(s));
        assert!(w.contains(e));
        assert!(w.contains(s + Duration::minutes(30)));
    }

    #[test]
    fn contains_rejects_outside() {
        let s = epoch();
        let e = s + Duration::hours(1);
        let w = TimeWindow::new(s, e).unwrap();
        assert!(!w.contains(s - Duration::seconds(1)));
        assert!(!w.contains(e + Duration::seconds(1)));
    }

    #[test]
    fn new_rejects_inverted_range() {
        let s = epoch();
        let e = s - Duration::hours(1);
        assert!(TimeWindow::new(s, e).is_err());
    }

    #[test]
    fn new_accepts_zero_duration() {
        let t = epoch();
        let w = TimeWindow::new(t, t).unwrap();
        assert!(w.contains(t));
    }
}
