//! Change window value object.
//!
//! Wraps a `TimeWindow` from `sx_engagement` and adds BAS-specific semantics
//! around `contains_now` / `is_active_at`. A change window is required by
//! `ActiveExploit` and `RedTeam` modes.

use serde::{Deserialize, Serialize};
use sx_engagement::prelude::TimeWindow;
use time::OffsetDateTime;

use crate::error::BasError;

/// A bounded time interval during which active modes may execute.
///
/// Inclusive on both ends. Constructed via [`ChangeWindow::new`] which
/// validates `start <= end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeWindow {
    /// Underlying inclusive time interval.
    pub window: TimeWindow,
}

impl ChangeWindow {
    /// Build a validated change window.
    pub fn new(start: OffsetDateTime, end: OffsetDateTime) -> Result<Self, BasError> {
        let window = TimeWindow::new(start, end)
            .map_err(|e| BasError::invalid_input(format!("invalid change window: {e}")))?;
        Ok(Self { window })
    }

    /// Returns `true` when `now` is within `[start, end]`.
    #[must_use]
    pub fn contains(&self, now: OffsetDateTime) -> bool {
        self.window.contains(now)
    }

    /// Inclusive lower bound.
    #[must_use]
    pub const fn start(&self) -> OffsetDateTime {
        self.window.start
    }

    /// Inclusive upper bound.
    #[must_use]
    pub const fn end(&self) -> OffsetDateTime {
        self.window.end
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::ChangeWindow;
    use time::{Duration, OffsetDateTime};

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn change_window_contains_inclusive() {
        let s = epoch();
        let e = s + Duration::hours(1);
        let w = ChangeWindow::new(s, e).unwrap();
        assert!(w.contains(s));
        assert!(w.contains(e));
        assert!(w.contains(s + Duration::minutes(30)));
    }

    #[test]
    fn change_window_rejects_inverted() {
        let s = epoch();
        let e = s - Duration::hours(1);
        assert!(ChangeWindow::new(s, e).is_err());
    }

    #[test]
    fn change_window_excludes_outside() {
        let s = epoch();
        let e = s + Duration::hours(1);
        let w = ChangeWindow::new(s, e).unwrap();
        assert!(!w.contains(s - Duration::seconds(1)));
        assert!(!w.contains(e + Duration::seconds(1)));
    }
}
