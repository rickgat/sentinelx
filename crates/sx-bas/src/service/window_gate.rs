//! Change-window gate.
//!
//! Active modes (`ActiveExploit`, `RedTeam`) require an active change window.
//! Safer modes do not require a window; if one is supplied, the gate still
//! enforces it.

use time::OffsetDateTime;
use tracing::warn;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::window::ChangeWindow;

/// Stateless gate that enforces change-window membership.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowGate;

impl WindowGate {
    /// Construct the gate.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluate the gate.
    ///
    /// - Active modes (`ActiveExploit`, `RedTeam`) require `window` to be
    ///   present **and** `now` to lie within it.
    /// - Safer modes pass if no window is supplied; if one is supplied, it
    ///   must contain `now`.
    // `self` is a stateless gate token for fluent call sites.
    #[allow(clippy::unused_self)]
    pub fn evaluate(
        self,
        engagement_id: &str,
        technique_id: &str,
        mode: AttackMode,
        now: OffsetDateTime,
        window: Option<&ChangeWindow>,
    ) -> Result<(), BasError> {
        match (mode.requires_roe_and_change_window(), window) {
            (true, None) => {
                warn!(
                    target = "sx_bas::gate",
                    gate = "window",
                    engagement_id = engagement_id,
                    technique_id = technique_id,
                    mode = %mode,
                    reason = "active mode requires a change window but none was supplied",
                    "window gate denied",
                );
                Err(BasError::OutsideChangeWindow)
            }
            (_, Some(w)) if !w.contains(now) => {
                warn!(
                    target = "sx_bas::gate",
                    gate = "window",
                    engagement_id = engagement_id,
                    technique_id = technique_id,
                    mode = %mode,
                    reason = "current time is outside the change window",
                    "window gate denied",
                );
                Err(BasError::OutsideChangeWindow)
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::WindowGate;
    use crate::model::mode::AttackMode;
    use crate::model::window::ChangeWindow;
    use time::{Duration, OffsetDateTime};

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn window_gate_allows_inside_window() {
        let gate = WindowGate::new();
        let start = epoch();
        let end = start + Duration::hours(1);
        let w = ChangeWindow::new(start, end).unwrap();
        let now = start + Duration::minutes(10);
        assert!(gate
            .evaluate("e1", "t1", AttackMode::ActiveExploit, now, Some(&w))
            .is_ok());
    }

    #[test]
    fn window_gate_denies_outside_window() {
        let gate = WindowGate::new();
        let start = epoch();
        let end = start + Duration::hours(1);
        let w = ChangeWindow::new(start, end).unwrap();
        let now = end + Duration::seconds(1);
        assert!(gate
            .evaluate("e1", "t1", AttackMode::ActiveExploit, now, Some(&w))
            .is_err());
    }

    #[test]
    fn window_gate_active_requires_window() {
        let gate = WindowGate::new();
        assert!(gate
            .evaluate("e1", "t1", AttackMode::ActiveExploit, epoch(), None)
            .is_err());
    }

    #[test]
    fn window_gate_safe_modes_skip_when_none() {
        let gate = WindowGate::new();
        assert!(gate
            .evaluate("e1", "t1", AttackMode::SafeInteractive, epoch(), None)
            .is_ok());
        assert!(gate
            .evaluate("e1", "t1", AttackMode::Theoretical, epoch(), None)
            .is_ok());
    }
}
