//! Per-user UEBA baseline lifecycle state.
//!
//! See [`BaselineState`] for the canonical state machine. The state machine
//! is intentionally small — three states, four transitions — because
//! anti-poisoning safety hinges on the operator being able to reason about
//! it in their head.

use serde::{Deserialize, Serialize};

/// Lifecycle state of a per-user UEBA baseline.
///
/// Values serialise as snake-case strings (`"learning"` / `"active"` /
/// `"frozen"`) so the on-the-wire shape stays stable across Rust enum
/// reorderings. The `Default` is [`BaselineState::Learning`] — every brand
/// new `(tenant_id, user_id)` starts in the silent warm-up phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BaselineState {
    /// Cold start: observe events, accumulate statistics, do NOT score.
    /// Prevents the "every login looks anomalous" noise problem for fresh
    /// users until the histogram is statistically meaningful.
    #[default]
    Learning,
    /// Steady state: score every event against the running baseline AND
    /// fold the event back into it.
    Active,
    /// Anti-poisoning hold: score every event against the snapshot recorded
    /// at freeze-time. New events do NOT mutate the underlying baseline so
    /// an attacker inside the perimeter cannot drift the user's "normal"
    /// to mask their behaviour.
    Frozen,
}

impl BaselineState {
    /// Stable lowercase code suitable for metrics labels, audit payload
    /// `code` fields, and Postgres `TEXT` columns.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Learning => "learning",
            Self::Active => "active",
            Self::Frozen => "frozen",
        }
    }

    /// `true` when the state requires the event scorer to be live.
    #[must_use]
    pub const fn should_score(self) -> bool {
        matches!(self, Self::Active | Self::Frozen)
    }

    /// `true` when ingested events are allowed to fold into the live
    /// baseline. Frozen + Learning both gate the writer for different
    /// reasons:
    /// * `Learning` writes update statistics but the scorer is silent;
    /// * `Frozen` blocks writes entirely so the snapshot stays immutable.
    #[must_use]
    pub const fn should_update_live_baseline(self) -> bool {
        matches!(self, Self::Learning | Self::Active)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_is_learning() {
        assert_eq!(BaselineState::default(), BaselineState::Learning);
    }

    #[test]
    fn codes_are_stable() {
        assert_eq!(BaselineState::Learning.code(), "learning");
        assert_eq!(BaselineState::Active.code(), "active");
        assert_eq!(BaselineState::Frozen.code(), "frozen");
    }

    #[test]
    fn should_score_only_in_active_or_frozen() {
        assert!(!BaselineState::Learning.should_score());
        assert!(BaselineState::Active.should_score());
        assert!(BaselineState::Frozen.should_score());
    }

    #[test]
    fn should_update_live_baseline_blocks_frozen() {
        assert!(BaselineState::Learning.should_update_live_baseline());
        assert!(BaselineState::Active.should_update_live_baseline());
        assert!(!BaselineState::Frozen.should_update_live_baseline());
    }

    #[test]
    fn serde_round_trip_is_snake_case() {
        for (state, code) in [
            (BaselineState::Learning, "\"learning\""),
            (BaselineState::Active, "\"active\""),
            (BaselineState::Frozen, "\"frozen\""),
        ] {
            let raw = serde_json::to_string(&state).expect("serialise");
            assert_eq!(raw, code);
            let back: BaselineState = serde_json::from_str(&raw).expect("deserialise");
            assert_eq!(state, back);
        }
    }
}
