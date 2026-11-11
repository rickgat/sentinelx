//! API-shaped view of a [`crate::service::kill_switch::KillSwitchEvent`].

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::service::kill_switch::{KillReason, KillSwitchEvent, KillSwitchScope};

/// Wire-friendly view of a kill-switch trip event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchEventView {
    /// Display form of the scope that was tripped.
    pub scope: String,
    /// Display form of the reason it was tripped.
    pub reason: String,
    /// When the switch was tripped.
    pub at: OffsetDateTime,
}

impl KillSwitchEventView {
    /// Construct a view from raw parts.
    #[must_use]
    pub fn from_parts(scope: KillSwitchScope, reason: KillReason, at: OffsetDateTime) -> Self {
        Self {
            scope: scope.to_string(),
            reason: reason.to_string(),
            at,
        }
    }
}

impl From<KillSwitchEvent> for KillSwitchEventView {
    fn from(e: KillSwitchEvent) -> Self {
        Self::from_parts(e.scope, e.reason, e.at)
    }
}
