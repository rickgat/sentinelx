//! Finding status — the state machine that tracks a finding's lifecycle.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// Lifecycle status of a [`crate::entity::Finding`].
///
/// The happy path is
/// `Discovered → Triaged → Confirmed → Assigned → InProgress → Remediated → Verified → Closed`.
///
/// Three terminal states short-circuit the path:
/// - [`FindingStatus::AcceptedRisk`] — entered with explicit approval
/// - [`FindingStatus::FalsePositive`] — entered when triage determines no real issue
/// - [`FindingStatus::Closed`] — the standard terminal state after verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// The finding has just been recorded.
    Discovered,
    /// A triager has reviewed and assigned priority.
    Triaged,
    /// The finding has been reproduced / validated.
    Confirmed,
    /// Ownership has been assigned to a remediator.
    Assigned,
    /// Remediation is actively underway.
    InProgress,
    /// The fix has been applied (awaiting verification).
    Remediated,
    /// The fix has been verified.
    Verified,
    /// Lifecycle complete.
    Closed,
    /// Triage determined this is a false positive.
    FalsePositive,
    /// The risk has been formally accepted.
    AcceptedRisk,
}

impl fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Discovered => "discovered",
            Self::Triaged => "triaged",
            Self::Confirmed => "confirmed",
            Self::Assigned => "assigned",
            Self::InProgress => "in_progress",
            Self::Remediated => "remediated",
            Self::Verified => "verified",
            Self::Closed => "closed",
            Self::FalsePositive => "false_positive",
            Self::AcceptedRisk => "accepted_risk",
        };
        f.write_str(s)
    }
}

impl FindingStatus {
    /// Whether `self` is a terminal state — no further transitions allowed.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::FalsePositive | Self::AcceptedRisk
        )
    }

    /// Attempt to transition into `to`. Returns
    /// [`DomainError::InvalidStateTransition`] if the move is illegal.
    pub fn try_transition(self, to: Self) -> Result<Self, DomainError> {
        if self == to {
            return Ok(self);
        }
        if self.is_terminal() {
            return Err(reject(self, to));
        }
        if Self::is_allowed(self, to) {
            Ok(to)
        } else {
            Err(reject(self, to))
        }
    }

    const fn is_allowed(from: Self, to: Self) -> bool {
        // Short-circuit terminals from any non-terminal state.
        if matches!(to, Self::FalsePositive | Self::AcceptedRisk) {
            return !from.is_terminal();
        }
        matches!(
            (from, to),
            (Self::Discovered, Self::Triaged)
                | (Self::Triaged, Self::Confirmed)
                | (Self::Confirmed, Self::Assigned)
                | (Self::Assigned, Self::InProgress)
                | (Self::InProgress, Self::Remediated)
                | (Self::Remediated, Self::Verified)
                | (Self::Verified, Self::Closed)
        )
    }
}

fn reject(from: FindingStatus, to: FindingStatus) -> DomainError {
    DomainError::InvalidStateTransition {
        from: from.to_string(),
        to: to.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn happy_path() {
        let stages: [(FindingStatus, FindingStatus); 7] = [
            (FindingStatus::Discovered, FindingStatus::Triaged),
            (FindingStatus::Triaged, FindingStatus::Confirmed),
            (FindingStatus::Confirmed, FindingStatus::Assigned),
            (FindingStatus::Assigned, FindingStatus::InProgress),
            (FindingStatus::InProgress, FindingStatus::Remediated),
            (FindingStatus::Remediated, FindingStatus::Verified),
            (FindingStatus::Verified, FindingStatus::Closed),
        ];
        for (from, to) in stages {
            assert!(from.try_transition(to).is_ok(), "{from} -> {to}");
        }
    }

    #[rstest]
    #[case(FindingStatus::Discovered, FindingStatus::FalsePositive)]
    #[case(FindingStatus::Triaged, FindingStatus::AcceptedRisk)]
    #[case(FindingStatus::InProgress, FindingStatus::AcceptedRisk)]
    fn short_circuit_to_terminals(#[case] from: FindingStatus, #[case] to: FindingStatus) {
        assert!(from.try_transition(to).is_ok());
    }

    #[rstest]
    #[case(FindingStatus::Discovered, FindingStatus::Closed)]
    #[case(FindingStatus::Triaged, FindingStatus::Verified)]
    #[case(FindingStatus::Confirmed, FindingStatus::Discovered)]
    fn rejects_skips(#[case] from: FindingStatus, #[case] to: FindingStatus) {
        assert!(from.try_transition(to).is_err());
    }

    #[test]
    fn terminal_is_terminal() {
        assert!(FindingStatus::Closed
            .try_transition(FindingStatus::Discovered)
            .is_err());
        assert!(FindingStatus::FalsePositive
            .try_transition(FindingStatus::Triaged)
            .is_err());
        assert!(FindingStatus::AcceptedRisk
            .try_transition(FindingStatus::Closed)
            .is_err());
    }

    #[test]
    fn self_transition_is_noop() {
        assert_eq!(
            FindingStatus::Triaged
                .try_transition(FindingStatus::Triaged)
                .unwrap(),
            FindingStatus::Triaged,
        );
    }
}
