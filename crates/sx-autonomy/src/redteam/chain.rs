//! MITRE ATT&CK kill-chain primitives.
//!
//! [`KillChainPhase`] enumerates the 14 ATT&CK Enterprise tactics in their
//! canonical order. A [`ChainStep`] anchors a single technique id to a
//! phase with a heuristic `[0.0, 1.0]` confidence. An [`AttackChain`] is
//! an ordered, deduplicated sequence of steps whose phases are
//! monotonically non-decreasing — i.e. the chain reads "left to right"
//! down the kill chain, no time travel.

use serde::{Deserialize, Serialize};

/// One of the 14 MITRE ATT&CK Enterprise tactics, in canonical kill-chain
/// order.
///
/// The `Ord` impl is derived from declaration order — do not reorder
/// variants. Phase ordering drives `AttackChain` validity (monotonic
/// non-decreasing) and the per-phase weighting in
/// [`crate::redteam::scoring`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillChainPhase {
    /// TA0043 — observation prior to intrusion.
    Reconnaissance,
    /// TA0042 — staging capabilities the adversary will use later.
    ResourceDevelopment,
    /// TA0001 — first foothold.
    InitialAccess,
    /// TA0002 — running adversary-controlled code.
    Execution,
    /// TA0003 — maintaining the foothold across reboots / sessions.
    Persistence,
    /// TA0004 — gaining a higher permission level.
    PrivilegeEscalation,
    /// TA0005 — evading detection.
    DefenseEvasion,
    /// TA0006 — stealing account names and passwords.
    CredentialAccess,
    /// TA0007 — figuring out the environment.
    Discovery,
    /// TA0008 — pivoting through the environment.
    LateralMovement,
    /// TA0009 — gathering data of interest.
    Collection,
    /// TA0011 — communicating with the compromised system.
    CommandAndControl,
    /// TA0010 — stealing data.
    Exfiltration,
    /// TA0040 — manipulate, interrupt, or destroy systems and data.
    Impact,
}

impl KillChainPhase {
    /// Every phase, in canonical order.
    ///
    /// Returned as an owned slice so callers can iterate without holding
    /// a reference into a `static`. The order matches `Ord`.
    #[must_use]
    pub const fn all() -> [Self; 14] {
        [
            Self::Reconnaissance,
            Self::ResourceDevelopment,
            Self::InitialAccess,
            Self::Execution,
            Self::Persistence,
            Self::PrivilegeEscalation,
            Self::DefenseEvasion,
            Self::CredentialAccess,
            Self::Discovery,
            Self::LateralMovement,
            Self::Collection,
            Self::CommandAndControl,
            Self::Exfiltration,
            Self::Impact,
        ]
    }

    /// Zero-based index in [`Self::all`] — useful for phase-weight tables.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::Reconnaissance => 0,
            Self::ResourceDevelopment => 1,
            Self::InitialAccess => 2,
            Self::Execution => 3,
            Self::Persistence => 4,
            Self::PrivilegeEscalation => 5,
            Self::DefenseEvasion => 6,
            Self::CredentialAccess => 7,
            Self::Discovery => 8,
            Self::LateralMovement => 9,
            Self::Collection => 10,
            Self::CommandAndControl => 11,
            Self::Exfiltration => 12,
            Self::Impact => 13,
        }
    }

    /// Short, stable ATT&CK tactic code (`TA0001` etc).
    #[must_use]
    pub const fn tactic_code(self) -> &'static str {
        match self {
            Self::Reconnaissance => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
        }
    }
}

impl std::fmt::Display for KillChainPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Reconnaissance => "reconnaissance",
            Self::ResourceDevelopment => "resource_development",
            Self::InitialAccess => "initial_access",
            Self::Execution => "execution",
            Self::Persistence => "persistence",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::DefenseEvasion => "defense_evasion",
            Self::CredentialAccess => "credential_access",
            Self::Discovery => "discovery",
            Self::LateralMovement => "lateral_movement",
            Self::Collection => "collection",
            Self::CommandAndControl => "command_and_control",
            Self::Exfiltration => "exfiltration",
            Self::Impact => "impact",
        };
        f.write_str(s)
    }
}

/// One step in a composed kill chain.
///
/// `confidence` is the heuristic score for this step, in `[0.0, 1.0]`.
/// It is the value used by [`crate::redteam::scoring::chain_score`] when
/// multiplying step confidences into a chain-wide score. Construction is
/// fallible to enforce the `[0.0, 1.0]` invariant up front.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainStep {
    /// The ATT&CK tactic this step belongs to.
    pub phase: KillChainPhase,
    /// Stable MITRE ATT&CK technique identifier (e.g. `T1190`).
    pub technique_id: String,
    /// Per-step confidence, in `[0.0, 1.0]`.
    pub confidence: f64,
}

impl ChainStep {
    /// Construct a new step. Clamps `confidence` into `[0.0, 1.0]` so the
    /// invariant cannot be violated downstream.
    #[must_use]
    pub fn new(phase: KillChainPhase, technique_id: impl Into<String>, confidence: f64) -> Self {
        let clamped = if confidence.is_finite() {
            confidence.clamp(0.0, 1.0)
        } else {
            0.0
        };
        Self {
            phase,
            technique_id: technique_id.into(),
            confidence: clamped,
        }
    }
}

/// An ordered, monotonically non-decreasing-by-phase sequence of steps.
///
/// `AttackChain` is the public output of
/// [`crate::redteam::selector::compose`]. The invariant — that
/// `steps[i].phase <= steps[i+1].phase` for all `i` — is upheld by the
/// composer and verified by [`Self::is_monotonic`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AttackChain {
    /// Ordered steps, lowest phase first.
    pub steps: Vec<ChainStep>,
}

impl AttackChain {
    /// New empty chain.
    #[must_use]
    pub const fn empty() -> Self {
        Self { steps: Vec::new() }
    }

    /// Wrap an already-built vector of steps.
    #[must_use]
    pub const fn from_steps(steps: Vec<ChainStep>) -> Self {
        Self { steps }
    }

    /// `true` when there are no steps.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Number of steps in the chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    /// `true` when phases are non-decreasing from left to right.
    #[must_use]
    pub fn is_monotonic(&self) -> bool {
        self.steps.windows(2).all(|w| {
            // `windows(2)` always yields slices of length 2; we destructure
            // explicitly to keep `clippy::indexing_slicing` happy.
            match w {
                [a, b] => a.phase <= b.phase,
                _ => true,
            }
        })
    }

    /// Distinct phases covered by the chain, in order.
    #[must_use]
    pub fn distinct_phases(&self) -> Vec<KillChainPhase> {
        let mut out: Vec<KillChainPhase> = Vec::with_capacity(self.steps.len());
        for s in &self.steps {
            if out.last().copied() != Some(s.phase) {
                out.push(s.phase);
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn all_phases_are_fourteen_and_ordered() {
        let all = KillChainPhase::all();
        assert_eq!(all.len(), 14);
        // Strict monotonic increase across the canonical ordering.
        for w in all.windows(2) {
            if let [a, b] = w {
                assert!(a < b);
            }
        }
    }

    #[test]
    fn ordinal_matches_position_in_all() {
        for (i, phase) in KillChainPhase::all().into_iter().enumerate() {
            assert_eq!(usize::from(phase.ordinal()), i);
        }
    }

    #[test]
    fn tactic_codes_are_stable() {
        assert_eq!(KillChainPhase::InitialAccess.tactic_code(), "TA0001");
        assert_eq!(KillChainPhase::Impact.tactic_code(), "TA0040");
        assert_eq!(KillChainPhase::Reconnaissance.tactic_code(), "TA0043");
    }

    #[test]
    fn step_confidence_is_clamped() {
        let s = ChainStep::new(KillChainPhase::Execution, "T1059", 1.7);
        assert_eq!(s.confidence, 1.0);
        let t = ChainStep::new(KillChainPhase::Execution, "T1059", -0.5);
        assert_eq!(t.confidence, 0.0);
        let u = ChainStep::new(KillChainPhase::Execution, "T1059", f64::NAN);
        assert_eq!(u.confidence, 0.0);
    }

    #[test]
    fn empty_chain_is_monotonic() {
        let c = AttackChain::empty();
        assert!(c.is_empty());
        assert!(c.is_monotonic());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn distinct_phases_collapses_runs() {
        let c = AttackChain::from_steps(vec![
            ChainStep::new(KillChainPhase::InitialAccess, "T1190", 0.5),
            ChainStep::new(KillChainPhase::InitialAccess, "T1133", 0.5),
            ChainStep::new(KillChainPhase::Execution, "T1059", 0.5),
        ]);
        assert_eq!(
            c.distinct_phases(),
            vec![KillChainPhase::InitialAccess, KillChainPhase::Execution],
        );
    }
}
