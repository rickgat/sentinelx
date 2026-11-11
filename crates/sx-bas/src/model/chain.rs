//! Lateral-movement simulation chain model (P2-015).
//!
//! A [`LateralChain`] is an ordered sequence of [`TechniqueRef`] entries.
//! Each entry points at a technique already registered in the BAS
//! [`crate::service::registry::TechniqueRegistry`] by its stable `id`.
//!
//! The chain is **data**: chains do not embed exploit logic. Execution is
//! performed by [`crate::service::chain_executor::ChainExecutor`], which
//! re-uses the safety pipeline for every step.
//!
//! # Pre-canned catalogue
//!
//! Three canonical chains ship with this crate so the API surface can list
//! and replay them without a tenant having to compose their own:
//!
//! - `ransomware_style_v1`        — T1078 → T1021 → T1486 (stub)
//! - `supply_chain_compromise_v1` — T1199 → T1078.004 → T1611
//! - `phishing_privesc_lateral_v1` — T1566 → T1548 → T1021
//!
//! Each entry's `technique_id` matches the registry id; see
//! [`canonical_chains`].

use serde::{Deserialize, Serialize};

/// Reference to a technique in the registry.
///
/// `display_name` is a human-readable label used for traces and audit; it
/// has no operational effect. `kill_on_failure` controls whether the
/// remainder of the chain is skipped when this step fails: callers can
/// model "best-effort" steps with `kill_on_failure = false` and "must
/// succeed" steps with `kill_on_failure = true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TechniqueRef {
    /// Registry id of the technique (e.g. `"t1021_remote_services_v1"`).
    pub technique_id: String,
    /// MITRE ATT&CK technique id used for display (e.g. `"T1021"`).
    pub mitre_id: String,
    /// Human-readable label.
    pub display_name: String,
    /// Whether a failure of this step terminates the chain.
    pub kill_on_failure: bool,
}

impl TechniqueRef {
    /// Construct a new reference.
    #[must_use]
    pub fn new(
        technique_id: impl Into<String>,
        mitre_id: impl Into<String>,
        display_name: impl Into<String>,
        kill_on_failure: bool,
    ) -> Self {
        Self {
            technique_id: technique_id.into(),
            mitre_id: mitre_id.into(),
            display_name: display_name.into(),
            kill_on_failure,
        }
    }
}

/// A named, ordered sequence of [`TechniqueRef`] entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LateralChain {
    /// Stable chain id (e.g. `"ransomware_style_v1"`).
    pub id: String,
    /// Human-readable chain name.
    pub name: String,
    /// One-sentence description of the chain's intent.
    pub description: String,
    /// Ordered steps. The executor runs them sequentially.
    pub steps: Vec<TechniqueRef>,
}

impl LateralChain {
    /// Construct a new chain.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        steps: Vec<TechniqueRef>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            steps,
        }
    }

    /// Number of steps in the chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    /// `true` when the chain has no steps.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Status of a single chain-step execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainStepStatus {
    /// The step ran and produced a [`crate::model::simulation::StepResult::Simulated`] outcome.
    Success,
    /// The step ran but returned an error or non-success outcome.
    Failure,
    /// The step was skipped — either the chain was already terminated, the
    /// safety pipeline denied it, or its mode ceiling rejected it.
    Skipped,
}

/// Per-step record produced by the chain executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStepRecord {
    /// Zero-based step index in the originating chain.
    pub step_index: u32,
    /// Registry id of the technique that ran (or would have run).
    pub technique_id: String,
    /// MITRE technique id for display.
    pub mitre_id: String,
    /// Status of this step.
    pub status: ChainStepStatus,
    /// Free-text evidence summary. Never carries payload material.
    pub evidence: String,
}

/// Top-level status of a chain run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainRunStatus {
    /// Run is currently executing.
    Running,
    /// Every required step succeeded.
    Completed,
    /// At least one required step failed; remaining steps were skipped.
    Failed,
    /// The chain was halted by the kill switch.
    Aborted,
}

/// Materialised result of executing a [`LateralChain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainRun {
    /// Unique run id (UUID v4 as string).
    pub run_id: String,
    /// Tenant under which the run executed.
    pub tenant_id: String,
    /// Chain id that produced this run.
    pub chain_id: String,
    /// Top-level status.
    pub status: ChainRunStatus,
    /// Per-step records, in the order steps were attempted.
    pub steps: Vec<ChainStepRecord>,
    /// RFC3339 start timestamp.
    pub started_at: String,
    /// RFC3339 finish timestamp (only set when `status != Running`).
    pub finished_at: Option<String>,
}

impl ChainRun {
    /// `true` when every step succeeded.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self.status, ChainRunStatus::Completed)
    }
}

/// Returns the three pre-canned chains shipped by the crate.
///
/// These reference technique ids that exist in `sx-bas`'s safe-only
/// registry today. The `T1486` (Data Encrypted for Impact) step in the
/// ransomware chain is intentionally a stub: it points at the lateral-tool
/// transfer technique with a destructive-style display name. The
/// ransomware-impact technique itself is **not** shipped — see the
/// safe-only invariant on the crate root.
#[must_use]
pub fn canonical_chains() -> Vec<LateralChain> {
    vec![
        LateralChain::new(
            "ransomware_style_v1",
            "Ransomware-style chain",
            "Valid-account abuse → lateral movement → destructive-impact stub.",
            vec![
                TechniqueRef::new("t1078_valid_accounts_v1", "T1078", "Valid Accounts", true),
                TechniqueRef::new("t1021_remote_services_v1", "T1021", "Remote Services", true),
                TechniqueRef::new(
                    "t1570_lateral_tool_transfer_v1",
                    "T1486",
                    "Data Encrypted for Impact (stub)",
                    false,
                ),
            ],
        ),
        LateralChain::new(
            "supply_chain_compromise_v1",
            "Supply-chain compromise",
            "Trusted relationship → cloud-account abuse → container escape.",
            vec![
                TechniqueRef::new(
                    "t1199_trusted_relationship_v1",
                    "T1199",
                    "Trusted Relationship",
                    true,
                ),
                TechniqueRef::new(
                    "t1078_004_cloud_accounts_v1",
                    "T1078.004",
                    "Cloud Accounts",
                    true,
                ),
                TechniqueRef::new("t1611_escape_to_host_v1", "T1611", "Escape to Host", true),
            ],
        ),
        LateralChain::new(
            "phishing_privesc_lateral_v1",
            "Phishing → privilege escalation → lateral",
            "Phishing initial access → UAC/elevation abuse → remote services.",
            vec![
                TechniqueRef::new("t1566_phishing_v1", "T1566", "Phishing", true),
                TechniqueRef::new(
                    "t1548_abuse_elevation_control_v1",
                    "T1548",
                    "Abuse Elevation Control",
                    true,
                ),
                TechniqueRef::new("t1021_remote_services_v1", "T1021", "Remote Services", true),
            ],
        ),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::{canonical_chains, ChainRunStatus, ChainStepStatus, LateralChain, TechniqueRef};

    #[test]
    fn canonical_catalogue_has_three_chains_with_three_steps_each() {
        let chains = canonical_chains();
        assert_eq!(chains.len(), 3);
        for c in &chains {
            assert_eq!(c.len(), 3, "chain {} should have 3 steps", c.id);
            assert!(!c.is_empty());
        }
    }

    #[test]
    fn ransomware_chain_step_order_matches_spec() {
        let chains = canonical_chains();
        let ransom = chains
            .iter()
            .find(|c| c.id == "ransomware_style_v1")
            .unwrap();
        assert_eq!(ransom.steps[0].mitre_id, "T1078");
        assert_eq!(ransom.steps[1].mitre_id, "T1021");
        assert_eq!(ransom.steps[2].mitre_id, "T1486");
    }

    #[test]
    fn supply_chain_step_order_matches_spec() {
        let chains = canonical_chains();
        let sc = chains
            .iter()
            .find(|c| c.id == "supply_chain_compromise_v1")
            .unwrap();
        assert_eq!(sc.steps[0].mitre_id, "T1199");
        assert_eq!(sc.steps[1].mitre_id, "T1078.004");
        assert_eq!(sc.steps[2].mitre_id, "T1611");
    }

    #[test]
    fn phishing_chain_step_order_matches_spec() {
        let chains = canonical_chains();
        let ph = chains
            .iter()
            .find(|c| c.id == "phishing_privesc_lateral_v1")
            .unwrap();
        assert_eq!(ph.steps[0].mitre_id, "T1566");
        assert_eq!(ph.steps[1].mitre_id, "T1548");
        assert_eq!(ph.steps[2].mitre_id, "T1021");
    }

    #[test]
    fn chain_status_serialises_snake_case() {
        let s = serde_json::to_string(&ChainRunStatus::Completed).unwrap();
        assert_eq!(s, "\"completed\"");
        let s = serde_json::to_string(&ChainStepStatus::Skipped).unwrap();
        assert_eq!(s, "\"skipped\"");
    }

    #[test]
    fn lateral_chain_constructors_round_trip() {
        let chain = LateralChain::new(
            "x",
            "x-name",
            "desc",
            vec![TechniqueRef::new("a", "T0001", "A", true)],
        );
        assert_eq!(chain.id, "x");
        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
    }
}
