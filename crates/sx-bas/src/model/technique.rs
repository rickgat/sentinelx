//! Attack-technique abstraction and MITRE ATT&CK tagging.
//!
//! Every concrete technique implements [`AttackTechnique`] and declares:
//!
//! - a stable `id` (versioned, e.g. `theoretical_reachability_v1`),
//! - its MITRE ATT&CK coordinates ([`MitreTag`]),
//! - the maximum [`crate::model::mode::AttackMode`] under which it may run,
//! - its capabilities ([`Capabilities`]).
//!
//! All concrete techniques in this crate are **safe-only**. Active and
//! RedTeam paths return [`crate::error::BasError::ExecutionBlocked`] unless a
//! `dangerous_execution` feature flag is enabled — which is never on here.

use async_trait::async_trait;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::simulation::{SimulationStepContext, StepResult};

/// MITRE ATT&CK coordinates for a technique.
// The `_id` suffix on every field matches MITRE's own taxonomy
// (tactic id / technique id / sub-technique id); renaming would obscure intent.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MitreTag {
    /// ATT&CK tactic id (e.g. `"TA0001"` for `Initial Access`).
    pub tactic_id: &'static str,
    /// ATT&CK technique id (e.g. `"T1190"`).
    pub technique_id: &'static str,
    /// Optional sub-technique id (e.g. `Some("T1078.001")`).
    pub sub_technique_id: Option<&'static str>,
}

impl MitreTag {
    /// Construct a new MITRE tag.
    #[must_use]
    pub const fn new(
        tactic_id: &'static str,
        technique_id: &'static str,
        sub_technique_id: Option<&'static str>,
    ) -> Self {
        Self {
            tactic_id,
            technique_id,
            sub_technique_id,
        }
    }
}

/// Coarse intensity hint, used for telemetry labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntensityHint {
    /// Pure reasoning — no I/O.
    None,
    /// Low-volume / passive lookups.
    Low,
    /// Moderate, e.g. an OOB callback.
    Medium,
    /// High — would generate exploit traffic in a non-safe-only build.
    High,
}

/// Static description of what a technique would do at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capabilities {
    /// Intensity hint for telemetry / labels.
    pub intensity: IntensityHint,
    /// `true` when the technique would generate outbound network traffic in
    /// its real implementation. Safe-only stubs in this crate set this flag
    /// to advertise the *intended* behaviour, even though the stub itself
    /// short-circuits to `Simulated`.
    pub network_egress: bool,
    /// `true` when the technique can mutate target-side state.
    pub destructive: bool,
}

impl Capabilities {
    /// A purely-analytical capability set: no I/O, no egress, non-destructive.
    pub const ANALYTICAL: Self = Self {
        intensity: IntensityHint::None,
        network_egress: false,
        destructive: false,
    };
}

/// Polymorphic interface every technique implements.
///
/// # Kill-switch SLA
///
/// Implementations MUST poll
/// [`SimulationStepContext::kill_switch_signal`](crate::model::simulation::SimulationStepContext)
/// between sub-steps. The end-to-end SLA from `KillSwitch::trip()` to all
/// techniques aborting is **≤ 5 seconds**; an implementation that performs
/// sub-step work for more than one second without polling violates the SLA.
#[async_trait]
pub trait AttackTechnique: Send + Sync + std::fmt::Debug {
    /// Stable, versioned identifier (e.g. `"theoretical_reachability_v1"`).
    fn id(&self) -> &'static str;

    /// MITRE ATT&CK coordinates.
    fn mitre(&self) -> MitreTag;

    /// Maximum permissible operating mode for this technique.
    fn max_mode(&self) -> AttackMode;

    /// Capabilities (intensity hint, egress flag, destructive flag).
    fn capabilities(&self) -> Capabilities;

    /// Execute one step.
    ///
    /// Implementations MUST cooperate with the kill switch by polling
    /// `ctx.kill_switch_signal` between sub-steps.
    async fn step(&self, ctx: SimulationStepContext) -> Result<StepResult, BasError>;
}
