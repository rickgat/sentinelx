//! Safety pipeline.
//!
//! Composes the four gates in **fixed order**:
//!
//! ```text
//! mode → window → approval → kill_switch
//! ```
//!
//! The pipeline short-circuits on the first denial — once a gate returns
//! `Err`, no subsequent gate is consulted. This ordering is deliberate:
//!
//! 1. **Mode** is cheapest and the single most important invariant.
//! 2. **Window** rejects out-of-band executions before any approval lookup.
//! 3. **Approval** + RoE enforcement.
//! 4. **Kill switch** has the final say — even with everything else green,
//!    a tripped kill switch denies execution.
//!
//! Each denial path emits a structured `tracing::warn!` carrying
//! `engagement_id`, `technique_id`, `gate`, and `reason`.

use std::sync::Arc;

use crate::error::BasError;
use crate::model::simulation::SimulationRequest;
use crate::model::technique::AttackTechnique;
use crate::service::approval_gate::DualApprovalGate;
use crate::service::kill_switch_gate::KillSwitchGate;
use crate::service::mode_gate::ModeGate;
use crate::service::window_gate::WindowGate;

/// Fixed-order composition of the four BAS safety gates.
#[derive(Debug, Clone)]
pub struct SafetyPipeline {
    mode: ModeGate,
    window: WindowGate,
    approval: DualApprovalGate,
    kill_switch: KillSwitchGate,
}

impl SafetyPipeline {
    /// Construct the pipeline.
    ///
    /// `kill_switch` carries the port. The other gates are stateless and are
    /// constructed in place.
    #[must_use]
    pub const fn new(kill_switch: KillSwitchGate) -> Self {
        Self {
            mode: ModeGate::new(),
            window: WindowGate::new(),
            approval: DualApprovalGate::new(),
            kill_switch,
        }
    }

    /// Borrow the kill-switch gate (for the use case to acquire the notify
    /// signal).
    #[must_use]
    pub const fn kill_switch(&self) -> &KillSwitchGate {
        &self.kill_switch
    }

    /// Evaluate every gate in order. Returns `Ok(())` only when every gate
    /// passes; returns the first denial otherwise.
    pub async fn evaluate(
        &self,
        req: &SimulationRequest,
        technique: &Arc<dyn AttackTechnique>,
    ) -> Result<(), BasError> {
        let engagement_id = req.engagement_id.to_string();
        let technique_id = technique.id();

        // 1. Mode
        self.mode
            .evaluate(&engagement_id, req.mode, technique.as_ref())?;

        // 2. Window
        self.window.evaluate(
            &engagement_id,
            technique_id,
            req.mode,
            req.now,
            req.change_window.as_ref(),
        )?;

        // 3. Approval (+ RoE for active modes)
        self.approval.evaluate(
            &engagement_id,
            technique_id,
            req.mode,
            &req.approvals,
            req.roe.as_ref(),
            req.now,
        )?;

        // 4. Kill switch
        self.kill_switch
            .evaluate(&engagement_id, technique_id)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::SafetyPipeline;
    use crate::error::BasError;
    use crate::model::approval::Approval;
    use crate::model::mode::AttackMode;
    use crate::model::simulation::{SimulationRequest, SimulationStepContext, StepResult};
    use crate::model::technique::{AttackTechnique, Capabilities, MitreTag};
    use crate::service::kill_switch_gate::{KillSwitchGate, KillSwitchPort, NotifyKillSwitchPort};
    use crate::technique::safe_ssrf_probe::SafeSsrfProbe;
    use async_trait::async_trait;
    use std::sync::Arc;
    use sx_core::value_object::ids::{EngagementId, TenantId, UserId};
    use time::{Duration, OffsetDateTime};

    /// In-test stub that lifts the `max_mode` ceiling to `ActiveExploit` so the
    /// pipeline's downstream gates (window, approval) actually get a chance to
    /// fire. The production crate intentionally exposes no concrete technique
    /// at this ceiling — see the safe-only invariant documented on
    /// [`AttackTechnique`].
    #[derive(Debug)]
    struct ActiveModeStub;

    #[async_trait]
    impl AttackTechnique for ActiveModeStub {
        fn id(&self) -> &'static str {
            "active_mode_test_stub_v1"
        }
        fn mitre(&self) -> MitreTag {
            MitreTag::new("TA0001", "T9999", None)
        }
        fn max_mode(&self) -> AttackMode {
            AttackMode::ActiveExploit
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::ANALYTICAL
        }
        async fn step(&self, _ctx: SimulationStepContext) -> Result<StepResult, BasError> {
            Ok(StepResult::Simulated {
                summary: "stub".to_owned(),
                details: std::collections::HashMap::new(),
            })
        }
    }

    fn pipeline() -> (SafetyPipeline, Arc<NotifyKillSwitchPort>) {
        let port = Arc::new(NotifyKillSwitchPort::new());
        let gate = KillSwitchGate::new(port.clone() as Arc<dyn KillSwitchPort>);
        (SafetyPipeline::new(gate), port)
    }

    fn request(mode: AttackMode, approvals: Vec<Approval>) -> SimulationRequest {
        SimulationRequest {
            tenant_id: TenantId::new(),
            engagement_id: EngagementId::new(),
            technique_id: "x".into(),
            mode,
            change_window: None,
            roe: None,
            approvals,
            now: OffsetDateTime::UNIX_EPOCH,
            deadline: OffsetDateTime::UNIX_EPOCH + Duration::seconds(30),
        }
    }

    #[tokio::test]
    async fn safety_pipeline_short_circuits_on_first_failure() {
        // SafeSsrfProbe declares max_mode = SafeInteractive, so running it
        // under Theoretical fires the MODE gate (1st gate) first. We make the
        // approval state also bad to prove only the FIRST failure surfaces.
        let (pipe, _port) = pipeline();
        let t: Arc<dyn AttackTechnique> = Arc::new(SafeSsrfProbe::new(
            "https://target.example".into(),
            "https://oob.example".into(),
        ));
        let mut req = request(AttackMode::Theoretical, Vec::new());
        req.mode = AttackMode::Theoretical;
        // Also break the approval gate (would only fire for active modes,
        // but proves we don't get past mode).
        req.approvals = Vec::new();
        let err = pipe.evaluate(&req, &t).await.unwrap_err();
        assert!(matches!(err, BasError::ModeViolation { .. }));
    }

    #[tokio::test]
    async fn safety_pipeline_passes_for_safe_technique_under_safe_mode() {
        let (pipe, _port) = pipeline();
        let t: Arc<dyn AttackTechnique> = Arc::new(SafeSsrfProbe::new(
            "https://target.example".into(),
            "https://oob.example".into(),
        ));
        let req = request(AttackMode::SafeInteractive, Vec::new());
        assert!(pipe.evaluate(&req, &t).await.is_ok());
    }

    #[tokio::test]
    async fn safety_pipeline_kill_switch_runs_last() {
        let (pipe, port) = pipeline();
        port.trip();
        let t: Arc<dyn AttackTechnique> = Arc::new(SafeSsrfProbe::new(
            "https://target.example".into(),
            "https://oob.example".into(),
        ));
        let req = request(AttackMode::SafeInteractive, Vec::new());
        let err = pipe.evaluate(&req, &t).await.unwrap_err();
        assert!(matches!(err, BasError::KillSwitchTripped(_)));
    }

    #[tokio::test]
    async fn safety_pipeline_approval_gate_active_exploit_needs_two() {
        // The mode gate must pass: only the in-test `ActiveModeStub` raises
        // `max_mode` to `ActiveExploit`. The window gate must pass: build a
        // window that bracket-contains `now`. The RoE check must pass at
        // `now`. With those upstream gates green, a single approver MUST
        // trigger the approval gate.
        let (pipe, _port) = pipeline();
        let t: Arc<dyn AttackTechnique> = Arc::new(ActiveModeStub);

        // Anchor `now` to a real wall-clock instant so the window-gate
        // semantics match production. The pipeline reads `req.now`, so the
        // fixture only needs the engagement window to contain it.
        let now = OffsetDateTime::now_utc();
        let start = now - Duration::minutes(5);
        let end = now + Duration::hours(1);

        let mut req = request(AttackMode::ActiveExploit, Vec::new());
        req.now = now;
        req.deadline = now + Duration::seconds(30);
        req.change_window = Some(crate::model::window::ChangeWindow::new(start, end).unwrap());
        req.roe = Some(
            crate::model::approval::RulesOfEngagement::new(
                UserId::new(),
                start,
                end + Duration::seconds(1),
            )
            .unwrap(),
        );
        // One approver under ActiveExploit -> approval gate denies.
        req.approvals = vec![Approval::new(UserId::new(), now)];
        let err = pipe.evaluate(&req, &t).await.unwrap_err();
        assert!(
            matches!(err, BasError::ApprovalsInsufficient { have: 1, need: 2 }),
            "expected approval-gate denial, got {err:?}"
        );

        // Two distinct approvers -> approval gate passes; pipeline overall
        // passes (kill switch is not tripped in this fixture).
        req.approvals = vec![
            Approval::new(UserId::new(), now),
            Approval::new(UserId::new(), now),
        ];
        assert!(pipe.evaluate(&req, &t).await.is_ok());
    }
}
