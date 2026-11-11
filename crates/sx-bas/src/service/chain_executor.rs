//! Sequential chain executor (P2-015).
//!
//! Runs every [`crate::model::chain::TechniqueRef`] in a
//! [`crate::model::chain::LateralChain`] sequentially via the existing
//! [`crate::controller::run_simulation::RunSimulationUseCase`].
//!
//! For each step we capture a [`crate::model::chain::ChainStepRecord`] with:
//!
//! - `technique_id` (registry id),
//! - `status` (success / failure / skipped),
//! - `evidence` (free-text summary; never carries payload material).
//!
//! Once a `kill_on_failure = true` step fails, the remainder of the chain
//! is recorded as [`crate::model::chain::ChainStepStatus::Skipped`] and the
//! run is marked [`crate::model::chain::ChainRunStatus::Failed`]. If the
//! kill switch fires partway through the run, the run is marked
//! [`crate::model::chain::ChainRunStatus::Aborted`].

use std::sync::Arc;

use time::OffsetDateTime;
use tracing::{info, warn};
use uuid::Uuid;

use crate::controller::run_simulation::RunSimulationUseCase;
use crate::error::BasError;
use crate::model::approval::Approval;
use crate::model::chain::{
    ChainRun, ChainRunStatus, ChainStepRecord, ChainStepStatus, LateralChain,
};
use crate::model::mode::AttackMode;
use crate::model::simulation::{SimulationOutcome, SimulationRequest, StepResult};
use sx_core::value_object::ids::{EngagementId, TenantId};

/// Per-run execution context.
///
/// Carries the tenant + engagement + active mode + per-step deadline +
/// approval ledger so each technique resolution shares one safety stance.
#[derive(Debug, Clone)]
pub struct ChainExecutionContext {
    /// Tenant under which the run executes.
    pub tenant_id: TenantId,
    /// Engagement that authorises the run.
    pub engagement_id: EngagementId,
    /// Operating mode ceiling for every step.
    pub mode: AttackMode,
    /// Now-instant the safety pipeline should use for window/RoE checks.
    pub now: OffsetDateTime,
    /// Per-step deadline.
    pub deadline: OffsetDateTime,
    /// Approver ledger forwarded to every step.
    pub approvals: Vec<Approval>,
}

/// Composes the [`RunSimulationUseCase`] into a sequential chain runner.
#[derive(Debug, Clone)]
pub struct ChainExecutor {
    use_case: Arc<RunSimulationUseCase>,
}

impl ChainExecutor {
    /// Construct an executor over a shared [`RunSimulationUseCase`].
    #[must_use]
    pub const fn new(use_case: Arc<RunSimulationUseCase>) -> Self {
        Self { use_case }
    }

    /// Execute every step in `chain` sequentially.
    ///
    /// Returns a [`ChainRun`] capturing the per-step ledger. The
    /// [`BasError`] return path is reserved for use-case-level errors that
    /// are not recoverable into a per-step `Failure` (the current
    /// implementation has none — every per-step error is converted into a
    /// `ChainStepStatus::Failure` record).
    // Linear orchestration plus three failure-handling arms; the apparent
    // complexity comes from the structured outcome match, not branching.
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    pub async fn run(
        &self,
        chain: &LateralChain,
        ctx: &ChainExecutionContext,
    ) -> Result<ChainRun, BasError> {
        let run_id = Uuid::new_v4().to_string();
        let started_at = format_rfc3339(ctx.now);

        info!(
            target = "sx_bas::chain_executor",
            chain_id = %chain.id,
            run_id = %run_id,
            engagement_id = %ctx.engagement_id,
            steps = chain.len(),
            "chain run starting",
        );

        let mut records: Vec<ChainStepRecord> = Vec::with_capacity(chain.len());
        let mut terminated = false;
        let mut aborted = false;
        let mut any_failure = false;

        for (idx, step) in chain.steps.iter().enumerate() {
            let step_index: u32 = u32::try_from(idx).unwrap_or(u32::MAX);

            if terminated || aborted {
                records.push(ChainStepRecord {
                    step_index,
                    technique_id: step.technique_id.clone(),
                    mitre_id: step.mitre_id.clone(),
                    status: ChainStepStatus::Skipped,
                    evidence: if aborted {
                        "skipped: chain aborted by kill switch".to_owned()
                    } else {
                        "skipped: prior step failed".to_owned()
                    },
                });
                continue;
            }

            let req = SimulationRequest {
                tenant_id: ctx.tenant_id,
                engagement_id: ctx.engagement_id,
                technique_id: step.technique_id.clone(),
                mode: ctx.mode,
                change_window: None,
                roe: None,
                approvals: ctx.approvals.clone(),
                now: ctx.now,
                deadline: ctx.deadline,
            };

            let record = match self.use_case.execute(req).await {
                Ok(SimulationOutcome::Simulated {
                    technique_id,
                    step: step_res,
                }) => {
                    let (status, evidence) = match step_res {
                        StepResult::Simulated { summary, .. }
                        | StepResult::Executed { summary } => (ChainStepStatus::Success, summary),
                        StepResult::Skipped { reason } => (
                            ChainStepStatus::Skipped,
                            format!("technique skipped: {reason}"),
                        ),
                    };
                    ChainStepRecord {
                        step_index,
                        technique_id,
                        mitre_id: step.mitre_id.clone(),
                        status,
                        evidence,
                    }
                }
                Ok(SimulationOutcome::Denied {
                    technique_id,
                    reason,
                }) => {
                    warn!(
                        target = "sx_bas::chain_executor",
                        chain_id = %chain.id,
                        run_id = %run_id,
                        technique_id = %technique_id,
                        reason = %reason,
                        "chain step denied by safety pipeline",
                    );
                    ChainStepRecord {
                        step_index,
                        technique_id,
                        mitre_id: step.mitre_id.clone(),
                        status: ChainStepStatus::Failure,
                        evidence: format!("denied: {reason}"),
                    }
                }
                Ok(SimulationOutcome::Killed { technique_id }) => {
                    warn!(
                        target = "sx_bas::chain_executor",
                        chain_id = %chain.id,
                        run_id = %run_id,
                        technique_id = %technique_id,
                        "chain step killed by kill switch; aborting remainder",
                    );
                    aborted = true;
                    ChainStepRecord {
                        step_index,
                        technique_id,
                        mitre_id: step.mitre_id.clone(),
                        status: ChainStepStatus::Failure,
                        evidence: "killed: kill switch tripped".to_owned(),
                    }
                }
                Err(e) => {
                    warn!(
                        target = "sx_bas::chain_executor",
                        chain_id = %chain.id,
                        run_id = %run_id,
                        technique_id = %step.technique_id,
                        reason = %e,
                        "chain step returned BasError",
                    );
                    ChainStepRecord {
                        step_index,
                        technique_id: step.technique_id.clone(),
                        mitre_id: step.mitre_id.clone(),
                        status: ChainStepStatus::Failure,
                        evidence: format!("error: {e}"),
                    }
                }
            };

            if matches!(record.status, ChainStepStatus::Failure) {
                any_failure = true;
                if step.kill_on_failure {
                    terminated = true;
                }
            }
            records.push(record);
        }

        let status = if aborted {
            ChainRunStatus::Aborted
        } else if any_failure {
            ChainRunStatus::Failed
        } else {
            ChainRunStatus::Completed
        };

        let finished_at = Some(format_rfc3339(OffsetDateTime::now_utc()));

        info!(
            target = "sx_bas::chain_executor",
            chain_id = %chain.id,
            run_id = %run_id,
            engagement_id = %ctx.engagement_id,
            status = ?status,
            "chain run finished",
        );

        Ok(ChainRun {
            run_id,
            tenant_id: ctx.tenant_id.to_string(),
            chain_id: chain.id.clone(),
            status,
            steps: records,
            started_at,
            finished_at,
        })
    }
}

fn format_rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::{ChainExecutionContext, ChainExecutor};
    use crate::controller::run_simulation::RunSimulationUseCase;
    use crate::model::chain::{
        canonical_chains, ChainRunStatus, ChainStepStatus, LateralChain, TechniqueRef,
    };
    use crate::model::mode::AttackMode;
    use crate::model::simulation::{SimulationStepContext, StepResult};
    use crate::model::technique::{AttackTechnique, Capabilities, MitreTag};
    use crate::service::kill_switch_gate::{KillSwitchGate, KillSwitchPort, NotifyKillSwitchPort};
    use crate::service::registry::TechniqueRegistry;
    use crate::service::safety_pipeline::SafetyPipeline;
    use async_trait::async_trait;
    use std::sync::Arc;
    use sx_core::value_object::ids::{EngagementId, TenantId};
    use time::{Duration, OffsetDateTime};

    /// Always-success mock technique. Records evidence and returns
    /// `StepResult::Simulated`.
    #[derive(Debug)]
    struct MockOk {
        id: &'static str,
    }

    #[async_trait]
    impl AttackTechnique for MockOk {
        fn id(&self) -> &'static str {
            self.id
        }
        fn mitre(&self) -> MitreTag {
            MitreTag::new("TA0008", "T9000", None)
        }
        fn max_mode(&self) -> AttackMode {
            AttackMode::Theoretical
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::ANALYTICAL
        }
        async fn step(
            &self,
            _ctx: SimulationStepContext,
        ) -> Result<StepResult, crate::error::BasError> {
            Ok(StepResult::Simulated {
                summary: format!("ok-{}", self.id),
                details: std::collections::HashMap::new(),
            })
        }
    }

    /// Always-fail mock technique. Returns a BasError.
    #[derive(Debug)]
    struct MockFail {
        id: &'static str,
    }

    #[async_trait]
    impl AttackTechnique for MockFail {
        fn id(&self) -> &'static str {
            self.id
        }
        fn mitre(&self) -> MitreTag {
            MitreTag::new("TA0008", "T9001", None)
        }
        fn max_mode(&self) -> AttackMode {
            AttackMode::Theoretical
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::ANALYTICAL
        }
        async fn step(
            &self,
            _ctx: SimulationStepContext,
        ) -> Result<StepResult, crate::error::BasError> {
            Err(crate::error::BasError::internal("boom"))
        }
    }

    fn ctx() -> ChainExecutionContext {
        ChainExecutionContext {
            tenant_id: TenantId::new(),
            engagement_id: EngagementId::new(),
            mode: AttackMode::Theoretical,
            now: OffsetDateTime::UNIX_EPOCH,
            deadline: OffsetDateTime::UNIX_EPOCH + Duration::seconds(30),
            approvals: Vec::new(),
        }
    }

    fn build_executor(techniques: Vec<Arc<dyn AttackTechnique>>) -> ChainExecutor {
        let mut registry = TechniqueRegistry::new();
        for t in techniques {
            registry.register(t).unwrap();
        }
        let port = Arc::new(NotifyKillSwitchPort::new());
        let gate = KillSwitchGate::new(port as Arc<dyn KillSwitchPort>);
        let pipeline = Arc::new(SafetyPipeline::new(gate));
        let uc = Arc::new(RunSimulationUseCase::new(Arc::new(registry), pipeline));
        ChainExecutor::new(uc)
    }

    #[tokio::test]
    async fn synthetic_chain_runs_every_step_in_order() {
        let executor = build_executor(vec![
            Arc::new(MockOk { id: "s1" }),
            Arc::new(MockOk { id: "s2" }),
            Arc::new(MockOk { id: "s3" }),
        ]);
        let chain = LateralChain::new(
            "test",
            "test-chain",
            "desc",
            vec![
                TechniqueRef::new("s1", "T0001", "Step1", true),
                TechniqueRef::new("s2", "T0002", "Step2", true),
                TechniqueRef::new("s3", "T0003", "Step3", false),
            ],
        );
        let run = executor.run(&chain, &ctx()).await.unwrap();
        assert_eq!(run.steps.len(), 3);
        assert_eq!(run.steps[0].step_index, 0);
        assert_eq!(run.steps[1].step_index, 1);
        assert_eq!(run.steps[2].step_index, 2);
        assert_eq!(run.steps[0].technique_id, "s1");
        assert_eq!(run.steps[1].technique_id, "s2");
        assert_eq!(run.steps[2].technique_id, "s3");
        for s in &run.steps {
            assert!(matches!(s.status, ChainStepStatus::Success));
            assert!(!s.evidence.is_empty(), "evidence must be captured");
        }
        assert!(matches!(run.status, ChainRunStatus::Completed));
    }

    #[tokio::test]
    async fn chain_terminates_on_kill_on_failure_step() {
        let executor = build_executor(vec![
            Arc::new(MockOk { id: "a" }),
            Arc::new(MockFail { id: "b" }),
            Arc::new(MockOk { id: "c" }),
        ]);
        let chain = LateralChain::new(
            "term",
            "term-chain",
            "desc",
            vec![
                TechniqueRef::new("a", "T1", "A", true),
                TechniqueRef::new("b", "T2", "B", true),
                TechniqueRef::new("c", "T3", "C", true),
            ],
        );
        let run = executor.run(&chain, &ctx()).await.unwrap();
        assert_eq!(run.steps.len(), 3);
        assert!(matches!(run.steps[0].status, ChainStepStatus::Success));
        assert!(matches!(run.steps[1].status, ChainStepStatus::Failure));
        assert!(matches!(run.steps[2].status, ChainStepStatus::Skipped));
        assert!(matches!(run.status, ChainRunStatus::Failed));
    }

    #[tokio::test]
    async fn chain_continues_past_best_effort_failure() {
        let executor = build_executor(vec![
            Arc::new(MockOk { id: "a" }),
            Arc::new(MockFail { id: "b" }),
            Arc::new(MockOk { id: "c" }),
        ]);
        let chain = LateralChain::new(
            "best",
            "best-effort",
            "desc",
            vec![
                TechniqueRef::new("a", "T1", "A", true),
                TechniqueRef::new("b", "T2", "B", false),
                TechniqueRef::new("c", "T3", "C", true),
            ],
        );
        let run = executor.run(&chain, &ctx()).await.unwrap();
        assert_eq!(run.steps.len(), 3);
        assert!(matches!(run.steps[0].status, ChainStepStatus::Success));
        assert!(matches!(run.steps[1].status, ChainStepStatus::Failure));
        assert!(matches!(run.steps[2].status, ChainStepStatus::Success));
        // The presence of any Failure marks the run Failed even though we
        // continued past it.
        assert!(matches!(run.status, ChainRunStatus::Failed));
    }

    #[tokio::test]
    async fn unknown_technique_id_records_failure() {
        let executor = build_executor(vec![Arc::new(MockOk { id: "known" })]);
        let chain = LateralChain::new(
            "miss",
            "missing",
            "desc",
            vec![TechniqueRef::new("nope", "T9999", "Missing", true)],
        );
        // The executor surfaces an unknown technique as a per-step Failure
        // record rather than propagating the BasError. This keeps the
        // run-level summary useful for replay/debugging.
        let run = executor.run(&chain, &ctx()).await.unwrap();
        assert_eq!(run.steps.len(), 1);
        assert!(matches!(run.steps[0].status, ChainStepStatus::Failure));
        assert!(run.steps[0].evidence.contains("technique not found"));
        assert!(matches!(run.status, ChainRunStatus::Failed));
    }

    #[test]
    fn canonical_chains_form_expected_shape() {
        let chains = canonical_chains();
        assert_eq!(chains.len(), 3);
        let ids: Vec<&str> = chains.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"ransomware_style_v1"));
        assert!(ids.contains(&"supply_chain_compromise_v1"));
        assert!(ids.contains(&"phishing_privesc_lateral_v1"));
    }
}
