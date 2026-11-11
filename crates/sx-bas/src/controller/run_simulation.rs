//! `RunSimulationUseCase` — the public entry point for executing a single
//! BAS technique under the four-gate safety pipeline.
//!
//! # Flow
//!
//! 1. Resolve the technique by id (lookup in the [`TechniqueRegistry`]).
//! 2. Run the [`SafetyPipeline`] (mode → window → approval → kill_switch).
//!    On denial, emit a denial trace and return
//!    [`SimulationOutcome::Denied`].
//! 3. Race the technique future against the kill-switch [`tokio::sync::Notify`]
//!    using `tokio::select!`. On kill, return [`SimulationOutcome::Killed`].
//! 4. Aggregate the [`StepResult`] into [`SimulationOutcome::Simulated`].

use std::sync::Arc;

use tracing::{info, warn};

use crate::error::BasError;
use crate::model::simulation::{
    EvidenceSink, InMemoryEvidenceSink, SimulationOutcome, SimulationRequest,
    SimulationStepContext, StepResult,
};
use crate::service::registry::TechniqueRegistry;
use crate::service::safety_pipeline::SafetyPipeline;

/// Composition of the registry + safety pipeline behind a single async entry
/// point.
#[derive(Debug, Clone)]
pub struct RunSimulationUseCase {
    registry: Arc<TechniqueRegistry>,
    pipeline: Arc<SafetyPipeline>,
    evidence_sink: Arc<dyn EvidenceSink>,
}

impl RunSimulationUseCase {
    /// Construct the use case with an in-memory evidence sink. Production
    /// composition roots replace the sink via
    /// [`RunSimulationUseCase::with_evidence_sink`].
    #[must_use]
    pub fn new(registry: Arc<TechniqueRegistry>, pipeline: Arc<SafetyPipeline>) -> Self {
        Self {
            registry,
            pipeline,
            evidence_sink: Arc::new(InMemoryEvidenceSink::new()),
        }
    }

    /// Construct with an explicit evidence sink.
    #[must_use]
    pub fn with_evidence_sink(
        registry: Arc<TechniqueRegistry>,
        pipeline: Arc<SafetyPipeline>,
        evidence_sink: Arc<dyn EvidenceSink>,
    ) -> Self {
        Self {
            registry,
            pipeline,
            evidence_sink,
        }
    }

    /// Returns a handle to the configured evidence sink (useful in tests).
    #[must_use]
    pub fn evidence_sink(&self) -> Arc<dyn EvidenceSink> {
        Arc::clone(&self.evidence_sink)
    }

    /// Execute the simulation.
    // Linear orchestration (resolve → safety pipeline → race → finalize); the
    // complexity comes from the structured tokio::select! arms, not branching.
    #[allow(clippy::cognitive_complexity)]
    pub async fn execute(&self, req: SimulationRequest) -> Result<SimulationOutcome, BasError> {
        // 1. Resolve.
        let technique = self
            .registry
            .get(&req.technique_id)
            .ok_or_else(|| BasError::TechniqueNotFound(req.technique_id.clone()))?;

        // 2. Safety pipeline.
        if let Err(e) = self.pipeline.evaluate(&req, &technique).await {
            warn!(
                target = "sx_bas::run_simulation",
                engagement_id = %req.engagement_id,
                technique_id = %technique.id(),
                reason = %e,
                "simulation denied by safety pipeline",
            );
            return Ok(SimulationOutcome::Denied {
                technique_id: technique.id().to_owned(),
                reason: e.to_string(),
            });
        }

        // 3. Race technique future against kill switch.
        let kill_signal = self.pipeline.kill_switch().signal();
        let ctx = SimulationStepContext {
            tenant_id: req.tenant_id,
            engagement_id: req.engagement_id,
            mode: req.mode,
            kill_switch_signal: Arc::clone(&kill_signal),
            deadline: req.deadline,
            evidence_sink: Arc::clone(&self.evidence_sink),
        };

        info!(
            target = "sx_bas::run_simulation",
            engagement_id = %req.engagement_id,
            technique_id = %technique.id(),
            mode = %req.mode,
            "executing technique step",
        );

        let step_future = technique.step(ctx);
        tokio::pin!(step_future);

        let outcome: SimulationOutcome = tokio::select! {
            biased;
            () = kill_signal.notified() => {
                warn!(
                    target = "sx_bas::run_simulation",
                    engagement_id = %req.engagement_id,
                    technique_id = %technique.id(),
                    "kill switch fired during step; aborting",
                );
                SimulationOutcome::Killed {
                    technique_id: technique.id().to_owned(),
                }
            }
            step_res = &mut step_future => {
                match step_res {
                    Ok(step) => SimulationOutcome::Simulated {
                        technique_id: technique.id().to_owned(),
                        step,
                    },
                    Err(e) => {
                        warn!(
                            target = "sx_bas::run_simulation",
                            engagement_id = %req.engagement_id,
                            technique_id = %technique.id(),
                            reason = %e,
                            "technique step returned error",
                        );
                        return Err(e);
                    }
                }
            }
        };

        // 4. Done.
        info!(
            target = "sx_bas::run_simulation",
            engagement_id = %req.engagement_id,
            technique_id = %technique.id(),
            outcome = ?std::mem::discriminant(&outcome),
            "simulation finished",
        );

        // Wire-back convenience for tests: ensure step compile-warns are
        // silenced for the `StepResult` re-export.
        let _ = StepResult::Skipped {
            reason: String::new(),
        };
        Ok(outcome)
    }
}

#[cfg(test)]
// `panic!` is used for explicit "unexpected variant" branches in match-on-enum
// assertions; `indexing_slicing` is fine on fixed-size test vectors.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::default_trait_access,
    clippy::match_wildcard_for_single_variants
)]
mod tests {
    use super::RunSimulationUseCase;
    use crate::model::approval::Approval;
    use crate::model::mode::AttackMode;
    use crate::model::simulation::{
        EvidenceSink, InMemoryEvidenceSink, SimulationOutcome, SimulationRequest, StepResult,
    };
    use crate::model::technique::{AttackTechnique, Capabilities, MitreTag};
    use crate::service::kill_switch_gate::{KillSwitchGate, KillSwitchPort, NotifyKillSwitchPort};
    use crate::service::registry::TechniqueRegistry;
    use crate::service::safety_pipeline::SafetyPipeline;
    use crate::technique::theoretical_reachability::TheoreticalReachability;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::time::Duration as StdDuration;
    use sx_core::value_object::ids::{EngagementId, TenantId};
    use time::{Duration, OffsetDateTime};
    use tokio::time::{timeout, Instant};

    fn build_use_case_with_kill_switch() -> (
        RunSimulationUseCase,
        Arc<NotifyKillSwitchPort>,
        Arc<InMemoryEvidenceSink>,
        TenantId,
        EngagementId,
    ) {
        let mut registry = TechniqueRegistry::new();
        let t = Arc::new(TheoreticalReachability::new(
            vec![("a".into(), "b".into())],
            "a".into(),
            None,
        ));
        registry.register(t).unwrap();
        let port = Arc::new(NotifyKillSwitchPort::new());
        let gate = KillSwitchGate::new(port.clone() as Arc<dyn KillSwitchPort>);
        let pipeline = Arc::new(SafetyPipeline::new(gate));
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let uc = RunSimulationUseCase::with_evidence_sink(
            Arc::new(registry),
            pipeline,
            sink.clone() as Arc<dyn EvidenceSink>,
        );
        (uc, port, sink, TenantId::new(), EngagementId::new())
    }

    fn req(tenant: TenantId, engagement: EngagementId, technique_id: &str) -> SimulationRequest {
        SimulationRequest {
            tenant_id: tenant,
            engagement_id: engagement,
            technique_id: technique_id.to_owned(),
            mode: AttackMode::Theoretical,
            change_window: None,
            roe: None,
            approvals: Vec::<Approval>::new(),
            now: OffsetDateTime::UNIX_EPOCH,
            deadline: OffsetDateTime::UNIX_EPOCH + Duration::seconds(30),
        }
    }

    #[tokio::test]
    async fn run_simulation_emits_evidence_for_simulated_outcome() {
        let (uc, _port, sink, t, e) = build_use_case_with_kill_switch();
        let outcome = uc
            .execute(req(t, e, "theoretical_reachability_v1"))
            .await
            .unwrap();
        match outcome {
            SimulationOutcome::Simulated { technique_id, step } => {
                assert_eq!(technique_id, "theoretical_reachability_v1");
                assert!(matches!(step, StepResult::Simulated { .. }));
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
        assert_eq!(sink.len().await, 1);
    }

    #[tokio::test]
    async fn run_simulation_returns_denied_for_unknown_technique_via_error() {
        let (uc, _port, _sink, t, e) = build_use_case_with_kill_switch();
        let err = uc.execute(req(t, e, "nope")).await.unwrap_err();
        assert!(matches!(err, crate::error::BasError::TechniqueNotFound(_)));
    }

    /// Cooperative-loop technique used by the SLA test. Loops in
    /// ~100ms ticks polling the kill-switch signal between ticks.
    #[derive(Debug)]
    struct LoopingTechnique;

    #[async_trait]
    impl AttackTechnique for LoopingTechnique {
        fn id(&self) -> &'static str {
            "looping_v1"
        }
        fn mitre(&self) -> MitreTag {
            MitreTag::new("TA0001", "T1190", None)
        }
        fn max_mode(&self) -> AttackMode {
            AttackMode::Theoretical
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::ANALYTICAL
        }
        async fn step(
            &self,
            ctx: crate::model::simulation::SimulationStepContext,
        ) -> Result<StepResult, crate::error::BasError> {
            // ~10 seconds worst-case; the use-case-level select! will abort
            // us long before. Includes per-iteration kill-switch poll.
            for _ in 0..100 {
                tokio::select! {
                    biased;
                    () = ctx.kill_switch_signal.notified() => {
                        return Err(crate::error::BasError::kill_switch("technique-poll"));
                    }
                    () = tokio::time::sleep(StdDuration::from_millis(100)) => {}
                }
            }
            Ok(StepResult::Simulated {
                summary: "done".into(),
                details: Default::default(),
            })
        }
    }

    fn build_uc_with(
        t: Arc<dyn AttackTechnique>,
    ) -> (
        RunSimulationUseCase,
        Arc<NotifyKillSwitchPort>,
        TenantId,
        EngagementId,
    ) {
        let mut registry = TechniqueRegistry::new();
        registry.register(t).unwrap();
        let port = Arc::new(NotifyKillSwitchPort::new());
        let gate = KillSwitchGate::new(port.clone() as Arc<dyn KillSwitchPort>);
        let pipeline = Arc::new(SafetyPipeline::new(gate));
        let uc = RunSimulationUseCase::new(Arc::new(registry), pipeline);
        (uc, port, TenantId::new(), EngagementId::new())
    }

    #[tokio::test]
    async fn run_simulation_returns_killed_when_kill_signal_arrives() {
        let (uc, port, t, e) = build_uc_with(Arc::new(LoopingTechnique));

        // Trip the switch ~50ms after start; race the result.
        let port_clone = port.clone();
        let trip_handle = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(50)).await;
            port_clone.trip();
        });

        let req = req(t, e, "looping_v1");
        let outcome = timeout(StdDuration::from_secs(3), uc.execute(req))
            .await
            .unwrap()
            .unwrap();
        trip_handle.await.unwrap();

        match outcome {
            SimulationOutcome::Killed { technique_id } => {
                assert_eq!(technique_id, "looping_v1");
            }
            other => panic!("expected Killed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn kill_switch_5s_sla_proven_by_in_process_test() {
        let (uc, port, t, e) = build_uc_with(Arc::new(LoopingTechnique));
        let started = Instant::now();

        let port_clone = port.clone();
        tokio::spawn(async move {
            // Trip immediately — we want the *gate* to deny up front, and we
            // also want to prove the in-flight select! arm responds quickly.
            tokio::time::sleep(StdDuration::from_millis(20)).await;
            port_clone.trip();
        });

        let req = req(t, e, "looping_v1");
        let outcome = uc.execute(req).await.unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < StdDuration::from_secs(5),
            "kill switch SLA breached: elapsed = {elapsed:?}",
        );
        // Either the gate denied (because the trip raced ahead of the
        // pipeline's kill-switch check) or the in-flight signal won the
        // race. Both are acceptable: both abort within the SLA.
        match outcome {
            SimulationOutcome::Killed { .. } | SimulationOutcome::Denied { .. } => {}
            other => panic!("expected Killed or Denied, got {other:?}"),
        }
    }
}
