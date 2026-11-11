//! BAS-backed implementation of `sx_autonomy::prelude::SimulationPort`.
//!
//! This adapter lives in the composition root (not in either crate) so that
//! `sx-autonomy` and `sx-bas` remain mutually independent:
//!
//! - `sx-autonomy` declares the narrow [`SimulationPort`] trait it needs
//!   (`async fn execute(tenant, engagement, technique_id) -> outcome`).
//! - `sx-bas` exposes the real safety-pipeline-fronted use case
//!   [`RunSimulationUseCase`].
//! - This module is the only place where the two crates meet — every
//!   production validation pass in `sx-autonomy::service::validation_engine`
//!   now flows through the four-gate BAS safety pipeline
//!   (mode → window → approval → kill_switch).
//!
//! # Mapping summary
//!
//! ## Request: autonomy → bas
//!
//! | autonomy port field             | bas `SimulationRequest` field   |
//! |---------------------------------|---------------------------------|
//! | `tenant_id` (`TenantId`)        | `tenant_id`                     |
//! | `engagement_id` (`EngagementId`)| `engagement_id`                 |
//! | `technique_id` (`String`)       | `technique_id`                  |
//! | implicit "safe default"         | `mode = AttackMode::Theoretical`|
//! | implicit "no window"            | `change_window = None`          |
//! | implicit "no RoE"               | `roe = None`                    |
//! | implicit "no approvals"         | `approvals = Vec::new()`        |
//! | now (`OffsetDateTime::now_utc`) | `now`                           |
//! | now + [`DEFAULT_DEADLINE`]      | `deadline`                      |
//!
//! The continuous-validation engine in `sx-autonomy` runs unattended on a
//! cron-like schedule. It deliberately does NOT carry mode/window/RoE in
//! its port: validation always runs at the safest mode
//! ([`AttackMode::Theoretical`]) so that no packets, no exploits, and no
//! real side effects are ever produced from the autonomy loop. Operators
//! who want destructive runs go through the human-driven BAS API instead.
//!
//! ## Response: bas → autonomy
//!
//! | `SimulationOutcome`                            | `SimulationPortOutcome::kind` |
//! |------------------------------------------------|-------------------------------|
//! | `Simulated { step: Simulated { summary, .. } }`| [`SimulationOutcomeKind::Pass`]   |
//! | `Simulated { step: Executed { summary } }`     | [`SimulationOutcomeKind::Pass`]   |
//! | `Simulated { step: Skipped { reason } }`       | [`SimulationOutcomeKind::Skipped`]|
//! | `Killed { .. }`                                | [`SimulationOutcomeKind::Killed`] |
//! | `Denied { reason, .. }`                        | [`SimulationOutcomeKind::Aborted`]|
//!
//! ## Errors: bas → autonomy
//!
//! | `BasError`                                  | `AutonomyError`                 |
//! |---------------------------------------------|---------------------------------|
//! | `KillSwitchTripped(_)`                      | `KillSwitchTripped`             |
//! | `TechniqueNotFound(id)`                     | `SimulatorError("technique not found: <id>")` |
//! | `ModeViolation { .. }`                      | `SimulatorError("mode violation: <display>")` |
//! | `OutsideChangeWindow`                       | `SimulatorError("outside change window")`     |
//! | `ApprovalsInsufficient { .. }`              | `SimulatorError("approvals insufficient: <display>")` |
//! | `RoeInvalid(m)`                             | `SimulatorError("roe invalid: <m>")`          |
//! | `ExecutionBlocked { reason }`               | `SimulatorError("execution blocked: <reason>")` |
//! | `InvalidInput(m)`                           | `SimulatorError("invalid input: <m>")`        |
//! | `DeadlineExceeded`                          | `SimulatorError("step deadline exceeded")`    |
//! | `DuplicateTechnique(id)`                    | `SimulatorError("duplicate technique: <id>")` |
//! | `Internal(m)`                               | `SimulatorError("internal: <m>")`             |
//!
//! Note: a [`SimulationOutcome::Denied`] is NOT an error from the use case's
//! perspective (it returns `Ok(Denied {..})`); the safety pipeline produced
//! a structured deny verdict. We surface this as
//! [`SimulationOutcomeKind::Aborted`] so the continuous validation report
//! records the deny and keeps the engine running for subsequent ticks.

use std::sync::Arc;

use async_trait::async_trait;
use sx_autonomy::error::AutonomyError;
use sx_autonomy::prelude::{SimulationOutcomeKind, SimulationPort, SimulationPortOutcome};
use sx_bas::controller::run_simulation::RunSimulationUseCase;
use sx_bas::error::BasError;
use sx_bas::model::mode::AttackMode;
use sx_bas::model::simulation::{SimulationOutcome, SimulationRequest, StepResult};
use sx_core::value_object::ids::{EngagementId, TenantId};
use time::{Duration, OffsetDateTime};
use tracing::{debug, warn};

/// Per-step deadline allowance for autonomy-triggered BAS runs.
///
/// Generous (60s) because the continuous validation engine targets
/// safe-only techniques whose worst-case work is bounded but may include
/// graph traversal over a large engagement scope. Should the technique
/// exceed this, BAS returns [`BasError::DeadlineExceeded`] which maps to
/// [`AutonomyError::SimulatorError`] and the engine records the failure
/// in the next [`sx_autonomy::prelude::ValidationReport`].
pub(crate) const DEFAULT_DEADLINE: Duration = Duration::seconds(60);

/// Adapter that fulfils the [`SimulationPort`] contract by delegating to
/// [`RunSimulationUseCase`].
///
/// Cloning is cheap — both fields are `Arc`-shared.
#[derive(Debug, Clone)]
pub(crate) struct BasSimulationAdapter {
    run_use_case: Arc<RunSimulationUseCase>,
}

impl BasSimulationAdapter {
    /// Construct a new adapter around the shared BAS use case.
    #[must_use]
    pub(crate) const fn new(run_use_case: Arc<RunSimulationUseCase>) -> Self {
        Self { run_use_case }
    }

    /// Build the [`SimulationRequest`] handed to [`RunSimulationUseCase::execute`].
    ///
    /// Factored out so tests can assert on the shape directly without
    /// having to round-trip through the real use case.
    fn build_request(
        tenant_id: TenantId,
        engagement_id: EngagementId,
        technique_id: String,
    ) -> SimulationRequest {
        let now = OffsetDateTime::now_utc();
        SimulationRequest {
            tenant_id,
            engagement_id,
            technique_id,
            // Autonomy loops always run at the safest mode. Promotion to a
            // higher mode is operator-driven and goes through the BAS HTTP
            // surface, never this adapter.
            mode: AttackMode::Theoretical,
            change_window: None,
            roe: None,
            approvals: Vec::new(),
            now,
            deadline: now + DEFAULT_DEADLINE,
        }
    }
}

#[async_trait]
impl SimulationPort for BasSimulationAdapter {
    async fn execute(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        technique_id: String,
    ) -> Result<SimulationPortOutcome, AutonomyError> {
        let request = Self::build_request(tenant_id, engagement_id, technique_id.clone());
        debug!(
            target = "adapters.bas_simulator",
            technique_id = %technique_id,
            mode = %request.mode,
            "delegating to RunSimulationUseCase",
        );
        match self.run_use_case.execute(request).await {
            Ok(outcome) => Ok(map_outcome(outcome)),
            Err(err) => {
                warn!(
                    target = "adapters.bas_simulator",
                    technique_id = %technique_id,
                    error = %err,
                    "bas use case returned error",
                );
                Err(map_error(err))
            }
        }
    }
}

/// Translate a successful [`SimulationOutcome`] into the autonomy port's
/// coarser [`SimulationPortOutcome`].
fn map_outcome(outcome: SimulationOutcome) -> SimulationPortOutcome {
    match outcome {
        SimulationOutcome::Simulated { technique_id, step } => match step {
            StepResult::Simulated { summary, .. } => SimulationPortOutcome::new(
                SimulationOutcomeKind::Pass,
                format!("{technique_id}: {summary}"),
            ),
            StepResult::Executed { summary } => SimulationPortOutcome::new(
                SimulationOutcomeKind::Pass,
                format!("{technique_id}: executed: {summary}"),
            ),
            StepResult::Skipped { reason } => SimulationPortOutcome::new(
                SimulationOutcomeKind::Skipped,
                format!("{technique_id}: skipped: {reason}"),
            ),
        },
        SimulationOutcome::Killed { technique_id } => SimulationPortOutcome::new(
            SimulationOutcomeKind::Killed,
            format!("{technique_id}: kill switch tripped"),
        ),
        SimulationOutcome::Denied {
            technique_id,
            reason,
        } => SimulationPortOutcome::new(
            SimulationOutcomeKind::Aborted,
            format!("{technique_id}: denied by safety pipeline: {reason}"),
        ),
    }
}

/// Translate a [`BasError`] into the autonomy port's [`AutonomyError`].
///
/// `KillSwitchTripped` is the only BAS error that has a dedicated
/// autonomy variant — every other variant is coarsened into
/// [`AutonomyError::SimulatorError`] with a `Display` form that preserves
/// the original cause. The autonomy continuous-validation engine reads the
/// message into the next [`sx_autonomy::prelude::ValidationReport`] under
/// the `Aborted` outcome.
fn map_error(err: BasError) -> AutonomyError {
    match err {
        BasError::KillSwitchTripped(_) => AutonomyError::KillSwitchTripped,
        other => AutonomyError::SimulatorError(other.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use sx_bas::model::simulation::{EvidenceSink, InMemoryEvidenceSink};
    use sx_bas::service::kill_switch_gate::{KillSwitchGate, KillSwitchPort, NotifyKillSwitchPort};
    use sx_bas::service::registry::TechniqueRegistry;
    use sx_bas::service::safety_pipeline::SafetyPipeline;
    use sx_bas::technique::theoretical_reachability::TheoreticalReachability;
    use sx_core::value_object::ids::{EngagementId, TenantId};
    use tokio::sync::Notify;

    /// Build a minimal `RunSimulationUseCase` registering one known-good
    /// technique (`theoretical_reachability_v1`) and a fresh in-memory
    /// evidence sink. Returns the use case + sink + port so individual
    /// tests can assert on side-effect counts and trip the kill switch.
    fn build_uc_with_good_technique() -> (
        Arc<RunSimulationUseCase>,
        Arc<InMemoryEvidenceSink>,
        Arc<NotifyKillSwitchPort>,
    ) {
        let mut registry = TechniqueRegistry::new();
        registry
            .register(Arc::new(TheoreticalReachability::new(
                vec![("a".into(), "b".into())],
                "a".into(),
                None,
            )))
            .unwrap();
        let port = Arc::new(NotifyKillSwitchPort::new());
        let gate = KillSwitchGate::new(Arc::clone(&port) as Arc<dyn KillSwitchPort>);
        let pipeline = Arc::new(SafetyPipeline::new(gate));
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let uc = Arc::new(RunSimulationUseCase::with_evidence_sink(
            Arc::new(registry),
            pipeline,
            Arc::clone(&sink) as Arc<dyn EvidenceSink>,
        ));
        (uc, sink, port)
    }

    /// `BasError::ExecutionBlocked`-emitting technique used to exercise the
    /// "safety-policy violation maps to the expected variant" path.
    ///
    /// This represents a technique that would violate safety policy when
    /// asked to run (e.g. a dangerous-execution path that is permanently
    /// disabled in this crate). The use case propagates the
    /// `ExecutionBlocked` error verbatim, which the adapter then folds into
    /// [`AutonomyError::SimulatorError`] with the original `Display` form
    /// preserved.
    #[derive(Debug)]
    struct SafetyBlockedTechnique;

    #[async_trait]
    impl sx_bas::model::technique::AttackTechnique for SafetyBlockedTechnique {
        fn id(&self) -> &'static str {
            "safety_blocked_v1"
        }
        fn mitre(&self) -> sx_bas::model::technique::MitreTag {
            sx_bas::model::technique::MitreTag::new("TA0001", "T1190", None)
        }
        fn max_mode(&self) -> AttackMode {
            AttackMode::Theoretical
        }
        fn capabilities(&self) -> sx_bas::model::technique::Capabilities {
            sx_bas::model::technique::Capabilities::ANALYTICAL
        }
        async fn step(
            &self,
            _ctx: sx_bas::model::simulation::SimulationStepContext,
        ) -> Result<StepResult, BasError> {
            Err(BasError::execution_blocked(
                "dangerous_execution permanently disabled",
            ))
        }
    }

    /// Technique that records whether `step` was called and asserts that
    /// the inbound context carries the safe `Theoretical` mode.
    ///
    /// Used by the "dry-run propagates / no side effects" test. The
    /// `recorded` flag flips iff `step` ran end-to-end without producing
    /// a real side effect.
    #[derive(Debug)]
    struct SpyTechnique {
        observed_mode: Arc<std::sync::Mutex<Option<AttackMode>>>,
        stepped: Arc<AtomicBool>,
    }

    #[async_trait]
    impl sx_bas::model::technique::AttackTechnique for SpyTechnique {
        fn id(&self) -> &'static str {
            "spy_v1"
        }
        fn mitre(&self) -> sx_bas::model::technique::MitreTag {
            sx_bas::model::technique::MitreTag::new("TA0001", "T1190", None)
        }
        fn max_mode(&self) -> AttackMode {
            AttackMode::Theoretical
        }
        fn capabilities(&self) -> sx_bas::model::technique::Capabilities {
            sx_bas::model::technique::Capabilities::ANALYTICAL
        }
        async fn step(
            &self,
            ctx: sx_bas::model::simulation::SimulationStepContext,
        ) -> Result<StepResult, BasError> {
            *self.observed_mode.lock().unwrap() = Some(ctx.mode);
            self.stepped.store(true, Ordering::SeqCst);
            // Crucially: we do NOT record any evidence here — the spy
            // simulates a side-effect-free technique to mirror the
            // dry-run contract.
            let _ = ctx.evidence_sink.clone();
            let _: Arc<Notify> = ctx.kill_switch_signal;
            let _ = ctx.deadline;
            let _ = ctx.tenant_id;
            let _ = ctx.engagement_id;
            Ok(StepResult::Simulated {
                summary: "spy ran".to_owned(),
                details: std::collections::HashMap::new(),
            })
        }
    }

    /// A known-good technique completes with `Ok(Pass)`.
    #[tokio::test]
    async fn bas_simulator_returns_success_for_valid_technique() {
        let (uc, sink, _port) = build_uc_with_good_technique();
        let adapter = BasSimulationAdapter::new(uc);

        let outcome = adapter
            .execute(
                TenantId::new(),
                EngagementId::new(),
                "theoretical_reachability_v1".to_owned(),
            )
            .await
            .expect("adapter ok");

        assert_eq!(outcome.kind, SimulationOutcomeKind::Pass);
        assert!(
            outcome.note.contains("theoretical_reachability_v1"),
            "note should include technique id, got: {note}",
            note = outcome.note,
        );
        // The technique emitted exactly one evidence record.
        assert_eq!(sink.len().await, 1);
    }

    /// A safety-policy violation (here: a `BasError::ExecutionBlocked`
    /// raised by the technique) maps to
    /// [`AutonomyError::SimulatorError`] with a message that names the
    /// underlying cause.
    #[tokio::test]
    async fn bas_simulator_maps_safety_block_error() {
        let mut registry = TechniqueRegistry::new();
        registry.register(Arc::new(SafetyBlockedTechnique)).unwrap();
        let port = Arc::new(NotifyKillSwitchPort::new());
        let gate = KillSwitchGate::new(Arc::clone(&port) as Arc<dyn KillSwitchPort>);
        let pipeline = Arc::new(SafetyPipeline::new(gate));
        let uc = Arc::new(RunSimulationUseCase::new(Arc::new(registry), pipeline));
        let adapter = BasSimulationAdapter::new(uc);

        let err = adapter
            .execute(
                TenantId::new(),
                EngagementId::new(),
                "safety_blocked_v1".to_owned(),
            )
            .await
            .expect_err("expected SimulatorError");

        match err {
            AutonomyError::SimulatorError(msg) => {
                assert!(
                    msg.contains("execution blocked"),
                    "expected message to mention 'execution blocked', got: {msg}",
                );
            }
            other => panic!("expected SimulatorError, got {other:?}"),
        }
    }

    /// The adapter passes the safest defaults through — the technique
    /// observes `mode = Theoretical` and produces no evidence-sink side
    /// effects beyond the technique's own emit.
    ///
    /// This is the "dry-run propagates through and produces no actual side
    /// effects" guarantee: the autonomy port has no `dry_run` field; the
    /// invariant the adapter upholds is that every autonomy-driven run
    /// targets `AttackMode::Theoretical` (no packets, no exploits).
    #[tokio::test]
    async fn bas_simulator_passes_dry_run_through() {
        let observed_mode: Arc<std::sync::Mutex<Option<AttackMode>>> =
            Arc::new(std::sync::Mutex::new(None));
        let stepped = Arc::new(AtomicBool::new(false));
        let spy = SpyTechnique {
            observed_mode: Arc::clone(&observed_mode),
            stepped: Arc::clone(&stepped),
        };
        let mut registry = TechniqueRegistry::new();
        registry.register(Arc::new(spy)).unwrap();
        let port = Arc::new(NotifyKillSwitchPort::new());
        let gate = KillSwitchGate::new(Arc::clone(&port) as Arc<dyn KillSwitchPort>);
        let pipeline = Arc::new(SafetyPipeline::new(gate));
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let uc = Arc::new(RunSimulationUseCase::with_evidence_sink(
            Arc::new(registry),
            pipeline,
            Arc::clone(&sink) as Arc<dyn EvidenceSink>,
        ));
        let adapter = BasSimulationAdapter::new(uc);

        let outcome = adapter
            .execute(TenantId::new(), EngagementId::new(), "spy_v1".to_owned())
            .await
            .expect("adapter ok");

        assert_eq!(outcome.kind, SimulationOutcomeKind::Pass);
        assert!(stepped.load(Ordering::SeqCst), "spy step must have run");
        assert_eq!(
            *observed_mode.lock().unwrap(),
            Some(AttackMode::Theoretical),
            "autonomy-driven runs must always be Theoretical (the safe-default)",
        );
        // No real side effects: the spy never wrote to the evidence sink.
        assert!(sink.is_empty().await, "spy must not have emitted evidence",);
    }

    /// A `BasError::KillSwitchTripped` returned by the use case maps to
    /// the dedicated [`AutonomyError::KillSwitchTripped`] variant — the
    /// engine treats this as a terminal state and halts the loop.
    #[test]
    fn map_error_kill_switch_translates_to_dedicated_variant() {
        let mapped = map_error(BasError::kill_switch("global"));
        assert!(matches!(mapped, AutonomyError::KillSwitchTripped));
    }

    /// Every other `BasError` collapses to `SimulatorError` carrying the
    /// original `Display` form.
    #[test]
    fn map_error_other_variants_collapse_to_simulator_error() {
        let cases = [
            BasError::TechniqueNotFound("x".into()),
            BasError::OutsideChangeWindow,
            BasError::DeadlineExceeded,
            BasError::RoeInvalid("expired".into()),
            BasError::execution_blocked("dangerous_execution disabled"),
            BasError::InvalidInput("nope".into()),
            BasError::ApprovalsInsufficient { have: 0, need: 2 },
            BasError::DuplicateTechnique("dup".into()),
            BasError::ModeViolation {
                technique_id: "x".into(),
                technique_max: AttackMode::RedTeam,
                active: AttackMode::Theoretical,
            },
            BasError::Internal("boom".into()),
        ];
        for case in cases {
            let display = case.to_string();
            match map_error(case) {
                AutonomyError::SimulatorError(msg) => {
                    assert_eq!(msg, display, "should preserve Display verbatim");
                }
                other => panic!("expected SimulatorError, got {other:?}"),
            }
        }
    }

    /// `Simulated`+`Simulated`/`Executed` map to `Pass`; `Skipped` to
    /// `Skipped`; `Killed` to `Killed`; `Denied` to `Aborted`.
    #[test]
    fn map_outcome_covers_every_variant() {
        let sim = map_outcome(SimulationOutcome::Simulated {
            technique_id: "t".into(),
            step: StepResult::Simulated {
                summary: "ok".into(),
                details: std::collections::HashMap::new(),
            },
        });
        assert_eq!(sim.kind, SimulationOutcomeKind::Pass);
        assert!(sim.note.contains("ok"));

        let exec = map_outcome(SimulationOutcome::Simulated {
            technique_id: "t".into(),
            step: StepResult::Executed {
                summary: "ran".into(),
            },
        });
        assert_eq!(exec.kind, SimulationOutcomeKind::Pass);

        let skip = map_outcome(SimulationOutcome::Simulated {
            technique_id: "t".into(),
            step: StepResult::Skipped {
                reason: "mode".into(),
            },
        });
        assert_eq!(skip.kind, SimulationOutcomeKind::Skipped);
        assert!(skip.note.contains("mode"));

        let kill = map_outcome(SimulationOutcome::Killed {
            technique_id: "t".into(),
        });
        assert_eq!(kill.kind, SimulationOutcomeKind::Killed);

        let denied = map_outcome(SimulationOutcome::Denied {
            technique_id: "t".into(),
            reason: "outside window".into(),
        });
        assert_eq!(denied.kind, SimulationOutcomeKind::Aborted);
        assert!(denied.note.contains("outside window"));
    }

    /// The translated request carries the safe defaults the adapter
    /// promises in its module docs.
    #[test]
    fn build_request_uses_safe_defaults() {
        let tenant = TenantId::new();
        let engagement = EngagementId::new();
        let req = BasSimulationAdapter::build_request(tenant, engagement, "spy_v1".to_owned());
        assert_eq!(req.tenant_id, tenant);
        assert_eq!(req.engagement_id, engagement);
        assert_eq!(req.technique_id, "spy_v1");
        assert_eq!(req.mode, AttackMode::Theoretical);
        assert!(req.change_window.is_none());
        assert!(req.roe.is_none());
        assert!(req.approvals.is_empty());
        assert!(
            req.deadline > req.now,
            "deadline must be strictly after now",
        );
    }
}
