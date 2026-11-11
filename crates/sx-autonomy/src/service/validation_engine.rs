//! Continuous validation engine.
//!
//! Schedules BAS techniques to run against a fixed engagement on a cron-like
//! interval and emits a [`crate::model::validation_report::ValidationReport`]
//! per run.
//!
//! # Wiring into `sx-bas`
//!
//! The engine consumes the simulator through the [`SimulationPort`] trait so
//! that this crate compiles independently of the `sx-bas` scaffold. A real
//! deployment wires the bas use case in as a one-method adapter:
//!
//! ```rust,ignore
//! struct BasSimAdapter(Arc<sx_bas::prelude::RunSimulationUseCase>);
//!
//! #[async_trait::async_trait]
//! impl sx_autonomy::prelude::SimulationPort for BasSimAdapter {
//!     async fn execute(
//!         &self,
//!         tenant_id: TenantId,
//!         engagement_id: EngagementId,
//!         technique_id: String,
//!     ) -> Result<SimulationPortOutcome, AutonomyError> {
//!         // Delegate to the sx-bas safety pipeline.
//!         // implementation calls into RunSimulationUseCase::execute
//!         unimplemented!()
//!     }
//! }
//! ```
//!
//! The adapter never bypasses the BAS safety pipeline. The engine itself
//! treats `Killed` as a terminal state and shuts down the loop.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use sx_core::value_object::ids::{EngagementId, TenantId};
use time::OffsetDateTime;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::error::AutonomyError;
use crate::model::schedule::Schedule;
use crate::model::validation_report::{TechniqueOutcome, ValidationOutcome, ValidationReport};

/// Coarse outcome bucket returned by a [`SimulationPort`].
///
/// This mirrors the subset of `sx_bas::prelude::SimulationOutcome` that the
/// continuous validation engine cares about, without coupling this crate's
/// compilation to `sx-bas`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationOutcomeKind {
    /// Technique completed; no compromise detected.
    Pass,
    /// Technique completed; compromise detected.
    Fail,
    /// Technique was halted by the kill switch.
    Killed,
    /// Technique aborted for any other safety-pipeline reason.
    Aborted,
    /// Technique skipped (e.g. mode-ladder violation).
    Skipped,
}

impl From<SimulationOutcomeKind> for ValidationOutcome {
    fn from(value: SimulationOutcomeKind) -> Self {
        match value {
            SimulationOutcomeKind::Pass => Self::Pass,
            SimulationOutcomeKind::Fail => Self::Fail,
            SimulationOutcomeKind::Killed => Self::Killed,
            SimulationOutcomeKind::Aborted => Self::Aborted,
            SimulationOutcomeKind::Skipped => Self::Skipped,
        }
    }
}

/// Outcome the port hands back per technique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationPortOutcome {
    /// Outcome bucket.
    pub kind: SimulationOutcomeKind,
    /// Short, secret-free note suitable for logs and the validation report.
    pub note: String,
}

impl SimulationPortOutcome {
    /// Build a new outcome.
    #[must_use]
    pub fn new(kind: SimulationOutcomeKind, note: impl Into<String>) -> Self {
        Self {
            kind,
            note: note.into(),
        }
    }
}

/// Narrow port the engine uses to invoke the BAS simulator without depending
/// on the `sx-bas` crate's still-in-progress controller layer.
#[async_trait]
pub trait SimulationPort: Send + Sync + std::fmt::Debug {
    /// Run a single technique against `(tenant_id, engagement_id)`.
    ///
    /// Implementations MUST delegate to the BAS safety pipeline (mode gate,
    /// approval gate, change-window gate, kill-switch gate). The engine will
    /// not call this method again for the same engagement once it observes
    /// [`SimulationOutcomeKind::Killed`].
    async fn execute(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        technique_id: String,
    ) -> Result<SimulationPortOutcome, AutonomyError>;
}

/// Sink that receives reports as the engine emits them.
#[async_trait]
pub trait ValidationReportSink: Send + Sync + std::fmt::Debug {
    /// Append a freshly-emitted report.
    async fn append(&self, report: ValidationReport) -> Result<(), AutonomyError>;
}

/// Handle returned by [`ContinuousValidationEngine::execute`].
#[derive(Debug)]
pub struct EngineHandle {
    join: Option<JoinHandle<()>>,
    shutdown: Arc<Notify>,
}

impl EngineHandle {
    /// Signal the engine to stop and wait for the spawned task to join.
    ///
    /// Uses [`Notify::notify_one`] (not `notify_waiters`) so that the
    /// shutdown signal is preserved as a permit when the engine task
    /// hasn't yet polled its `shutdown.notified()` future — this avoids
    /// a startup race where `shutdown()` is called before the spawned
    /// task has registered as a waiter.
    pub async fn shutdown(mut self) -> Result<(), AutonomyError> {
        self.shutdown.notify_one();
        if let Some(join) = self.join.take() {
            join.await
                .map_err(|e| AutonomyError::internal(format!("join: {e}")))?;
        }
        Ok(())
    }

    /// Borrow the shutdown notifier — useful in tests that want to trip the
    /// switch without consuming the handle.
    #[must_use]
    pub fn shutdown_signal(&self) -> Arc<Notify> {
        Arc::clone(&self.shutdown)
    }
}

/// Continuous validation engine.
///
/// Constructed with a fixed list of technique ids, a [`SimulationPort`], and
/// a [`ValidationReportSink`]. Once started, runs the configured technique
/// list once per schedule tick, forwarding each report to the sink. Stops on
/// either of:
///
/// - the [`EngineHandle::shutdown`] call (operator-initiated shutdown), or
/// - any per-technique outcome of [`SimulationOutcomeKind::Killed`] (engagement
///   kill switch tripped).
#[derive(Debug)]
pub struct ContinuousValidationEngine {
    schedule: Schedule,
    technique_ids: Vec<String>,
    simulator: Arc<dyn SimulationPort>,
    sink: Arc<dyn ValidationReportSink>,
}

impl ContinuousValidationEngine {
    /// Construct the engine.
    pub fn new(
        schedule: Schedule,
        technique_ids: Vec<String>,
        simulator: Arc<dyn SimulationPort>,
        sink: Arc<dyn ValidationReportSink>,
    ) -> Result<Self, AutonomyError> {
        if technique_ids.is_empty() {
            return Err(AutonomyError::invalid_input(
                "technique_ids must be non-empty",
            ));
        }
        Ok(Self {
            schedule,
            technique_ids,
            simulator,
            sink,
        })
    }

    /// Start the engine loop and return its handle.
    ///
    /// The loop:
    ///
    /// 1. Awaits one tick (or the shutdown signal — whichever fires first).
    /// 2. Runs every configured technique through the [`SimulationPort`].
    /// 3. Builds a [`ValidationReport`] and forwards it to the sink.
    /// 4. If any per-technique outcome was `Killed`, the loop terminates
    ///    cleanly without rescheduling.
    #[allow(clippy::unused_async)]
    pub async fn execute(
        self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
    ) -> Result<EngineHandle, AutonomyError> {
        let shutdown = Arc::new(Notify::new());
        let shutdown_for_task = Arc::clone(&shutdown);

        let Self {
            schedule,
            technique_ids,
            simulator,
            sink,
        } = self;

        let period = schedule.tick();
        let join = tokio::spawn(async move {
            run_loop(
                period,
                technique_ids,
                simulator,
                sink,
                tenant_id,
                engagement_id,
                shutdown_for_task,
            )
            .await;
        });

        Ok(EngineHandle {
            join: Some(join),
            shutdown,
        })
    }
}

/// The actual loop body, factored out for readability.
// Top-level scheduler loop: tokio::select! + interval ticking + shutdown
// inflate the complexity score, but the control flow is intentionally linear.
#[allow(clippy::cognitive_complexity)]
async fn run_loop(
    period: Duration,
    technique_ids: Vec<String>,
    simulator: Arc<dyn SimulationPort>,
    sink: Arc<dyn ValidationReportSink>,
    tenant_id: TenantId,
    engagement_id: EngagementId,
    shutdown: Arc<Notify>,
) {
    info!(period_secs = period.as_secs(), "validation engine started");
    let mut interval = tokio::time::interval(period);
    // The first `tick()` fires immediately. Skip it so callers see exactly
    // one report per `period`.
    interval.tick().await;

    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                info!("validation engine shutdown signal received");
                return;
            }
            _ = interval.tick() => {
                let killed = run_pass(
                    &technique_ids,
                    simulator.as_ref(),
                    sink.as_ref(),
                    tenant_id,
                    engagement_id,
                )
                .await;
                if killed {
                    warn!("validation engine halting: kill switch tripped");
                    return;
                }
            }
        }
    }
}

/// Run one full pass over the technique list. Returns `true` when the kill
/// switch tripped and the loop must stop.
// One iteration per technique with per-step kill-switch + sink + classification
// branches; cognitive complexity is inflated by per-branch trace logging.
#[allow(clippy::cognitive_complexity)]
async fn run_pass(
    technique_ids: &[String],
    simulator: &dyn SimulationPort,
    sink: &dyn ValidationReportSink,
    tenant_id: TenantId,
    engagement_id: EngagementId,
) -> bool {
    let started_at = OffsetDateTime::now_utc();
    let mut outcomes: Vec<TechniqueOutcome> = Vec::with_capacity(technique_ids.len());
    let mut killed = false;

    for id in technique_ids {
        match simulator
            .execute(tenant_id, engagement_id, id.clone())
            .await
        {
            Ok(out) => {
                if out.kind == SimulationOutcomeKind::Killed {
                    killed = true;
                }
                outcomes.push(TechniqueOutcome::new(
                    id.clone(),
                    ValidationOutcome::from(out.kind),
                    out.note,
                ));
                if killed {
                    break;
                }
            }
            Err(e) => {
                warn!(technique = %id, error = %e, "technique invocation failed");
                outcomes.push(TechniqueOutcome::new(
                    id.clone(),
                    ValidationOutcome::Aborted,
                    format!("error: {e}"),
                ));
            }
        }
    }

    let finished_at = OffsetDateTime::now_utc();
    let report = ValidationReport::new(
        tenant_id,
        engagement_id,
        started_at,
        finished_at,
        outcomes,
        killed,
    );
    if let Err(e) = sink.append(report).await {
        warn!(error = %e, "report sink rejected validation report");
    }
    debug!(killed, "validation pass complete");
    killed
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct CapturingSink {
        reports: Mutex<Vec<ValidationReport>>,
    }

    #[async_trait]
    impl ValidationReportSink for CapturingSink {
        async fn append(&self, report: ValidationReport) -> Result<(), AutonomyError> {
            self.reports
                .lock()
                .map_err(|e| AutonomyError::internal(format!("lock: {e}")))?
                .push(report);
            Ok(())
        }
    }

    impl CapturingSink {
        fn snapshot(&self) -> Vec<ValidationReport> {
            self.reports.lock().map(|g| g.clone()).unwrap_or_default()
        }
    }

    #[derive(Debug)]
    struct ScriptedSimulator {
        outcomes: Mutex<Vec<SimulationPortOutcome>>,
        /// Tracks how many times `execute` has returned. Tests wait
        /// for this count to reach the expected technique count before
        /// inspecting the captured report. Using an unbounded channel
        /// makes every individual call observable rather than relying
        /// on a single shared `Notify` (which collapses concurrent
        /// signals).
        done_tx: tokio::sync::mpsc::UnboundedSender<()>,
    }

    impl ScriptedSimulator {
        fn new(
            outcomes: Vec<SimulationPortOutcome>,
        ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            (
                Self {
                    outcomes: Mutex::new(outcomes),
                    done_tx: tx,
                },
                rx,
            )
        }
    }

    #[async_trait]
    impl SimulationPort for ScriptedSimulator {
        async fn execute(
            &self,
            _tenant_id: TenantId,
            _engagement_id: EngagementId,
            _technique_id: String,
        ) -> Result<SimulationPortOutcome, AutonomyError> {
            let out = {
                let mut g = self
                    .outcomes
                    .lock()
                    .map_err(|e| AutonomyError::internal(format!("lock: {e}")))?;
                if g.is_empty() {
                    SimulationPortOutcome::new(SimulationOutcomeKind::Pass, "default")
                } else {
                    g.remove(0)
                }
            };
            // Signal *after* releasing the lock so the test waiter
            // cannot race the next call. An unbounded mpsc means every
            // call to `execute` is observable, even if many fire back
            // to back inside a single `run_pass`.
            let _ = self.done_tx.send(());
            Ok(out)
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn validation_engine_runs_configured_techniques_once_then_stops_on_kill() {
        let (sim, mut done_rx) = ScriptedSimulator::new(vec![
            SimulationPortOutcome::new(SimulationOutcomeKind::Pass, "t1 ok"),
            SimulationPortOutcome::new(SimulationOutcomeKind::Killed, "kill switch"),
        ]);
        let sim = Arc::new(sim);
        let sink = Arc::new(CapturingSink::default());

        let engine = ContinuousValidationEngine::new(
            Schedule::from_interval(Duration::from_secs(1)).unwrap(),
            vec!["t1".into(), "t2".into()],
            sim.clone(),
            sink.clone(),
        )
        .unwrap();

        let handle = engine
            .execute(TenantId::new(), EngagementId::new())
            .await
            .unwrap();

        // Drive the engine's interval forward by one tick.
        tokio::time::advance(Duration::from_secs(2)).await;

        // Wait for both simulator calls (t1 Pass, then t2 Killed) to
        // complete. Each call sends one message on `done_rx`; a 5s
        // bounded wait surfaces hangs as test failures instead of
        // letting CI sit forever.
        for technique in ["t1", "t2"] {
            tokio::select! {
                biased;
                msg = done_rx.recv() => {
                    assert!(msg.is_some(), "channel closed before {technique} signal");
                }
                () = tokio::time::sleep(Duration::from_secs(5)) => {
                    panic!("scripted simulator did not fire its done signal for {technique}");
                }
            }
        }
        // Let the engine append the report and observe the kill.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        handle.shutdown().await.unwrap();

        let reports = sink.snapshot();
        assert_eq!(reports.len(), 1, "expected exactly one pass");
        let r = reports.first().expect("at least one report");
        assert!(r.killed, "report should be marked as killed");
        // t2 should be present as Killed, no further techniques attempted.
        assert_eq!(r.outcomes.len(), 2);
        assert_eq!(
            r.outcomes.first().expect("first outcome").outcome,
            ValidationOutcome::Pass
        );
        assert_eq!(
            r.outcomes.get(1).expect("second outcome").outcome,
            ValidationOutcome::Killed
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn validation_engine_pauses_on_kill_signal() {
        let (sim, _done_rx) = ScriptedSimulator::new(vec![]);
        let sim = Arc::new(sim);
        let sink = Arc::new(CapturingSink::default());

        let engine = ContinuousValidationEngine::new(
            Schedule::from_interval(Duration::from_secs(60)).unwrap(),
            vec!["t1".into()],
            sim,
            sink.clone(),
        )
        .unwrap();

        let handle = engine
            .execute(TenantId::new(), EngagementId::new())
            .await
            .unwrap();

        // Shut down before any tick fires.
        handle.shutdown().await.unwrap();
        assert!(
            sink.snapshot().is_empty(),
            "no reports should have been emitted before shutdown"
        );
    }
}
