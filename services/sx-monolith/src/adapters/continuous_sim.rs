//! 24/7 continuous attack simulator spawn helper.
//!
//! Spawns a long-running tokio task that polls a
//! [`sx_autonomy::continuous::scheduler::ContinuousSimulator`] on a
//! one-minute cadence. The job exits cleanly on
//! [`CancellationToken::cancelled`].
//!
//! ## Scope
//!
//! This helper is the composition-root scaffolding for the simulator:
//!
//! - The [`sx_autonomy::service::validation_engine::SimulationPort`]
//!   passed in is the real port — the monolith currently hands a stub
//!   that always returns `Pass` while the BAS simulator hookup is
//!   deferred to a follow-up phase.
//! - The [`sx_autonomy::continuous::scheduler::KillSwitch`] is built by
//!   the composition root (never tripped at boot).
//! - The [`sx_autonomy::redteam::selector::TechniqueCatalogue`] passed
//!   in is a stub. With an empty stub catalogue `run_one` returns
//!   `Ok(None)` on every tick — exactly the no-op behaviour we want
//!   while the wider wiring lands.
//!
//! ## Safety + logging
//!
//! - No `unwrap`/`expect`/`panic!` on production paths.
//! - The task never logs secrets — only the simulator-supplied
//!   `technique_id`, the outcome bucket, and the note (which the
//!   `SimulationPortOutcome` contract already requires to be
//!   secret-free).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use sx_autonomy::continuous::budget::{Clock, DailyBudget, SystemClock};
use sx_autonomy::continuous::scheduler::{
    ContinuousSimulator, KillSwitch, SchedulerRng, SimulatorEngagement,
};
use sx_autonomy::error::AutonomyError;
use sx_autonomy::redteam::selector::{TargetSpec, TechniqueCatalogue, TechniqueEntry};
use sx_autonomy::service::validation_engine::{
    SimulationOutcomeKind, SimulationPort, SimulationPortOutcome,
};
use sx_core::value_object::ids::{EngagementId, TenantId};
use sx_core::value_object::intensity::ScanIntensity;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Cadence between simulator polls.
const TICK_INTERVAL: Duration = Duration::from_secs(60);

/// Default daily run cap for the stub simulator. Generous enough that
/// the 1-minute cadence never burns through it in a single UTC day
/// (1440 ticks vs. 5000 budget), while still being a finite ceiling
/// so a misconfigured loop cannot exhaust resources unboundedly.
const STUB_DAILY_BUDGET: u32 = 5_000;

/// Empty stub catalogue used by [`build_stub_simulator`]. With no
/// entries, `ContinuousSimulator::run_one` deterministically returns
/// `Ok(None)` on every tick ("no fitting candidates"), which is the
/// safest behaviour while the real catalogue + BAS port hookup are
/// deferred to a follow-up phase.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StubCatalogue;

impl TechniqueCatalogue for StubCatalogue {
    fn entries(&self) -> &[TechniqueEntry] {
        &[]
    }
}

/// Stub [`SimulationPort`] that always reports a `Pass` outcome with
/// a fixed, secret-free note. Never reached while paired with
/// [`StubCatalogue`] (the empty catalogue short-circuits before
/// dispatch) — kept so the simulator wiring compiles end-to-end.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StubPassSimulationPort;

#[async_trait]
impl SimulationPort for StubPassSimulationPort {
    async fn execute(
        &self,
        _tenant_id: TenantId,
        _engagement_id: EngagementId,
        _technique_id: String,
    ) -> Result<SimulationPortOutcome, AutonomyError> {
        Ok(SimulationPortOutcome::new(
            SimulationOutcomeKind::Pass,
            "stub-pass",
        ))
    }
}

/// Build the stub [`ContinuousSimulator`] handed to [`spawn`] at
/// monolith boot.
///
/// The wiring uses:
///
/// - [`StubCatalogue`] — no entries, so every tick short-circuits to
///   `Ok(None)`.
/// - [`StubPassSimulationPort`] — never reached but supplied so the
///   constructor signature is satisfied.
/// - [`KillSwitch::new`] — initial (untripped) state.
/// - [`DailyBudget`] sized at [`STUB_DAILY_BUDGET`].
/// - [`SystemClock`] for the daily-rollover boundary.
///
/// # Errors
/// Propagates [`AutonomyError::InvalidInput`] when the daily budget
/// constant is misconfigured to `0`. The constant above is hard-coded
/// non-zero, so this branch is unreachable in practice — kept for
/// defence-in-depth.
pub(crate) fn build_stub_simulator(
) -> Result<Arc<ContinuousSimulator<StubCatalogue>>, AutonomyError> {
    let now = OffsetDateTime::now_utc();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let budget = Arc::new(DailyBudget::new(STUB_DAILY_BUDGET, now)?);
    let kill_switch = Arc::new(KillSwitch::new());
    let port: Arc<dyn SimulationPort> = Arc::new(StubPassSimulationPort);
    let target = TargetSpec::new(["linux"], true, ScanIntensity::SafeInteractive);
    let engagement = SimulatorEngagement::new(TenantId::new(), EngagementId::new(), target);
    Ok(Arc::new(ContinuousSimulator::new(
        StubCatalogue,
        budget,
        clock,
        port,
        kill_switch,
        engagement,
    )))
}

/// Adapter that bridges [`rand::rngs::StdRng`] onto the
/// [`SchedulerRng`] surface the simulator expects.
///
/// `StdRng::from_entropy` is invoked once per spawned task — the
/// adapter then owns the generator for the lifetime of the loop.
#[derive(Debug)]
struct StdRngAdapter {
    inner: StdRng,
}

impl StdRngAdapter {
    fn from_entropy() -> Self {
        Self {
            inner: StdRng::from_entropy(),
        }
    }
}

impl SchedulerRng for StdRngAdapter {
    fn gen_range(&mut self, upper: u32) -> u32 {
        if upper == 0 {
            return 0;
        }
        self.inner.gen_range(0..upper)
    }
}

/// Spawn the continuous-simulator loop.
///
/// Returns the [`JoinHandle`] so the composition root can store it
/// alongside the other background-job handles. The loop exits on
/// `shutdown.cancelled()`; otherwise it polls `simulator.run_one(...)`
/// every [`TICK_INTERVAL`] until the runtime drops the task.
pub(crate) fn spawn<C>(
    simulator: Arc<ContinuousSimulator<C>>,
    shutdown: CancellationToken,
) -> JoinHandle<()>
where
    C: TechniqueCatalogue + Send + Sync + std::fmt::Debug + 'static,
{
    tokio::spawn(async move {
        info!(
            target: "adapters.continuous_sim",
            interval_secs = TICK_INTERVAL.as_secs(),
            "continuous simulator loop started",
        );
        let mut rng = StdRngAdapter::from_entropy();
        let mut ticker = tokio::time::interval(TICK_INTERVAL);
        // First tick fires immediately by default; skip it so the rest
        // of `AppState` has time to settle before the first dispatch.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Burn the first tick.
        let _ = ticker.tick().await;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!(
                        target: "adapters.continuous_sim",
                        "continuous simulator received cancellation, exiting",
                    );
                    return;
                }
                _ = ticker.tick() => {
                    run_tick(simulator.as_ref(), &mut rng).await;
                }
            }
        }
    })
}

/// Execute one tick of the simulator. Pulled out so unit tests can
/// exercise the dispatch path without the spawn loop.
async fn run_tick<C, R>(simulator: &ContinuousSimulator<C>, rng: &mut R)
where
    C: TechniqueCatalogue + Send + Sync + std::fmt::Debug,
    R: SchedulerRng,
{
    match simulator.run_one(rng).await {
        Ok(Some(outcome)) => {
            debug!(
                target: "adapters.continuous_sim",
                technique_id = %outcome.technique_id,
                kind = ?outcome.kind,
                note = %outcome.note,
                "continuous simulator dispatched technique",
            );
        }
        Ok(None) => {
            debug!(
                target: "adapters.continuous_sim",
                "continuous simulator tick: no dispatch (kill switch / budget / no candidates)",
            );
        }
        Err(err) => {
            warn!(
                target: "adapters.continuous_sim",
                error = %err,
                "continuous simulator tick failed",
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_returns_join_handle_that_exits_on_cancel() {
        let sim = build_stub_simulator().expect("stub simulator must build");
        let token = CancellationToken::new();
        let handle = spawn(sim, token.clone());
        // Trip cancellation immediately. The loop must exit well within
        // the 60-second tick interval — we give it 2 seconds of slack.
        token.cancel();
        let outcome = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            outcome.is_ok(),
            "spawned task should exit within 2s of cancellation",
        );
        // The JoinHandle must complete successfully (no panic).
        let join_result = outcome.unwrap();
        assert!(join_result.is_ok(), "spawned task panicked");
    }

    #[tokio::test(start_paused = true)]
    async fn paused_clock_advance_drives_at_least_one_tick() {
        // With a paused tokio clock we can advance virtual time without
        // sleeping. The empty stub catalogue means `run_one` resolves to
        // `Ok(None)` — the test verifies the dispatch path is wired up
        // and the loop survives a tick before cancellation.
        let sim = build_stub_simulator().expect("stub simulator must build");
        let token = CancellationToken::new();
        let handle = spawn(Arc::clone(&sim), token.clone());

        // Burn the first interval (initial tick is consumed by the
        // spawn helper itself) and then one real tick.
        tokio::time::advance(TICK_INTERVAL).await;
        tokio::time::advance(TICK_INTERVAL).await;
        // Yield so the spawned task gets a chance to observe the ticks.
        tokio::task::yield_now().await;

        token.cancel();
        let outcome = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(outcome.is_ok(), "spawned task should exit after cancel");
    }

    #[test]
    fn std_rng_adapter_handles_zero_upper_without_panic() {
        let mut rng = StdRngAdapter::from_entropy();
        // Must not panic and must return 0.
        assert_eq!(rng.gen_range(0), 0);
    }

    #[test]
    fn std_rng_adapter_returns_value_below_upper() {
        let mut rng = StdRngAdapter::from_entropy();
        for _ in 0..32 {
            let v = rng.gen_range(10);
            assert!(v < 10, "value {v} must be strictly less than 10");
        }
    }

    #[tokio::test]
    async fn run_tick_handles_empty_catalogue_cleanly() {
        let sim = build_stub_simulator().expect("stub simulator must build");
        let mut rng = StdRngAdapter::from_entropy();
        // Should be a no-op: `Ok(None)` returns and is logged at DEBUG.
        run_tick(sim.as_ref(), &mut rng).await;
    }

    #[test]
    fn stub_catalogue_is_empty() {
        let cat = StubCatalogue;
        assert!(cat.entries().is_empty());
    }

    #[tokio::test]
    async fn stub_simulation_port_returns_pass() {
        let port = StubPassSimulationPort;
        let outcome = port
            .execute(TenantId::new(), EngagementId::new(), "T-stub".into())
            .await
            .expect("stub port must succeed");
        assert_eq!(outcome.kind, SimulationOutcomeKind::Pass);
    }
}
