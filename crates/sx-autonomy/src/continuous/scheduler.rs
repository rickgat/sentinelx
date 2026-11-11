//! 24/7 continuous attack simulator scheduler.
//!
//! [`ContinuousSimulator`] picks a fitting safe-mode technique from a
//! [`crate::redteam::selector::TechniqueCatalogue`] and dispatches it
//! through a [`crate::service::validation_engine::SimulationPort`]. It
//! is intended to be polled in a long-running loop — one invocation
//! corresponds to one prospective simulation, gated by:
//!
//! - the configured [`DailyBudget`] (refuses when the budget is
//!   exhausted), and
//! - the supplied [`KillSwitch`] (refuses when the operator has tripped
//!   the engagement-wide stop).
//!
//! The technique is chosen *fitness-first*: the catalogue is scanned
//! for safe-mode entries whose required intensity is within the
//! configured target spec; among those, a uniform random pick weighted
//! by `base_confidence` is taken via the provided RNG hook.
//!
//! # What this is *not*
//!
//! - Not a scheduler in the cron sense — caller decides cadence.
//! - Not coupled to `sx-bas` — uses the same narrow [`SimulationPort`]
//!   trait the validation engine does.
//! - Not concerned with reporting — `run_one` returns a small
//!   [`SimulationOutcome`] struct and the caller forwards it onward.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sx_core::value_object::ids::{EngagementId, TenantId};
use tracing::{debug, info, warn};

use crate::continuous::budget::{Clock, DailyBudget};
use crate::error::AutonomyError;
use crate::redteam::selector::{TargetSpec, TechniqueCatalogue, TechniqueEntry};
use crate::service::validation_engine::{
    SimulationOutcomeKind, SimulationPort, SimulationPortOutcome,
};

/// Outcome of a single continuous-simulator run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationOutcome {
    /// Technique id that was dispatched.
    pub technique_id: String,
    /// Outcome bucket from the underlying [`SimulationPort`].
    pub kind: SimulationOutcomeKind,
    /// Short, secret-free note from the simulator.
    pub note: String,
}

/// Pluggable RNG hook for the scheduler.
///
/// Used to break ties between equally-fitting candidates. The trait is
/// intentionally tiny so tests can drive deterministic picks without
/// pulling in `rand`'s trait surface.
pub trait SchedulerRng: Send {
    /// Return an integer in `[0, upper)`. Implementations must never
    /// return `upper` itself. When `upper == 0` the return value is
    /// unused but must not panic.
    fn gen_range(&mut self, upper: u32) -> u32;
}

/// Engagement-wide kill switch. Sharing an [`Arc<KillSwitch>`] between
/// the scheduler, the BAS pipeline, and the operator surface lets any
/// of them halt simulation activity within one poll cycle.
#[derive(Debug, Default)]
pub struct KillSwitch {
    tripped: AtomicBool,
}

impl KillSwitch {
    /// Build a kill switch in the initial (not-tripped) state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tripped: AtomicBool::new(false),
        }
    }

    /// Trip the kill switch. Idempotent.
    pub fn trip(&self) {
        self.tripped.store(true, Ordering::Release);
        warn!("continuous simulator kill switch tripped");
    }

    /// `true` when the switch is tripped.
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::Acquire)
    }
}

/// 24/7 continuous attack simulator.
///
/// Construct with a [`TechniqueCatalogue`], a [`DailyBudget`], a
/// [`Clock`], and a target spec. Each call to
/// [`ContinuousSimulator::run_one`] picks one technique and dispatches
/// it — returning `Some(outcome)` on dispatch, `None` when no run was
/// performed (budget exhausted, kill switch tripped, or no fitting
/// technique available).
#[derive(Debug)]
pub struct ContinuousSimulator<C: TechniqueCatalogue + Send + Sync + std::fmt::Debug> {
    catalogue: C,
    budget: Arc<DailyBudget>,
    clock: Arc<dyn Clock>,
    simulator: Arc<dyn SimulationPort>,
    kill_switch: Arc<KillSwitch>,
    target: TargetSpec,
    tenant_id: TenantId,
    engagement_id: EngagementId,
}

/// Engagement-scope wiring fed to [`ContinuousSimulator::new`]. Bundles
/// the fields that vary per engagement so the constructor stays under
/// the workspace-wide `too_many_arguments` ceiling.
#[derive(Debug)]
pub struct SimulatorEngagement {
    /// Tenant the simulator dispatches under.
    pub tenant_id: TenantId,
    /// Engagement the simulator dispatches under.
    pub engagement_id: EngagementId,
    /// Target spec used to filter the catalogue.
    pub target: TargetSpec,
}

impl SimulatorEngagement {
    /// Build a new engagement wiring.
    #[must_use]
    pub const fn new(tenant_id: TenantId, engagement_id: EngagementId, target: TargetSpec) -> Self {
        Self {
            tenant_id,
            engagement_id,
            target,
        }
    }
}

impl<C: TechniqueCatalogue + Send + Sync + std::fmt::Debug> ContinuousSimulator<C> {
    /// Build a new continuous simulator.
    #[must_use]
    pub fn new(
        catalogue: C,
        budget: Arc<DailyBudget>,
        clock: Arc<dyn Clock>,
        simulator: Arc<dyn SimulationPort>,
        kill_switch: Arc<KillSwitch>,
        engagement: SimulatorEngagement,
    ) -> Self {
        let SimulatorEngagement {
            tenant_id,
            engagement_id,
            target,
        } = engagement;
        Self {
            catalogue,
            budget,
            clock,
            simulator,
            kill_switch,
            target,
            tenant_id,
            engagement_id,
        }
    }

    /// Borrow the shared kill switch — useful for handing a single
    /// switch to multiple subsystems.
    #[must_use]
    pub fn kill_switch(&self) -> Arc<KillSwitch> {
        Arc::clone(&self.kill_switch)
    }

    /// Borrow the daily budget — useful for status surfaces.
    #[must_use]
    pub fn budget(&self) -> Arc<DailyBudget> {
        Arc::clone(&self.budget)
    }

    /// Try to dispatch one technique.
    ///
    /// Returns:
    /// - `Ok(Some(outcome))` — a fitting technique was picked, the
    ///   budget was acquired, and the [`SimulationPort`] returned.
    /// - `Ok(None)` — no dispatch happened because the kill switch is
    ///   tripped, the budget is exhausted, or no catalogue entry fit
    ///   the target.
    ///
    /// # Errors
    /// [`AutonomyError::SimulatorError`] when the underlying
    /// [`SimulationPort`] returns an error. Budget is *not* refunded
    /// in that case — the run was attempted.
    // Linear orchestration with discrete guard branches (kill switch,
    // candidates, picker, budget); each branch traces and returns.
    #[allow(clippy::cognitive_complexity)]
    pub async fn run_one<R: SchedulerRng>(
        &self,
        rng: &mut R,
    ) -> Result<Option<SimulationOutcome>, AutonomyError> {
        if self.kill_switch.is_tripped() {
            debug!("continuous simulator: kill switch tripped, skipping");
            return Ok(None);
        }

        let candidates = self.fitting_candidates();
        if candidates.is_empty() {
            debug!("continuous simulator: no fitting candidates");
            return Ok(None);
        }

        let pick = pick_weighted(&candidates, rng);
        let Some(entry) = pick else {
            debug!("continuous simulator: weighted picker returned nothing");
            return Ok(None);
        };

        if !self.budget.try_acquire(self.clock.as_ref()) {
            info!("continuous simulator: daily budget exhausted");
            return Ok(None);
        }

        let technique_id = entry.technique_id.to_owned();
        debug!(technique = %technique_id, "continuous simulator: dispatching");
        let outcome: SimulationPortOutcome = self
            .simulator
            .execute(self.tenant_id, self.engagement_id, technique_id.clone())
            .await
            .map_err(|e| AutonomyError::SimulatorError(e.to_string()))?;

        // A `Killed` outcome also trips the kill switch so subsequent
        // polls short-circuit without burning budget.
        if outcome.kind == SimulationOutcomeKind::Killed {
            self.kill_switch.trip();
        }

        Ok(Some(SimulationOutcome {
            technique_id,
            kind: outcome.kind,
            note: outcome.note,
        }))
    }

    fn fitting_candidates(&self) -> Vec<TechniqueEntry> {
        self.catalogue
            .entries()
            .iter()
            .copied()
            .filter(TechniqueEntry::is_safe_mode)
            .filter(|e| e.required_intensity <= self.target.max_intensity)
            .filter(|e| matches_target(&self.target, e))
            .collect()
    }
}

/// `true` when the entry is plausibly applicable to the target. Less
/// strict than the chain composer's scoring: we only need *some*
/// plausibility for the candidate to enter the weighted pool.
fn matches_target(target: &TargetSpec, entry: &TechniqueEntry) -> bool {
    if entry.needs_internet_facing && !target.internet_facing {
        return false;
    }
    if entry.platforms.is_empty() {
        return true;
    }
    entry
        .platforms
        .iter()
        .any(|p| target.platforms.iter().any(|tp| tp.eq_ignore_ascii_case(p)))
}

/// Weighted pick over `candidates` using `base_confidence * 1000` as
/// the weight (avoids floating-point sampling). When all weights are
/// zero the picker returns `None`. Deterministic when paired with a
/// deterministic [`SchedulerRng`].
fn pick_weighted<R: SchedulerRng>(
    candidates: &[TechniqueEntry],
    rng: &mut R,
) -> Option<TechniqueEntry> {
    if candidates.is_empty() {
        return None;
    }
    let weights: Vec<u32> = candidates.iter().map(weight_for).collect();
    let total: u32 = weights.iter().copied().sum();
    if total == 0 {
        return candidates.first().copied();
    }
    let mut pick = rng.gen_range(total);
    for (i, w) in weights.iter().enumerate() {
        if pick < *w {
            return candidates.get(i).copied();
        }
        pick -= *w;
    }
    candidates.last().copied()
}

/// `base_confidence * 1000` clamped to `[0, 1000]` and rounded down.
/// Lives outside `pick_weighted` so the cast lints can be silenced for
/// the smallest possible span.
fn weight_for(entry: &TechniqueEntry) -> u32 {
    let scaled = entry.base_confidence.clamp(0.0, 1.0) * 1000.0;
    // `scaled` is in `[0.0, 1000.0]`, so the cast is in-range. We
    // accept the truncation explicitly: the picker doesn't care about
    // sub-unit precision.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let w = scaled as u32;
    w
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::continuous::budget::FakeClock;
    use crate::redteam::chain::KillChainPhase;
    use crate::redteam::selector::EmbeddedCatalogue;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use sx_core::value_object::intensity::ScanIntensity;
    use time::macros::datetime;

    /// Deterministic RNG that emits the next value from a script.
    #[derive(Debug)]
    struct ScriptedRng {
        values: Mutex<Vec<u32>>,
    }

    impl ScriptedRng {
        fn new(values: Vec<u32>) -> Self {
            Self {
                values: Mutex::new(values),
            }
        }

        fn always_zero() -> Self {
            Self::new(vec![])
        }
    }

    impl SchedulerRng for ScriptedRng {
        fn gen_range(&mut self, upper: u32) -> u32 {
            let v = {
                let mut g = self.values.lock().unwrap();
                if g.is_empty() {
                    return 0;
                }
                g.remove(0)
            };
            if upper == 0 {
                0
            } else {
                v % upper
            }
        }
    }

    #[derive(Debug)]
    struct RecordingSimulator {
        outcome: SimulationPortOutcome,
        calls: Mutex<Vec<String>>,
    }

    impl RecordingSimulator {
        fn pass() -> Self {
            Self {
                outcome: SimulationPortOutcome::new(SimulationOutcomeKind::Pass, "ok"),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn killed() -> Self {
            Self {
                outcome: SimulationPortOutcome::new(SimulationOutcomeKind::Killed, "kill"),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SimulationPort for RecordingSimulator {
        async fn execute(
            &self,
            _tenant_id: TenantId,
            _engagement_id: EngagementId,
            technique_id: String,
        ) -> Result<SimulationPortOutcome, AutonomyError> {
            self.calls.lock().unwrap().push(technique_id);
            Ok(self.outcome.clone())
        }
    }

    fn make_simulator(
        rec: Arc<RecordingSimulator>,
        budget: Arc<DailyBudget>,
        clock: Arc<dyn Clock>,
        kill_switch: Arc<KillSwitch>,
    ) -> ContinuousSimulator<EmbeddedCatalogue> {
        let target = TargetSpec::new(["linux", "web"], true, ScanIntensity::SafeInteractive);
        ContinuousSimulator::new(
            EmbeddedCatalogue,
            budget,
            clock,
            rec as Arc<dyn SimulationPort>,
            kill_switch,
            SimulatorEngagement::new(TenantId::new(), EngagementId::new(), target),
        )
    }

    #[tokio::test]
    async fn picks_fitting_technique_within_budget() {
        let now = datetime!(2026-01-01 10:00:00 UTC);
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(now));
        let budget = Arc::new(DailyBudget::new(10, now).unwrap());
        let rec = Arc::new(RecordingSimulator::pass());
        let kill = Arc::new(KillSwitch::new());
        let sim = make_simulator(
            Arc::clone(&rec),
            Arc::clone(&budget),
            Arc::clone(&clock),
            Arc::clone(&kill),
        );

        let mut rng = ScriptedRng::always_zero();
        let out = sim.run_one(&mut rng).await.unwrap();
        assert!(
            out.is_some(),
            "should dispatch when budget+kill+catalogue OK"
        );
        let outcome = out.unwrap();
        assert_eq!(outcome.kind, SimulationOutcomeKind::Pass);
        assert_eq!(rec.calls().len(), 1);
        assert_eq!(budget.remaining(clock.as_ref()), 9);
    }

    #[tokio::test]
    async fn none_when_budget_exhausted() {
        let now = datetime!(2026-01-01 10:00:00 UTC);
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(now));
        let budget = Arc::new(DailyBudget::new(1, now).unwrap());
        let rec = Arc::new(RecordingSimulator::pass());
        let kill = Arc::new(KillSwitch::new());
        let sim = make_simulator(
            Arc::clone(&rec),
            Arc::clone(&budget),
            Arc::clone(&clock),
            Arc::clone(&kill),
        );

        let mut rng = ScriptedRng::always_zero();
        assert!(sim.run_one(&mut rng).await.unwrap().is_some());
        // Budget now 0.
        let next = sim.run_one(&mut rng).await.unwrap();
        assert!(next.is_none(), "exhausted budget must yield None");
        assert_eq!(rec.calls().len(), 1, "no extra dispatch when budget gone");
    }

    #[tokio::test]
    async fn none_when_kill_switch_tripped() {
        let now = datetime!(2026-01-01 10:00:00 UTC);
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(now));
        let budget = Arc::new(DailyBudget::new(10, now).unwrap());
        let rec = Arc::new(RecordingSimulator::pass());
        let kill = Arc::new(KillSwitch::new());
        kill.trip();
        let sim = make_simulator(
            Arc::clone(&rec),
            Arc::clone(&budget),
            Arc::clone(&clock),
            Arc::clone(&kill),
        );

        let mut rng = ScriptedRng::always_zero();
        let out = sim.run_one(&mut rng).await.unwrap();
        assert!(out.is_none(), "tripped kill switch must short-circuit");
        assert_eq!(rec.calls().len(), 0, "no dispatch when killed");
        assert_eq!(budget.remaining(clock.as_ref()), 10, "no budget burned");
    }

    #[tokio::test]
    async fn killed_outcome_trips_kill_switch() {
        let now = datetime!(2026-01-01 10:00:00 UTC);
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(now));
        let budget = Arc::new(DailyBudget::new(10, now).unwrap());
        let rec = Arc::new(RecordingSimulator::killed());
        let kill = Arc::new(KillSwitch::new());
        let sim = make_simulator(
            Arc::clone(&rec),
            Arc::clone(&budget),
            Arc::clone(&clock),
            Arc::clone(&kill),
        );

        let mut rng = ScriptedRng::always_zero();
        let out = sim.run_one(&mut rng).await.unwrap();
        let outcome = out.unwrap();
        assert_eq!(outcome.kind, SimulationOutcomeKind::Killed);
        assert!(kill.is_tripped(), "Killed outcome must trip switch");

        // Subsequent run should short-circuit.
        let next = sim.run_one(&mut rng).await.unwrap();
        assert!(next.is_none());
    }

    #[tokio::test]
    async fn picks_only_safe_mode_techniques() {
        let now = datetime!(2026-01-01 10:00:00 UTC);
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(now));
        let budget = Arc::new(DailyBudget::new(50, now).unwrap());
        let rec = Arc::new(RecordingSimulator::pass());
        let kill = Arc::new(KillSwitch::new());
        let sim = make_simulator(
            Arc::clone(&rec),
            Arc::clone(&budget),
            Arc::clone(&clock),
            Arc::clone(&kill),
        );

        let mut rng = ScriptedRng::new((0..50).collect());
        for _ in 0..20 {
            let _ = sim.run_one(&mut rng).await.unwrap();
        }
        for tid in rec.calls() {
            let entry = EmbeddedCatalogue::ENTRIES
                .iter()
                .find(|e| e.technique_id == tid)
                .expect("dispatched id must be in catalogue");
            assert!(
                entry.is_safe_mode(),
                "dispatched non-safe-mode technique {tid}"
            );
        }
    }

    #[test]
    fn matches_target_filters_internet_facing() {
        let target = TargetSpec::new(["linux"], false, ScanIntensity::SafeInteractive);
        let entry = TechniqueEntry {
            technique_id: "T-test",
            name: "test",
            phase: KillChainPhase::InitialAccess,
            base_confidence: 0.5,
            platforms: &[],
            needs_internet_facing: true,
            required_intensity: ScanIntensity::SafeInteractive,
        };
        assert!(!matches_target(&target, &entry));
    }

    #[test]
    fn weighted_picker_returns_some_when_total_positive() {
        let candidates = vec![TechniqueEntry {
            technique_id: "T-x",
            name: "x",
            phase: KillChainPhase::Reconnaissance,
            base_confidence: 0.5,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::PassiveValidation,
        }];
        let mut rng = ScriptedRng::always_zero();
        let pick = pick_weighted(&candidates, &mut rng);
        assert!(pick.is_some());
    }
}
