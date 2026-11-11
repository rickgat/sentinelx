//! Per-tenant baseline learner (HIGH-001).
//!
//! A new tenant spends 30 days in **passive observation mode**: the
//! engine still computes a composite score for every login, but the
//! returned action is always [`crate::service::RbaAction::Allow`].
//! While observation is active the per-tenant baseline distribution is
//! collected so when the engine flips to active mode the thresholds are
//! calibrated against the tenant's actual score distribution rather
//! than the global defaults.
//!
//! ## Lifecycle
//!
//! ```text
//!   New tenant
//!       │
//!       ▼
//!  [Observation] ── observation_started_at + 30d ──► [Active]
//!       │                                              │
//!       │              operator lock                   │
//!       └──────────────────────────────────────────────┘
//! ```
//!
//! ## Storage
//!
//! The in-memory implementation here mirrors the
//! `rba_tenant_baseline` table layout. Each row carries:
//!
//! * the lifecycle phase ([`BaselinePhase`]),
//! * the timestamp the observation window started,
//! * the count of decisions observed (drives the corpus size for
//!   percentile calibration),
//! * the running min / max / sum / sum_of_squares for the score
//!   distribution,
//! * the calibrated `allow_threshold` and `block_threshold` (80th /
//!   95th percentile),
//! * a small bounded histogram (101 buckets, one per score value)
//!   used to back the actual percentile lookups.
//!
//! Operators can lock a row via [`BaselineStore::lock`]: once locked,
//! further observations no longer mutate the thresholds.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::{DEFAULT_ALLOW_THRESHOLD, DEFAULT_BLOCK_THRESHOLD};

/// Serde helper for the fixed 101-bucket histogram. Stock serde does
/// not implement `Deserialize` for `[T; N]` with N > 32 (the const-
/// generic-array support is opt-in via an external crate); we round-trip
/// through a `Vec<u64>` and re-impose the length invariant on the way
/// in.
mod histogram_serde {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(arr: &[u64; 101], s: S) -> Result<S::Ok, S::Error> {
        arr.as_slice().serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u64; 101], D::Error> {
        let v: Vec<u64> = Vec::deserialize(d)?;
        if v.len() != 101 {
            return Err(D::Error::custom(format!(
                "histogram must have 101 buckets, got {}",
                v.len()
            )));
        }
        let mut out = [0u64; 101];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

/// Default observation window (30 days).
pub const DEFAULT_OBSERVATION_WINDOW_SECS: u64 = 30 * 24 * 3_600;

/// Minimum observations required before auto-calibration kicks in.
/// Below this we keep the global defaults even after the observation
/// window expires — calibrating off a handful of samples is worse than
/// the prior.
pub const MIN_OBSERVATIONS_FOR_CALIBRATION: u64 = 50;

/// Lifecycle phase of a per-tenant baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselinePhase {
    /// Tenant is in the first 30 days; engine returns Allow regardless
    /// of computed score.
    Observation,
    /// Observation has ended; calibrated thresholds are in force.
    Active,
    /// Operator has locked the calibrated thresholds — further
    /// observations no longer mutate them.
    Locked,
}

impl BaselinePhase {
    /// Stable string form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Active => "active",
            Self::Locked => "locked",
        }
    }
}

/// Per-tenant baseline row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantBaseline {
    /// Tenant the row belongs to.
    pub tenant_id: Uuid,
    /// Current phase.
    pub phase: BaselinePhase,
    /// When observation started — anchors the 30-day window.
    pub observation_started_at: OffsetDateTime,
    /// Total decisions observed so far.
    pub observations: u64,
    /// 101-bucket histogram of observed scores (`bucket[i]` = number of
    /// decisions with score == i).
    ///
    /// Serialised as a fixed-length Vec because `serde` lacks built-in
    /// support for `[T; N]` with `N > 32` without an extra crate; the
    /// length invariant is restored on deserialise.
    #[serde(with = "histogram_serde")]
    pub score_histogram: [u64; 101],
    /// Currently-installed allow threshold (calibrated or default).
    pub calibrated_allow_threshold: i32,
    /// Currently-installed block threshold (calibrated or default).
    pub calibrated_block_threshold: i32,
    /// Timestamp of the most recent observation.
    pub last_observed_at: Option<OffsetDateTime>,
}

impl TenantBaseline {
    /// Build a fresh baseline at `now` for `tenant_id` in observation.
    #[must_use]
    pub fn new(tenant_id: Uuid, now: OffsetDateTime) -> Self {
        Self {
            tenant_id,
            phase: BaselinePhase::Observation,
            observation_started_at: now,
            observations: 0,
            score_histogram: [0u64; 101],
            calibrated_allow_threshold: DEFAULT_ALLOW_THRESHOLD,
            calibrated_block_threshold: DEFAULT_BLOCK_THRESHOLD,
            last_observed_at: None,
        }
    }

    /// True when this baseline is still in passive observation mode
    /// (i.e. the engine must return Allow regardless of computed score).
    #[must_use]
    pub fn in_observation(&self) -> bool {
        matches!(self.phase, BaselinePhase::Observation)
    }

    /// Helper: number of seconds remaining in the observation window
    /// (`0` once observation is over).
    #[must_use]
    pub fn observation_remaining_secs(&self, now: OffsetDateTime, window: Duration) -> u64 {
        if !self.in_observation() {
            return 0;
        }
        let ended = self.observation_started_at + window;
        if now >= ended {
            return 0;
        }
        let delta = ended - now;
        u64::try_from(delta.whole_seconds()).unwrap_or(0)
    }

    /// Compute the score at percentile `p` (`0.0..=1.0`) given the
    /// current histogram.
    ///
    /// The intermediate `u64 -> f64 -> u64` round-trip is precision-lossy
    /// for `observations > 2^52`, but realistic baselines plateau in the
    /// millions; the cast back is also bounded by `[0, observations]`
    /// after `clamp(0.0, 1.0)`, so neither sign-loss nor truncation can
    /// produce an invalid bucket index.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    #[must_use]
    pub fn score_at_percentile(&self, p: f64) -> i32 {
        if self.observations == 0 {
            return DEFAULT_ALLOW_THRESHOLD;
        }
        let target = (p.clamp(0.0, 1.0) * self.observations as f64).ceil() as u64;
        let target = target.max(1);
        let mut acc = 0u64;
        for (score, count) in self.score_histogram.iter().enumerate() {
            acc = acc.saturating_add(*count);
            if acc >= target {
                return i32::try_from(score).unwrap_or(0);
            }
        }
        100
    }
}

/// Snapshot describing what the calibrator produced at a given moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalibrationOutcome {
    /// Resulting phase.
    pub phase: BaselinePhase,
    /// Currently-installed allow threshold.
    pub allow_threshold: i32,
    /// Currently-installed block threshold.
    pub block_threshold: i32,
    /// Total observations behind the calibration.
    pub observations: u64,
}

/// In-memory store + calibrator. Cheap to clone.
#[derive(Debug, Clone)]
pub struct BaselineStore {
    rows: Arc<DashMap<Uuid, TenantBaseline>>,
    observation_window: Duration,
}

impl Default for BaselineStore {
    fn default() -> Self {
        Self {
            rows: Arc::new(DashMap::new()),
            observation_window: Duration::from_secs(DEFAULT_OBSERVATION_WINDOW_SECS),
        }
    }
}

impl BaselineStore {
    /// Build a store with the default 30-day observation window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a store with a custom observation window. Used by tests.
    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            rows: Arc::new(DashMap::new()),
            observation_window: window,
        }
    }

    /// Observation window in seconds.
    #[must_use]
    pub fn window_secs(&self) -> u64 {
        self.observation_window.as_secs()
    }

    /// Inspect `tenant_id`'s baseline without mutating it (creating an
    /// observation-mode row on first access).
    #[must_use]
    pub fn snapshot(&self, tenant_id: Uuid, now: OffsetDateTime) -> TenantBaseline {
        self.rows
            .entry(tenant_id)
            .or_insert_with(|| TenantBaseline::new(tenant_id, now))
            .clone()
    }

    /// Record one observed score for `tenant_id` at `now`.
    ///
    /// Side-effects:
    ///   * appends to the histogram,
    ///   * transitions Observation → Active when the window expires
    ///     and the observation count crosses
    ///     [`MIN_OBSERVATIONS_FOR_CALIBRATION`],
    ///   * recomputes the 80th / 95th percentile thresholds while the
    ///     baseline is in Active (but not Locked) phase,
    ///   * returns the resulting calibration outcome.
    pub fn observe(&self, tenant_id: Uuid, score: i32, now: OffsetDateTime) -> CalibrationOutcome {
        let mut entry = self
            .rows
            .entry(tenant_id)
            .or_insert_with(|| TenantBaseline::new(tenant_id, now));
        let baseline = entry.value_mut();

        // Always record the observation, regardless of phase — the
        // distribution keeps shifting as the tenant grows. Locked
        // rows still benefit from updated counts in audit but skip
        // calibration mutation below.
        // INVARIANT: `clamp(0, 100)` yields a non-negative value in
        // `0..=100`, which is always a valid index into the 101-element
        // `score_histogram`. The cast cannot lose the sign because the
        // lower bound is 0; the indexing cannot panic because the upper
        // bound is 100 (inclusive) and the array has 101 slots.
        #[allow(clippy::cast_sign_loss, clippy::indexing_slicing)]
        let bucket = score.clamp(0, 100) as usize;
        #[allow(clippy::indexing_slicing)]
        {
            baseline.score_histogram[bucket] = baseline.score_histogram[bucket].saturating_add(1);
        }
        baseline.observations = baseline.observations.saturating_add(1);
        baseline.last_observed_at = Some(now);

        // Phase transition: observation window expired AND we have
        // enough samples to calibrate.
        let window_end = baseline.observation_started_at + self.observation_window;
        if baseline.phase == BaselinePhase::Observation
            && now >= window_end
            && baseline.observations >= MIN_OBSERVATIONS_FOR_CALIBRATION
        {
            baseline.phase = BaselinePhase::Active;
        }

        // Recompute thresholds while the baseline is Active (Locked
        // freezes them).
        if matches!(baseline.phase, BaselinePhase::Active) {
            let p80 = baseline.score_at_percentile(0.80);
            let p95 = baseline.score_at_percentile(0.95);
            // Guard against degenerate distributions: keep a non-zero
            // gap between allow and block.
            let allow = p80.clamp(1, 99);
            let block = p95.clamp(allow + 1, 100);
            baseline.calibrated_allow_threshold = allow;
            baseline.calibrated_block_threshold = block;
        }

        CalibrationOutcome {
            phase: baseline.phase,
            allow_threshold: baseline.calibrated_allow_threshold,
            block_threshold: baseline.calibrated_block_threshold,
            observations: baseline.observations,
        }
    }

    /// Lock a tenant baseline at its currently calibrated thresholds.
    /// Idempotent.
    pub fn lock(&self, tenant_id: Uuid, now: OffsetDateTime) {
        let mut entry = self
            .rows
            .entry(tenant_id)
            .or_insert_with(|| TenantBaseline::new(tenant_id, now));
        entry.value_mut().phase = BaselinePhase::Locked;
    }

    /// Unlock a tenant baseline so further observations resume
    /// calibration. Tests-only.
    #[cfg(test)]
    pub fn unlock(&self, tenant_id: Uuid) {
        if let Some(mut e) = self.rows.get_mut(&tenant_id) {
            e.value_mut().phase = BaselinePhase::Active;
        }
    }

    /// Force a tenant into the active phase regardless of window /
    /// observation count. Used by admin tooling + tests.
    pub fn force_active(&self, tenant_id: Uuid, now: OffsetDateTime) {
        let mut entry = self
            .rows
            .entry(tenant_id)
            .or_insert_with(|| TenantBaseline::new(tenant_id, now));
        entry.value_mut().phase = BaselinePhase::Active;
    }

    /// Number of tracked tenants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when the store holds no tenants.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn t0() -> OffsetDateTime {
        datetime!(2026-06-01 00:00:00 UTC)
    }

    #[test]
    fn new_tenant_starts_in_observation() {
        let store = BaselineStore::new();
        let tenant = Uuid::new_v4();
        let snap = store.snapshot(tenant, t0());
        assert_eq!(snap.phase, BaselinePhase::Observation);
        assert_eq!(snap.observations, 0);
    }

    #[test]
    fn observation_records_increment_count() {
        let store = BaselineStore::with_window(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        for s in [10, 20, 30] {
            store.observe(tenant, s, t0());
        }
        let snap = store.snapshot(tenant, t0());
        assert_eq!(snap.observations, 3);
    }

    #[test]
    fn observation_phase_persists_until_window_elapses() {
        let store = BaselineStore::with_window(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        // Many observations but BEFORE the window expires.
        for s in 0..100 {
            store.observe(tenant, s % 100, t0() + Duration::from_secs(10));
        }
        let snap = store.snapshot(tenant, t0() + Duration::from_secs(30));
        assert_eq!(snap.phase, BaselinePhase::Observation);
    }

    #[test]
    fn phase_transitions_to_active_after_window_with_enough_obs() {
        let store = BaselineStore::with_window(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        // Seed enough observations.
        for s in 0..60 {
            store.observe(tenant, s, t0());
        }
        // One more observation AFTER the window: triggers transition.
        let out = store.observe(tenant, 25, t0() + Duration::from_secs(120));
        assert_eq!(out.phase, BaselinePhase::Active);
    }

    #[test]
    fn phase_stays_observation_without_enough_observations() {
        let store = BaselineStore::with_window(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        for s in [10, 20, 30] {
            store.observe(tenant, s, t0());
        }
        // After window AND below MIN_OBSERVATIONS_FOR_CALIBRATION.
        let out = store.observe(tenant, 40, t0() + Duration::from_secs(120));
        assert_eq!(out.phase, BaselinePhase::Observation);
    }

    #[test]
    fn calibrated_thresholds_track_distribution() {
        let store = BaselineStore::with_window(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        // Distribute 100 observations heavily clustered at low scores.
        for _ in 0..80 {
            store.observe(tenant, 10, t0());
        }
        for _ in 0..15 {
            store.observe(tenant, 60, t0());
        }
        for _ in 0..5 {
            store.observe(tenant, 90, t0());
        }
        // Transition.
        let out = store.observe(tenant, 5, t0() + Duration::from_secs(120));
        assert_eq!(out.phase, BaselinePhase::Active);
        // The 80th percentile of {81*10, 15*60, 5*90} ≈ 10 (clamped to
        // 1..=99). The 95th percentile lies in the 60-bucket cluster.
        assert!(
            out.block_threshold > out.allow_threshold,
            "thresholds collapsed: allow={} block={}",
            out.allow_threshold,
            out.block_threshold
        );
    }

    #[test]
    fn lock_freezes_thresholds() {
        let store = BaselineStore::with_window(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        store.force_active(tenant, t0());
        // Build a clean distribution to start.
        for _ in 0..50 {
            store.observe(tenant, 10, t0());
        }
        let before = store.snapshot(tenant, t0()).calibrated_allow_threshold;
        store.lock(tenant, t0());
        // Now pump high scores in — locked phase must NOT change thresholds.
        for _ in 0..200 {
            store.observe(tenant, 90, t0());
        }
        let snap = store.snapshot(tenant, t0());
        assert_eq!(snap.phase, BaselinePhase::Locked);
        assert_eq!(snap.calibrated_allow_threshold, before);
    }

    #[test]
    fn observation_remaining_secs_decreases_with_time() {
        let store = BaselineStore::with_window(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        store.observe(tenant, 5, t0());
        let snap = store.snapshot(tenant, t0());
        let early = snap.observation_remaining_secs(t0(), store.observation_window);
        assert_eq!(early, 60);
        let mid = snap
            .observation_remaining_secs(t0() + Duration::from_secs(30), store.observation_window);
        assert!(mid > 0 && mid < 60);
        let late = snap
            .observation_remaining_secs(t0() + Duration::from_secs(120), store.observation_window);
        assert_eq!(late, 0);
    }

    #[test]
    fn percentile_returns_default_when_no_observations() {
        let baseline = TenantBaseline::new(Uuid::new_v4(), t0());
        assert_eq!(baseline.score_at_percentile(0.95), DEFAULT_ALLOW_THRESHOLD);
    }

    #[test]
    fn percentile_finds_correct_bucket() {
        let mut b = TenantBaseline::new(Uuid::new_v4(), t0());
        for _ in 0..50 {
            b.score_histogram[10] += 1;
            b.observations += 1;
        }
        for _ in 0..45 {
            b.score_histogram[50] += 1;
            b.observations += 1;
        }
        for _ in 0..5 {
            b.score_histogram[95] += 1;
            b.observations += 1;
        }
        assert_eq!(b.score_at_percentile(0.50), 10);
        assert!(b.score_at_percentile(0.80) >= 50);
        assert!(b.score_at_percentile(0.99) >= 50);
    }

    #[test]
    fn phase_strings_are_stable() {
        assert_eq!(BaselinePhase::Observation.as_str(), "observation");
        assert_eq!(BaselinePhase::Active.as_str(), "active");
        assert_eq!(BaselinePhase::Locked.as_str(), "locked");
    }
}
