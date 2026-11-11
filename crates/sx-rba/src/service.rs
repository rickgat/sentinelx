//! The [`RbaService`] — single front door to the engine.
//!
//! Callers (the IAM login flow at one end, the admin / dashboard
//! endpoints at the other) only ever see this type. It bundles:
//!
//! * Per-tenant configuration (via [`crate::config::RbaConfig`]),
//! * The three signal collectors,
//! * The pluggable [`crate::scorer::Scorer`],
//! * An in-memory ring buffer of recent decisions used to back
//!   `GET /v1/rba/decisions`.
//!
//! Every call to [`RbaService::evaluate`] audits regardless of action
//! — even an "allow" decision lands in the ring buffer so the SOC can
//! reconstruct the decision later.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot_min::Mutex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::baseline::{BaselinePhase, BaselineStore};
use crate::config::RbaConfig;
use crate::scorer::rule_based::RuleBasedScorer;
use crate::scorer::{Scorer, SignalContribution};
use crate::signals::business_hours::BusinessHoursStatus;
use crate::signals::device_fp::{
    DeviceFingerprintRow, DeviceFingerprintSignal, DeviceFingerprintStore,
    MemDeviceFingerprintLedger,
};
use crate::signals::impossible_travel::{
    ImpossibleTravelSignal, MemTravelStore, TravelStore, DEFAULT_MAX_SPEED_KMH,
};
use crate::signals::ip_geo::CountryDb;
use crate::signals::ip_geo_centroid::IpGeoCentroid;
use crate::signals::mfa_recent::{MfaRecentSignal, MfaRecentTracker};
use crate::signals::success_rate::{LoginHistory, SuccessRateSignal};
use crate::signals::velocity::VelocityTracker;

/// Minimum-feature parking_lot stand-in for the std `Mutex` — kept
/// inside the crate so we don't pull a heavy dep just for one usage.
mod parking_lot_min {
    pub(super) use std::sync::Mutex;
}

/// Default size of the decision ring buffer per tenant.
pub const DEFAULT_DECISION_RING_CAPACITY: usize = 500;

/// Hard cap on `limit` requested by the API. Prevents an admin from
/// pulling an unbounded list.
pub const MAX_DECISIONS_PER_REQUEST: usize = 500;

/// Errors raised by the [`RbaService`].
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RbaError {
    /// The supplied configuration failed validation.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// Internal failure.
    #[error("internal: {0}")]
    Internal(String),
}

/// Input bundle handed to [`RbaService::evaluate`].
#[derive(Debug, Clone)]
pub struct LoginContext {
    /// Tenant the user belongs to.
    pub tenant_id: Uuid,
    /// User id, if known at decision time. Failed credential lookups
    /// may pass `None`; the audit row records `NULL` in that case and
    /// the per-user signals (device fingerprint, MFA recency, success
    /// rate) are reported as their "unknown" sentinels.
    pub user_id: Option<Uuid>,
    /// Lower-cased email used as the velocity identity key.
    pub email: String,
    /// Caller IP. The IPv4 path is the only one resolved by the MVP
    /// geo table; IPv6 addresses fall through to "unknown country".
    pub ip: Ipv4Addr,
    /// Opaque device fingerprint (e.g. SHA-256 of a UA + cookie).
    /// Recorded on the audit row and resolved against the per-tenant
    /// fingerprint ledger (HIGH-001).
    pub device_fingerprint: Option<String>,
    /// Timestamp the login was observed at. Caller-supplied so unit
    /// tests don't need to pin the wall clock.
    pub observed_at: OffsetDateTime,
}

/// Action mapped from the composite score.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RbaAction {
    /// Allow without friction.
    Allow,
    /// Force a step-up MFA challenge.
    StepUpMfa,
    /// Block + alert SOC.
    Block,
}

impl RbaAction {
    /// Stable string form for SQL / JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::StepUpMfa => "step_up_mfa",
            Self::Block => "block",
        }
    }
}

/// Snapshot of every collected signal — handed to the scorer and
/// included verbatim on the decision audit row.
///
/// HIGH-001 added four signal fields (`device_fingerprint`,
/// `mfa_recent`, `success_rate`, `impossible_travel`). Existing callers
/// can keep them at `None`; the scorer falls back to the "unknown"
/// sub-scores, which remain risk-conservative.
#[derive(Debug, Clone, Default)]
pub struct SignalSnapshot {
    /// ISO-3166 alpha-2 country code (or the `XX` / `??` sentinels).
    pub country: Option<String>,
    /// Tenant's anchor country (the "trusted" geo). Reused by the
    /// scorer to award `0` for in-country logins.
    pub home_country: Option<String>,
    /// Count of attempts in the current sliding window (>= 1).
    pub velocity_window_count: usize,
    /// Result of the business-hours check, if available.
    pub business_hours_status: Option<BusinessHoursStatus>,
    /// Device fingerprint status (HIGH-001).
    pub device_fingerprint: Option<DeviceFingerprintSignal>,
    /// MFA recency signal (HIGH-001).
    pub mfa_recent: Option<MfaRecentSignal>,
    /// 7-day rolling success rate (HIGH-001).
    pub success_rate: Option<SuccessRateSignal>,
    /// Impossible-travel signal (HIGH-001).
    pub impossible_travel: Option<ImpossibleTravelSignal>,
}

impl SignalSnapshot {
    /// Project into a `HashMap<String, serde_json::Value>` suitable
    /// for the `signals` JSONB column.
    #[must_use]
    pub fn to_map(&self) -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        if let Some(c) = &self.country {
            m.insert("country".into(), serde_json::Value::String(c.clone()));
        }
        if let Some(h) = &self.home_country {
            m.insert("home_country".into(), serde_json::Value::String(h.clone()));
        }
        m.insert(
            "velocity_window_count".into(),
            serde_json::Value::from(self.velocity_window_count),
        );
        if let Some(b) = self.business_hours_status {
            if let Ok(v) = serde_json::to_value(b) {
                m.insert("business_hours".into(), v);
            }
        }
        if let Some(d) = &self.device_fingerprint {
            if let Ok(v) = serde_json::to_value(d) {
                m.insert("device_fingerprint".into(), v);
            }
        }
        if let Some(mfa) = &self.mfa_recent {
            if let Ok(v) = serde_json::to_value(mfa) {
                m.insert("mfa_recent".into(), v);
            }
        }
        if let Some(sr) = &self.success_rate {
            if let Ok(v) = serde_json::to_value(sr) {
                m.insert("success_rate".into(), v);
            }
        }
        if let Some(it) = &self.impossible_travel {
            if let Ok(v) = serde_json::to_value(it) {
                m.insert("impossible_travel".into(), v);
            }
        }
        m
    }
}

/// One emitted decision.
#[derive(Debug, Clone)]
pub struct RbaDecision {
    /// Unique decision id (suitable for primary-key use).
    pub id: Uuid,
    /// Tenant scope.
    pub tenant_id: Uuid,
    /// User id if known.
    pub user_id: Option<Uuid>,
    /// IP that triggered the decision.
    pub ip: Ipv4Addr,
    /// Composite score in `[0, 100]`.
    pub score: i32,
    /// Mapped action. While the tenant is in passive-observation phase
    /// this is forced to [`RbaAction::Allow`] regardless of `score`.
    pub action: RbaAction,
    /// Per-signal JSON bundle (the same map persisted as `signals` in
    /// the audit table).
    pub signals: HashMap<String, serde_json::Value>,
    /// Full snapshot of every collected signal — recorded verbatim so
    /// the SOC can replay the decision later (HIGH-001 audit
    /// requirement).
    pub snapshot: SignalSnapshot,
    /// Per-signal sub-score / weight / weighted contribution
    /// breakdown (LOW-007). Empty if every signal was disabled (the
    /// scorer omits zero-weight rows). Persisted into the
    /// `rba_decisions.signal_contributions` JSONB column.
    pub signal_contributions: Vec<SignalContribution>,
    /// Human-readable reason emitted by the scorer.
    pub reason: String,
    /// Per-tenant baseline phase the decision was made under.
    pub baseline_phase: BaselinePhase,
    /// Time the decision was made.
    pub decided_at: OffsetDateTime,
}

/// Same as [`RbaDecision`] but trimmed for the audit listing view.
///
/// LOW-007: this row now carries `signal_contributions`, the per-signal
/// breakdown produced by the scorer. The wire DTO
/// (`sx_api::view::rba_view::RbaDecisionView`) only surfaces it to
/// callers carrying the `admin:users` capability — the engine's
/// `DecisionAudit` itself is always fully populated so the in-process
/// caller is free to decide whether to redact downstream.
#[derive(Debug, Clone)]
pub struct DecisionAudit {
    /// Decision id.
    pub id: Uuid,
    /// Tenant.
    pub tenant_id: Uuid,
    /// User id, if known.
    pub user_id: Option<Uuid>,
    /// IP.
    pub ip: Ipv4Addr,
    /// Composite score.
    pub score: i32,
    /// Action string (`allow` / `step_up_mfa` / `block`).
    pub action: String,
    /// Reason.
    pub reason: String,
    /// Per-signal sub-score / weight / weighted contribution
    /// breakdown (LOW-007). Empty when every signal was disabled.
    pub signal_contributions: Vec<SignalContribution>,
    /// Wall-clock time.
    pub decided_at: OffsetDateTime,
}

impl From<&RbaDecision> for DecisionAudit {
    fn from(d: &RbaDecision) -> Self {
        Self {
            id: d.id,
            tenant_id: d.tenant_id,
            user_id: d.user_id,
            ip: d.ip,
            score: d.score,
            action: d.action.as_str().to_owned(),
            reason: d.reason.clone(),
            signal_contributions: d.signal_contributions.clone(),
            decided_at: d.decided_at,
        }
    }
}

/// Ring buffer of recent decisions, one ring per tenant.
#[derive(Debug, Default)]
struct DecisionRing {
    items: Vec<RbaDecision>,
    capacity: usize,
}

impl DecisionRing {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity.min(64)),
            capacity,
        }
    }

    fn push(&mut self, d: RbaDecision) {
        if self.items.len() >= self.capacity && !self.items.is_empty() {
            let _ = self.items.remove(0);
        }
        self.items.push(d);
    }

    fn recent(&self, limit: usize) -> Vec<DecisionAudit> {
        self.items
            .iter()
            .rev()
            .take(limit)
            .map(DecisionAudit::from)
            .collect()
    }
}

/// Front-door service. Cheap to clone (`Arc` internally).
#[derive(Clone)]
pub struct RbaService {
    inner: Arc<RbaInner>,
}

struct RbaInner {
    geo: CountryDb,
    geo_centroid: IpGeoCentroid,
    velocity: VelocityTracker,
    scorer: Arc<dyn Scorer>,
    configs: DashMap<Uuid, RbaConfig>,
    decisions: DashMap<Uuid, Mutex<DecisionRing>>,
    default_home_country: String,
    ring_capacity: usize,
    // HIGH-001 collectors + state.
    //
    // `fingerprints` was originally the concrete in-memory ledger;
    // LOW-004 extracted the [`DeviceFingerprintStore`] trait so the
    // composition root can install either `MemDeviceFingerprintLedger`
    // (tests) or `PgDeviceFingerprintLedger` (production) without the
    // engine knowing which it has. The pointer is `Arc<dyn ...>` to
    // keep the service cheap to clone.
    fingerprints: Arc<dyn DeviceFingerprintStore>,
    mfa_recent: MfaRecentTracker,
    login_history: LoginHistory,
    travel: Arc<dyn TravelStore>,
    baseline: BaselineStore,
}

impl std::fmt::Debug for RbaService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RbaService")
            .field("ring_capacity", &self.inner.ring_capacity)
            .field("default_home_country", &self.inner.default_home_country)
            .finish_non_exhaustive()
    }
}

impl Default for RbaService {
    fn default() -> Self {
        Self::with_scorer(Arc::new(RuleBasedScorer))
    }
}

impl RbaService {
    /// Build a service with the given scorer.
    ///
    /// Both pluggable backing stores default to their in-memory impls:
    /// [`MemDeviceFingerprintLedger`] for the device-fingerprint ledger
    /// (LOW-004) and [`MemTravelStore`] for the impossible-travel
    /// last-sighting ledger (LOW-005). Production callers should reach
    /// for [`Self::with_scorer_and_stores`] so a `sx-monolith` restart
    /// does not flush either ledger.
    #[must_use]
    pub fn with_scorer(scorer: Arc<dyn Scorer>) -> Self {
        Self::with_scorer_and_stores(
            scorer,
            Arc::new(MemDeviceFingerprintLedger::new()),
            Arc::new(MemTravelStore::new()),
        )
    }

    /// LOW-004 composition-root entry point: scorer + device-fingerprint
    /// store injected, travel store defaulted to in-memory. Kept as a
    /// stable shape for callers that only need to override the
    /// fingerprint ledger.
    #[must_use]
    pub fn with_scorer_and_fingerprints(
        scorer: Arc<dyn Scorer>,
        fingerprints: Arc<dyn DeviceFingerprintStore>,
    ) -> Self {
        Self::with_scorer_and_stores(scorer, fingerprints, Arc::new(MemTravelStore::new()))
    }

    /// LOW-005 composition-root entry point: scorer + travel store
    /// injected, fingerprint store defaulted to in-memory. Symmetric to
    /// [`Self::with_scorer_and_fingerprints`].
    #[must_use]
    pub fn with_scorer_and_travel_store(
        scorer: Arc<dyn Scorer>,
        travel: Arc<dyn TravelStore>,
    ) -> Self {
        Self::with_scorer_and_stores(scorer, Arc::new(MemDeviceFingerprintLedger::new()), travel)
    }

    /// Master constructor — scorer + both persistent stores injected.
    /// Production wiring uses this so both the device-fingerprint
    /// ledger (LOW-004) and the impossible-travel last-sighting ledger
    /// (LOW-005) survive a process restart.
    #[must_use]
    pub fn with_scorer_and_stores(
        scorer: Arc<dyn Scorer>,
        fingerprints: Arc<dyn DeviceFingerprintStore>,
        travel: Arc<dyn TravelStore>,
    ) -> Self {
        Self {
            inner: Arc::new(RbaInner {
                geo: CountryDb::default(),
                geo_centroid: IpGeoCentroid::default(),
                velocity: VelocityTracker::default(),
                scorer,
                configs: DashMap::new(),
                decisions: DashMap::new(),
                default_home_country: "US".to_owned(),
                ring_capacity: DEFAULT_DECISION_RING_CAPACITY,
                fingerprints,
                mfa_recent: MfaRecentTracker::new(),
                login_history: LoginHistory::new(),
                travel,
                baseline: BaselineStore::new(),
            }),
        }
    }

    /// Build a service with the default scorer + an injected travel
    /// store. Equivalent to [`Self::with_scorer_and_travel_store`] with
    /// the rule-based scorer pre-filled — convenient from tests and
    /// from the composition root when only the travel store changes.
    #[must_use]
    pub fn with_travel_store(travel: Arc<dyn TravelStore>) -> Self {
        Self::with_scorer_and_travel_store(Arc::new(RuleBasedScorer), travel)
    }

    /// Borrow the underlying [`VelocityTracker`] — used by tests.
    #[must_use]
    pub fn velocity(&self) -> &VelocityTracker {
        &self.inner.velocity
    }

    /// Borrow the underlying [`CountryDb`] — used by tests.
    #[must_use]
    pub fn geo(&self) -> &CountryDb {
        &self.inner.geo
    }

    /// Borrow the underlying [`DeviceFingerprintStore`] trait object.
    ///
    /// Returned as a reference to a trait object so tests that hold a
    /// `Mem...Ledger` directly and the production wiring (which holds a
    /// `Pg...Ledger`) can both share this accessor without the engine
    /// caring which is installed.
    #[must_use]
    pub fn fingerprints(&self) -> &dyn DeviceFingerprintStore {
        self.inner.fingerprints.as_ref()
    }

    /// Borrow the underlying [`MfaRecentTracker`].
    #[must_use]
    pub fn mfa_recent(&self) -> &MfaRecentTracker {
        &self.inner.mfa_recent
    }

    /// Borrow the underlying 7-day login history.
    #[must_use]
    pub fn login_history(&self) -> &LoginHistory {
        &self.inner.login_history
    }

    /// Borrow the underlying [`BaselineStore`].
    #[must_use]
    pub fn baseline(&self) -> &BaselineStore {
        &self.inner.baseline
    }

    /// Borrow the underlying [`TravelStore`] (HIGH-001 / LOW-005).
    #[must_use]
    pub fn travel(&self) -> &dyn TravelStore {
        self.inner.travel.as_ref()
    }

    /// Borrow the underlying [`IpGeoCentroid`] reader (HIGH-001).
    #[must_use]
    pub fn geo_centroid(&self) -> &IpGeoCentroid {
        &self.inner.geo_centroid
    }

    /// Record a successful MFA completion for `(tenant, user)`. Wires
    /// the `sx-iam` WebAuthn / TOTP completion paths into the RBA
    /// scorer's MFA-recency signal.
    pub fn record_mfa_completion(&self, tenant_id: Uuid, user_id: Uuid, at: OffsetDateTime) {
        self.inner.mfa_recent.record(tenant_id, user_id, at);
        tracing::debug!(
            target: "sx_rba.mfa",
            tenant_id = %tenant_id,
            user_id = %user_id,
            "recorded mfa completion",
        );
    }

    /// Record the outcome of one login attempt for the 7-day success
    /// rate signal. Wires the `sx-iam` authentication path into the
    /// RBA scorer.
    pub fn record_login_outcome(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        success: bool,
        at: OffsetDateTime,
    ) {
        self.inner
            .login_history
            .record(tenant_id, user_id, success, at);
    }

    /// Mark a fingerprint as enrolled for `(tenant, user)`.
    pub fn enroll_device_fingerprint(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        fp_hash: &str,
        at: OffsetDateTime,
    ) {
        self.inner
            .fingerprints
            .record(tenant_id, user_id, fp_hash, at);
        tracing::info!(
            target: "sx_rba.device_fp",
            tenant_id = %tenant_id,
            user_id = %user_id,
            "device fingerprint enrolled",
        );
    }

    /// Revoke a fingerprint (operator or end-user lost-device flow).
    pub fn revoke_device_fingerprint(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str) {
        self.inner.fingerprints.revoke(tenant_id, user_id, fp_hash);
        tracing::warn!(
            target: "sx_rba.device_fp",
            tenant_id = %tenant_id,
            user_id = %user_id,
            "device fingerprint revoked",
        );
    }

    /// List every enrolled device fingerprint for `(tenant, user)`.
    /// Returns rows newest-`last_seen_at`-first; revoked rows are
    /// included and tagged via their `status`.
    #[must_use]
    pub fn list_user_devices(&self, tenant_id: Uuid, user_id: Uuid) -> Vec<DeviceFingerprintRow> {
        let mut rows = self.inner.fingerprints.list_for_user(tenant_id, user_id);
        rows.sort_by(|a, b| b.last_seen_at.cmp(&a.last_seen_at));
        rows
    }

    /// Record a successful login geo-fix for impossible-travel
    /// tracking. Callers wire this in after an `evaluate()` call has
    /// decided to allow the login.
    pub fn record_login_geo(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        lat: f64,
        lon: f64,
        at: OffsetDateTime,
    ) {
        self.inner.travel.record(tenant_id, user_id, lat, lon, at);
    }

    /// Lock the per-tenant baseline at its currently-calibrated
    /// thresholds. Emits an audit log line.
    pub fn lock_baseline(&self, tenant_id: Uuid, at: OffsetDateTime) {
        self.inner.baseline.lock(tenant_id, at);
        tracing::info!(
            target: "sx_rba.baseline",
            tenant_id = %tenant_id,
            "baseline locked by operator",
        );
    }

    /// Retrieve the configuration for `tenant_id`, falling back to
    /// [`RbaConfig::default`].
    #[must_use]
    pub fn config_for(&self, tenant_id: Uuid) -> RbaConfig {
        self.inner
            .configs
            .get(&tenant_id)
            .map_or_else(RbaConfig::default, |r| r.clone())
    }

    /// Install a new configuration for `tenant_id`.
    ///
    /// Returns the freshly validated copy on success.
    pub fn put_config(&self, tenant_id: Uuid, cfg: RbaConfig) -> Result<RbaConfig, RbaError> {
        cfg.validate()
            .map_err(|e| RbaError::InvalidConfig(e.to_string()))?;
        self.inner.configs.insert(tenant_id, cfg.clone());
        Ok(cfg)
    }

    /// Evaluate one login attempt. Always audits, even on allow.
    ///
    /// When the per-tenant baseline is still in observation phase the
    /// returned `action` is forced to [`RbaAction::Allow`] even if the
    /// computed score would otherwise step up or block (HIGH-001).
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)] // moved fields land in the audit row; HIGH-001 enrichment + audit emit lives inline by design
    pub fn evaluate(&self, ctx: LoginContext) -> RbaDecision {
        let cfg = self.config_for(ctx.tenant_id);
        let country = self.inner.geo.lookup(ctx.ip);
        let velocity_count = self
            .inner
            .velocity
            .record_and_count(&ctx.tenant_id.to_string(), &ctx.email);
        let bh_status = cfg.business_hours.evaluate(ctx.observed_at);

        // HIGH-001 signals — only resolved when we have a user id.
        // Anonymous attempts (failed credential lookup) keep them at
        // `None`, which the scorer maps to the conservative
        // "unknown" sub-scores.
        let (fp_signal, mfa_signal, sr_signal, travel_signal) = match ctx.user_id {
            Some(user_id) => {
                let fp = ctx
                    .device_fingerprint
                    .as_deref()
                    .map(|hash| self.inner.fingerprints.lookup(ctx.tenant_id, user_id, hash));
                let mfa = Some(self.inner.mfa_recent.lookup(
                    ctx.tenant_id,
                    user_id,
                    ctx.observed_at,
                ));
                let sr = Some(self.inner.login_history.signal(
                    ctx.tenant_id,
                    user_id,
                    ctx.observed_at,
                ));
                // Impossible-travel: resolve current IP to lat/lon via
                // the centroid reader, then compare against the
                // tracker's last sighting. We DO NOT mutate the tracker
                // here — that happens once we decide to allow the
                // attempt (`record_login_geo`).
                let (lat, lon) = self
                    .inner
                    .geo_centroid
                    .lookup_latlon(ctx.ip)
                    .map_or((None, None), |(la, lo)| (Some(la), Some(lo)));
                let travel = Some(self.inner.travel.evaluate(
                    ctx.tenant_id,
                    user_id,
                    lat,
                    lon,
                    ctx.observed_at,
                    DEFAULT_MAX_SPEED_KMH,
                ));
                (fp, mfa, sr, travel)
            }
            None => (None, None, None, None),
        };

        let snapshot = SignalSnapshot {
            country: Some(country),
            home_country: Some(self.inner.default_home_country.clone()),
            velocity_window_count: velocity_count,
            business_hours_status: Some(bh_status),
            device_fingerprint: fp_signal,
            mfa_recent: mfa_signal,
            success_rate: sr_signal,
            impossible_travel: travel_signal,
        };
        let scored = self.inner.scorer.score(&snapshot, &cfg);

        // LOW-006: per-signal Prometheus instrumentation. Records the
        // histogram unconditionally and bumps the `rba_signal_fired_total`
        // counter for every enabled signal whose sub-score is non-zero.
        record_signal_metrics(&snapshot, &cfg, ctx.tenant_id);

        // Observe the score against the per-tenant baseline. The
        // outcome carries the active phase + calibrated thresholds the
        // engine should use.
        let outcome = self
            .inner
            .baseline
            .observe(ctx.tenant_id, scored.score, ctx.observed_at);

        // Threshold pick:
        // 1. If the tenant has an *explicit* `put_config` on file,
        //    those thresholds win — the operator chose them, no auto-
        //    calibration may override them.
        // 2. Otherwise, when the baseline is Active or Locked, use the
        //    calibrated thresholds.
        // 3. Falling all the way through (observation phase, no explicit
        //    config) we use the defaults carried in `cfg`.
        let has_explicit_cfg = self.inner.configs.contains_key(&ctx.tenant_id);
        let (allow_threshold, block_threshold) = if has_explicit_cfg {
            (cfg.allow_threshold, cfg.block_threshold)
        } else if matches!(outcome.phase, BaselinePhase::Active | BaselinePhase::Locked) {
            (outcome.allow_threshold, outcome.block_threshold)
        } else {
            (cfg.allow_threshold, cfg.block_threshold)
        };

        let computed_action = if scored.score < allow_threshold {
            RbaAction::Allow
        } else if scored.score >= block_threshold {
            RbaAction::Block
        } else {
            RbaAction::StepUpMfa
        };

        // Passive observation: regardless of computed action, return
        // Allow. The decision row still carries the would-be action via
        // the `reason` so the SOC can audit shadow-mode mistakes.
        let action = if matches!(outcome.phase, BaselinePhase::Observation) {
            RbaAction::Allow
        } else {
            computed_action
        };

        let reason = if matches!(outcome.phase, BaselinePhase::Observation) {
            format!(
                "observation-mode (would-be {}): {}",
                computed_action.as_str(),
                scored.reason
            )
        } else {
            scored.reason
        };

        let signals_map = snapshot.to_map();
        let decision = RbaDecision {
            id: Uuid::new_v4(),
            tenant_id: ctx.tenant_id,
            user_id: ctx.user_id,
            ip: ctx.ip,
            score: scored.score,
            action,
            signals: signals_map,
            snapshot,
            signal_contributions: scored.contributions,
            reason,
            baseline_phase: outcome.phase,
            decided_at: ctx.observed_at,
        };

        // LOW-006: decision counter — one bump per emitted decision,
        // labelled by the resolved action + tenant. Mirrors the
        // observation-mode discipline so a baseline-shadowed Allow is
        // still counted as Allow on the wire.
        crate::metrics::record_decision(decision.action, decision.tenant_id);

        // Tracing: never logs the email; the decision id + score + action
        // is enough for the SOC to correlate with the audit row.
        tracing::info!(
            target: "sx_rba.evaluate",
            decision_id = %decision.id,
            tenant_id = %decision.tenant_id,
            score = decision.score,
            action = decision.action.as_str(),
            baseline_phase = outcome.phase.as_str(),
            "rba decision",
        );

        // Audit ALWAYS — independent of action.
        let entry = self
            .inner
            .decisions
            .entry(decision.tenant_id)
            .or_insert_with(|| Mutex::new(DecisionRing::with_capacity(self.inner.ring_capacity)));
        if let Ok(mut ring) = entry.value().lock() {
            ring.push(decision.clone());
        }
        drop(entry);
        decision
    }

    /// Return the most recent decisions for `tenant_id`. The list is
    /// capped at [`MAX_DECISIONS_PER_REQUEST`].
    #[must_use]
    pub fn recent_decisions(&self, tenant_id: Uuid, limit: usize) -> Vec<DecisionAudit> {
        let limit = limit.min(MAX_DECISIONS_PER_REQUEST);
        self.inner
            .decisions
            .get(&tenant_id)
            .map(|r| {
                r.value()
                    .lock()
                    .map(|ring| ring.recent(limit))
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Score one login attempt with **every** enrichment signal
    /// resolved (HIGH-001 + the legacy three). Equivalent to
    /// [`Self::evaluate`] but exposes the [`SignalSnapshot`] AS WELL
    /// AS the bucketed action — used by the integration test suite to
    /// assert per-signal contributions without going through the
    /// decision-ring side-effect.
    ///
    /// Unlike [`Self::evaluate`] this method does not record the
    /// decision in the per-tenant ring buffer. The audit-row write
    /// still belongs to `evaluate()`.
    #[allow(clippy::needless_pass_by_value)]
    // ctx fields land in the returned EnrichedDecision; keeping the by-value signature matches `evaluate()` for symmetry.
    #[must_use]
    pub fn score_with_enriched_context(&self, ctx: LoginContext) -> EnrichedDecision {
        let cfg = self.config_for(ctx.tenant_id);
        let country = self.inner.geo.lookup(ctx.ip);
        let velocity_count = self
            .inner
            .velocity
            .record_and_count(&ctx.tenant_id.to_string(), &ctx.email);
        let bh_status = cfg.business_hours.evaluate(ctx.observed_at);

        let (fp_signal, mfa_signal, sr_signal, travel_signal) = match ctx.user_id {
            Some(user_id) => {
                let fp = ctx
                    .device_fingerprint
                    .as_deref()
                    .map(|hash| self.inner.fingerprints.lookup(ctx.tenant_id, user_id, hash));
                let mfa = Some(self.inner.mfa_recent.lookup(
                    ctx.tenant_id,
                    user_id,
                    ctx.observed_at,
                ));
                let sr = Some(self.inner.login_history.signal(
                    ctx.tenant_id,
                    user_id,
                    ctx.observed_at,
                ));
                let (lat, lon) = self
                    .inner
                    .geo_centroid
                    .lookup_latlon(ctx.ip)
                    .map_or((None, None), |(la, lo)| (Some(la), Some(lo)));
                let travel = Some(self.inner.travel.evaluate(
                    ctx.tenant_id,
                    user_id,
                    lat,
                    lon,
                    ctx.observed_at,
                    DEFAULT_MAX_SPEED_KMH,
                ));
                (fp, mfa, sr, travel)
            }
            None => (None, None, None, None),
        };

        let snapshot = SignalSnapshot {
            country: Some(country),
            home_country: Some(self.inner.default_home_country.clone()),
            velocity_window_count: velocity_count,
            business_hours_status: Some(bh_status),
            device_fingerprint: fp_signal,
            mfa_recent: mfa_signal,
            success_rate: sr_signal,
            impossible_travel: travel_signal,
        };
        let scored = self.inner.scorer.score(&snapshot, &cfg);
        let action = bucket_action(scored.score, &cfg);
        EnrichedDecision {
            score: scored.score,
            action,
            reason: scored.reason,
            snapshot,
        }
    }
}

/// LOW-006: walk every enabled signal and emit the per-signal
/// histogram + bumped counter via the `crate::metrics` module.
///
/// Lives next to [`bucket_action`] so the iteration order over signals
/// stays in lock-step with the scorer (also using `RbaFeatureFlags` to
/// gate the same set).
fn record_signal_metrics(snapshot: &SignalSnapshot, cfg: &RbaConfig, tenant_id: Uuid) {
    use crate::metrics::{record_signal, SignalDetail};
    use crate::scorer::rule_based::RuleBasedScorer;
    use crate::signals::SignalKind;

    let flags = &cfg.feature_flags;

    if flags.enable_ip_geo {
        record_signal(
            SignalKind::IpGeo,
            RuleBasedScorer::ip_score(snapshot),
            SignalDetail::None,
            tenant_id,
        );
    }
    if flags.enable_velocity {
        record_signal(
            SignalKind::Velocity,
            RuleBasedScorer::velocity_score(snapshot),
            SignalDetail::None,
            tenant_id,
        );
    }
    if flags.enable_business_hours {
        record_signal(
            SignalKind::BusinessHours,
            RuleBasedScorer::hours_score(snapshot),
            SignalDetail::BusinessHours(snapshot.business_hours_status),
            tenant_id,
        );
    }
    if flags.enable_device_fp {
        record_signal(
            SignalKind::DeviceFingerprint,
            RuleBasedScorer::device_fp_score(snapshot),
            SignalDetail::DeviceFingerprint(snapshot.device_fingerprint.as_ref()),
            tenant_id,
        );
    }
    if flags.enable_mfa_recent {
        record_signal(
            SignalKind::MfaRecent,
            RuleBasedScorer::mfa_recent_score(snapshot),
            SignalDetail::MfaRecent(snapshot.mfa_recent.as_ref()),
            tenant_id,
        );
    }
    if flags.enable_success_rate {
        record_signal(
            SignalKind::SuccessRate,
            RuleBasedScorer::success_rate_score(snapshot),
            SignalDetail::SuccessRate(snapshot.success_rate.as_ref()),
            tenant_id,
        );
    }
    if flags.enable_impossible_travel {
        record_signal(
            SignalKind::ImpossibleTravel,
            RuleBasedScorer::impossible_travel_score(snapshot),
            SignalDetail::ImpossibleTravel(snapshot.impossible_travel.as_ref()),
            tenant_id,
        );
    }
}

/// Bucket a `[0, 100]` composite score into an [`RbaAction`] using the
/// configured allow / block thresholds. Used by both
/// [`RbaService::score_with_enriched_context`] and the integration test
/// harness so they cannot drift apart.
#[must_use]
pub fn bucket_action(score: i32, cfg: &RbaConfig) -> RbaAction {
    if score < cfg.allow_threshold {
        RbaAction::Allow
    } else if score >= cfg.block_threshold {
        RbaAction::Block
    } else {
        RbaAction::StepUpMfa
    }
}

/// Return type of [`RbaService::score_with_enriched_context`].
#[derive(Debug, Clone)]
pub struct EnrichedDecision {
    /// Composite score in `[0, 100]`.
    pub score: i32,
    /// Bucketed action (allow / step-up / block).
    pub action: RbaAction,
    /// Human-readable reason from the scorer.
    pub reason: String,
    /// Full snapshot of every resolved signal.
    pub snapshot: SignalSnapshot,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn ctx(ip: Ipv4Addr, email: &str, ts: OffsetDateTime) -> LoginContext {
        LoginContext {
            tenant_id: Uuid::nil(),
            user_id: Some(Uuid::new_v4()),
            email: email.to_owned(),
            ip,
            device_fingerprint: Some("fp".into()),
            observed_at: ts,
        }
    }

    #[test]
    fn first_us_login_in_business_hours_is_allowed() {
        let svc = RbaService::default();
        let d = svc.evaluate(ctx(
            Ipv4Addr::new(8, 8, 8, 8),
            "alice@x.test",
            datetime!(2026-06-12 10:00:00 UTC),
        ));
        assert_eq!(d.action, RbaAction::Allow);
        assert!(d.score < 30);
    }

    #[test]
    fn off_country_after_hours_steps_up() {
        let svc = RbaService::default();
        // Escape the 30-day passive-observation phase so the engine
        // actually returns the computed action (rather than forced
        // Allow). Locking is the test-friendly path; production tenants
        // transition naturally once the window expires.
        svc.lock_baseline(Uuid::nil(), datetime!(2026-06-12 22:00:00 UTC));
        // Unknown country (sub-score 80) + deep-night UTC (sub-score 60
        // = 40 after-hours + 20 deep-night bump) is enough to cross the
        // 30 allow-threshold even with the conservative HIGH-001
        // defaults.
        let d = svc.evaluate(ctx(
            Ipv4Addr::new(240, 0, 0, 1), // outside the embedded CSV → '??'
            "alice@x.test",
            datetime!(2026-06-12 04:00:00 UTC),
        ));
        assert_eq!(d.action, RbaAction::StepUpMfa, "score={}", d.score);
    }

    #[test]
    fn burst_unknown_country_blocks() {
        let svc = RbaService::default();
        let ts = datetime!(2026-06-12 02:00:00 UTC);
        svc.lock_baseline(Uuid::nil(), ts);
        // Drop the per-tenant weights' floor and disable HIGH-001
        // signals for this scenario — we want to exercise the legacy
        // burst-unknown-country path on its own, the way the original
        // P1-003 acceptance criteria targeted it. With HIGH-001's
        // conservative defaults the composite would otherwise sit just
        // under the block threshold (~56) even on a maximally hostile
        // legacy input.
        svc.put_config(
            Uuid::nil(),
            RbaConfig {
                feature_flags: crate::config::RbaFeatureFlags {
                    enable_device_fp: false,
                    enable_mfa_recent: false,
                    enable_success_rate: false,
                    enable_impossible_travel: false,
                    ..crate::config::RbaFeatureFlags::default()
                },
                ..Default::default()
            },
        )
        .expect("config valid");
        // Spam attempts from an IP outside the embedded /8 table (so the
        // ip-geo lookup returns the unknown sentinel, sub-score 80) at
        // deep-night UTC. With 11+ velocity attempts the composite must
        // exceed the block threshold.
        let ip = Ipv4Addr::new(240, 0, 0, 1);
        let mut last = svc.evaluate(ctx(ip, "alice@x.test", ts));
        for _ in 0..14 {
            last = svc.evaluate(ctx(ip, "alice@x.test", ts));
        }
        assert_eq!(last.action, RbaAction::Block, "score={}", last.score);
    }

    #[test]
    fn audit_records_even_allow_decisions() {
        let svc = RbaService::default();
        let _ = svc.evaluate(ctx(
            Ipv4Addr::new(8, 8, 8, 8),
            "alice@x.test",
            datetime!(2026-06-12 10:00:00 UTC),
        ));
        let list = svc.recent_decisions(Uuid::nil(), 10);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].action, "allow");
    }

    #[test]
    fn audit_caps_at_ring_capacity() {
        let svc = RbaService::default();
        for i in 0..1000 {
            let _ = svc.evaluate(ctx(
                Ipv4Addr::new(8, 8, 8, ((i & 0xff) as u8).max(1)),
                "alice@x.test",
                datetime!(2026-06-12 10:00:00 UTC),
            ));
        }
        let list = svc.recent_decisions(Uuid::nil(), 5000);
        assert!(list.len() <= DEFAULT_DECISION_RING_CAPACITY);
    }

    #[test]
    fn put_config_validates() {
        let svc = RbaService::default();
        let tenant = Uuid::new_v4();
        let bad = RbaConfig {
            allow_threshold: 80,
            block_threshold: 30,
            ..Default::default()
        };
        assert!(svc.put_config(tenant, bad).is_err());
        let good = RbaConfig::default();
        assert!(svc.put_config(tenant, good).is_ok());
    }

    #[test]
    fn per_tenant_config_takes_effect() {
        let svc = RbaService::default();
        let tenant = Uuid::new_v4();
        // Squeeze the allow band so even an in-country in-hours login
        // ends up step-up: lift allow_threshold above 0 but set it to
        // 1 → any non-zero score steps up.
        svc.put_config(
            tenant,
            RbaConfig {
                allow_threshold: 1,
                block_threshold: 99,
                ..Default::default()
            },
        )
        .unwrap();
        // Lock out of observation phase so the configured thresholds
        // actually drive the decision.
        svc.lock_baseline(tenant, datetime!(2026-06-12 10:00:00 UTC));
        let mut c = ctx(
            Ipv4Addr::new(89, 0, 0, 1), // RU
            "alice@x.test",
            datetime!(2026-06-12 10:00:00 UTC),
        );
        c.tenant_id = tenant;
        let d = svc.evaluate(c);
        assert_eq!(d.action, RbaAction::StepUpMfa);
    }

    #[test]
    fn decisions_are_tenant_scoped() {
        let svc = RbaService::default();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let mut c = ctx(
            Ipv4Addr::new(8, 8, 8, 8),
            "alice@x.test",
            datetime!(2026-06-12 10:00:00 UTC),
        );
        c.tenant_id = a;
        let _ = svc.evaluate(c.clone());
        let mut c2 = c;
        c2.tenant_id = b;
        let _ = svc.evaluate(c2);
        assert_eq!(svc.recent_decisions(a, 10).len(), 1);
        assert_eq!(svc.recent_decisions(b, 10).len(), 1);
    }

    #[test]
    fn decision_carries_signal_contributions_for_audit_persistence() {
        // LOW-007: every emitted decision must carry the per-signal
        // breakdown. Default config enables all seven signals so the
        // breakdown is exactly seven rows.
        let svc = RbaService::default();
        let d = svc.evaluate(ctx(
            Ipv4Addr::new(8, 8, 8, 8),
            "alice@x.test",
            datetime!(2026-06-12 10:00:00 UTC),
        ));
        assert_eq!(
            d.signal_contributions.len(),
            7,
            "default config: every signal enabled → 7 contributions, got {:?}",
            d.signal_contributions,
        );
        // Every weighted row matches sub_score * weight.
        for c in &d.signal_contributions {
            let expected = f64::from(c.sub_score) * c.weight;
            assert!(
                (c.weighted - expected).abs() < 1e-9,
                "contribution {:?} has weighted {} but sub_score*weight is {}",
                c.signal,
                c.weighted,
                expected,
            );
        }
        // The audit projection carries the same set.
        let audits = svc.recent_decisions(Uuid::nil(), 1);
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].signal_contributions.len(), 7);
    }

    #[test]
    fn disabled_signals_are_omitted_from_contributions() {
        // LOW-007 + HIGH-001 interaction: when an operator turns off a
        // signal via feature_flags, the per-signal row vanishes from
        // the breakdown rather than reporting weight=0. Investigators
        // need to know which signals were ACTIVE at decision time.
        let svc = RbaService::default();
        let tenant = Uuid::new_v4();
        svc.put_config(
            tenant,
            RbaConfig {
                feature_flags: crate::config::RbaFeatureFlags {
                    enable_device_fp: false,
                    enable_mfa_recent: false,
                    enable_success_rate: false,
                    enable_impossible_travel: false,
                    ..crate::config::RbaFeatureFlags::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let mut c = ctx(
            Ipv4Addr::new(8, 8, 8, 8),
            "alice@x.test",
            datetime!(2026-06-12 10:00:00 UTC),
        );
        c.tenant_id = tenant;
        let d = svc.evaluate(c);
        // Only the legacy three (ip_geo, velocity, business_hours)
        // remain enabled. The breakdown must reflect that.
        assert_eq!(d.signal_contributions.len(), 3);
        let labels: Vec<_> = d.signal_contributions.iter().map(|c| c.signal).collect();
        assert!(labels.contains(&crate::SignalKind::IpGeo));
        assert!(labels.contains(&crate::SignalKind::Velocity));
        assert!(labels.contains(&crate::SignalKind::BusinessHours));
        assert!(!labels.contains(&crate::SignalKind::DeviceFingerprint));
    }

    #[test]
    fn signals_serialise_to_jsonb_friendly_map() {
        let svc = RbaService::default();
        let d = svc.evaluate(ctx(
            Ipv4Addr::new(8, 8, 8, 8),
            "alice@x.test",
            datetime!(2026-06-12 10:00:00 UTC),
        ));
        // serde_json round-trip → must produce an object.
        let v = serde_json::Value::Object(
            d.signals
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<serde_json::Map<String, serde_json::Value>>(),
        );
        assert!(v.is_object());
        assert!(v["country"].is_string());
        assert!(v["velocity_window_count"].is_number());
    }
}
