//! HIGH-007 — Neo4j graceful-degrade fallback with circuit breaker.
//!
//! Wraps a *primary* [`KnowledgeGraph`] (typically
//! [`super::Neo4jKnowledgeGraph`]) and a *secondary* in-memory adapter
//! ([`super::InMemoryKnowledgeGraph`]) behind a single port. When the
//! primary fails with a connection-shaped error (bolt timeout, refused,
//! auth) the call is transparently retried against the secondary, a
//! [`tracing`] line is emitted, and the
//! `graph_fallback_engaged_total{reason}` Prometheus counter is bumped
//! via the workspace-shared `metrics` façade (registered by
//! `sx-telemetry::metrics`).
//!
//! Shape borrowed from CRIT-006 (`sx-audit::tsa_fallback`):
//!
//! - [`CircuitBreaker`] with `Closed -> Open -> HalfOpen -> Closed`.
//! - [`CircuitBreaker::FAILURE_THRESHOLD`] = 5 consecutive errors trips
//!   the breaker (per HIGH-007 spec — TSA uses 3).
//! - [`CircuitBreaker::COOL_DOWN`] = 60 s before the next probe.
//! - A background [`ReconnectProbe`] task pokes the primary every
//!   [`ReconnectProbe::PROBE_INTERVAL`] (30 s) while the breaker is
//!   `Open`; the first success closes the breaker and returns the
//!   service to the primary.
//!
//! The wrapper exposes both the raw [`KnowledgeGraph`] surface (so the
//! existing `FindAttackPathsUseCase` can drive it) and a richer
//! [`FallbackKnowledgeGraph::find_attack_paths_with_engine`] that
//! returns [`AttackPathsResponse`] — the latter carries the
//! `engine` + `degraded` flags the API layer plumbs through the wire DTO.
//!
//! ## Why a separate response shape
//!
//! `KnowledgeGraph::find_attack_paths` returns `Vec<AttackPath>` with no
//! room for the degradation marker. Re-purposing the existing trait
//! would propagate the new flags through every adapter (production
//! Neo4j adapter, in-memory adapter, mock adapters in tests) for no
//! benefit. The richer shape is therefore exposed on the wrapper
//! itself, and the adapter layer (`sx-monolith adapters::phase3`)
//! prefers the wrapper API when the wrapper is configured.

#![allow(
    clippy::module_name_repetitions,
    clippy::doc_lazy_continuation,
    clippy::too_long_first_doc_paragraph,
    clippy::significant_drop_tightening,
    clippy::needless_pass_by_value
)]

use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, instrument, warn};

use crate::error::GraphError;
use crate::model::attack_path::{AttackPath, PropagatedRisk};
use crate::model::edge::GraphEdge;
use crate::model::node::{GraphNode, NodeId};
use crate::port::{AttackPathQuery, KnowledgeGraph};

// ---------------------------------------------------------------------------
// Engine tag + response wrapper
// ---------------------------------------------------------------------------

/// Which backend served a given request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphEngine {
    /// The primary Neo4j backend produced the result.
    Neo4j,
    /// The in-memory adjacency-list backend produced the result —
    /// degraded service.
    Memory,
}

impl GraphEngine {
    /// Stable string tag for logs / metrics / wire DTOs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Neo4j => "neo4j",
            Self::Memory => "memory",
        }
    }

    /// `true` when the request was served by the secondary (memory)
    /// backend.
    #[must_use]
    pub const fn is_degraded(self) -> bool {
        matches!(self, Self::Memory)
    }
}

/// Engine-aware response for [`FallbackKnowledgeGraph::find_attack_paths_with_engine`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPathsResponse {
    /// The attack paths discovered.
    pub paths: Vec<AttackPath>,
    /// Which backend produced `paths`.
    pub engine: GraphEngine,
    /// `true` when the wrapper served the request from the secondary
    /// (i.e. `engine == Memory`). Convenience for the API layer; it is
    /// strictly equivalent to `engine.is_degraded()`.
    pub degraded: bool,
}

// ---------------------------------------------------------------------------
// Reason classification
// ---------------------------------------------------------------------------

/// Why the wrapper fell back from primary to secondary.
///
/// Surfaced as a Prometheus label on `graph_fallback_engaged_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    /// Bolt-level transport problem (timeout, refused, TLS handshake).
    Connection,
    /// Authentication failure against the primary (bad credentials or
    /// rotated password).
    Auth,
    /// Breaker was `Open` — the wrapper short-circuited the primary.
    BreakerOpen,
    /// Any other primary-side error treated as "primary unhealthy".
    /// We deliberately do NOT fall back on `InvalidQuery` /
    /// `TenantBoundary` / `NotFound` / `Conflict` — those are caller
    /// errors that the in-memory backend would surface identically.
    PrimaryError,
}

impl FallbackReason {
    /// String tag for metrics + logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Auth => "auth",
            Self::BreakerOpen => "breaker_open",
            Self::PrimaryError => "primary_error",
        }
    }
}

/// Classify a [`GraphError`] returned by the primary backend.
///
/// Returns `Some(reason)` if the error should trigger a fallback,
/// `None` if the error is a caller fault and must be propagated as-is.
#[must_use]
pub fn classify_primary_error(err: &GraphError) -> Option<FallbackReason> {
    match err {
        GraphError::Connection(msg) => {
            // Try to spot auth-shaped messages so the metric label is
            // useful. The Neo4j driver typically renders "auth" /
            // "unauthorized" / "credentials" in these.
            let lower = msg.to_ascii_lowercase();
            if lower.contains("auth")
                || lower.contains("unauthor")
                || lower.contains("credential")
                || lower.contains("forbidden")
            {
                Some(FallbackReason::Auth)
            } else {
                Some(FallbackReason::Connection)
            }
        }
        // Query / Cypher errors on the primary mean the primary is
        // misbehaving — fall back so the user gets a degraded answer.
        GraphError::Query(_) | GraphError::Cypher(_) | GraphError::Internal(_) => {
            Some(FallbackReason::PrimaryError)
        }
        // Caller faults: never fall back. Returning `None` makes the
        // wrapper re-raise the original error.
        GraphError::Config(_)
        | GraphError::NotFound { .. }
        | GraphError::Conflict { .. }
        | GraphError::TenantBoundary { .. }
        | GraphError::InvalidQuery(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Clock abstraction (mirrors CRIT-006)
// ---------------------------------------------------------------------------

/// Trait abstracting "what time is it now" so unit tests can advance
/// the clock without sleeping. Mirrors `sx-audit::tsa_fallback::Clock`.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Current wall-clock time in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// Production clock — delegates to [`OffsetDateTime::now_utc`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Manually-driven clock for tests.
#[derive(Debug)]
pub struct ManualClock {
    inner: Mutex<OffsetDateTime>,
}

impl ManualClock {
    /// New clock pinned to `start`.
    #[must_use]
    pub fn new(start: OffsetDateTime) -> Self {
        Self {
            inner: Mutex::new(start),
        }
    }

    /// Advance the clock by `delta`.
    pub async fn advance(&self, delta: StdDuration) {
        let mut g = self.inner.lock().await;
        *g += delta;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        // Synchronous read — use try_lock to avoid blocking. Tests
        // never contend, so this is fine.
        self.inner
            .try_lock()
            .map_or(OffsetDateTime::UNIX_EPOCH, |g| *g)
    }
}

// ---------------------------------------------------------------------------
// Circuit breaker (shape mirrors CRIT-006)
// ---------------------------------------------------------------------------

/// Per-wrapper breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    /// Primary is healthy; traffic flows.
    Closed,
    /// Primary is unhealthy; calls short-circuit until cool-down.
    Open,
    /// One probe permitted; the breaker is "trying again".
    HalfOpen,
}

impl BreakerState {
    /// Short-string tag for logs / metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// What the breaker tells the caller to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDecision {
    /// Caller MAY execute the protected operation against the primary.
    Allow,
    /// Caller MUST short-circuit; the breaker is `Open`.
    Reject,
}

/// Snapshot of breaker counters — handy in tests and as a metrics export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerSnapshot {
    /// Current state.
    pub state: BreakerState,
    /// Consecutive failures since the last success.
    pub consecutive_failures: u32,
    /// Total successes.
    pub total_successes: u64,
    /// Total failures.
    pub total_failures: u64,
    /// Total rejections (calls short-circuited while `Open`).
    pub total_rejections: u64,
    /// Wall-clock when the breaker last flipped to `Open`.
    pub opened_at: Option<OffsetDateTime>,
}

#[derive(Debug)]
struct BreakerInner {
    state: BreakerState,
    consecutive_failures: u32,
    total_successes: u64,
    total_failures: u64,
    total_rejections: u64,
    opened_at: Option<OffsetDateTime>,
}

impl BreakerInner {
    const fn new() -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            total_successes: 0,
            total_failures: 0,
            total_rejections: 0,
            opened_at: None,
        }
    }
}

/// Per-wrapper circuit breaker.
///
/// Mirrors the CRIT-006 [`sx_audit::tsa_fallback::CircuitBreaker`]
/// shape: `Closed -> Open` after `FAILURE_THRESHOLD` consecutive
/// failures, `Open -> HalfOpen` after `COOL_DOWN` elapses, `HalfOpen ->
/// Closed` on the next success or back to `Open` on failure.
///
/// All state lives behind a [`Mutex`] — graph queries are tens-of-ms
/// scale, so contention is irrelevant.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Human-readable label (used in logs).
    label: String,
    /// Failure threshold before opening — defaults to
    /// [`Self::FAILURE_THRESHOLD`].
    failure_threshold: u32,
    /// Cool-down after which `Open -> HalfOpen`.
    cool_down: StdDuration,
    /// Shared clock.
    clock: Arc<dyn Clock>,
    /// Mutex-guarded state.
    inner: Mutex<BreakerInner>,
}

impl CircuitBreaker {
    /// HIGH-007 spec — 5 consecutive errors trip the breaker.
    pub const FAILURE_THRESHOLD: u32 = 5;
    /// HIGH-007 spec — 60 s cool-down before the breaker probes again.
    pub const COOL_DOWN: StdDuration = StdDuration::from_secs(60);

    /// New breaker with the spec defaults + a [`SystemClock`].
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self::with_clock(label, Arc::new(SystemClock))
    }

    /// New breaker with the spec defaults + a caller-supplied clock.
    #[must_use]
    pub fn with_clock(label: impl Into<String>, clock: Arc<dyn Clock>) -> Self {
        Self::with_thresholds(label, Self::FAILURE_THRESHOLD, Self::COOL_DOWN, clock)
    }

    /// New breaker with custom thresholds — used by tests that want a
    /// tighter setup.
    #[must_use]
    pub fn with_thresholds(
        label: impl Into<String>,
        failure_threshold: u32,
        cool_down: StdDuration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            label: label.into(),
            failure_threshold,
            cool_down,
            clock,
            inner: Mutex::new(BreakerInner::new()),
        }
    }

    /// Breaker label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Ask the breaker whether the caller may execute the protected
    /// operation. Side effect: transitions `Open -> HalfOpen` when the
    /// cool-down has expired, and counts rejections otherwise.
    pub async fn on_call(&self) -> CallDecision {
        let now = self.clock.now();
        let mut g = self.inner.lock().await;
        match g.state {
            BreakerState::Closed | BreakerState::HalfOpen => CallDecision::Allow,
            BreakerState::Open => {
                let elapsed_ok = g.opened_at.is_some_and(|opened| {
                    let elapsed = now - opened;
                    elapsed
                        >= time::Duration::try_from(self.cool_down).unwrap_or(time::Duration::ZERO)
                });
                if elapsed_ok {
                    debug!(label = %self.label, "graph breaker Open -> HalfOpen");
                    g.state = BreakerState::HalfOpen;
                    CallDecision::Allow
                } else {
                    g.total_rejections = g.total_rejections.saturating_add(1);
                    CallDecision::Reject
                }
            }
        }
    }

    /// Record a successful call — resets the failure counter and
    /// closes the breaker if it was `HalfOpen`.
    pub async fn on_success(&self) {
        let mut g = self.inner.lock().await;
        g.total_successes = g.total_successes.saturating_add(1);
        g.consecutive_failures = 0;
        if g.state != BreakerState::Closed {
            info!(
                label = %self.label,
                prev = g.state.as_str(),
                "graph breaker -> Closed",
            );
            g.state = BreakerState::Closed;
            g.opened_at = None;
        }
    }

    /// Record a failed call — bumps the failure counter and may flip
    /// the breaker to `Open`.
    pub async fn on_failure(&self) {
        let now = self.clock.now();
        let mut g = self.inner.lock().await;
        g.total_failures = g.total_failures.saturating_add(1);
        g.consecutive_failures = g.consecutive_failures.saturating_add(1);
        match g.state {
            BreakerState::HalfOpen => {
                warn!(label = %self.label, "graph breaker HalfOpen -> Open (probe failed)");
                g.state = BreakerState::Open;
                g.opened_at = Some(now);
            }
            BreakerState::Closed if g.consecutive_failures >= self.failure_threshold => {
                warn!(
                    label = %self.label,
                    consecutive = g.consecutive_failures,
                    "graph breaker Closed -> Open (threshold breached)",
                );
                g.state = BreakerState::Open;
                g.opened_at = Some(now);
            }
            BreakerState::Closed | BreakerState::Open => {}
        }
    }

    /// Snapshot the breaker for tests / metrics.
    pub async fn snapshot(&self) -> BreakerSnapshot {
        let g = self.inner.lock().await;
        BreakerSnapshot {
            state: g.state,
            consecutive_failures: g.consecutive_failures,
            total_successes: g.total_successes,
            total_failures: g.total_failures,
            total_rejections: g.total_rejections,
            opened_at: g.opened_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Metric names
// ---------------------------------------------------------------------------

/// Counter name for fallback engagements.
///
/// Labelled `reason` ∈ {`connection`, `auth`, `breaker_open`, `primary_error`}.
pub const METRIC_GRAPH_FALLBACK_ENGAGED: &str = "graph_fallback_engaged_total";

/// Counter name for successful primary recoveries (probe closed the
/// breaker).
pub const METRIC_GRAPH_RECOVERED: &str = "graph_primary_recovered_total";

/// Bump the fallback counter once with the supplied reason.
fn record_fallback(reason: FallbackReason) {
    metrics::counter!(
        METRIC_GRAPH_FALLBACK_ENGAGED,
        "reason" => reason.as_str(),
    )
    .increment(1);
}

/// Bump the recovery counter once.
fn record_recovery() {
    metrics::counter!(METRIC_GRAPH_RECOVERED).increment(1);
}

// ---------------------------------------------------------------------------
// Fallback wrapper
// ---------------------------------------------------------------------------

/// `KnowledgeGraph` impl that fronts a primary + secondary pair.
///
/// On primary error (connection / query / cypher / internal) the call
/// is retried against the secondary. The wrapper records the fallback
/// in Prometheus + tracing, and trips a circuit breaker after
/// [`CircuitBreaker::FAILURE_THRESHOLD`] consecutive primary failures.
///
/// When the breaker is `Open` the wrapper short-circuits the primary
/// entirely and serves from the secondary until the next probe.
#[derive(Debug)]
pub struct FallbackKnowledgeGraph {
    primary: Arc<dyn KnowledgeGraph>,
    secondary: Arc<dyn KnowledgeGraph>,
    breaker: Arc<CircuitBreaker>,
}

impl FallbackKnowledgeGraph {
    /// Build a wrapper with the spec-default circuit breaker and a
    /// [`SystemClock`].
    #[must_use]
    pub fn new(primary: Arc<dyn KnowledgeGraph>, secondary: Arc<dyn KnowledgeGraph>) -> Self {
        Self::with_breaker(
            primary,
            secondary,
            Arc::new(CircuitBreaker::new("sx-graph.fallback")),
        )
    }

    /// Build a wrapper with a caller-supplied breaker — used by tests
    /// that want a tighter threshold and a [`ManualClock`].
    #[must_use]
    pub fn with_breaker(
        primary: Arc<dyn KnowledgeGraph>,
        secondary: Arc<dyn KnowledgeGraph>,
        breaker: Arc<CircuitBreaker>,
    ) -> Self {
        Self {
            primary,
            secondary,
            breaker,
        }
    }

    /// Borrow the breaker — tests use this to drive state transitions
    /// and the API layer can expose the snapshot in `/admin/health`.
    #[must_use]
    pub fn breaker(&self) -> Arc<CircuitBreaker> {
        Arc::clone(&self.breaker)
    }

    /// Probe the primary with a lightweight call. Returns `Ok(())` if
    /// the primary is responsive, otherwise an error mirroring the
    /// underlying [`GraphError`].
    ///
    /// We use [`KnowledgeGraph::neighbors`] with a synthetic node id at
    /// depth 1 — every adapter answers this with either an empty `Vec`
    /// (in-memory + the production Neo4j adapter both treat unknown
    /// ids as "no neighbours") or a connection error. That makes the
    /// probe both cheap and free of side effects.
    pub async fn probe_primary(&self) -> Result<(), GraphError> {
        let probe_id = NodeId::new("__sx_graph_fallback_probe__");
        match self.primary.neighbors(&probe_id, 1).await {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Wrapper around [`KnowledgeGraph::find_attack_paths`] that
    /// surfaces the engine + degraded flags. Use this from the API
    /// adapter so the wire DTO can carry the markers.
    #[instrument(skip(self, query))]
    pub async fn find_attack_paths_with_engine(
        &self,
        query: &AttackPathQuery,
    ) -> Result<AttackPathsResponse, GraphError> {
        // Validate up-front so an invalid request never touches either
        // backend — keeps the metric clean.
        query.validate()?;

        // Consult the breaker.
        let decision = self.breaker.on_call().await;
        if matches!(decision, CallDecision::Reject) {
            debug!("graph breaker Open — serving from secondary");
            record_fallback(FallbackReason::BreakerOpen);
            let paths = self.secondary.find_attack_paths(query).await?;
            return Ok(AttackPathsResponse {
                paths,
                engine: GraphEngine::Memory,
                degraded: true,
            });
        }

        match self.primary.find_attack_paths(query).await {
            Ok(paths) => {
                self.breaker.on_success().await;
                Ok(AttackPathsResponse {
                    paths,
                    engine: GraphEngine::Neo4j,
                    degraded: false,
                })
            }
            Err(err) => match classify_primary_error(&err) {
                None => {
                    // Caller fault — do not bump breaker, do not
                    // fall back, propagate as-is.
                    Err(err)
                }
                Some(reason) => {
                    warn!(
                        reason = reason.as_str(),
                        error = %err,
                        "graph primary failed — falling back to in-memory",
                    );
                    self.breaker.on_failure().await;
                    record_fallback(reason);
                    let paths = self.secondary.find_attack_paths(query).await?;
                    Ok(AttackPathsResponse {
                        paths,
                        engine: GraphEngine::Memory,
                        degraded: true,
                    })
                }
            },
        }
    }
}

#[async_trait]
impl KnowledgeGraph for FallbackKnowledgeGraph {
    async fn upsert_node(&self, node: &GraphNode) -> Result<(), GraphError> {
        // Writes go to the primary only. The secondary is read-only
        // from the wrapper's perspective; any seeding must be done by
        // the composition root. This matches the spec — the in-memory
        // backend is a *degraded read* path, not a parallel write
        // mirror.
        match self.breaker.on_call().await {
            CallDecision::Reject => {
                record_fallback(FallbackReason::BreakerOpen);
                Err(GraphError::connection(
                    "graph primary breaker open — writes blocked",
                ))
            }
            CallDecision::Allow => match self.primary.upsert_node(node).await {
                Ok(()) => {
                    self.breaker.on_success().await;
                    Ok(())
                }
                Err(err) => {
                    if let Some(reason) = classify_primary_error(&err) {
                        self.breaker.on_failure().await;
                        record_fallback(reason);
                    }
                    Err(err)
                }
            },
        }
    }

    async fn upsert_edge(&self, edge: &GraphEdge) -> Result<(), GraphError> {
        match self.breaker.on_call().await {
            CallDecision::Reject => {
                record_fallback(FallbackReason::BreakerOpen);
                Err(GraphError::connection(
                    "graph primary breaker open — writes blocked",
                ))
            }
            CallDecision::Allow => match self.primary.upsert_edge(edge).await {
                Ok(()) => {
                    self.breaker.on_success().await;
                    Ok(())
                }
                Err(err) => {
                    if let Some(reason) = classify_primary_error(&err) {
                        self.breaker.on_failure().await;
                        record_fallback(reason);
                    }
                    Err(err)
                }
            },
        }
    }

    async fn find_attack_paths(
        &self,
        query: &AttackPathQuery,
    ) -> Result<Vec<AttackPath>, GraphError> {
        // Delegate to the engine-aware path and drop the flag — keeps
        // the `KnowledgeGraph` trait signature unchanged so existing
        // call sites continue to compile.
        self.find_attack_paths_with_engine(query)
            .await
            .map(|r| r.paths)
    }

    async fn compute_risk_propagation(&self, path_id: &str) -> Result<PropagatedRisk, GraphError> {
        match self.breaker.on_call().await {
            CallDecision::Reject => {
                record_fallback(FallbackReason::BreakerOpen);
                self.secondary.compute_risk_propagation(path_id).await
            }
            CallDecision::Allow => match self.primary.compute_risk_propagation(path_id).await {
                Ok(v) => {
                    self.breaker.on_success().await;
                    Ok(v)
                }
                Err(err) => match classify_primary_error(&err) {
                    None => Err(err),
                    Some(reason) => {
                        self.breaker.on_failure().await;
                        record_fallback(reason);
                        self.secondary.compute_risk_propagation(path_id).await
                    }
                },
            },
        }
    }

    async fn neighbors(&self, node_id: &NodeId, depth: u8) -> Result<Vec<GraphNode>, GraphError> {
        match self.breaker.on_call().await {
            CallDecision::Reject => {
                record_fallback(FallbackReason::BreakerOpen);
                self.secondary.neighbors(node_id, depth).await
            }
            CallDecision::Allow => match self.primary.neighbors(node_id, depth).await {
                Ok(v) => {
                    self.breaker.on_success().await;
                    Ok(v)
                }
                Err(err) => match classify_primary_error(&err) {
                    None => Err(err),
                    Some(reason) => {
                        self.breaker.on_failure().await;
                        record_fallback(reason);
                        self.secondary.neighbors(node_id, depth).await
                    }
                },
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Background reconnect probe
// ---------------------------------------------------------------------------

/// Handle to the background probe task spawned by
/// [`ReconnectProbe::spawn`]. Drop or call [`Self::abort`] to stop the
/// probe; shutting down the wrapper without aborting leaves the task
/// running until tokio shuts the runtime down.
#[derive(Debug)]
pub struct ReconnectProbeHandle {
    handle: JoinHandle<()>,
}

impl ReconnectProbeHandle {
    /// Abort the probe task. Idempotent.
    pub fn abort(&self) {
        self.handle.abort();
    }

    /// Whether the task has finished (gracefully or aborted).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

impl Drop for ReconnectProbeHandle {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Background reconnect-probe task.
///
/// Every [`Self::PROBE_INTERVAL`] the task asks the wrapper to
/// [`FallbackKnowledgeGraph::probe_primary`]. The probe runs only when
/// the breaker is `Open` or `HalfOpen` — there is no point poking a
/// `Closed` breaker. On the first probe success after a degraded
/// period, the breaker is closed via `on_success` and a
/// `graph_primary_recovered_total` counter is bumped.
#[derive(Debug)]
pub struct ReconnectProbe;

impl ReconnectProbe {
    /// HIGH-007 spec — probe every 30 s.
    pub const PROBE_INTERVAL: StdDuration = StdDuration::from_secs(30);

    /// Spawn the probe task. Returns a handle so the composition root
    /// can abort the probe on shutdown.
    #[must_use]
    pub fn spawn(graph: Arc<FallbackKnowledgeGraph>) -> ReconnectProbeHandle {
        Self::spawn_with_interval(graph, Self::PROBE_INTERVAL)
    }

    /// Spawn the probe with a custom interval — used by tests.
    #[must_use]
    pub fn spawn_with_interval(
        graph: Arc<FallbackKnowledgeGraph>,
        interval: StdDuration,
    ) -> ReconnectProbeHandle {
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate first tick so the wrapper has a chance
            // to take traffic before the probe fires.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let snap = graph.breaker.snapshot().await;
                if matches!(snap.state, BreakerState::Closed) {
                    continue;
                }
                match graph.probe_primary().await {
                    Ok(()) => {
                        // Closes the breaker (HalfOpen -> Closed) and
                        // returns the wrapper to primary service.
                        graph.breaker.on_success().await;
                        record_recovery();
                        info!("graph primary recovered — breaker Closed");
                    }
                    Err(err) => {
                        debug!(error = %err, "graph primary still unreachable");
                        // Probe failure does NOT call breaker.on_failure
                        // — the failure threshold is reserved for
                        // user-visible calls. We just leave the breaker
                        // Open and wait for the next tick.
                    }
                }
            }
        });
        ReconnectProbeHandle { handle }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use sx_core::value_object::ids::TenantId;

    use super::*;
    use crate::model::node::NodeKind;
    use crate::service::in_memory_graph::InMemoryKnowledgeGraph;

    // --- Test doubles --------------------------------------------------------

    /// `KnowledgeGraph` impl that returns a configurable error on every
    /// call. Used to drive the breaker into `Open`.
    #[derive(Debug)]
    struct AlwaysFailGraph {
        kind: FailKind,
        call_count: AtomicU32,
    }

    #[derive(Debug, Clone, Copy)]
    enum FailKind {
        Connection,
        Auth,
        InvalidQuery,
    }

    impl AlwaysFailGraph {
        fn new(kind: FailKind) -> Self {
            Self {
                kind,
                call_count: AtomicU32::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.call_count.load(Ordering::SeqCst)
        }

        fn build_err(&self) -> GraphError {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            match self.kind {
                FailKind::Connection => GraphError::connection("bolt timeout"),
                FailKind::Auth => GraphError::connection("authentication failure: unauthorized"),
                FailKind::InvalidQuery => GraphError::invalid_query("bad query"),
            }
        }
    }

    #[async_trait]
    impl KnowledgeGraph for AlwaysFailGraph {
        async fn upsert_node(&self, _node: &GraphNode) -> Result<(), GraphError> {
            Err(self.build_err())
        }
        async fn upsert_edge(&self, _edge: &GraphEdge) -> Result<(), GraphError> {
            Err(self.build_err())
        }
        async fn find_attack_paths(
            &self,
            _query: &AttackPathQuery,
        ) -> Result<Vec<AttackPath>, GraphError> {
            Err(self.build_err())
        }
        async fn compute_risk_propagation(
            &self,
            _path_id: &str,
        ) -> Result<PropagatedRisk, GraphError> {
            Err(self.build_err())
        }
        async fn neighbors(
            &self,
            _node_id: &NodeId,
            _depth: u8,
        ) -> Result<Vec<GraphNode>, GraphError> {
            Err(self.build_err())
        }
    }

    /// Toggleable primary: starts failing, can be flipped to healthy
    /// for the reconnect-probe test.
    #[derive(Debug)]
    struct ToggleGraph {
        healthy: tokio::sync::RwLock<bool>,
    }

    impl ToggleGraph {
        fn new(healthy: bool) -> Self {
            Self {
                healthy: tokio::sync::RwLock::new(healthy),
            }
        }
        async fn set_healthy(&self, v: bool) {
            *self.healthy.write().await = v;
        }
    }

    #[async_trait]
    impl KnowledgeGraph for ToggleGraph {
        async fn upsert_node(&self, _node: &GraphNode) -> Result<(), GraphError> {
            if *self.healthy.read().await {
                Ok(())
            } else {
                Err(GraphError::connection("primary down"))
            }
        }
        async fn upsert_edge(&self, _edge: &GraphEdge) -> Result<(), GraphError> {
            if *self.healthy.read().await {
                Ok(())
            } else {
                Err(GraphError::connection("primary down"))
            }
        }
        async fn find_attack_paths(
            &self,
            _query: &AttackPathQuery,
        ) -> Result<Vec<AttackPath>, GraphError> {
            if *self.healthy.read().await {
                Ok(vec![])
            } else {
                Err(GraphError::connection("primary down"))
            }
        }
        async fn compute_risk_propagation(
            &self,
            path_id: &str,
        ) -> Result<PropagatedRisk, GraphError> {
            if *self.healthy.read().await {
                Ok(PropagatedRisk {
                    path_id: path_id.to_owned(),
                    composite_score: 0.0,
                    bottleneck_node_id: NodeId::new("toggle"),
                })
            } else {
                Err(GraphError::connection("primary down"))
            }
        }
        async fn neighbors(
            &self,
            _node_id: &NodeId,
            _depth: u8,
        ) -> Result<Vec<GraphNode>, GraphError> {
            if *self.healthy.read().await {
                Ok(vec![])
            } else {
                Err(GraphError::connection("primary down"))
            }
        }
    }

    // --- Helpers -------------------------------------------------------------

    fn valid_query() -> AttackPathQuery {
        AttackPathQuery {
            tenant_id: TenantId::new(),
            entry_kind: NodeKind::Asset,
            target_kind: NodeKind::Asset,
            max_depth: 3,
            max_paths: 5,
        }
    }

    // --- Classification ------------------------------------------------------

    #[test]
    fn classify_connection_is_fallback() {
        let r = classify_primary_error(&GraphError::connection("bolt timeout"));
        assert_eq!(r, Some(FallbackReason::Connection));
    }

    #[test]
    fn classify_auth_message_is_auth() {
        let r = classify_primary_error(&GraphError::connection(
            "authentication failed: unauthorized",
        ));
        assert_eq!(r, Some(FallbackReason::Auth));
    }

    #[test]
    fn classify_invalid_query_is_not_fallback() {
        let r = classify_primary_error(&GraphError::invalid_query("bad"));
        assert!(r.is_none());
    }

    #[test]
    fn classify_query_error_is_primary_error() {
        let r = classify_primary_error(&GraphError::query("syntax"));
        assert_eq!(r, Some(FallbackReason::PrimaryError));
    }

    #[test]
    fn classify_tenant_boundary_is_not_fallback() {
        let r = classify_primary_error(&GraphError::tenant_boundary("Asset", "a", "b"));
        assert!(r.is_none());
    }

    // --- Breaker state transitions ------------------------------------------

    #[tokio::test]
    async fn breaker_opens_after_threshold_failures() {
        let clock = Arc::new(ManualClock::new(OffsetDateTime::UNIX_EPOCH));
        let breaker = CircuitBreaker::with_thresholds(
            "test",
            3,
            StdDuration::from_secs(60),
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        for _ in 0..3 {
            breaker.on_failure().await;
        }
        let snap = breaker.snapshot().await;
        assert_eq!(snap.state, BreakerState::Open);
        assert_eq!(snap.consecutive_failures, 3);
    }

    #[tokio::test]
    async fn breaker_stays_closed_under_threshold() {
        let clock = Arc::new(ManualClock::new(OffsetDateTime::UNIX_EPOCH));
        let breaker = CircuitBreaker::with_thresholds(
            "test",
            5,
            StdDuration::from_secs(60),
            clock as Arc<dyn Clock>,
        );
        for _ in 0..4 {
            breaker.on_failure().await;
        }
        let snap = breaker.snapshot().await;
        assert_eq!(snap.state, BreakerState::Closed);
        assert_eq!(snap.consecutive_failures, 4);
    }

    #[tokio::test]
    async fn breaker_rejects_calls_while_open() {
        let clock = Arc::new(ManualClock::new(OffsetDateTime::UNIX_EPOCH));
        let breaker = CircuitBreaker::with_thresholds(
            "test",
            2,
            StdDuration::from_secs(60),
            clock as Arc<dyn Clock>,
        );
        breaker.on_failure().await;
        breaker.on_failure().await;
        assert_eq!(breaker.on_call().await, CallDecision::Reject);
    }

    #[tokio::test]
    async fn breaker_transitions_open_to_halfopen_after_cooldown() {
        let clock = Arc::new(ManualClock::new(OffsetDateTime::UNIX_EPOCH));
        let breaker = CircuitBreaker::with_thresholds(
            "test",
            1,
            StdDuration::from_secs(60),
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        breaker.on_failure().await;
        assert_eq!(breaker.snapshot().await.state, BreakerState::Open);
        // Before cool-down: still rejecting.
        assert_eq!(breaker.on_call().await, CallDecision::Reject);
        // Advance past cool-down.
        clock.advance(StdDuration::from_secs(61)).await;
        assert_eq!(breaker.on_call().await, CallDecision::Allow);
        assert_eq!(breaker.snapshot().await.state, BreakerState::HalfOpen);
    }

    #[tokio::test]
    async fn breaker_halfopen_success_closes() {
        let clock = Arc::new(ManualClock::new(OffsetDateTime::UNIX_EPOCH));
        let breaker = CircuitBreaker::with_thresholds(
            "test",
            1,
            StdDuration::from_secs(60),
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        breaker.on_failure().await;
        clock.advance(StdDuration::from_secs(61)).await;
        let _ = breaker.on_call().await; // HalfOpen
        breaker.on_success().await;
        let snap = breaker.snapshot().await;
        assert_eq!(snap.state, BreakerState::Closed);
        assert_eq!(snap.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn breaker_halfopen_failure_reopens() {
        let clock = Arc::new(ManualClock::new(OffsetDateTime::UNIX_EPOCH));
        let breaker = CircuitBreaker::with_thresholds(
            "test",
            1,
            StdDuration::from_secs(60),
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        breaker.on_failure().await;
        clock.advance(StdDuration::from_secs(61)).await;
        let _ = breaker.on_call().await; // HalfOpen
        breaker.on_failure().await;
        let snap = breaker.snapshot().await;
        assert_eq!(snap.state, BreakerState::Open);
    }

    // --- Wrapper behaviour ---------------------------------------------------

    #[tokio::test]
    async fn primary_success_returns_neo4j_engine() {
        let primary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let wrapper = FallbackKnowledgeGraph::new(primary, secondary);
        let resp = wrapper
            .find_attack_paths_with_engine(&valid_query())
            .await
            .unwrap();
        assert_eq!(resp.engine, GraphEngine::Neo4j);
        assert!(!resp.degraded);
    }

    #[tokio::test]
    async fn primary_connection_error_falls_back_to_secondary() {
        let primary: Arc<dyn KnowledgeGraph> = Arc::new(AlwaysFailGraph::new(FailKind::Connection));
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let wrapper = FallbackKnowledgeGraph::new(primary, secondary);
        let resp = wrapper
            .find_attack_paths_with_engine(&valid_query())
            .await
            .unwrap();
        assert_eq!(resp.engine, GraphEngine::Memory);
        assert!(resp.degraded);
        assert!(resp.paths.is_empty());
    }

    #[tokio::test]
    async fn primary_auth_error_falls_back_and_records_auth_reason() {
        let primary: Arc<dyn KnowledgeGraph> = Arc::new(AlwaysFailGraph::new(FailKind::Auth));
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let wrapper = FallbackKnowledgeGraph::new(primary, secondary);
        let resp = wrapper
            .find_attack_paths_with_engine(&valid_query())
            .await
            .unwrap();
        assert_eq!(resp.engine, GraphEngine::Memory);
        assert!(resp.degraded);
    }

    #[tokio::test]
    async fn primary_invalid_query_is_not_fallback() {
        let primary: Arc<dyn KnowledgeGraph> =
            Arc::new(AlwaysFailGraph::new(FailKind::InvalidQuery));
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let wrapper = FallbackKnowledgeGraph::new(primary, secondary);
        // Wrapper's own validate() runs first → it'd accept ours.
        // The primary's `find_attack_paths` then returns InvalidQuery,
        // which classify_primary_error treats as a caller fault → no
        // fallback, error re-raised.
        let err = wrapper
            .find_attack_paths_with_engine(&valid_query())
            .await
            .unwrap_err();
        assert!(matches!(err, GraphError::InvalidQuery(_)));
        // Breaker must NOT be Open after a caller fault.
        let snap = wrapper.breaker().snapshot().await;
        assert_eq!(snap.state, BreakerState::Closed);
    }

    #[tokio::test]
    async fn breaker_opens_after_five_consecutive_primary_errors() {
        let primary = Arc::new(AlwaysFailGraph::new(FailKind::Connection));
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let wrapper =
            FallbackKnowledgeGraph::new(Arc::clone(&primary) as Arc<dyn KnowledgeGraph>, secondary);
        for _ in 0..5 {
            let _ = wrapper
                .find_attack_paths_with_engine(&valid_query())
                .await
                .unwrap();
        }
        let snap = wrapper.breaker().snapshot().await;
        assert_eq!(snap.state, BreakerState::Open);
        // Primary was hit 5 times — the 6th would short-circuit via
        // the breaker without touching it.
        assert_eq!(primary.calls(), 5);

        // 6th call now short-circuits the primary entirely.
        let resp = wrapper
            .find_attack_paths_with_engine(&valid_query())
            .await
            .unwrap();
        assert_eq!(resp.engine, GraphEngine::Memory);
        assert!(resp.degraded);
        // Primary was NOT touched.
        assert_eq!(primary.calls(), 5);
    }

    #[tokio::test]
    async fn engine_as_str_matches_wire_tag() {
        assert_eq!(GraphEngine::Neo4j.as_str(), "neo4j");
        assert_eq!(GraphEngine::Memory.as_str(), "memory");
        assert!(GraphEngine::Memory.is_degraded());
        assert!(!GraphEngine::Neo4j.is_degraded());
    }

    #[tokio::test]
    async fn writes_propagate_to_primary_only() {
        let primary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let wrapper = FallbackKnowledgeGraph::new(Arc::clone(&primary), Arc::clone(&secondary));
        let node = GraphNode::Asset(crate::model::node::GraphAsset {
            id: NodeId::new("a1"),
            tenant_id: TenantId::new(),
            name: "a1".into(),
            exposure: sx_core::value_object::exposure::ExposureLevel::Internet,
            criticality: sx_core::value_object::criticality::AssetCriticality::Production,
            risk_score: Some(1.0),
            properties: std::collections::BTreeMap::new(),
        });
        wrapper.upsert_node(&node).await.unwrap();
        let primary_concrete = primary.clone();
        let neighbors = primary_concrete
            .neighbors(&NodeId::new("a1"), 0)
            .await
            .unwrap();
        // The in-memory backend echoes the node back at depth 0.
        assert_eq!(neighbors.len(), 1);
    }

    #[tokio::test]
    async fn write_with_open_breaker_returns_connection_error() {
        let clock = Arc::new(ManualClock::new(OffsetDateTime::UNIX_EPOCH));
        let breaker = Arc::new(CircuitBreaker::with_thresholds(
            "test",
            1,
            StdDuration::from_secs(60),
            clock as Arc<dyn Clock>,
        ));
        // Force breaker to Open.
        breaker.on_failure().await;
        let primary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let wrapper = FallbackKnowledgeGraph::with_breaker(primary, secondary, breaker);
        let node = GraphNode::Asset(crate::model::node::GraphAsset {
            id: NodeId::new("a2"),
            tenant_id: TenantId::new(),
            name: "a2".into(),
            exposure: sx_core::value_object::exposure::ExposureLevel::Internet,
            criticality: sx_core::value_object::criticality::AssetCriticality::Production,
            risk_score: Some(1.0),
            properties: std::collections::BTreeMap::new(),
        });
        let err = wrapper.upsert_node(&node).await.unwrap_err();
        assert!(matches!(err, GraphError::Connection(_)));
    }

    // --- Reconnect probe ----------------------------------------------------

    #[tokio::test]
    async fn reconnect_probe_closes_breaker_when_primary_recovers() {
        let primary = Arc::new(ToggleGraph::new(false));
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let breaker = Arc::new(CircuitBreaker::with_thresholds(
            "probe-test",
            1, // Trip immediately.
            StdDuration::from_millis(50),
            Arc::new(SystemClock) as Arc<dyn Clock>,
        ));
        let wrapper = Arc::new(FallbackKnowledgeGraph::with_breaker(
            Arc::clone(&primary) as Arc<dyn KnowledgeGraph>,
            secondary,
            Arc::clone(&breaker),
        ));
        // First call trips the breaker.
        let _ = wrapper
            .find_attack_paths_with_engine(&valid_query())
            .await
            .unwrap();
        assert_eq!(breaker.snapshot().await.state, BreakerState::Open);
        // Heal the primary, kick a short-interval probe.
        primary.set_healthy(true).await;
        let _probe =
            ReconnectProbe::spawn_with_interval(Arc::clone(&wrapper), StdDuration::from_millis(50));
        // Wait long enough for the cool-down + at least one probe tick.
        tokio::time::sleep(StdDuration::from_millis(400)).await;
        let snap = breaker.snapshot().await;
        assert_eq!(snap.state, BreakerState::Closed);
    }

    #[tokio::test]
    async fn fallback_response_serialises_engine_and_degraded() {
        let resp = AttackPathsResponse {
            paths: vec![],
            engine: GraphEngine::Memory,
            degraded: true,
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"engine\":\"memory\""));
        assert!(s.contains("\"degraded\":true"));
    }
}
