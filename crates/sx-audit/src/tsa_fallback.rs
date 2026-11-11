//! CRIT-006 — TSA fallback, circuit breaker, queued retry, and
//! failure-mode classification.
//!
//! Sits on top of [`crate::anchor_external`] (the raw RFC 3161 transport)
//! and provides a *resilient* outer composition: a primary TSA endpoint
//! with N backups, each guarded by its own circuit breaker, plus a
//! per-tenant retry queue for transient outages.
//!
//! ## Why this exists
//!
//! P1-015 assumed the TSA was always reachable. Reality bites: regional
//! DNS hiccups, ISP throttling, TSA operator outages, and even routine
//! cert rotations all manifest as failed anchor runs. Without fallback
//! the audit chain develops gaps; the chain-verifier then escalates the
//! gap as a `BROKEN_CHAIN` CRITICAL — a false positive that paged ops
//! for what was a benign TSA blip.
//!
//! The contract this module enforces:
//!
//! 1. **Multi-TSA**: a tenant's anchor config carries one primary plus a
//!    small Vec of backups. Each TSA has its *own* pinned CA cert (RFC
//!    3161 cert pinning is per-issuer, not global) and its own timeout.
//! 2. **Circuit breaker**: each TSA gets an independent [`CircuitBreaker`].
//!    After [`CircuitBreaker::FAILURE_THRESHOLD`] consecutive failures
//!    the state flips to `Open` and the [`MultiTsaClient`] short-circuits
//!    that endpoint for [`CircuitBreaker::COOL_DOWN`]. After the cool-
//!    down a single probe is allowed (`HalfOpen`); success returns to
//!    `Closed`, failure re-opens.
//! 3. **Failure-mode classification**: not every TSA error is equal. A
//!    transport timeout ([`TsaFailureClass::Unreachable`]) means "queue
//!    + retry, do not page ops". A signature-verification fail
//!    ([`TsaFailureClass::TimestampInvalid`]) means "MitM or compromise
//!    — CRITICAL + IR incident NOW". A malformed body
//!    ([`TsaFailureClass::ResponseMalformed`]) is treated identically
//!    to `TimestampInvalid` because a non-RFC-3161 body strongly suggests
//!    interception.
//! 4. **Queued retry**: failures whose class is `Unreachable` push an
//!    [`AnchorQueueEntry`] onto the per-tenant queue. A separate
//!    [`AnchorQueueRetryer::tick`] re-runs the anchor; on success the
//!    entry transitions to `Recovered`. After
//!    [`AnchorQueueRetryer::RETRY_WINDOW`] without success the entry
//!    flips to `Exhausted` and a `audit.anchor.queue_exhausted` CRITICAL
//!    is emitted.
//! 5. **Pinned CAs stay strict**: the circuit breaker never widens the
//!    trust boundary. A TSA whose response fails the pinned-CA check is
//!    classified as `TimestampInvalid` and never queued.

#![allow(
    clippy::module_name_repetitions,
    clippy::doc_lazy_continuation,
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::needless_pass_by_value,
    clippy::assigning_clones,
    clippy::significant_drop_tightening,
    clippy::option_if_let_else,
    clippy::too_many_lines,
    clippy::single_match_else
)]

use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use sx_core::value_object::ids::TenantId;

use crate::anchor_external::{
    AnchorError, AnchorRequest, FreeTsaClient, MerkleTreeBuilder, TsaAnchorClient,
    TsaAnchorResponse, SHA256_LEN,
};
use crate::anchor_run::{
    AnchorRunError, AnchorRunId, AnchorRunRepository, AnchorRunner, AuditAnchorRun,
    CriticalEventSink, JsonTsaClient, RunOutcome, TenantAnchorConfig, TsaTokenVerifier,
    TsaVerification,
};

// ---------------------------------------------------------------------------
// Failure classification
// ---------------------------------------------------------------------------

/// Failure mode of a single TSA attempt — see module docs.
///
/// The classification is decided exclusively from the error returned by
/// the underlying client; callers never set it manually. This keeps the
/// failure-mode logic in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsaFailureClass {
    /// Network / timeout / non-2xx HTTP — the TSA is up the wrong way of
    /// reachable. Eligible for retry-queue.
    Unreachable,
    /// The TSA replied but the embedded signature failed verification.
    /// Treated as CRITICAL (auto-open IR incident); never queued.
    TimestampInvalid,
    /// The TSA replied but the body shape is not RFC 3161 — strong
    /// suggestion of an interception proxy / captive portal. CRITICAL.
    ResponseMalformed,
}

impl TsaFailureClass {
    /// String tag for logs / metrics / audit events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreachable => "TSA_UNREACHABLE",
            Self::TimestampInvalid => "TSA_TIMESTAMP_INVALID",
            Self::ResponseMalformed => "TSA_RESPONSE_MALFORMED",
        }
    }

    /// Whether the failure is *transient* (queue + retry) or *permanent*
    /// from the caller's point of view (auto-fire incident).
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::Unreachable)
    }
}

/// Heuristically distinguishes a malformed-body verifier failure from a
/// cryptographic signature-invalid failure. A token that does not even
/// parse as the SentinelX JSON wrapper (or whose schema is wrong) yields
/// a "token parse" / "unsupported token version" error — those are
/// `ResponseMalformed`. Everything else (CA-verify / TSA-verify / bad
/// b64) is `TimestampInvalid`.
#[must_use]
pub fn is_malformed_token_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("token parse")
        || lower.contains("unsupported token version")
        || lower.contains("not a der sequence")
        || lower.contains("response is not")
        || lower.contains("malformed")
        || lower.contains("expected value")
}

/// Classify an [`AnchorError`] returned by the underlying transport.
///
/// Transport errors are `Unreachable`; `InvalidResponse` is
/// `ResponseMalformed`; `TimeFormat` / `DerEncoding` / `EmptyTree` are
/// *programmer* errors and not produced by the network, so they map
/// conservatively to `Unreachable` (the queue will give the operator a
/// chance to fix config). Verifier errors are classified by the wrapping
/// orchestrator, not here — see [`MultiTsaError`].
#[must_use]
pub const fn classify_anchor_error(err: &AnchorError) -> TsaFailureClass {
    match err {
        AnchorError::Transport(_) => TsaFailureClass::Unreachable,
        AnchorError::InvalidResponse(_) => TsaFailureClass::ResponseMalformed,
        AnchorError::EmptyTree | AnchorError::DerEncoding(_) | AnchorError::TimeFormat(_) => {
            // Conservative — these never happen on a real TSA wire,
            // so we shove them into the queue rather than auto-page.
            TsaFailureClass::Unreachable
        }
    }
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

/// Per-endpoint circuit-breaker state — see module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    /// All systems go — traffic flows.
    Closed,
    /// Cooling down — traffic is short-circuited until
    /// `opened_at + cool_down`.
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

/// Outcome of [`CircuitBreaker::on_call`] — what the caller should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDecision {
    /// Caller MAY execute the protected operation.
    Allow,
    /// Caller MUST short-circuit; the breaker is `Open`.
    Reject,
}

/// Snapshot of internal counters — handy for assertions in tests and for
/// metrics export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerSnapshot {
    /// Current state.
    pub state: BreakerState,
    /// Consecutive failure count since the last success.
    pub consecutive_failures: u32,
    /// Total successes observed.
    pub total_successes: u64,
    /// Total failures observed.
    pub total_failures: u64,
    /// Total rejections (calls short-circuited while `Open`).
    pub total_rejections: u64,
    /// Wall-clock instant the breaker last flipped to `Open`. Optional —
    /// `None` if the breaker has never opened.
    pub opened_at: Option<OffsetDateTime>,
}

/// Shared mutable state behind a [`CircuitBreaker`].
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

/// Trait abstracting "what time is it now" so unit tests can advance the
/// clock without sleeping.
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

/// Manually-driven clock — only for tests.
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
        // Synchronous read — we use try_lock + fallback to avoid
        // blocking. The mutex contention is negligible in tests.
        self.inner
            .try_lock()
            .map_or(OffsetDateTime::UNIX_EPOCH, |g| *g)
    }
}

/// Per-endpoint circuit breaker.
///
/// `Closed -> Open` after `FAILURE_THRESHOLD` consecutive failures.
/// `Open -> HalfOpen` after `COOL_DOWN` elapses.
/// `HalfOpen -> Closed` on the next success, or back to `Open` on
/// failure.
///
/// All state lives behind a [`Mutex`] so multiple in-flight calls share
/// the same view. Contention is irrelevant — anchor calls are seconds-
/// scale, not microseconds-scale.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Human-readable label for logs / metrics.
    label: String,
    /// Failure threshold before the breaker opens.
    failure_threshold: u32,
    /// Cool-down after which an `Open` breaker transitions to `HalfOpen`.
    cool_down: StdDuration,
    /// Shared clock — production uses [`SystemClock`].
    clock: Arc<dyn Clock>,
    /// Mutex-guarded counters / state.
    inner: Mutex<BreakerInner>,
}

impl CircuitBreaker {
    /// Failure threshold — three consecutive errors trips the breaker
    /// (per CRIT-006 spec).
    pub const FAILURE_THRESHOLD: u32 = 3;
    /// Cool-down before the breaker transitions `Open -> HalfOpen` (per
    /// spec).
    pub const COOL_DOWN: StdDuration = StdDuration::from_secs(60);

    /// New breaker with the spec defaults and a [`SystemClock`].
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self::with_clock(label, Arc::new(SystemClock))
    }

    /// New breaker with a caller-supplied clock — used by tests to
    /// advance the wall-clock without sleeping.
    #[must_use]
    pub fn with_clock(label: impl Into<String>, clock: Arc<dyn Clock>) -> Self {
        Self {
            label: label.into(),
            failure_threshold: Self::FAILURE_THRESHOLD,
            cool_down: Self::COOL_DOWN,
            clock,
            inner: Mutex::new(BreakerInner::new()),
        }
    }

    /// New breaker with custom thresholds — used by tests that want a
    /// tighter threshold.
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

    /// The breaker's label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Ask the breaker whether the caller may execute the protected
    /// operation. Side effect: transitions `Open -> HalfOpen` when the
    /// cool-down has expired, and counts rejections.
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
                    debug!(label = %self.label, "circuit breaker Open -> HalfOpen");
                    g.state = BreakerState::HalfOpen;
                    CallDecision::Allow
                } else {
                    g.total_rejections = g.total_rejections.saturating_add(1);
                    CallDecision::Reject
                }
            }
        }
    }

    /// Record a successful call — resets the failure counter and closes
    /// the breaker if it was `HalfOpen`.
    pub async fn on_success(&self) {
        let mut g = self.inner.lock().await;
        g.total_successes = g.total_successes.saturating_add(1);
        g.consecutive_failures = 0;
        if g.state != BreakerState::Closed {
            info!(label = %self.label, prev = g.state.as_str(), "circuit breaker -> Closed");
            g.state = BreakerState::Closed;
            g.opened_at = None;
        }
    }

    /// Record a failed call — bumps the failure counter and may flip the
    /// breaker to `Open`.
    pub async fn on_failure(&self) {
        let now = self.clock.now();
        let mut g = self.inner.lock().await;
        g.total_failures = g.total_failures.saturating_add(1);
        g.consecutive_failures = g.consecutive_failures.saturating_add(1);
        match g.state {
            BreakerState::HalfOpen => {
                // A probe failed in HalfOpen — re-open immediately.
                warn!(label = %self.label, "circuit breaker HalfOpen -> Open (probe failed)");
                g.state = BreakerState::Open;
                g.opened_at = Some(now);
            }
            BreakerState::Closed if g.consecutive_failures >= self.failure_threshold => {
                warn!(
                    label = %self.label,
                    consecutive = g.consecutive_failures,
                    "circuit breaker Closed -> Open (threshold breached)",
                );
                g.state = BreakerState::Open;
                g.opened_at = Some(now);
            }
            // Closed but below threshold, or already Open — nothing to
            // do beyond the counters.
            BreakerState::Closed | BreakerState::Open => {}
        }
    }

    /// Snapshot for tests / metrics.
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
// Multi-TSA endpoint config
// ---------------------------------------------------------------------------

/// One TSA endpoint inside a [`MultiTsaConfig`].
#[derive(Debug, Clone)]
pub struct TsaEndpoint {
    /// TSA URL (e.g. `https://freetsa.org/tsr`).
    pub url: String,
    /// Pinned per-issuer CA PEM — RSA SPKI, matching
    /// [`crate::anchor_run::DefaultTsaTokenVerifier`].
    pub ca_pem: String,
    /// Human label (used for logs + circuit-breaker keys). Optional —
    /// when omitted we derive from the URL host.
    pub label: Option<String>,
    /// Per-endpoint request timeout. Default 30 s per spec.
    pub timeout: StdDuration,
}

impl TsaEndpoint {
    /// Spec default — 30 s.
    pub const DEFAULT_TIMEOUT: StdDuration = StdDuration::from_secs(30);

    /// Convenience constructor.
    #[must_use]
    pub fn new(url: impl Into<String>, ca_pem: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ca_pem: ca_pem.into(),
            label: None,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// Effective label — explicit override or URL host.
    #[must_use]
    pub fn effective_label(&self) -> String {
        if let Some(l) = self.label.as_ref() {
            return l.clone();
        }
        self.url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("unknown")
            .to_owned()
    }
}

/// Per-tenant multi-TSA configuration backing the
/// `audit_tsa_config` table.
#[derive(Debug, Clone)]
pub struct MultiTsaConfig {
    /// Tenant the row scopes to.
    pub tenant_id: TenantId,
    /// Primary endpoint.
    pub primary: TsaEndpoint,
    /// Ordered backups — `Vec<>` rather than fixed-size so operators
    /// can drop a single backup without re-deploying. The spec
    /// recommends two.
    pub backups: Vec<TsaEndpoint>,
    /// Minimum TSAs that must successfully sign before a quorum anchor
    /// record is accepted. Defaults to `1` (legacy first-wins
    /// behaviour); MED-002 raises the operational default to `2` via
    /// [`crate::tsa_fallback::DEFAULT_QUORUM_REQUIRED`].
    pub quorum_required: usize,
    /// Target fan-out — the orchestrator attempts to collect this many
    /// signatures before deciding the run was successful. MUST be
    /// `>= quorum_required` and `<= endpoint_count()`. Excess endpoints
    /// past `quorum_total` are reserved as breaker-recovery probes.
    pub quorum_total: usize,
}

/// Default quorum ratio shipped by MED-002 — 2-of-3.
pub const DEFAULT_QUORUM_REQUIRED: usize = 2;
/// Default target fan-out shipped by MED-002 — 2-of-3.
pub const DEFAULT_QUORUM_TOTAL: usize = 3;

impl MultiTsaConfig {
    /// Total endpoint count — primary + backups.
    #[must_use]
    pub const fn endpoint_count(&self) -> usize {
        self.backups.len().saturating_add(1)
    }

    /// Iterator over `(index, endpoint)` in fallback order (primary
    /// first).
    pub fn endpoints(&self) -> impl Iterator<Item = (usize, &TsaEndpoint)> {
        std::iter::once(&self.primary)
            .chain(self.backups.iter())
            .enumerate()
    }

    /// Effective quorum-required, clamped into `[1, endpoint_count]`
    /// so an over-zealous operator config can never produce an
    /// impossible target (e.g. 3 required but only 2 endpoints
    /// configured). Callers MUST funnel decisions through this
    /// accessor rather than read the raw field.
    #[must_use]
    pub fn effective_quorum_required(&self) -> usize {
        self.quorum_required.max(1).min(self.endpoint_count())
    }

    /// Effective quorum-total, clamped into `[effective_quorum_required, endpoint_count]`.
    #[must_use]
    pub fn effective_quorum_total(&self) -> usize {
        self.quorum_total
            .max(self.effective_quorum_required())
            .min(self.endpoint_count())
    }
}

// ---------------------------------------------------------------------------
// Quorum anchor record (MED-002)
// ---------------------------------------------------------------------------

/// Verification status of one TSA signature inside a quorum anchor.
///
/// Set at *anchor time* by the orchestrator (`Verified` if the response
/// satisfied the pinned CA and the Merkle root matched what we sent;
/// `Failed` if the per-TSA verify call rejected the token). The same
/// flag is later updated by [`crate::anchor_run::AnchorRunner::verify_run_quorum`]
/// when an operator re-checks the persisted record — a TSA that has
/// since rotated its keys or been decommissioned shows up as
/// `Failed`, but as long as the quorum still holds the record stays
/// trustworthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumSignatureStatus {
    /// Pinned-CA + Merkle-root check both passed.
    Verified,
    /// Pinned-CA verify failed (signature invalid, CA decommissioned,
    /// merkle root mismatch). The signature is recorded so an
    /// investigator can re-examine, but it does NOT count toward the
    /// quorum.
    Failed,
    /// TSA was attempted at anchor time but produced no token (network
    /// error, breaker `Open`, etc.). The slot is preserved so the
    /// record's shape carries the full m for `m`-of-`n` accounting.
    NotAttempted,
}

impl QuorumSignatureStatus {
    /// String tag for logs / metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::NotAttempted => "not_attempted",
        }
    }

    /// Whether this signature counts toward the quorum.
    #[must_use]
    pub const fn counts_toward_quorum(self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// One TSA's contribution to a quorum anchor.
///
/// The token bytes are stored verbatim so the record can be re-verified
/// at any future point without re-contacting the TSA. The HTTP surface
/// MUST NOT expose `token` (only its length); see
/// [`crate::anchor_run::AuditAnchorRun::payload_bytes`] for the
/// engineering bar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumTsaSignature {
    /// Endpoint label as it appeared in [`MultiTsaConfig`].
    pub label: String,
    /// TSA-issued serial number (hex string). Empty when `status` is
    /// [`QuorumSignatureStatus::NotAttempted`] or `Failed` without a
    /// parseable token.
    pub tsa_serial: String,
    /// `genTime` extracted from the TSA reply, RFC 3339. The Unix
    /// epoch placeholder is used when no token was obtained.
    #[serde(with = "time::serde::rfc3339")]
    pub tsa_gen_time: OffsetDateTime,
    /// Raw TSA reply bytes — base64-encoded on the wire. Empty when
    /// `status` is `NotAttempted` or `Failed` pre-token-parse.
    #[serde(with = "bytes_b64_serde_opt")]
    pub token: Vec<u8>,
    /// Verification status as of the most recent verify pass.
    pub status: QuorumSignatureStatus,
    /// Optional reason string captured when `status` is `Failed` —
    /// surfaces back to the SOC investigator without re-running the
    /// verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl QuorumTsaSignature {
    /// New `NotAttempted` slot for `label` — used to pre-populate the
    /// m-of-n shape before any TSA call.
    #[must_use]
    pub fn not_attempted(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            tsa_serial: String::new(),
            tsa_gen_time: OffsetDateTime::UNIX_EPOCH,
            token: Vec::new(),
            status: QuorumSignatureStatus::NotAttempted,
            reason: None,
        }
    }
}

/// The quorum decision recorded alongside an anchor row.
///
/// Stored as a JSONB sidecar in the production Postgres schema (column
/// `audit_anchor_runs.quorum`); the in-memory adapter serialises through
/// `serde_json` end-to-end. Backward-compat: legacy rows produced before
/// MED-002 carry `None` on [`crate::anchor_run::AuditAnchorRun::quorum`]
/// and continue to round-trip through the existing verify-run path
/// unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumAnchorRecord {
    /// Minimum verified signatures required to accept the record
    /// (`n` of `m`). At anchor time the orchestrator refuses to persist
    /// if fewer than `required` verified; at verify time the API
    /// refuses to declare the record trustworthy if fewer than
    /// `required` still verify.
    pub required: u32,
    /// Target fan-out (`m` of `n`). Always `>= required` and `<= number
    /// of configured endpoints`.
    pub total: u32,
    /// Per-TSA signature slots — one entry per endpoint, primary first.
    /// Length is `<= total` at anchor time; verify-time updates mutate
    /// `status` in place without changing slot identity (`label`).
    pub signatures: Vec<QuorumTsaSignature>,
    /// Label of the TSA whose token was promoted to
    /// [`crate::anchor_run::AuditAnchorRun::payload_bytes`] — the "anchor
    /// leader" so the legacy verify-run path stays back-compat.
    pub leader_label: String,
}

impl QuorumAnchorRecord {
    /// Count signatures that currently `counts_toward_quorum`.
    #[must_use]
    pub fn verified_count(&self) -> usize {
        self.signatures
            .iter()
            .filter(|s| s.status.counts_toward_quorum())
            .count()
    }

    /// Whether the verified count is at least [`Self::required`].
    #[must_use]
    pub fn meets_quorum(&self) -> bool {
        u32::try_from(self.verified_count())
            .map(|c| c >= self.required)
            .unwrap_or(false)
    }

    /// Labels of TSAs currently verified.
    #[must_use]
    pub fn verified_labels(&self) -> Vec<String> {
        self.signatures
            .iter()
            .filter(|s| s.status.counts_toward_quorum())
            .map(|s| s.label.clone())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Dev-fixture defaults (FreeTSA, Sectigo, DigiCert, GlobalSign)
// ---------------------------------------------------------------------------

/// Empty placeholder CA PEM marker. Dev fixtures use this sentinel — a
/// real deployment MUST replace each CA PEM with the real issuer's
/// pinned public key before any live anchor call. The verifier will
/// refuse the marker, by design, so a misconfigured production drop
/// surfaces immediately rather than silently trusting nothing.
pub const DEV_PLACEHOLDER_CA_PEM: &str =
    "-----BEGIN PUBLIC KEY-----\nDEV_PLACEHOLDER_REPLACE_ME\n-----END PUBLIC KEY-----\n";

/// Dev-fixture TSA list shipped per spec. Production deployments MUST
/// override the CA PEMs.
#[must_use]
pub fn default_dev_endpoints() -> Vec<TsaEndpoint> {
    vec![
        TsaEndpoint {
            url: "https://freetsa.org/tsr".to_owned(),
            ca_pem: DEV_PLACEHOLDER_CA_PEM.to_owned(),
            label: Some("freetsa".to_owned()),
            timeout: TsaEndpoint::DEFAULT_TIMEOUT,
        },
        TsaEndpoint {
            url: "http://timestamp.sectigo.com".to_owned(),
            ca_pem: DEV_PLACEHOLDER_CA_PEM.to_owned(),
            label: Some("sectigo".to_owned()),
            timeout: TsaEndpoint::DEFAULT_TIMEOUT,
        },
        TsaEndpoint {
            url: "http://timestamp.digicert.com".to_owned(),
            ca_pem: DEV_PLACEHOLDER_CA_PEM.to_owned(),
            label: Some("digicert".to_owned()),
            timeout: TsaEndpoint::DEFAULT_TIMEOUT,
        },
        TsaEndpoint {
            url: "http://rfc3161timestamp.globalsign.com/standard".to_owned(),
            ca_pem: DEV_PLACEHOLDER_CA_PEM.to_owned(),
            label: Some("globalsign".to_owned()),
            timeout: TsaEndpoint::DEFAULT_TIMEOUT,
        },
    ]
}

// ---------------------------------------------------------------------------
// Multi-TSA client (TsaAnchorClient impl)
// ---------------------------------------------------------------------------

/// Error returned from [`MultiTsaClient`] when every endpoint either
/// failed or was short-circuited by its breaker.
#[derive(Debug, Error)]
pub enum MultiTsaError {
    /// At least one endpoint actually fired but the final classification
    /// after the cascade was `Unreachable` — caller should queue + retry.
    #[error("all tsa endpoints unreachable: tried {tried} endpoints")]
    AllUnreachable {
        /// Number of endpoints attempted.
        tried: usize,
        /// Best-effort summary of last per-endpoint failure.
        last_label: String,
        /// Last underlying error message.
        last_message: String,
    },
    /// A TSA replied but the embedded signature failed verification —
    /// CRITICAL.
    #[error("tsa signature invalid at {label}: {message}")]
    SignatureInvalid {
        /// Label of the endpoint that produced the invalid signature.
        label: String,
        /// Detail message.
        message: String,
    },
    /// A TSA replied with a body whose shape is not RFC 3161 — CRITICAL
    /// (suggests MitM).
    #[error("tsa response malformed at {label}: {message}")]
    ResponseMalformed {
        /// Label of the offending endpoint.
        label: String,
        /// Detail message.
        message: String,
    },
}

impl MultiTsaError {
    /// Map back to a [`TsaFailureClass`].
    #[must_use]
    pub const fn class(&self) -> TsaFailureClass {
        match self {
            Self::AllUnreachable { .. } => TsaFailureClass::Unreachable,
            Self::SignatureInvalid { .. } => TsaFailureClass::TimestampInvalid,
            Self::ResponseMalformed { .. } => TsaFailureClass::ResponseMalformed,
        }
    }
}

/// `TsaAnchorClient` that fans out to a list of endpoints, each guarded
/// by its own circuit breaker.
///
/// Iteration order is primary -> backups. For each endpoint the breaker
/// is consulted first; if it `Reject`s the endpoint is skipped. If the
/// underlying [`FreeTsaClient`] returns `Ok`, the breaker is informed
/// of success and the response is returned immediately. On failure the
/// breaker is bumped and we move to the next endpoint.
///
/// On a non-transient failure (response is malformed, suggesting MitM)
/// we short-circuit the cascade and return immediately so the caller
/// can fire a CRITICAL — there is no point trying backups for a MitM.
#[derive(Debug)]
pub struct MultiTsaClient {
    /// `Vec<(label, FreeTsaClient, CircuitBreaker)>` — one slot per
    /// endpoint, primary first.
    endpoints: Vec<EndpointSlot>,
}

#[derive(Debug)]
struct EndpointSlot {
    label: String,
    client: Arc<dyn TsaAnchorClient>,
    breaker: Arc<CircuitBreaker>,
}

impl MultiTsaClient {
    /// Build a client from a [`MultiTsaConfig`]. Each endpoint gets its
    /// own [`CircuitBreaker`] with the spec defaults and a
    /// [`SystemClock`].
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::Transport`] if reqwest cannot build a
    /// pinned-feature client for any endpoint (typically only at boot
    /// on hosts without the rustls feature).
    pub fn from_config(cfg: &MultiTsaConfig) -> Result<Self, AnchorError> {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        Self::from_config_with_clock(cfg, clock)
    }

    /// Same as [`Self::from_config`] but with a caller-supplied clock so
    /// integration tests can advance time deterministically.
    pub fn from_config_with_clock(
        cfg: &MultiTsaConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AnchorError> {
        let mut endpoints = Vec::with_capacity(cfg.endpoint_count());
        for (idx, ep) in cfg.endpoints() {
            let label = ep.effective_label();
            // Use the SentinelX JSON-wrapper TSA client — it accepts any
            // non-empty response body and surfaces malformed bodies
            // through the verifier. The classic `FreeTsaClient` enforces
            // an RFC-3161 DER prologue at the transport layer and is
            // wrapped separately by callers who speak raw RFC 3161.
            let client: Arc<dyn TsaAnchorClient> =
                Arc::new(JsonTsaClient::new(&ep.url)?.with_provider(label.clone()));
            let breaker = Arc::new(CircuitBreaker::with_thresholds(
                label.clone(),
                CircuitBreaker::FAILURE_THRESHOLD,
                CircuitBreaker::COOL_DOWN,
                Arc::clone(&clock),
            ));
            debug!(
                idx,
                url = %ep.url,
                label = %label,
                "multi-tsa endpoint registered",
            );
            endpoints.push(EndpointSlot {
                label,
                client,
                breaker,
            });
        }
        Ok(Self { endpoints })
    }

    /// Number of endpoints registered.
    #[must_use]
    pub const fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Borrow the circuit breaker for the endpoint at `idx`. Returns
    /// `None` if `idx` is out of range. Useful for tests + metrics.
    #[must_use]
    pub fn breaker(&self, idx: usize) -> Option<Arc<CircuitBreaker>> {
        self.endpoints
            .get(idx)
            .map(|slot| Arc::clone(&slot.breaker))
    }

    /// Borrow the label for the endpoint at `idx`.
    #[must_use]
    pub fn label(&self, idx: usize) -> Option<&str> {
        self.endpoints.get(idx).map(|slot| slot.label.as_str())
    }

    /// Run the fallback cascade.
    ///
    /// The return distinguishes the structured failure modes so the
    /// orchestrator above can route them correctly (queue vs. CRITICAL).
    #[instrument(skip_all, fields(endpoints = self.endpoints.len()))]
    pub async fn anchor_with_fallback(
        &self,
        req: &AnchorRequest,
    ) -> Result<TsaAnchorResponse, MultiTsaError> {
        let mut tried = 0usize;
        let mut last_label = String::new();
        let mut last_message = String::from("no endpoints attempted");
        for (idx, slot) in self.endpoints.iter().enumerate() {
            // Consult the breaker first.
            let decision = slot.breaker.on_call().await;
            if matches!(decision, CallDecision::Reject) {
                debug!(
                    idx,
                    label = %slot.label,
                    "skipping endpoint — breaker Open",
                );
                continue;
            }
            tried = tried.saturating_add(1);
            last_label.clone_from(&slot.label);
            match slot.client.anchor(req).await {
                Ok(resp) => {
                    slot.breaker.on_success().await;
                    info!(
                        idx,
                        label = %slot.label,
                        "tsa anchor succeeded",
                    );
                    return Ok(resp);
                }
                Err(err) => {
                    let class = classify_anchor_error(&err);
                    last_message = err.to_string();
                    warn!(
                        idx,
                        label = %slot.label,
                        class = class.as_str(),
                        error = %err,
                        "tsa anchor failed",
                    );
                    slot.breaker.on_failure().await;
                    if matches!(class, TsaFailureClass::ResponseMalformed) {
                        // MitM-shaped — bail out immediately. There is
                        // no point cascading to backups: an attacker who
                        // can mangle one TSA reply can mangle all of
                        // them.
                        return Err(MultiTsaError::ResponseMalformed {
                            label: slot.label.clone(),
                            message: last_message,
                        });
                    }
                    // Else fall through to the next endpoint.
                }
            }
        }
        Err(MultiTsaError::AllUnreachable {
            tried,
            last_label,
            last_message,
        })
    }

    /// MED-002 — Collect signatures from `quorum_total` TSAs (or as many
    /// as can be reached) and return all attempts.
    ///
    /// Unlike [`Self::anchor_with_fallback`], this does NOT short-circuit
    /// on the first success — it walks the endpoint list trying every
    /// breaker-`Closed` slot until either:
    ///
    /// 1. it has collected `quorum_total` successful responses
    ///    (`Ok(..)` from the underlying client), OR
    /// 2. every endpoint has been attempted (Open breakers count as
    ///    `NotAttempted` slots so the m-of-n shape is preserved).
    ///
    /// The caller (typically [`ResilientAnchorRunner::run_once_quorum`])
    /// is responsible for running the per-token signature verifier and
    /// classifying which entries actually count toward the quorum.
    ///
    /// **MitM short-circuit.** As with the legacy cascade, a
    /// `ResponseMalformed` reply still trips the cascade — once any TSA
    /// returns a non-RFC-3161 body we stop collecting and return the
    /// malformed marker so the orchestrator can fire a CRITICAL. There
    /// is no benefit to gathering more "signatures" from an environment
    /// where an interception proxy is rewriting at least one of them.
    #[instrument(skip_all, fields(endpoints = self.endpoints.len(), quorum_total))]
    pub async fn collect_quorum_attempts(
        &self,
        req: &AnchorRequest,
        quorum_total: usize,
    ) -> Result<Vec<QuorumAttempt>, MultiTsaError> {
        let mut attempts: Vec<QuorumAttempt> = Vec::with_capacity(self.endpoints.len());
        let mut successes = 0usize;
        let target = quorum_total.max(1).min(self.endpoints.len());
        for (idx, slot) in self.endpoints.iter().enumerate() {
            if successes >= target {
                // We have enough attempted-successful responses; preserve
                // the remaining endpoints as `NotAttempted` slots so the
                // record carries the full m-of-n shape.
                attempts.push(QuorumAttempt {
                    label: slot.label.clone(),
                    outcome: QuorumAttemptOutcome::NotAttempted,
                });
                continue;
            }
            // Breaker check — Open endpoints contribute a NotAttempted slot.
            let decision = slot.breaker.on_call().await;
            if matches!(decision, CallDecision::Reject) {
                debug!(
                    idx,
                    label = %slot.label,
                    "quorum: skipping endpoint — breaker Open",
                );
                attempts.push(QuorumAttempt {
                    label: slot.label.clone(),
                    outcome: QuorumAttemptOutcome::NotAttempted,
                });
                continue;
            }
            match slot.client.anchor(req).await {
                Ok(resp) => {
                    slot.breaker.on_success().await;
                    successes = successes.saturating_add(1);
                    info!(
                        idx,
                        label = %slot.label,
                        "quorum: tsa anchor succeeded",
                    );
                    attempts.push(QuorumAttempt {
                        label: slot.label.clone(),
                        outcome: QuorumAttemptOutcome::Success(resp),
                    });
                }
                Err(err) => {
                    let class = classify_anchor_error(&err);
                    let msg = err.to_string();
                    warn!(
                        idx,
                        label = %slot.label,
                        class = class.as_str(),
                        error = %err,
                        "quorum: tsa anchor failed",
                    );
                    slot.breaker.on_failure().await;
                    if matches!(class, TsaFailureClass::ResponseMalformed) {
                        // Same MitM short-circuit as the legacy cascade.
                        return Err(MultiTsaError::ResponseMalformed {
                            label: slot.label.clone(),
                            message: msg,
                        });
                    }
                    attempts.push(QuorumAttempt {
                        label: slot.label.clone(),
                        outcome: QuorumAttemptOutcome::Failed(msg),
                    });
                }
            }
        }
        Ok(attempts)
    }
}

/// One TSA attempt inside [`MultiTsaClient::collect_quorum_attempts`].
#[derive(Debug)]
pub struct QuorumAttempt {
    /// Endpoint label as it appeared in [`MultiTsaConfig`].
    pub label: String,
    /// What happened.
    pub outcome: QuorumAttemptOutcome,
}

/// Outcome of one [`QuorumAttempt`].
#[derive(Debug)]
pub enum QuorumAttemptOutcome {
    /// TSA returned a response — caller still needs to verify the
    /// embedded signature against the pinned CA.
    Success(TsaAnchorResponse),
    /// TSA returned an error (network / non-2xx / etc.). The reason is
    /// preserved for the audit log.
    Failed(String),
    /// Endpoint was skipped entirely — either the breaker was Open or
    /// we already collected enough successes earlier in the iteration.
    NotAttempted,
}

#[async_trait]
impl TsaAnchorClient for MultiTsaClient {
    async fn anchor(&self, req: &AnchorRequest) -> Result<TsaAnchorResponse, AnchorError> {
        match self.anchor_with_fallback(req).await {
            Ok(resp) => Ok(resp),
            Err(MultiTsaError::AllUnreachable { last_message, .. }) => {
                Err(AnchorError::Transport(last_message))
            }
            // SignatureInvalid is produced only by the orchestrator that
            // wraps a verifier — the raw transport never reaches that
            // branch via the `TsaAnchorClient` trait. Both invalid-
            // signature and malformed-body map to `InvalidResponse` so
            // the caller sees a single "not-trustworthy reply" code.
            Err(
                MultiTsaError::ResponseMalformed { message, .. }
                | MultiTsaError::SignatureInvalid { message, .. },
            ) => Err(AnchorError::InvalidResponse(message)),
        }
    }
}

// ---------------------------------------------------------------------------
// Anchor retry queue
// ---------------------------------------------------------------------------

/// Status of an [`AnchorQueueEntry`] — see module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorQueueStatus {
    /// Awaiting retry — the retryer will pick it up.
    Pending,
    /// Successfully re-anchored — terminal.
    Recovered,
    /// Window stayed beyond `RETRY_WINDOW` without success — terminal,
    /// CRITICAL emitted.
    Exhausted,
}

impl AnchorQueueStatus {
    /// Lowercase tag for serialisation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Recovered => "recovered",
            Self::Exhausted => "exhausted",
        }
    }
}

/// One row of the `audit_anchor_queue` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorQueueEntry {
    /// Stable opaque queue id.
    pub queue_id: Uuid,
    /// Tenant scoping the entry.
    pub tenant_id: TenantId,
    /// Inclusive lower bound of the missed window (UTC RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub window_start: OffsetDateTime,
    /// Inclusive upper bound of the missed window.
    #[serde(with = "time::serde::rfc3339")]
    pub window_end: OffsetDateTime,
    /// Inclusive audit seq pair the window covers.
    pub audit_seqs: (u64, u64),
    /// Merkle root the orchestrator computed at first attempt — replayed
    /// verbatim by the retryer so the proof binds to the same window.
    #[serde(with = "hex_array_serde")]
    pub merkle_root: [u8; SHA256_LEN],
    /// Pre-computed chain hashes — kept so the retryer can re-run the
    /// pipeline without re-reading the audit log. In production this is
    /// stored as a `BYTEA[]`; the in-memory adapter mirrors that.
    pub chain_hashes: Vec<[u8; SHA256_LEN]>,
    /// Wall-clock of the original failure.
    #[serde(with = "time::serde::rfc3339")]
    pub queued_at: OffsetDateTime,
    /// Number of retry attempts already performed.
    pub attempts: u32,
    /// Current status.
    pub status: AnchorQueueStatus,
    /// Reason recorded with the original failure.
    pub last_failure_reason: String,
}

/// Repository port for the `audit_anchor_queue` table.
#[async_trait]
pub trait AnchorQueueRepository: Send + Sync + std::fmt::Debug {
    /// Enqueue a freshly-failed window for retry.
    async fn enqueue(&self, entry: AnchorQueueEntry) -> Result<(), AnchorRunError>;

    /// List `Pending` entries for `tenant_id` (newest first), capped at
    /// `limit`.
    async fn list_pending(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<Vec<AnchorQueueEntry>, AnchorRunError>;

    /// List ALL `Pending` entries across every tenant — used by the
    /// global retryer tick. Returns rows newest-first capped at `limit`.
    async fn list_all_pending(&self, limit: usize)
        -> Result<Vec<AnchorQueueEntry>, AnchorRunError>;

    /// Transition a Pending row to `Recovered`.
    async fn mark_recovered(
        &self,
        tenant_id: &TenantId,
        queue_id: Uuid,
    ) -> Result<(), AnchorRunError>;

    /// Transition a Pending row to `Exhausted`.
    async fn mark_exhausted(
        &self,
        tenant_id: &TenantId,
        queue_id: Uuid,
        reason: &str,
    ) -> Result<(), AnchorRunError>;

    /// Bump the attempt counter + record the latest failure reason on a
    /// row that stays Pending.
    async fn bump_attempt(
        &self,
        tenant_id: &TenantId,
        queue_id: Uuid,
        reason: &str,
    ) -> Result<(), AnchorRunError>;
}

/// In-memory queue — dev / test default.
#[derive(Debug, Default)]
pub struct InMemoryAnchorQueueRepository {
    inner: Mutex<Vec<AnchorQueueEntry>>,
}

impl InMemoryAnchorQueueRepository {
    /// New empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot all entries (any status) — handy in tests.
    pub async fn snapshot(&self) -> Vec<AnchorQueueEntry> {
        self.inner.lock().await.clone()
    }
}

#[async_trait]
impl AnchorQueueRepository for InMemoryAnchorQueueRepository {
    async fn enqueue(&self, entry: AnchorQueueEntry) -> Result<(), AnchorRunError> {
        self.inner.lock().await.push(entry);
        Ok(())
    }

    async fn list_pending(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<Vec<AnchorQueueEntry>, AnchorRunError> {
        let mut rows: Vec<AnchorQueueEntry> = self
            .inner
            .lock()
            .await
            .iter()
            .filter(|e| &e.tenant_id == tenant_id && e.status == AnchorQueueStatus::Pending)
            .cloned()
            .collect();
        rows.sort_by(|a, b| b.queued_at.cmp(&a.queued_at));
        rows.truncate(limit);
        Ok(rows)
    }

    async fn list_all_pending(
        &self,
        limit: usize,
    ) -> Result<Vec<AnchorQueueEntry>, AnchorRunError> {
        let mut rows: Vec<AnchorQueueEntry> = self
            .inner
            .lock()
            .await
            .iter()
            .filter(|e| e.status == AnchorQueueStatus::Pending)
            .cloned()
            .collect();
        rows.sort_by(|a, b| b.queued_at.cmp(&a.queued_at));
        rows.truncate(limit);
        Ok(rows)
    }

    async fn mark_recovered(
        &self,
        tenant_id: &TenantId,
        queue_id: Uuid,
    ) -> Result<(), AnchorRunError> {
        let mut g = self.inner.lock().await;
        for e in g.iter_mut() {
            if e.queue_id == queue_id && &e.tenant_id == tenant_id {
                e.status = AnchorQueueStatus::Recovered;
                return Ok(());
            }
        }
        Err(AnchorRunError::NotFound)
    }

    async fn mark_exhausted(
        &self,
        tenant_id: &TenantId,
        queue_id: Uuid,
        reason: &str,
    ) -> Result<(), AnchorRunError> {
        let mut g = self.inner.lock().await;
        for e in g.iter_mut() {
            if e.queue_id == queue_id && &e.tenant_id == tenant_id {
                e.status = AnchorQueueStatus::Exhausted;
                e.last_failure_reason = reason.to_owned();
                return Ok(());
            }
        }
        Err(AnchorRunError::NotFound)
    }

    async fn bump_attempt(
        &self,
        tenant_id: &TenantId,
        queue_id: Uuid,
        reason: &str,
    ) -> Result<(), AnchorRunError> {
        let mut g = self.inner.lock().await;
        for e in g.iter_mut() {
            if e.queue_id == queue_id && &e.tenant_id == tenant_id {
                e.attempts = e.attempts.saturating_add(1);
                e.last_failure_reason = reason.to_owned();
                return Ok(());
            }
        }
        Err(AnchorRunError::NotFound)
    }
}

// ---------------------------------------------------------------------------
// IR incident sink (for TSA_TIMESTAMP_INVALID)
// ---------------------------------------------------------------------------

/// One opened IR incident, returned to the caller for test assertions
/// and for the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenedIrIncident {
    /// Incident id (UUID v4 in-memory; v7 in production).
    pub incident_id: Uuid,
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Title (human readable).
    pub title: String,
    /// Severity tag.
    pub severity: String,
    /// Playbook id auto-fired (e.g. `"tsa-compromise"`).
    pub playbook_id: String,
    /// Wall-clock open time.
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: OffsetDateTime,
}

/// Port the CRIT-006 orchestrator uses to auto-fire an IR incident when
/// a TSA signature failure is detected. Real impl lives in the monolith
/// composition root and forwards to `sx-ir-playbooks`.
#[async_trait]
pub trait IrIncidentSink: Send + Sync + std::fmt::Debug {
    /// Open a fresh incident. Implementations MUST NOT block on the
    /// returned future for longer than `INCIDENT_OPEN_TIMEOUT` (the
    /// orchestrator is on the critical anchor path).
    async fn open_incident(&self, ev: OpenedIrIncident) -> Result<(), AnchorRunError>;
}

/// In-memory recorder for tests.
#[derive(Debug, Default)]
pub struct RecordingIrIncidentSink {
    inner: Mutex<Vec<OpenedIrIncident>>,
}

impl RecordingIrIncidentSink {
    /// New empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot recorded incidents.
    pub async fn incidents(&self) -> Vec<OpenedIrIncident> {
        self.inner.lock().await.clone()
    }
}

#[async_trait]
impl IrIncidentSink for RecordingIrIncidentSink {
    async fn open_incident(&self, ev: OpenedIrIncident) -> Result<(), AnchorRunError> {
        self.inner.lock().await.push(ev);
        Ok(())
    }
}

/// No-op sink (for unit tests that don't care).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopIrIncidentSink;

#[async_trait]
impl IrIncidentSink for NoopIrIncidentSink {
    async fn open_incident(&self, _ev: OpenedIrIncident) -> Result<(), AnchorRunError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Resilient anchor runner
// ---------------------------------------------------------------------------

/// Outcome of a single [`ResilientAnchorRunner::run_once`] call.
#[derive(Debug, Clone)]
pub enum ResilientOutcome {
    /// A new row landed in `audit_anchor_runs`.
    Anchored(AnchorRunId),
    /// Nothing to do this tick.
    Skipped(String),
    /// All TSAs reachable failed — entry enqueued for retry.
    Queued(Uuid),
}

/// Event types emitted on the audit channel by the orchestrator.
pub mod audit_event {
    /// Emitted when the fallback cascade exhausts every endpoint.
    pub const ANCHOR_FALLBACK_EXHAUSTED: &str = "audit.anchor.fallback_exhausted";
    /// Emitted when the queue retry window closes without success.
    pub const ANCHOR_QUEUE_EXHAUSTED: &str = "audit.anchor.queue_exhausted";
    /// Emitted on a TSA_TIMESTAMP_INVALID failure (auto-IR).
    pub const ANCHOR_TSA_SIGNATURE_INVALID: &str = "audit.anchor.tsa_signature_invalid";
    /// Emitted on a TSA_RESPONSE_MALFORMED failure.
    pub const ANCHOR_TSA_RESPONSE_MALFORMED: &str = "audit.anchor.tsa_response_malformed";
    /// Emitted on a recovered queue entry.
    pub const ANCHOR_QUEUE_RECOVERED: &str = "audit.anchor.queue_recovered";
    /// MED-002: emitted when an anchor attempt could not collect the
    /// required number of verified TSA signatures (`required` failed to
    /// hit `quorum_required`). The full per-TSA breakdown is included
    /// in the audit message body.
    pub const ANCHOR_QUORUM_SHORTFALL: &str = "audit.anchor.quorum_shortfall";
    /// MED-002: emitted at verify time when fewer than `quorum_required`
    /// TSAs still verify against the persisted record. The record is
    /// no longer trustworthy and must be re-anchored manually.
    pub const ANCHOR_QUORUM_VERIFY_SHORTFALL: &str = "audit.anchor.quorum_verify_shortfall";
}

/// Wraps an [`AnchorRunner`] + [`MultiTsaClient`] and a queue.
///
/// The orchestration logic on the *write* path:
///
/// 1. Build the Merkle root.
/// 2. Drive [`MultiTsaClient::anchor_with_fallback`].
/// 3. On `Ok` -> verify -> persist (same as classic runner).
/// 4. On `AllUnreachable` -> enqueue the entry; return
///    [`ResilientOutcome::Queued`].
/// 5. On `ResponseMalformed` or signature failure -> emit CRITICAL +
///    auto-open IR incident; return `Err`.
///
/// The *retry* path is in [`AnchorQueueRetryer`].
#[derive(Debug, Clone)]
pub struct ResilientAnchorRunner {
    /// Underlying multi-TSA client.
    multi: Arc<MultiTsaClient>,
    /// TSA verifier (signature check).
    verifier: Arc<dyn TsaTokenVerifier>,
    /// Anchor-run repository.
    repo: Arc<dyn AnchorRunRepository>,
    /// CRITICAL audit-event sink.
    critical: Arc<dyn CriticalEventSink>,
    /// IR incident sink (auto-opens for signature failure).
    ir_sink: Arc<dyn IrIncidentSink>,
    /// Retry queue.
    queue: Arc<dyn AnchorQueueRepository>,
    /// Clock for queue timestamps.
    clock: Arc<dyn Clock>,
}

impl ResilientAnchorRunner {
    /// Build a runner.
    #[must_use]
    pub fn new(
        multi: Arc<MultiTsaClient>,
        verifier: Arc<dyn TsaTokenVerifier>,
        repo: Arc<dyn AnchorRunRepository>,
        critical: Arc<dyn CriticalEventSink>,
        ir_sink: Arc<dyn IrIncidentSink>,
        queue: Arc<dyn AnchorQueueRepository>,
    ) -> Self {
        Self::with_clock(
            multi,
            verifier,
            repo,
            critical,
            ir_sink,
            queue,
            Arc::new(SystemClock),
        )
    }

    /// Build a runner with a custom clock (tests).
    #[must_use]
    pub fn with_clock(
        multi: Arc<MultiTsaClient>,
        verifier: Arc<dyn TsaTokenVerifier>,
        repo: Arc<dyn AnchorRunRepository>,
        critical: Arc<dyn CriticalEventSink>,
        ir_sink: Arc<dyn IrIncidentSink>,
        queue: Arc<dyn AnchorQueueRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            multi,
            verifier,
            repo,
            critical,
            ir_sink,
            queue,
            clock,
        }
    }

    /// Accessor for the underlying multi-TSA client (useful for tests).
    #[must_use]
    pub fn multi(&self) -> Arc<MultiTsaClient> {
        Arc::clone(&self.multi)
    }

    /// Accessor for the queue (useful for tests + the API surface).
    #[must_use]
    pub fn queue(&self) -> Arc<dyn AnchorQueueRepository> {
        Arc::clone(&self.queue)
    }

    /// Anchor one window with full resilience.
    ///
    /// `pinned_ca_pem` is the PINNED CA the verifier checks the
    /// successful endpoint's response against. In the multi-TSA world
    /// each endpoint has its own CA so callers normally pass the matching
    /// endpoint's CA; the simple form here pins to the *primary* CA. For
    /// strict per-endpoint pinning callers use
    /// [`Self::run_once_with_ca_resolver`].
    #[instrument(skip_all, fields(tenant = %tenant_id, leaves = chain_hashes.len()))]
    pub async fn run_once(
        &self,
        tenant_id: &TenantId,
        pinned_ca_pem: &str,
        chain_hashes: &[[u8; SHA256_LEN]],
        window_start: OffsetDateTime,
        window_end: OffsetDateTime,
        audit_seqs: (u64, u64),
    ) -> Result<ResilientOutcome, AnchorRunError> {
        self.run_once_with_ca_resolver(
            tenant_id,
            &|_label| Some(pinned_ca_pem.to_owned()),
            chain_hashes,
            window_start,
            window_end,
            audit_seqs,
        )
        .await
    }

    /// Same as [`Self::run_once`] but with a per-endpoint CA resolver.
    ///
    /// `ca_for` is consulted with the label of the endpoint that produced
    /// the successful response — when it returns `None` the orchestrator
    /// treats the response as `TimestampInvalid` (no pinned CA == no
    /// trust). This mirrors how production code threads the per-endpoint
    /// CA map through.
    #[instrument(skip_all, fields(tenant = %tenant_id, leaves = chain_hashes.len()))]
    pub async fn run_once_with_ca_resolver(
        &self,
        tenant_id: &TenantId,
        ca_for: &(dyn Fn(&str) -> Option<String> + Send + Sync),
        chain_hashes: &[[u8; SHA256_LEN]],
        window_start: OffsetDateTime,
        window_end: OffsetDateTime,
        audit_seqs: (u64, u64),
    ) -> Result<ResilientOutcome, AnchorRunError> {
        if chain_hashes.is_empty() {
            return Ok(ResilientOutcome::Skipped("empty window".to_owned()));
        }
        let merkle_root = MerkleTreeBuilder::new().build(chain_hashes)?;
        let req = AnchorRequest {
            tenant_id: *tenant_id,
            window_start,
            window_end,
            merkle_root,
            audit_seqs,
        };
        match self.multi.anchor_with_fallback(&req).await {
            Ok(resp) => {
                let Some(pinned) = ca_for(&resp.tsa_provider) else {
                    // No CA pinned for this endpoint -> treat as a
                    // signature-invalid case (CRITICAL).
                    return self
                        .handle_signature_invalid(
                            tenant_id,
                            &resp.tsa_provider,
                            "no pinned CA configured for endpoint",
                        )
                        .await;
                };
                match self.verifier.verify(&resp.token, &pinned) {
                    Ok(v) if v.merkle_root == merkle_root => {
                        let run = AuditAnchorRun {
                            run_id: AnchorRunId::new(),
                            tenant_id: *tenant_id,
                            merkle_root,
                            tsa_serial: v.serial,
                            tsa_gen_time: v.gen_time,
                            anchored_at: self.clock.now(),
                            payload_bytes: resp.token,
                            // Legacy first-wins path: no quorum sidecar.
                            quorum: None,
                        };
                        let id = run.run_id;
                        self.repo.insert(run).await?;
                        Ok(ResilientOutcome::Anchored(id))
                    }
                    Ok(_) => {
                        self.handle_signature_invalid(
                            tenant_id,
                            &resp.tsa_provider,
                            "merkle root mismatch",
                        )
                        .await
                    }
                    Err(err) => {
                        // Classify the verifier error: if it looks like
                        // a parse failure (token JSON malformed) we
                        // treat it as TSA_RESPONSE_MALFORMED (MitM);
                        // otherwise as TSA_TIMESTAMP_INVALID. Both are
                        // CRITICAL but route to different playbooks.
                        let msg = err.to_string();
                        if is_malformed_token_error(&msg) {
                            self.handle_response_malformed(tenant_id, &resp.tsa_provider, &msg)
                                .await
                        } else {
                            self.handle_signature_invalid(tenant_id, &resp.tsa_provider, &msg)
                                .await
                        }
                    }
                }
            }
            Err(MultiTsaError::AllUnreachable {
                tried,
                last_label,
                last_message,
            }) => {
                let entry = AnchorQueueEntry {
                    queue_id: Uuid::new_v4(),
                    tenant_id: *tenant_id,
                    window_start,
                    window_end,
                    audit_seqs,
                    merkle_root,
                    chain_hashes: chain_hashes.to_vec(),
                    queued_at: self.clock.now(),
                    attempts: 0,
                    status: AnchorQueueStatus::Pending,
                    last_failure_reason: format!(
                        "all-unreachable: tried={tried} last={last_label} msg={last_message}"
                    ),
                };
                let qid = entry.queue_id;
                self.queue.enqueue(entry).await?;
                self.critical
                    .emit_critical(
                        tenant_id,
                        &format!(
                            "{}: queued for retry (tried={tried})",
                            audit_event::ANCHOR_FALLBACK_EXHAUSTED
                        ),
                    )
                    .await;
                Ok(ResilientOutcome::Queued(qid))
            }
            Err(MultiTsaError::SignatureInvalid { label, message }) => {
                self.handle_signature_invalid(tenant_id, &label, &message)
                    .await
            }
            Err(MultiTsaError::ResponseMalformed { label, message }) => {
                self.handle_response_malformed(tenant_id, &label, &message)
                    .await
            }
        }
    }

    /// MED-002 — Anchor with a quorum-verified record.
    ///
    /// Walks `quorum_total` endpoints, verifies each returned token
    /// against `ca_for(label)`, and accepts the run only when at least
    /// `quorum_required` tokens successfully verify. The full per-TSA
    /// set lands on [`crate::anchor_run::AuditAnchorRun::quorum`] so a
    /// later [`Self::verify_run_once_with_quorum`] call can re-check the
    /// record against operator-pinned CAs and detect whether the quorum
    /// still holds.
    ///
    /// Backward compatibility: callers who pass `quorum_required == 1`
    /// get behaviour equivalent to the legacy [`Self::run_once_with_ca_resolver`]
    /// path (first-wins, no sidecar populated on the row).
    #[instrument(skip_all, fields(tenant = %tenant_id, leaves = chain_hashes.len(), quorum_required, quorum_total))]
    #[allow(clippy::too_many_arguments)]
    pub async fn run_once_quorum(
        &self,
        tenant_id: &TenantId,
        ca_for: &(dyn Fn(&str) -> Option<String> + Send + Sync),
        chain_hashes: &[[u8; SHA256_LEN]],
        window_start: OffsetDateTime,
        window_end: OffsetDateTime,
        audit_seqs: (u64, u64),
        quorum_required: usize,
        quorum_total: usize,
    ) -> Result<ResilientOutcome, AnchorRunError> {
        // Collapse to the legacy first-wins path when 1-of-1 is asked.
        if quorum_required <= 1 {
            return self
                .run_once_with_ca_resolver(
                    tenant_id,
                    ca_for,
                    chain_hashes,
                    window_start,
                    window_end,
                    audit_seqs,
                )
                .await;
        }
        if chain_hashes.is_empty() {
            return Ok(ResilientOutcome::Skipped("empty window".to_owned()));
        }
        let merkle_root = MerkleTreeBuilder::new().build(chain_hashes)?;
        let req = AnchorRequest {
            tenant_id: *tenant_id,
            window_start,
            window_end,
            merkle_root,
            audit_seqs,
        };
        let attempts = match self.multi.collect_quorum_attempts(&req, quorum_total).await {
            Ok(a) => a,
            Err(MultiTsaError::ResponseMalformed { label, message }) => {
                return self
                    .handle_response_malformed(tenant_id, &label, &message)
                    .await;
            }
            Err(other) => {
                // `collect_quorum_attempts` only emits the malformed
                // variant; defensively forward anything else through
                // the signature-invalid path.
                return self
                    .handle_signature_invalid(tenant_id, "quorum", &other.to_string())
                    .await;
            }
        };

        // Verify each successful response against its pinned CA. Build
        // the QuorumAnchorRecord in place.
        let mut signatures: Vec<QuorumTsaSignature> = Vec::with_capacity(attempts.len());
        let mut leader: Option<(String, Vec<u8>, TsaVerification)> = None;
        let mut verified_count: usize = 0;
        let mut failure_reasons: Vec<String> = Vec::new();
        for att in attempts {
            let label = att.label.clone();
            match att.outcome {
                QuorumAttemptOutcome::Success(resp) => {
                    let Some(pinned) = ca_for(&resp.tsa_provider).or_else(|| ca_for(&label)) else {
                        // No pinned CA for this endpoint → record as
                        // Failed (no trust) but do not bail; another TSA
                        // may still satisfy the quorum.
                        signatures.push(QuorumTsaSignature {
                            label: label.clone(),
                            tsa_serial: String::new(),
                            tsa_gen_time: OffsetDateTime::UNIX_EPOCH,
                            token: resp.token,
                            status: QuorumSignatureStatus::Failed,
                            reason: Some("no pinned CA configured for endpoint".to_owned()),
                        });
                        failure_reasons.push(format!("{label}: no pinned CA"));
                        continue;
                    };
                    match self.verifier.verify(&resp.token, &pinned) {
                        Ok(v) if v.merkle_root == merkle_root => {
                            verified_count = verified_count.saturating_add(1);
                            // Promote the first verified TSA to leader.
                            if leader.is_none() {
                                leader = Some((label.clone(), resp.token.clone(), v.clone()));
                            }
                            signatures.push(QuorumTsaSignature {
                                label,
                                tsa_serial: v.serial,
                                tsa_gen_time: v.gen_time,
                                token: resp.token,
                                status: QuorumSignatureStatus::Verified,
                                reason: None,
                            });
                        }
                        Ok(_) => {
                            failure_reasons.push(format!("{label}: merkle root mismatch"));
                            signatures.push(QuorumTsaSignature {
                                label,
                                tsa_serial: String::new(),
                                tsa_gen_time: OffsetDateTime::UNIX_EPOCH,
                                token: resp.token,
                                status: QuorumSignatureStatus::Failed,
                                reason: Some("merkle root mismatch".to_owned()),
                            });
                        }
                        Err(err) => {
                            let msg = err.to_string();
                            failure_reasons.push(format!("{label}: {msg}"));
                            signatures.push(QuorumTsaSignature {
                                label,
                                tsa_serial: String::new(),
                                tsa_gen_time: OffsetDateTime::UNIX_EPOCH,
                                token: resp.token,
                                status: QuorumSignatureStatus::Failed,
                                reason: Some(msg),
                            });
                        }
                    }
                }
                QuorumAttemptOutcome::Failed(msg) => {
                    failure_reasons.push(format!("{label}: {msg}"));
                    signatures.push(QuorumTsaSignature {
                        label,
                        tsa_serial: String::new(),
                        tsa_gen_time: OffsetDateTime::UNIX_EPOCH,
                        token: Vec::new(),
                        status: QuorumSignatureStatus::Failed,
                        reason: Some(msg),
                    });
                }
                QuorumAttemptOutcome::NotAttempted => {
                    signatures.push(QuorumTsaSignature::not_attempted(label));
                }
            }
        }

        if verified_count < quorum_required {
            // Quorum shortfall — emit audit + queue for retry (the
            // signatures we did collect are *not* persisted, the
            // retryer will re-anchor the window).
            let summary = format!(
                "{}: verified={verified_count}/{quorum_required} reasons=[{}]",
                audit_event::ANCHOR_QUORUM_SHORTFALL,
                failure_reasons.join("; "),
            );
            self.critical.emit_critical(tenant_id, &summary).await;
            // Queue for retry — same shape as AllUnreachable to reuse
            // the retryer plumbing.
            let entry = AnchorQueueEntry {
                queue_id: Uuid::new_v4(),
                tenant_id: *tenant_id,
                window_start,
                window_end,
                audit_seqs,
                merkle_root,
                chain_hashes: chain_hashes.to_vec(),
                queued_at: self.clock.now(),
                attempts: 0,
                status: AnchorQueueStatus::Pending,
                last_failure_reason: format!(
                    "quorum-shortfall: verified={verified_count}/{quorum_required} reasons=[{}]",
                    failure_reasons.join("; "),
                ),
            };
            let qid = entry.queue_id;
            self.queue.enqueue(entry).await?;
            return Ok(ResilientOutcome::Queued(qid));
        }

        // Quorum met — persist the row with the leader's token as
        // payload_bytes plus the full QuorumAnchorRecord sidecar.
        let Some((leader_label, leader_token, leader_verif)) = leader else {
            // Should be unreachable given verified_count >= quorum_required >= 2.
            return Err(AnchorRunError::Verification(
                "internal: quorum met but no leader recorded".to_owned(),
            ));
        };
        let quorum_record = QuorumAnchorRecord {
            required: u32::try_from(quorum_required).unwrap_or(u32::MAX),
            total: u32::try_from(quorum_total).unwrap_or(u32::MAX),
            signatures,
            leader_label,
        };
        let run = AuditAnchorRun {
            run_id: AnchorRunId::new(),
            tenant_id: *tenant_id,
            merkle_root,
            tsa_serial: leader_verif.serial,
            tsa_gen_time: leader_verif.gen_time,
            anchored_at: self.clock.now(),
            payload_bytes: leader_token,
            quorum: Some(quorum_record),
        };
        let id = run.run_id;
        self.repo.insert(run).await?;
        Ok(ResilientOutcome::Anchored(id))
    }

    async fn handle_signature_invalid(
        &self,
        tenant_id: &TenantId,
        label: &str,
        reason: &str,
    ) -> Result<ResilientOutcome, AnchorRunError> {
        error!(
            tenant = %tenant_id,
            label = %label,
            reason = %reason,
            "tsa signature invalid — opening IR incident",
        );
        self.critical
            .emit_critical(
                tenant_id,
                &format!(
                    "{}: endpoint={label} reason={reason}",
                    audit_event::ANCHOR_TSA_SIGNATURE_INVALID
                ),
            )
            .await;
        let incident = OpenedIrIncident {
            incident_id: Uuid::new_v4(),
            tenant_id: *tenant_id,
            title: format!("TSA signature invalid at {label}"),
            severity: "critical".to_owned(),
            playbook_id: "tsa-compromise".to_owned(),
            opened_at: self.clock.now(),
        };
        self.ir_sink.open_incident(incident).await?;
        Err(AnchorRunError::Verification(format!(
            "tsa signature invalid at {label}: {reason}"
        )))
    }

    async fn handle_response_malformed(
        &self,
        tenant_id: &TenantId,
        label: &str,
        reason: &str,
    ) -> Result<ResilientOutcome, AnchorRunError> {
        error!(
            tenant = %tenant_id,
            label = %label,
            reason = %reason,
            "tsa response malformed — opening IR incident",
        );
        self.critical
            .emit_critical(
                tenant_id,
                &format!(
                    "{}: endpoint={label} reason={reason}",
                    audit_event::ANCHOR_TSA_RESPONSE_MALFORMED
                ),
            )
            .await;
        let incident = OpenedIrIncident {
            incident_id: Uuid::new_v4(),
            tenant_id: *tenant_id,
            title: format!("TSA response malformed at {label}"),
            severity: "critical".to_owned(),
            playbook_id: "tsa-mitm".to_owned(),
            opened_at: self.clock.now(),
        };
        self.ir_sink.open_incident(incident).await?;
        Err(AnchorRunError::Verification(format!(
            "tsa response malformed at {label}: {reason}"
        )))
    }
}

// ---------------------------------------------------------------------------
// Backwards-compat: convert legacy `AnchorRunner` outcome -> resilient
// ---------------------------------------------------------------------------

impl From<RunOutcome> for ResilientOutcome {
    fn from(v: RunOutcome) -> Self {
        match v {
            RunOutcome::Anchored(id) => Self::Anchored(id),
            RunOutcome::Skipped(s) => Self::Skipped(s),
        }
    }
}

// ---------------------------------------------------------------------------
// Retryer
// ---------------------------------------------------------------------------

/// Outcome of one [`AnchorQueueRetryer::process_entry`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAction {
    /// Successfully re-anchored; queue row marked `Recovered`.
    Recovered,
    /// Still failing but inside the retry window; row stays `Pending`.
    StillPending,
    /// Retry window expired; row marked `Exhausted` and CRITICAL emitted.
    Exhausted,
}

/// Walks the `Pending` queue and re-attempts each entry through the
/// resilient runner. Designed to be called from a scheduler tick.
#[derive(Debug)]
pub struct AnchorQueueRetryer {
    runner: ResilientAnchorRunner,
    clock: Arc<dyn Clock>,
}

impl AnchorQueueRetryer {
    /// Retry window — spec says 24 h.
    pub const RETRY_WINDOW: StdDuration = StdDuration::from_secs(24 * 60 * 60);
    /// Hard cap on how many queue rows a single tick processes — keeps
    /// the retryer bounded.
    pub const MAX_PER_TICK: usize = 256;

    /// New retryer that drives `runner` and timestamps via `clock`.
    #[must_use]
    pub fn new(runner: ResilientAnchorRunner) -> Self {
        let clock = Arc::clone(&runner.clock);
        Self { runner, clock }
    }

    /// Run one tick — pull pending entries, retry each.
    ///
    /// `pinned_ca_for` is a tenant-scoped CA resolver (same shape as
    /// [`ResilientAnchorRunner::run_once_with_ca_resolver`]). On
    /// `Recovered` the row is updated; on persistent failure the
    /// attempts counter is bumped and we move on. When the entry is
    /// older than [`Self::RETRY_WINDOW`] we mark it `Exhausted`.
    pub async fn tick(
        &self,
        pinned_ca_for: &(dyn Fn(&TenantId, &str) -> Option<String> + Send + Sync),
    ) -> Result<Vec<(Uuid, RetryAction)>, AnchorRunError> {
        let pending = self
            .runner
            .queue
            .list_all_pending(Self::MAX_PER_TICK)
            .await?;
        let mut out = Vec::with_capacity(pending.len());
        for entry in pending {
            let action = self.process_entry(&entry, pinned_ca_for).await?;
            out.push((entry.queue_id, action));
        }
        Ok(out)
    }

    /// Process exactly one queue entry — exposed for tests.
    pub async fn process_entry(
        &self,
        entry: &AnchorQueueEntry,
        pinned_ca_for: &(dyn Fn(&TenantId, &str) -> Option<String> + Send + Sync),
    ) -> Result<RetryAction, AnchorRunError> {
        let now = self.clock.now();
        let age = now - entry.queued_at;
        let window = time::Duration::try_from(Self::RETRY_WINDOW).unwrap_or(time::Duration::ZERO);
        if age >= window {
            let reason = format!(
                "retry window {}s exceeded after {} attempts: {}",
                Self::RETRY_WINDOW.as_secs(),
                entry.attempts,
                entry.last_failure_reason,
            );
            self.runner
                .queue
                .mark_exhausted(&entry.tenant_id, entry.queue_id, &reason)
                .await?;
            self.runner
                .critical
                .emit_critical(
                    &entry.tenant_id,
                    &format!(
                        "{}: queue_id={}",
                        audit_event::ANCHOR_QUEUE_EXHAUSTED,
                        entry.queue_id
                    ),
                )
                .await;
            return Ok(RetryAction::Exhausted);
        }

        // Retry the underlying anchor.
        let tenant = entry.tenant_id;
        let resolver = move |label: &str| pinned_ca_for(&tenant, label);
        let outcome = self
            .runner
            .run_once_with_ca_resolver(
                &entry.tenant_id,
                &resolver,
                &entry.chain_hashes,
                entry.window_start,
                entry.window_end,
                entry.audit_seqs,
            )
            .await;
        match outcome {
            Ok(ResilientOutcome::Anchored(run_id)) => {
                self.runner
                    .queue
                    .mark_recovered(&entry.tenant_id, entry.queue_id)
                    .await?;
                self.runner
                    .critical
                    .emit_critical(
                        &entry.tenant_id,
                        &format!(
                            "{}: queue_id={} anchor_run_id={}",
                            audit_event::ANCHOR_QUEUE_RECOVERED,
                            entry.queue_id,
                            run_id,
                        ),
                    )
                    .await;
                Ok(RetryAction::Recovered)
            }
            Ok(ResilientOutcome::Queued(_)) => {
                // Still failing transiently — bump attempts.
                self.runner
                    .queue
                    .bump_attempt(
                        &entry.tenant_id,
                        entry.queue_id,
                        "retry: all endpoints still unreachable",
                    )
                    .await?;
                Ok(RetryAction::StillPending)
            }
            Ok(ResilientOutcome::Skipped(why)) => {
                self.runner
                    .queue
                    .bump_attempt(&entry.tenant_id, entry.queue_id, &format!("skipped: {why}"))
                    .await?;
                Ok(RetryAction::StillPending)
            }
            Err(err) => {
                // Verification / IR failure — terminal, mark exhausted
                // so the queue does not loop on a poisoned proof.
                let reason = format!("non-transient failure: {err}");
                self.runner
                    .queue
                    .mark_exhausted(&entry.tenant_id, entry.queue_id, &reason)
                    .await?;
                Ok(RetryAction::Exhausted)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience: pull AnchorRunner config alignment
// ---------------------------------------------------------------------------

/// Build a [`TenantAnchorConfig`] from a [`MultiTsaConfig`] using the
/// primary endpoint — handy for callers that still use the legacy
/// single-TSA pathway.
#[must_use]
pub fn tenant_anchor_config_from_primary(cfg: &MultiTsaConfig) -> TenantAnchorConfig {
    TenantAnchorConfig {
        tenant_id: cfg.tenant_id,
        tsa_url: Some(cfg.primary.url.clone()),
        pinned_ca_cert_pem: Some(cfg.primary.ca_pem.clone()),
        interval: TenantAnchorConfig::DEFAULT_INTERVAL,
    }
}

/// Build an [`AnchorRunner`] using the primary endpoint of a
/// [`MultiTsaConfig`]. Used by the resilient runner's fallback to the
/// legacy verify-run path inside the API surface.
///
/// # Errors
///
/// Returns [`AnchorError::Transport`] when the underlying reqwest client
/// cannot be built.
pub fn build_legacy_runner_from_primary(
    cfg: &MultiTsaConfig,
    verifier: Arc<dyn TsaTokenVerifier>,
    repo: Arc<dyn AnchorRunRepository>,
    critical: Arc<dyn CriticalEventSink>,
) -> Result<AnchorRunner, AnchorError> {
    let client: Arc<dyn TsaAnchorClient> = Arc::new(FreeTsaClient::new(&cfg.primary.url)?);
    Ok(AnchorRunner::new(client, verifier, repo, critical))
}

// ---------------------------------------------------------------------------
// Serde helpers
// ---------------------------------------------------------------------------

mod hex_array_serde {
    use super::SHA256_LEN;
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; SHA256_LEN],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<[u8; SHA256_LEN], D::Error> {
        let s = String::deserialize(de)?;
        let raw = hex::decode(&s).map_err(D::Error::custom)?;
        if raw.len() != SHA256_LEN {
            return Err(D::Error::custom(format!(
                "expected {SHA256_LEN}-byte hex, got {} bytes",
                raw.len(),
            )));
        }
        let mut out = [0u8; SHA256_LEN];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

/// Base64 (de)serializer for `Vec<u8>` token bytes — handles the empty
/// payload case (`NotAttempted` signatures) gracefully without forcing
/// the field to be `Option<Vec<u8>>` (preserves a stable wire shape).
mod bytes_b64_serde_opt {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&B64.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        B64.decode(s.as_bytes()).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Unit tests — circuit breaker state machine
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]
mod tests {
    use super::*;

    fn tenant(n: u128) -> TenantId {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&n.to_be_bytes());
        bytes[6] = (bytes[6] & 0x0F) | 0x70;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        Uuid::from_bytes(bytes).into()
    }

    #[tokio::test]
    async fn breaker_starts_closed_and_allows_calls() {
        let cb = CircuitBreaker::new("test");
        assert_eq!(cb.snapshot().await.state, BreakerState::Closed);
        assert_eq!(cb.on_call().await, CallDecision::Allow);
    }

    #[tokio::test]
    async fn breaker_opens_after_threshold_consecutive_failures() {
        let cb = CircuitBreaker::new("test");
        for _ in 0..CircuitBreaker::FAILURE_THRESHOLD - 1 {
            cb.on_failure().await;
        }
        // Below threshold -> still Closed.
        assert_eq!(cb.snapshot().await.state, BreakerState::Closed);
        cb.on_failure().await;
        // Threshold breached.
        assert_eq!(cb.snapshot().await.state, BreakerState::Open);
        // Subsequent on_call rejects.
        assert_eq!(cb.on_call().await, CallDecision::Reject);
        // Rejection counter ticked.
        assert_eq!(cb.snapshot().await.total_rejections, 1);
    }

    #[tokio::test]
    async fn breaker_success_resets_failure_counter() {
        let cb = CircuitBreaker::new("test");
        cb.on_failure().await;
        cb.on_failure().await;
        cb.on_success().await;
        let snap = cb.snapshot().await;
        assert_eq!(snap.state, BreakerState::Closed);
        assert_eq!(snap.consecutive_failures, 0);
        assert_eq!(snap.total_successes, 1);
        assert_eq!(snap.total_failures, 2);
    }

    #[tokio::test]
    async fn breaker_transitions_open_half_open_closed() {
        let clock = Arc::new(ManualClock::new(
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        ));
        let cb =
            CircuitBreaker::with_thresholds("test", 3, StdDuration::from_secs(60), clock.clone());
        // Trip the breaker.
        for _ in 0..3 {
            cb.on_failure().await;
        }
        assert_eq!(cb.snapshot().await.state, BreakerState::Open);
        // Before cool-down -> still rejects.
        assert_eq!(cb.on_call().await, CallDecision::Reject);
        // Advance past cool-down.
        clock.advance(StdDuration::from_secs(61)).await;
        // First call after cool-down transitions to HalfOpen and allows.
        assert_eq!(cb.on_call().await, CallDecision::Allow);
        assert_eq!(cb.snapshot().await.state, BreakerState::HalfOpen);
        // A success closes the breaker again.
        cb.on_success().await;
        let snap = cb.snapshot().await;
        assert_eq!(snap.state, BreakerState::Closed);
        assert_eq!(snap.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn breaker_half_open_failure_reopens() {
        let clock = Arc::new(ManualClock::new(
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        ));
        let cb = CircuitBreaker::with_thresholds("t", 3, StdDuration::from_secs(60), clock.clone());
        for _ in 0..3 {
            cb.on_failure().await;
        }
        clock.advance(StdDuration::from_secs(61)).await;
        // Drive into HalfOpen.
        assert_eq!(cb.on_call().await, CallDecision::Allow);
        assert_eq!(cb.snapshot().await.state, BreakerState::HalfOpen);
        // Failure during the probe -> back to Open.
        cb.on_failure().await;
        assert_eq!(cb.snapshot().await.state, BreakerState::Open);
    }

    #[test]
    fn classify_anchor_error_distinguishes_transport_vs_invalid() {
        assert_eq!(
            classify_anchor_error(&AnchorError::Transport("x".into())),
            TsaFailureClass::Unreachable
        );
        assert_eq!(
            classify_anchor_error(&AnchorError::InvalidResponse("x".into())),
            TsaFailureClass::ResponseMalformed
        );
        assert_eq!(
            classify_anchor_error(&AnchorError::DerEncoding("x".into())),
            TsaFailureClass::Unreachable
        );
    }

    #[test]
    fn failure_class_is_transient_only_for_unreachable() {
        assert!(TsaFailureClass::Unreachable.is_transient());
        assert!(!TsaFailureClass::TimestampInvalid.is_transient());
        assert!(!TsaFailureClass::ResponseMalformed.is_transient());
    }

    #[test]
    fn default_dev_endpoints_ships_freetsa_sectigo_digicert_globalsign() {
        let eps = default_dev_endpoints();
        let labels: Vec<_> = eps.iter().map(TsaEndpoint::effective_label).collect();
        assert_eq!(labels, vec!["freetsa", "sectigo", "digicert", "globalsign"]);
        assert!(eps.iter().all(|e| e.timeout == StdDuration::from_secs(30)));
        // All ship the placeholder CA so production deployments are
        // forced to replace.
        assert!(eps.iter().all(|e| e.ca_pem.contains("DEV_PLACEHOLDER")));
    }

    #[test]
    fn endpoint_effective_label_falls_back_to_host() {
        let ep = TsaEndpoint::new("https://example.com/tsr", "x");
        assert_eq!(ep.effective_label(), "example.com");
    }

    #[test]
    fn endpoint_explicit_label_wins() {
        let ep = TsaEndpoint {
            url: "https://example.com/tsr".to_owned(),
            ca_pem: "x".to_owned(),
            label: Some("custom".to_owned()),
            timeout: TsaEndpoint::DEFAULT_TIMEOUT,
        };
        assert_eq!(ep.effective_label(), "custom");
    }

    #[test]
    fn multi_tsa_config_iterates_primary_first() {
        let cfg = MultiTsaConfig {
            tenant_id: tenant(1),
            primary: TsaEndpoint::new("https://primary.example/tsr", "p"),
            backups: vec![
                TsaEndpoint::new("https://backup1.example/tsr", "b1"),
                TsaEndpoint::new("https://backup2.example/tsr", "b2"),
            ],
            quorum_required: 1,
            quorum_total: 1,
        };
        assert_eq!(cfg.endpoint_count(), 3);
        let labels: Vec<String> = cfg.endpoints().map(|(_, e)| e.effective_label()).collect();
        assert_eq!(
            labels,
            vec!["primary.example", "backup1.example", "backup2.example"]
        );
    }

    #[tokio::test]
    async fn queue_in_memory_round_trip() {
        let q = InMemoryAnchorQueueRepository::new();
        let t = tenant(7);
        let entry = AnchorQueueEntry {
            queue_id: Uuid::new_v4(),
            tenant_id: t,
            window_start: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            window_end: OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            audit_seqs: (1, 10),
            merkle_root: [0x11; SHA256_LEN],
            chain_hashes: vec![[0x11; SHA256_LEN]],
            queued_at: OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap(),
            attempts: 0,
            status: AnchorQueueStatus::Pending,
            last_failure_reason: "x".into(),
        };
        let qid = entry.queue_id;
        q.enqueue(entry).await.unwrap();
        let pending = q.list_pending(&t, 10).await.unwrap();
        assert_eq!(pending.len(), 1);
        q.mark_recovered(&t, qid).await.unwrap();
        let pending2 = q.list_pending(&t, 10).await.unwrap();
        assert!(pending2.is_empty());
        let snap = q.snapshot().await;
        assert_eq!(snap[0].status, AnchorQueueStatus::Recovered);
    }

    #[tokio::test]
    async fn queue_mark_exhausted_records_reason() {
        let q = InMemoryAnchorQueueRepository::new();
        let t = tenant(8);
        let entry = AnchorQueueEntry {
            queue_id: Uuid::new_v4(),
            tenant_id: t,
            window_start: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            window_end: OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            audit_seqs: (1, 10),
            merkle_root: [0x22; SHA256_LEN],
            chain_hashes: vec![],
            queued_at: OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap(),
            attempts: 0,
            status: AnchorQueueStatus::Pending,
            last_failure_reason: "x".into(),
        };
        let qid = entry.queue_id;
        q.enqueue(entry).await.unwrap();
        q.mark_exhausted(&t, qid, "window expired").await.unwrap();
        let snap = q.snapshot().await;
        assert_eq!(snap[0].status, AnchorQueueStatus::Exhausted);
        assert_eq!(snap[0].last_failure_reason, "window expired");
    }

    #[tokio::test]
    async fn queue_cross_tenant_lookup_returns_notfound() {
        let q = InMemoryAnchorQueueRepository::new();
        let t = tenant(1);
        let other = tenant(2);
        let entry = AnchorQueueEntry {
            queue_id: Uuid::new_v4(),
            tenant_id: t,
            window_start: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            window_end: OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            audit_seqs: (1, 10),
            merkle_root: [0x33; SHA256_LEN],
            chain_hashes: vec![],
            queued_at: OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap(),
            attempts: 0,
            status: AnchorQueueStatus::Pending,
            last_failure_reason: "x".into(),
        };
        let qid = entry.queue_id;
        q.enqueue(entry).await.unwrap();
        let err = q.mark_recovered(&other, qid).await.unwrap_err();
        assert!(matches!(err, AnchorRunError::NotFound));
    }
}
