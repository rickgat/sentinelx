//! Tenant-scoped GRC dispatcher — retry + dead-letter + audit.
//!
//! The dispatcher is the only public surface the monolith calls into.
//! It owns the per-tenant retry/backoff loop, the dead-letter queue,
//! and the audit emission so the concrete [`GrcConnector`]
//! implementations stay focused on the vendor wire shape.
//!
//! ## Retry policy
//!
//! Errors classify into two buckets:
//!
//! * **Permanent** — [`ConnectorError::Unauthorized`],
//!   [`ConnectorError::Format`], and [`ConnectorError::Unimplemented`].
//!   These short-circuit straight to the dead-letter queue with a
//!   single audit event.
//! * **Retryable** — [`ConnectorError::Transport`] and
//!   [`ConnectorError::RateLimited`]. The dispatcher loops up to
//!   `max_attempts`, sleeping `base_delay * 2^(attempt-1)` between
//!   retries (capped at `max_delay`). `RateLimited` respects the
//!   server-supplied `retry_after_secs` when present, choosing the
//!   maximum of the backoff value and the server hint.
//!
//! ## Dead-letter queue
//!
//! Permanent failures and retry-exhausted retryable failures land on a
//! shared in-memory dead-letter queue ([`GrcDeadLetterQueue`]) so an
//! operator (or a background sweeper) can replay them once the upstream
//! condition is fixed.
//!
//! ## Audit
//!
//! Every terminal outcome (success / retry / permanent / dead-letter)
//! emits exactly one [`GrcAuditEvent`] via the configured
//! [`GrcAuditSink`].

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::audit::{GrcAuditEvent, GrcAuditOutcome, GrcAuditResource, GrcAuditSink};
use super::connector::{
    ComplianceEvidence, ConnectorError, FindingState, GrcConnector, GrcKind, PushOutcome,
};

/// Dispatcher-level retry/backoff configuration.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Inclusive maximum number of attempts the dispatcher makes for a
    /// retryable error. Must be `>= 1`. A value of `1` disables retry.
    pub max_attempts: u32,
    /// Initial backoff delay between attempts.
    pub base_delay: Duration,
    /// Hard cap on the exponential backoff delay.
    pub max_delay: Duration,
}

impl RetryConfig {
    /// Construct a retry config, clamping `max_attempts` to `>= 1`.
    #[must_use]
    pub const fn new(max_attempts: u32, base_delay: Duration, max_delay: Duration) -> Self {
        let clamped = if max_attempts == 0 { 1 } else { max_attempts };
        Self {
            max_attempts: clamped,
            base_delay,
            max_delay,
        }
    }

    /// Production defaults — 5 attempts, 250 ms base, 8 s cap.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            max_attempts: 5,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(8),
        }
    }

    /// Compute the backoff for attempt index `attempt` (1-based).
    ///
    /// The formula is `base_delay * 2^(attempt-1)` capped at
    /// `max_delay`. Saturating arithmetic prevents overflow when
    /// `attempt` grows beyond 32.
    #[must_use]
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        if attempt <= 1 {
            return self.base_delay;
        }
        let shift = (attempt - 1).min(31);
        let factor: u64 = 1u64 << shift;
        // Clamp to u64::MAX so the cast cannot truncate.
        let base_ms = u64::try_from(self.base_delay.as_millis()).unwrap_or(u64::MAX);
        let scaled_ms = base_ms.saturating_mul(factor);
        let scaled = Duration::from_millis(scaled_ms);
        if scaled > self.max_delay {
            self.max_delay
        } else {
            scaled
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self::production()
    }
}

/// Dead-letter record — the canonical shape for a permanently failed
/// push. Stored in-memory by [`GrcDeadLetterQueue`] and surfaced by the
/// HTTP read endpoint at `/v1/grc/dead-letters`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeadLetter {
    /// Tenant uuid the push was scoped to.
    pub tenant_id: String,
    /// Connector kind the push targeted.
    pub kind: GrcKind,
    /// Resource kind that was pushed.
    pub resource: GrcAuditResource,
    /// SentinelX-side identifier (evidence id or finding id).
    pub source_ref: String,
    /// Final error code surfaced by the connector.
    pub error_code: String,
    /// Attempts the dispatcher made before giving up.
    pub attempts: u32,
    /// RFC 3339 timestamp the dispatcher dead-lettered this push.
    pub recorded_at: String,
}

/// In-memory dead-letter queue. Bounded by `cap` so a runaway error
/// loop cannot exhaust the process heap; the oldest entries are evicted
/// FIFO when the cap is reached.
#[derive(Clone)]
pub struct GrcDeadLetterQueue {
    inner: Arc<Mutex<Vec<DeadLetter>>>,
    cap: usize,
}

impl std::fmt::Debug for GrcDeadLetterQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrcDeadLetterQueue")
            .field("len", &self.len())
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

impl GrcDeadLetterQueue {
    /// Construct an empty dead-letter queue capped at `cap` entries.
    ///
    /// `cap` is clamped to `>= 1` to keep the data structure sane.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            inner: Arc::new(Mutex::new(Vec::with_capacity(cap.min(64)))),
            cap,
        }
    }

    /// Push a dead-letter record. Returns `true` when the record was
    /// recorded (it always is, but we honour the convention).
    pub fn record(&self, dl: DeadLetter) -> bool {
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        if guard.len() >= self.cap {
            guard.remove(0);
        }
        guard.push(dl);
        true
    }

    /// Snapshot of dead-letters for `tenant_id`, newest-first, capped at
    /// `limit`.
    #[must_use]
    pub fn list(&self, tenant_id: &str, limit: usize) -> Vec<DeadLetter> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        let mut out: Vec<DeadLetter> = guard
            .iter()
            .filter(|d| d.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.reverse();
        out.truncate(limit);
        out
    }

    /// Number of dead-letters currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or_default()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for GrcDeadLetterQueue {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// Async sleeper abstraction. Lets the test suite swap tokio sleeps for
/// a deterministic recorder so the retry-loop tests run in micro-seconds
/// without `tokio::time::pause`.
pub trait Sleeper: Send + Sync + std::fmt::Debug {
    /// Sleep for `dur`.
    fn sleep(
        &self,
        dur: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;
}

/// Tokio-backed sleeper used in production.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep(
        &self,
        dur: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
        Box::pin(async move {
            tokio::time::sleep(dur).await;
        })
    }
}

/// Tenant-scoped GRC dispatcher.
#[derive(Clone)]
pub struct GrcDispatcher {
    audit: Arc<dyn GrcAuditSink>,
    dlq: GrcDeadLetterQueue,
    retry: RetryConfig,
    sleeper: Arc<dyn Sleeper>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for GrcDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrcDispatcher")
            .field("retry", &self.retry)
            .field("dlq", &self.dlq)
            .finish_non_exhaustive()
    }
}

/// Wall-clock abstraction — the dispatcher stamps every audit/dead-letter
/// record with `Clock::now_rfc3339`. Tests override this for determinism.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Return the current UTC time as an RFC 3339 string.
    fn now_rfc3339(&self) -> String;
}

/// Default system clock backed by [`time::OffsetDateTime::now_utc`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_rfc3339(&self) -> String {
        let now = time::OffsetDateTime::now_utc();
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
    }
}

/// Fixed-clock used by tests.
#[derive(Debug, Clone)]
pub struct FixedClock(String);

impl FixedClock {
    /// Construct a fixed clock that always returns `ts`.
    #[must_use]
    pub fn new(ts: impl Into<String>) -> Self {
        Self(ts.into())
    }
}

impl Clock for FixedClock {
    fn now_rfc3339(&self) -> String {
        self.0.clone()
    }
}

impl GrcDispatcher {
    /// Construct a dispatcher with the supplied audit sink + dead-letter
    /// queue and the production retry defaults.
    #[must_use]
    pub fn new(audit: Arc<dyn GrcAuditSink>, dlq: GrcDeadLetterQueue) -> Self {
        Self {
            audit,
            dlq,
            retry: RetryConfig::production(),
            sleeper: Arc::new(TokioSleeper),
            clock: Arc::new(SystemClock),
        }
    }

    /// Override the retry config. Builder-style.
    #[must_use]
    pub const fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    /// Override the sleeper. Builder-style; intended for tests.
    #[must_use]
    pub fn with_sleeper(mut self, sleeper: Arc<dyn Sleeper>) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// Override the clock. Builder-style; intended for tests.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Borrow the dead-letter queue.
    #[must_use]
    pub const fn dead_letters(&self) -> &GrcDeadLetterQueue {
        &self.dlq
    }

    /// Push compliance evidence via `connector`, honouring the retry +
    /// audit + dead-letter contract.
    pub async fn push_evidence(
        &self,
        tenant_id: &str,
        connector: Arc<dyn GrcConnector>,
        evidence: &ComplianceEvidence,
    ) -> Result<PushOutcome, ConnectorError> {
        let kind = connector.kind();
        self.dispatch(
            tenant_id,
            kind,
            GrcAuditResource::Evidence,
            &evidence.id,
            || async {
                let c = Arc::clone(&connector);
                c.push_evidence(evidence).await
            },
        )
        .await
    }

    /// Push a finding lifecycle update via `connector`.
    pub async fn push_finding(
        &self,
        tenant_id: &str,
        connector: Arc<dyn GrcConnector>,
        finding: &FindingState,
    ) -> Result<PushOutcome, ConnectorError> {
        let kind = connector.kind();
        self.dispatch(
            tenant_id,
            kind,
            GrcAuditResource::Finding,
            &finding.id,
            || async {
                let c = Arc::clone(&connector);
                c.push_finding(finding).await
            },
        )
        .await
    }

    /// Core retry loop. Lets the caller plug in either
    /// `push_evidence` or `push_finding` without a code duplication.
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    async fn dispatch<F, Fut>(
        &self,
        tenant_id: &str,
        kind: GrcKind,
        resource: GrcAuditResource,
        source_ref: &str,
        mut op: F,
    ) -> Result<PushOutcome, ConnectorError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<PushOutcome, ConnectorError>>,
    {
        let mut attempt: u32 = 1;
        loop {
            let res = op().await;
            match res {
                Ok(outcome) => {
                    self.audit
                        .record(GrcAuditEvent {
                            tenant_id: tenant_id.to_owned(),
                            kind,
                            resource,
                            source_ref: source_ref.to_owned(),
                            outcome: GrcAuditOutcome::Success,
                            attempts: attempt,
                            upstream_id: outcome.upstream_id.clone(),
                            error_code: None,
                            emitted_at: self.clock.now_rfc3339(),
                        })
                        .await;
                    debug!(
                        target: "sx_integrations::grc::dispatcher",
                        tenant_id = %tenant_id,
                        kind = %kind,
                        resource = %resource.as_wire(),
                        attempts = attempt,
                        "grc push succeeded"
                    );
                    return Ok(outcome);
                }
                Err(err) => {
                    let code = error_code(&err);
                    if is_permanent(&err) {
                        warn!(
                            target: "sx_integrations::grc::dispatcher",
                            tenant_id = %tenant_id,
                            kind = %kind,
                            resource = %resource.as_wire(),
                            attempts = attempt,
                            error_code = %code,
                            "grc push permanent failure; dead-lettering"
                        );
                        self.audit
                            .record(GrcAuditEvent {
                                tenant_id: tenant_id.to_owned(),
                                kind,
                                resource,
                                source_ref: source_ref.to_owned(),
                                outcome: GrcAuditOutcome::Permanent,
                                attempts: attempt,
                                upstream_id: None,
                                error_code: Some(code.clone()),
                                emitted_at: self.clock.now_rfc3339(),
                            })
                            .await;
                        self.dlq.record(DeadLetter {
                            tenant_id: tenant_id.to_owned(),
                            kind,
                            resource,
                            source_ref: source_ref.to_owned(),
                            error_code: code,
                            attempts: attempt,
                            recorded_at: self.clock.now_rfc3339(),
                        });
                        return Err(err);
                    }
                    if attempt >= self.retry.max_attempts {
                        warn!(
                            target: "sx_integrations::grc::dispatcher",
                            tenant_id = %tenant_id,
                            kind = %kind,
                            resource = %resource.as_wire(),
                            attempts = attempt,
                            error_code = %code,
                            "grc push retries exhausted; dead-lettering"
                        );
                        self.audit
                            .record(GrcAuditEvent {
                                tenant_id: tenant_id.to_owned(),
                                kind,
                                resource,
                                source_ref: source_ref.to_owned(),
                                outcome: GrcAuditOutcome::DeadLetter,
                                attempts: attempt,
                                upstream_id: None,
                                error_code: Some(code.clone()),
                                emitted_at: self.clock.now_rfc3339(),
                            })
                            .await;
                        self.dlq.record(DeadLetter {
                            tenant_id: tenant_id.to_owned(),
                            kind,
                            resource,
                            source_ref: source_ref.to_owned(),
                            error_code: code,
                            attempts: attempt,
                            recorded_at: self.clock.now_rfc3339(),
                        });
                        return Err(err);
                    }
                    // Retryable + budget remaining — emit a Retry audit
                    // event, sleep, and try again.
                    let delay = effective_delay(self.retry.backoff_for(attempt), &err);
                    self.audit
                        .record(GrcAuditEvent {
                            tenant_id: tenant_id.to_owned(),
                            kind,
                            resource,
                            source_ref: source_ref.to_owned(),
                            outcome: GrcAuditOutcome::Retry,
                            attempts: attempt,
                            upstream_id: None,
                            error_code: Some(code.clone()),
                            emitted_at: self.clock.now_rfc3339(),
                        })
                        .await;
                    debug!(
                        target: "sx_integrations::grc::dispatcher",
                        tenant_id = %tenant_id,
                        kind = %kind,
                        resource = %resource.as_wire(),
                        attempt,
                        error_code = %code,
                        delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        "grc push retrying"
                    );
                    self.sleeper.sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
}

/// Whether the error is permanent (no retry) or retryable.
const fn is_permanent(err: &ConnectorError) -> bool {
    matches!(
        err,
        ConnectorError::Unauthorized | ConnectorError::Format(_) | ConnectorError::Unimplemented
    )
}

/// Project a [`ConnectorError`] into a stable string code for audit
/// emission.
fn error_code(err: &ConnectorError) -> String {
    match err {
        ConnectorError::Transport(_) => "transport".into(),
        ConnectorError::Format(_) => "format".into(),
        ConnectorError::Unauthorized => "unauthorized".into(),
        ConnectorError::RateLimited { .. } => "rate_limited".into(),
        ConnectorError::Unimplemented => "unimplemented".into(),
    }
}

/// Compute the effective sleep duration, honouring a server-supplied
/// `Retry-After` hint when present.
fn effective_delay(backoff: Duration, err: &ConnectorError) -> Duration {
    if let ConnectorError::RateLimited {
        retry_after_secs: Some(secs),
    } = err
    {
        let hinted = Duration::from_secs(*secs);
        if hinted > backoff {
            return hinted;
        }
    }
    backoff
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::grc::audit::{NoopAuditSink, RecordingAuditSink};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Test connector that returns scripted results in order.
    #[derive(Debug)]
    struct ScriptedConnector {
        kind: GrcKind,
        scripts: Mutex<Vec<Result<PushOutcome, ConnectorError>>>,
        evidence_calls: AtomicU32,
        finding_calls: AtomicU32,
    }

    impl ScriptedConnector {
        fn new(kind: GrcKind, scripts: Vec<Result<PushOutcome, ConnectorError>>) -> Self {
            Self {
                kind,
                scripts: Mutex::new(scripts),
                evidence_calls: AtomicU32::new(0),
                finding_calls: AtomicU32::new(0),
            }
        }

        fn next(&self) -> Result<PushOutcome, ConnectorError> {
            let mut g = self.scripts.lock().unwrap();
            if g.is_empty() {
                return Err(ConnectorError::Transport("script empty".into()));
            }
            g.remove(0)
        }
    }

    #[async_trait]
    impl GrcConnector for ScriptedConnector {
        fn kind(&self) -> GrcKind {
            self.kind
        }
        async fn push_evidence(
            &self,
            _evidence: &ComplianceEvidence,
        ) -> Result<PushOutcome, ConnectorError> {
            self.evidence_calls.fetch_add(1, Ordering::SeqCst);
            self.next()
        }
        async fn push_finding(
            &self,
            _finding: &FindingState,
        ) -> Result<PushOutcome, ConnectorError> {
            self.finding_calls.fetch_add(1, Ordering::SeqCst);
            self.next()
        }
    }

    /// Sleeper that records the delays without actually sleeping.
    #[derive(Debug, Default, Clone)]
    struct RecordingSleeper {
        delays: Arc<Mutex<Vec<Duration>>>,
    }

    impl Sleeper for RecordingSleeper {
        fn sleep(
            &self,
            dur: Duration,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
            self.delays.lock().unwrap().push(dur);
            Box::pin(async {})
        }
    }

    fn evidence() -> ComplianceEvidence {
        ComplianceEvidence {
            id: "ev-1".into(),
            tenant_id: "t-1".into(),
            framework: "soc2".into(),
            control_id: "CC6.1".into(),
            finding_ref: "f-7".into(),
            observation_ref: "obs-3".into(),
            collected_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    fn finding() -> FindingState {
        FindingState {
            id: "f-9".into(),
            tenant_id: "t-1".into(),
            severity: "high".into(),
            status: "open".into(),
            title: "T".into(),
            description: "D".into(),
            first_seen: "2027-01-01T00:00:00Z".into(),
            last_seen: "2027-01-02T00:00:00Z".into(),
        }
    }

    fn fast_retry() -> RetryConfig {
        RetryConfig::new(3, Duration::from_millis(10), Duration::from_millis(50))
    }

    fn dispatcher_for(audit: Arc<dyn GrcAuditSink>) -> (GrcDispatcher, RecordingSleeper) {
        let sleeper = RecordingSleeper::default();
        let dlq = GrcDeadLetterQueue::new(32);
        let d = GrcDispatcher::new(audit, dlq)
            .with_retry(fast_retry())
            .with_sleeper(Arc::new(sleeper.clone()))
            .with_clock(Arc::new(FixedClock::new("2027-01-01T00:00:00Z")));
        (d, sleeper)
    }

    #[tokio::test]
    async fn first_attempt_success_emits_single_audit_event() {
        let audit = RecordingAuditSink::new();
        let (d, _s) = dispatcher_for(Arc::new(audit.clone()));
        let c: Arc<dyn GrcConnector> = Arc::new(ScriptedConnector::new(
            GrcKind::Vanta,
            vec![Ok(PushOutcome {
                upstream_id: Some("up-1".into()),
                url: None,
            })],
        ));
        let outcome = d.push_evidence("t-1", c, &evidence()).await.unwrap();
        assert_eq!(outcome.upstream_id.as_deref(), Some("up-1"));
        let snap = audit.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].outcome, GrcAuditOutcome::Success);
        assert_eq!(snap[0].attempts, 1);
        assert!(d.dead_letters().is_empty());
    }

    #[tokio::test]
    async fn retryable_eventually_succeeds() {
        let audit = RecordingAuditSink::new();
        let (d, sleeper) = dispatcher_for(Arc::new(audit.clone()));
        let c: Arc<dyn GrcConnector> = Arc::new(ScriptedConnector::new(
            GrcKind::Vanta,
            vec![
                Err(ConnectorError::Transport("flap".into())),
                Err(ConnectorError::RateLimited {
                    retry_after_secs: None,
                }),
                Ok(PushOutcome {
                    upstream_id: Some("up-x".into()),
                    url: None,
                }),
            ],
        ));
        let outcome = d.push_finding("t-1", c, &finding()).await.unwrap();
        assert_eq!(outcome.upstream_id.as_deref(), Some("up-x"));
        let snap = audit.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].outcome, GrcAuditOutcome::Retry);
        assert_eq!(snap[1].outcome, GrcAuditOutcome::Retry);
        assert_eq!(snap[2].outcome, GrcAuditOutcome::Success);
        assert_eq!(snap[2].attempts, 3);
        // Two retries → two sleeps recorded.
        assert_eq!(sleeper.delays.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn permanent_short_circuits_to_dead_letter() {
        let audit = RecordingAuditSink::new();
        let (d, sleeper) = dispatcher_for(Arc::new(audit.clone()));
        let c: Arc<dyn GrcConnector> = Arc::new(ScriptedConnector::new(
            GrcKind::Vanta,
            vec![Err(ConnectorError::Unauthorized)],
        ));
        let err = d.push_evidence("t-1", c, &evidence()).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Unauthorized));
        let snap = audit.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].outcome, GrcAuditOutcome::Permanent);
        assert_eq!(snap[0].error_code.as_deref(), Some("unauthorized"));
        let dls = d.dead_letters().list("t-1", 10);
        assert_eq!(dls.len(), 1);
        assert_eq!(dls[0].error_code, "unauthorized");
        assert!(sleeper.delays.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn retry_exhausted_dead_letters() {
        let audit = RecordingAuditSink::new();
        let (d, _s) = dispatcher_for(Arc::new(audit.clone()));
        let c: Arc<dyn GrcConnector> = Arc::new(ScriptedConnector::new(
            GrcKind::Vanta,
            vec![
                Err(ConnectorError::Transport("a".into())),
                Err(ConnectorError::Transport("b".into())),
                Err(ConnectorError::Transport("c".into())),
            ],
        ));
        let err = d.push_evidence("t-1", c, &evidence()).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Transport(_)));
        let snap = audit.snapshot();
        // 2 retries (attempts 1,2) + 1 dead-letter (attempt 3).
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].outcome, GrcAuditOutcome::Retry);
        assert_eq!(snap[1].outcome, GrcAuditOutcome::Retry);
        assert_eq!(snap[2].outcome, GrcAuditOutcome::DeadLetter);
        assert_eq!(snap[2].attempts, 3);
        assert_eq!(d.dead_letters().list("t-1", 10).len(), 1);
    }

    #[tokio::test]
    async fn rate_limit_honours_retry_after_hint() {
        let audit = RecordingAuditSink::new();
        let (d, sleeper) = dispatcher_for(Arc::new(audit));
        let c: Arc<dyn GrcConnector> = Arc::new(ScriptedConnector::new(
            GrcKind::Vanta,
            vec![
                Err(ConnectorError::RateLimited {
                    retry_after_secs: Some(2),
                }),
                Ok(PushOutcome::empty()),
            ],
        ));
        let _ = d.push_finding("t-1", c, &finding()).await.unwrap();
        let delays = sleeper.delays.lock().unwrap().clone();
        assert_eq!(delays.len(), 1);
        // Should respect the 2s hint, not the 10ms backoff.
        assert!(delays[0] >= Duration::from_secs(2));
    }

    #[tokio::test]
    async fn dead_letter_queue_scoped_by_tenant() {
        let audit = RecordingAuditSink::new();
        let (d, _s) = dispatcher_for(Arc::new(audit));
        let c1: Arc<dyn GrcConnector> = Arc::new(ScriptedConnector::new(
            GrcKind::Vanta,
            vec![Err(ConnectorError::Unauthorized)],
        ));
        let c2: Arc<dyn GrcConnector> = Arc::new(ScriptedConnector::new(
            GrcKind::Vanta,
            vec![Err(ConnectorError::Unauthorized)],
        ));
        let _ = d.push_evidence("tenant-a", c1, &evidence()).await;
        let _ = d.push_evidence("tenant-b", c2, &evidence()).await;
        assert_eq!(d.dead_letters().list("tenant-a", 10).len(), 1);
        assert_eq!(d.dead_letters().list("tenant-b", 10).len(), 1);
        assert_eq!(d.dead_letters().list("tenant-c", 10).len(), 0);
    }

    #[test]
    fn backoff_caps_at_max_delay() {
        let cfg = RetryConfig::new(10, Duration::from_millis(100), Duration::from_millis(500));
        assert_eq!(cfg.backoff_for(1), Duration::from_millis(100));
        assert_eq!(cfg.backoff_for(2), Duration::from_millis(200));
        assert_eq!(cfg.backoff_for(3), Duration::from_millis(400));
        // 100 * 2^3 = 800 → capped at 500
        assert_eq!(cfg.backoff_for(4), Duration::from_millis(500));
        assert_eq!(cfg.backoff_for(30), Duration::from_millis(500));
    }

    #[test]
    fn retry_config_clamps_zero_to_one() {
        let cfg = RetryConfig::new(0, Duration::from_millis(1), Duration::from_millis(2));
        assert_eq!(cfg.max_attempts, 1);
    }

    #[test]
    fn dead_letter_queue_evicts_oldest_when_full() {
        let q = GrcDeadLetterQueue::new(2);
        for i in 0..4 {
            q.record(DeadLetter {
                tenant_id: "t".into(),
                kind: GrcKind::Vanta,
                resource: GrcAuditResource::Evidence,
                source_ref: format!("e-{i}"),
                error_code: "transport".into(),
                attempts: 1,
                recorded_at: "2027-01-01T00:00:00Z".into(),
            });
        }
        assert_eq!(q.len(), 2);
        let list = q.list("t", 10);
        // Newest first.
        assert_eq!(list[0].source_ref, "e-3");
        assert_eq!(list[1].source_ref, "e-2");
    }

    #[tokio::test]
    async fn noop_sink_path_compiles() {
        let dlq = GrcDeadLetterQueue::new(8);
        let d = GrcDispatcher::new(Arc::new(NoopAuditSink), dlq)
            .with_retry(fast_retry())
            .with_sleeper(Arc::new(RecordingSleeper::default()));
        let c: Arc<dyn GrcConnector> = Arc::new(ScriptedConnector::new(
            GrcKind::Drata,
            vec![Ok(PushOutcome::empty())],
        ));
        let _ = d.push_evidence("t-1", c, &evidence()).await.unwrap();
    }
}
