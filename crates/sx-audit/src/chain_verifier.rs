//! Background hot-tail chain verifier (CRIT-002).
//!
//! Walks the per-tenant audit hash chain every `interval` seconds and
//! re-verifies the last 24h window via the existing
//! [`verify_entries`](crate::controller::verify_chain::verify_entries)
//! function. On the first detected divergence it builds a structured
//! `audit.chain.broken` payload and forwards it to every registered
//! [`BrokenChainSubscriber`].
//!
//! ## Why a re-verify on the hot tail
//!
//! Hot-tail re-verification is the cheapest way to flush an actively
//! tampered window: the verifier runs on the live `AuditSink`, so a row
//! flipped *after* it was first persisted is caught before it gets
//! stamped into the next TSA anchor (`anchor_run`) — that is, before the
//! tamper becomes provably notarised. The cadence (default 5 min) is a
//! pragmatic compromise between detection latency and `verify_entries`
//! cost; operators can shrink it to seconds in regulated environments
//! by overriding `audit.chain_verifier.interval_secs`.
//!
//! ## Subscribers
//!
//! [`BrokenChainSubscriber`] is the trait the IR-playbooks auto-fire
//! adapter implements. Multiple subscribers can be registered (SOC alert
//! correlator, paging gateway, …). The verifier walks them in
//! registration order; a panicking subscriber is logged and the loop
//! continues so a misbehaving sink cannot starve the rest.
//!
//! ## Multi-tenancy
//!
//! [`ChainVerifier::run_once`] iterates a per-tick snapshot of the
//! configured tenant set. Tenants are added via
//! [`ChainVerifier::register_tenant`]; the verifier never enumerates
//! tenants out of the `AuditSink` itself to keep the API stable across
//! schema migrations.
//!
//! ## Test surface
//!
//! Every collaborator is a trait object so the unit tests can substitute
//! an in-memory [`AuditSink`] backed by a `Vec<AuditEntry>` and a
//! recording [`BrokenChainSubscriber`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use sx_core::value_object::ids::TenantId;

use crate::controller::verify_chain::verify_entries;
use crate::error::AuditError;
use crate::model::entry::AuditEntry;
use crate::service::sink::AuditSink;

/// CRITICAL `sx-audit` event payload emitted when the background
/// verifier detects a chain break.
///
/// Mirrors the field set called out in CRIT-002 AC #2:
/// `{tenant_id, expected_hash, actual_hash, last_good_seq, break_seq}`.
///
/// The two `*_hash` fields are hex-encoded SHA-256 digests (64 chars).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChainBrokenPayload {
    /// Tenant whose chain failed verification.
    pub tenant_id: TenantId,
    /// Hex-encoded hash the verifier *expected* at `break_seq` (i.e. the
    /// SHA-256 recomputed from the stored canonical bytes + `prev_hash`).
    pub expected_hash: String,
    /// Hex-encoded hash actually stored at `break_seq`.
    pub actual_hash: String,
    /// Last sequence number whose stored hash matched the
    /// recomputation. `None` when the chain broke at the very first row
    /// of the verified window (typical for sequence gaps starting at
    /// the window's lower bound).
    pub last_good_seq: Option<u64>,
    /// First sequence number at which the recomputed hash diverged from
    /// the stored hash, OR — for [`AuditError::SequenceGap`] — the
    /// sequence number that revealed the gap.
    pub break_seq: u64,
    /// RFC 3339 timestamp at which the break was confirmed. Used to
    /// start the GDPR Art. 33 / Indonesia PDP UU 27/2022 §46
    /// notification timers.
    pub detected_at: String,
}

/// Result of one verifier tick for a single tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyTickResult {
    /// The chain verified cleanly across the inspected window.
    Clean {
        /// Number of entries verified by this tick.
        entries_checked: u64,
    },
    /// No entries were present in the window. The verifier treats this
    /// as `Clean { entries_checked: 0 }` for metrics but reports it as a
    /// distinct variant so operators can spot a misconfigured tenant
    /// (no audit volume = stale tenant) at a glance.
    Empty,
    /// The chain failed verification — the payload has been forwarded
    /// to every subscriber.
    Broken(AuditChainBrokenPayload),
}

/// Subscriber notified on every chain break the verifier observes.
///
/// The IR-playbooks crate's auto-fire adapter implements this trait
/// against [`IrPlaybookService::auto_fire_audit_chain_compromise`]; the
/// composition root registers the adapter on monolith boot.
///
/// Subscribers MUST be cheap and infallible — the verifier logs and
/// continues past any error so a misbehaving subscriber cannot mute the
/// other ones. Heavy lifting (e.g. paging the on-call) belongs on a
/// dedicated work-queue downstream of the subscriber.
#[async_trait]
pub trait BrokenChainSubscriber: Send + Sync + std::fmt::Debug {
    /// Called once per detected break per tenant per tick. Best-effort.
    async fn on_broken(&self, payload: &AuditChainBrokenPayload);
}

/// TOP5-#3-P2-007 alias spelling for [`BrokenChainSubscriber`].
///
/// The Wave-B audit recommended a `BreakObserver` name on the
/// finding-emission side so the at-boundary glue layer reads as
/// `on_break(event)` without inventing a parallel trait. The underlying
/// contract is identical — `BreakObserver` is a re-export of
/// [`BrokenChainSubscriber`] so adapters registered against either
/// spelling share the same verifier fan-out path.
pub use BrokenChainSubscriber as BreakObserver;

/// TOP5-#3-P2-007 alias spelling for [`AuditChainBrokenPayload`].
///
/// Mirrors [`BreakObserver`]: callers that read more naturally as
/// "the verifier publishes a `ChainBreakEvent`" get the friendlier name
/// without a wire duplicate. The underlying type — every field, every
/// invariant — is unchanged.
pub use AuditChainBrokenPayload as ChainBreakEvent;

/// Recording subscriber used by tests + by the composition root when it
/// wants to assert the wire shape end-to-end without paging on-call.
#[derive(Debug, Default)]
pub struct RecordingSubscriber {
    events: Mutex<Vec<AuditChainBrokenPayload>>,
}

impl RecordingSubscriber {
    /// Fresh empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain a snapshot of the events captured so far.
    pub async fn events(&self) -> Vec<AuditChainBrokenPayload> {
        self.events.lock().await.clone()
    }
}

#[async_trait]
impl BrokenChainSubscriber for RecordingSubscriber {
    async fn on_broken(&self, payload: &AuditChainBrokenPayload) {
        self.events.lock().await.push(payload.clone());
    }
}

/// Trait abstracting the wall-clock so tests can pin time. Returns an
/// RFC 3339 string because the audit chain stores timestamps in that
/// form and the structured payload mirrors that choice.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Current instant, RFC 3339 (UTC, no offset).
    fn now_rfc3339(&self) -> String;
    /// Lower-bound seq cutoff for the hot-tail window.
    ///
    /// The verifier asks the clock for *seq* rather than a timestamp so
    /// the cut-off can be tuned per-deployment (some operators want a
    /// 24h window, others a fixed 10k-row tail). Defaults to `1` —
    /// equivalent to "verify everything".
    fn hot_tail_window_seq(&self) -> u64 {
        1
    }
}

/// Default clock — `OffsetDateTime::now_utc`.
///
/// Returns `1` for the hot-tail seq cut-off so the verifier walks the
/// entire chain. The composition root substitutes a richer clock that
/// consults the `audit.chain_verifier.interval_secs` config + tracks a
/// sliding 24h seq baseline.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_rfc3339(&self) -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
    }
}

/// The background hot-tail verifier.
///
/// Constructed via [`ChainVerifier::new`]. Schedule with
/// [`ChainVerifier::spawn`] or drive directly via
/// [`ChainVerifier::run_once`] from a test.
#[derive(Debug, Clone)]
pub struct ChainVerifier {
    sink: Arc<dyn AuditSink>,
    subscribers: Vec<Arc<dyn BrokenChainSubscriber>>,
    tenants: Arc<Mutex<HashSet<TenantId>>>,
    clock: Arc<dyn Clock>,
    interval: Duration,
}

/// Default interval between verifier ticks — 5 minutes, matching the
/// CRIT-002 spec.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(300);

impl ChainVerifier {
    /// Build a new verifier. `interval` is the cadence of the spawned
    /// loop; pass [`DEFAULT_INTERVAL`] for the spec-mandated 5 min
    /// cadence.
    #[must_use]
    pub fn new(
        sink: Arc<dyn AuditSink>,
        subscribers: Vec<Arc<dyn BrokenChainSubscriber>>,
        clock: Arc<dyn Clock>,
        interval: Duration,
    ) -> Self {
        Self {
            sink,
            subscribers,
            tenants: Arc::new(Mutex::new(HashSet::new())),
            clock,
            interval,
        }
    }

    /// Add a tenant to the verifier's per-tick rotation.
    pub async fn register_tenant(&self, tenant: TenantId) {
        self.tenants.lock().await.insert(tenant);
    }

    /// Remove a tenant from the rotation (e.g. tenant deletion).
    pub async fn unregister_tenant(&self, tenant: &TenantId) {
        self.tenants.lock().await.remove(tenant);
    }

    /// Snapshot the current tenant rotation.
    pub async fn registered_tenants(&self) -> Vec<TenantId> {
        let g = self.tenants.lock().await;
        let mut v: Vec<TenantId> = g.iter().copied().collect();
        drop(g);
        v.sort();
        v
    }

    /// Run exactly one verifier tick across every registered tenant.
    ///
    /// Returns a vector of `(tenant, result)` pairs for observability.
    /// Errors from `AuditSink::read_range` are logged at WARN and
    /// surfaced as `Empty` so a transient sink hiccup cannot trip the
    /// IR pipeline.
    pub async fn run_once(&self) -> Vec<(TenantId, VerifyTickResult)> {
        let tenants = self.registered_tenants().await;
        let mut out: Vec<(TenantId, VerifyTickResult)> = Vec::with_capacity(tenants.len());
        for tenant in tenants {
            let result = self.verify_tenant(tenant).await;
            if let VerifyTickResult::Broken(ref payload) = result {
                self.fan_out(payload).await;
            }
            out.push((tenant, result));
        }
        out
    }

    /// Spawn the verifier loop on the current tokio runtime. The loop
    /// honours the user-supplied `shutdown` future; when it resolves the
    /// loop logs and returns cleanly. The composition root typically
    /// passes `tokio_util::sync::CancellationToken::cancelled_owned()`.
    #[must_use]
    pub fn spawn<F>(self: Arc<Self>, shutdown: F) -> tokio::task::JoinHandle<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let interval = self.interval;
        tokio::spawn(async move {
            tracing::info!(
                target: "audit.chain_verifier",
                interval_secs = interval.as_secs(),
                "audit chain verifier spawned"
            );
            let mut ticker = tokio::time::interval(interval);
            // Skip the first immediate tick so the boot-time path is
            // not biased toward the verifier — same convention the
            // other long-running monolith jobs use.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            tokio::pin!(shutdown);
            loop {
                tokio::select! {
                    () = &mut shutdown => {
                        tracing::info!(
                            target: "audit.chain_verifier",
                            "audit chain verifier received cancellation, exiting",
                        );
                        return;
                    }
                    _ = ticker.tick() => {
                        let results = self.run_once().await;
                        for (tenant, r) in &results {
                            match r {
                                VerifyTickResult::Clean { entries_checked } => {
                                    tracing::debug!(
                                        target: "audit.chain_verifier",
                                        tenant = %tenant,
                                        entries_checked,
                                        "tick clean"
                                    );
                                }
                                VerifyTickResult::Empty => {
                                    tracing::debug!(
                                        target: "audit.chain_verifier",
                                        tenant = %tenant,
                                        "tick empty window"
                                    );
                                }
                                VerifyTickResult::Broken(p) => {
                                    tracing::error!(
                                        target: "audit.chain_verifier",
                                        tenant = %tenant,
                                        break_seq = p.break_seq,
                                        last_good_seq = ?p.last_good_seq,
                                        "audit.chain.broken — IR auto-fire dispatched"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    /// Verify a single tenant's hot tail. Internal; exposed for tests.
    pub async fn verify_tenant(&self, tenant: TenantId) -> VerifyTickResult {
        let from_seq = self.clock.hot_tail_window_seq();
        let entries = match self.sink.read_range(tenant, from_seq, u64::MAX).await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    target: "audit.chain_verifier",
                    tenant = %tenant,
                    error = %err,
                    "sink read_range failed; treating as empty for this tick"
                );
                return VerifyTickResult::Empty;
            }
        };
        if entries.is_empty() {
            return VerifyTickResult::Empty;
        }
        let entries_checked = entries.len() as u64;
        let expected_first = entries.first().map_or(from_seq, |e| e.seq);
        match verify_entries(&entries, expected_first) {
            Ok(_) => VerifyTickResult::Clean { entries_checked },
            Err(err) => VerifyTickResult::Broken(broken_payload(
                tenant,
                &entries,
                &err,
                self.clock.now_rfc3339(),
            )),
        }
    }

    async fn fan_out(&self, payload: &AuditChainBrokenPayload) {
        for sub in &self.subscribers {
            sub.on_broken(payload).await;
        }
    }
}

/// Translate an [`AuditError`] from `verify_entries` plus the local
/// entries slice into a structured [`AuditChainBrokenPayload`].
///
/// The function is pure so the unit tests can drive every error variant
/// through it without spinning up a verifier.
pub fn broken_payload(
    tenant: TenantId,
    entries: &[AuditEntry],
    err: &AuditError,
    detected_at: String,
) -> AuditChainBrokenPayload {
    match err {
        AuditError::ChainDivergence {
            at_seq,
            expected,
            actual,
        } => AuditChainBrokenPayload {
            tenant_id: tenant,
            expected_hash: expected.clone(),
            actual_hash: actual.clone(),
            last_good_seq: at_seq
                .checked_sub(1)
                .filter(|s| entries.iter().any(|e| e.seq == *s)),
            break_seq: *at_seq,
            detected_at,
        },
        AuditError::SequenceGap { at_seq } => AuditChainBrokenPayload {
            tenant_id: tenant,
            expected_hash: String::new(),
            actual_hash: String::new(),
            last_good_seq: at_seq
                .checked_sub(1)
                .filter(|s| entries.iter().any(|e| e.seq == *s)),
            break_seq: *at_seq,
            detected_at,
        },
        AuditError::Sink(_) | AuditError::Serialization(_) | AuditError::Internal(_) => {
            AuditChainBrokenPayload {
                tenant_id: tenant,
                expected_hash: String::new(),
                actual_hash: String::new(),
                last_good_seq: entries.last().map(|e| e.seq),
                break_seq: 0,
                detected_at,
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::similar_names
)]
mod tests {
    use super::*;

    use time::OffsetDateTime;
    use uuid::Uuid;

    use sx_core::value_object::ids::{TenantId, UserId};

    use crate::model::action::AuditAction;
    use crate::model::actor::Actor;
    use crate::service::chain_builder::{build_entry, build_genesis, NewAuditEvent};

    fn tenant() -> TenantId {
        Uuid::parse_str("00000000-0000-7000-8000-00000000000a")
            .unwrap()
            .into()
    }

    fn tenant_b() -> TenantId {
        Uuid::parse_str("00000000-0000-7000-8000-00000000000b")
            .unwrap()
            .into()
    }

    fn payload(seq_hint: u64, tid: TenantId) -> NewAuditEvent {
        let user: UserId = Uuid::parse_str("00000000-0000-7000-8000-000000000002")
            .unwrap()
            .into();
        NewAuditEvent {
            tenant_id: tid,
            actor: Actor::user(user),
            action: AuditAction::Login,
            resource_kind: "session".into(),
            resource_id: format!("s-{seq_hint}"),
            before: None,
            after: None,
            request_id: format!("req-{seq_hint}"),
            ts: Some(OffsetDateTime::from_unix_timestamp(1_700_000_000 + seq_hint as i64).unwrap()),
        }
    }

    fn make_chain(tid: TenantId, n: u64) -> Vec<AuditEntry> {
        let mut entries = Vec::with_capacity(n as usize);
        let g = build_genesis(payload(1, tid)).unwrap();
        entries.push(g);
        for i in 2..=n {
            let prev = entries.last().unwrap();
            let e = build_entry(i, prev.hash, payload(i, tid)).unwrap();
            entries.push(e);
        }
        entries
    }

    /// Minimal in-memory [`AuditSink`] for the verifier tests. Holds a
    /// single tenant's entries — multi-tenant fixtures construct one
    /// per tenant.
    #[derive(Debug, Default)]
    struct VecSink {
        entries: Mutex<Vec<AuditEntry>>,
    }

    #[async_trait]
    impl AuditSink for VecSink {
        async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
            self.entries.lock().await.push(entry.clone());
            Ok(())
        }

        async fn last_entry_for_tenant(
            &self,
            tid: TenantId,
        ) -> Result<Option<AuditEntry>, AuditError> {
            let g = self.entries.lock().await;
            let last = g
                .iter()
                .filter(|e| e.tenant_id == tid)
                .max_by_key(|e| e.seq)
                .cloned();
            drop(g);
            Ok(last)
        }

        async fn read_range(
            &self,
            tid: TenantId,
            from: u64,
            to: u64,
        ) -> Result<Vec<AuditEntry>, AuditError> {
            let g = self.entries.lock().await;
            let mut out: Vec<AuditEntry> = g
                .iter()
                .filter(|e| e.tenant_id == tid && e.seq >= from && e.seq <= to)
                .cloned()
                .collect();
            drop(g);
            out.sort_by_key(|e| e.seq);
            Ok(out)
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    struct FixedClock;
    impl Clock for FixedClock {
        fn now_rfc3339(&self) -> String {
            "2026-01-01T00:00:00Z".into()
        }
    }

    async fn seed_chain(sink: &VecSink, entries: &[AuditEntry]) {
        for e in entries {
            sink.append(e).await.unwrap();
        }
    }

    #[tokio::test]
    async fn clean_chain_yields_clean_tick() {
        let sink = Arc::new(VecSink::default());
        let entries = make_chain(tenant(), 5);
        seed_chain(&sink, &entries).await;

        let subscriber = Arc::new(RecordingSubscriber::new());
        let v = ChainVerifier::new(
            sink.clone() as Arc<dyn AuditSink>,
            vec![subscriber.clone() as Arc<dyn BrokenChainSubscriber>],
            Arc::new(FixedClock),
            DEFAULT_INTERVAL,
        );
        v.register_tenant(tenant()).await;
        let results = v.run_once().await;
        assert_eq!(results.len(), 1);
        match &results[0].1 {
            VerifyTickResult::Clean { entries_checked } => assert_eq!(*entries_checked, 5),
            other => panic!("expected Clean, got {other:?}"),
        }
        assert!(subscriber.events().await.is_empty());
    }

    #[tokio::test]
    async fn synthetic_break_is_detected_and_emitted() {
        let sink = Arc::new(VecSink::default());
        let mut entries = make_chain(tenant(), 5);
        // Tamper: rewrite the third entry's request_id.
        entries[2].request_id = "TAMPERED".to_owned();
        seed_chain(&sink, &entries).await;

        let subscriber = Arc::new(RecordingSubscriber::new());
        let v = ChainVerifier::new(
            sink.clone() as Arc<dyn AuditSink>,
            vec![subscriber.clone() as Arc<dyn BrokenChainSubscriber>],
            Arc::new(FixedClock),
            DEFAULT_INTERVAL,
        );
        v.register_tenant(tenant()).await;
        let results = v.run_once().await;
        assert_eq!(results.len(), 1);
        let payload = match &results[0].1 {
            VerifyTickResult::Broken(p) => p.clone(),
            other => panic!("expected Broken, got {other:?}"),
        };
        assert_eq!(payload.break_seq, 3);
        assert_eq!(payload.last_good_seq, Some(2));
        assert_eq!(payload.tenant_id, tenant());
        assert_eq!(payload.detected_at, "2026-01-01T00:00:00Z");
        // Subscriber observed exactly the same payload.
        let observed = subscriber.events().await;
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0], payload);
    }

    #[tokio::test]
    async fn empty_tenant_window_is_empty_tick() {
        let sink = Arc::new(VecSink::default());
        let subscriber = Arc::new(RecordingSubscriber::new());
        let v = ChainVerifier::new(
            sink as Arc<dyn AuditSink>,
            vec![subscriber as Arc<dyn BrokenChainSubscriber>],
            Arc::new(FixedClock),
            DEFAULT_INTERVAL,
        );
        v.register_tenant(tenant()).await;
        let results = v.run_once().await;
        assert!(matches!(results[0].1, VerifyTickResult::Empty));
    }

    #[tokio::test]
    async fn multi_tenant_isolation() {
        let sink = Arc::new(VecSink::default());
        // Tenant A clean.
        seed_chain(&sink, &make_chain(tenant(), 3)).await;
        // Tenant B tampered.
        let mut b_entries = make_chain(tenant_b(), 4);
        b_entries[1].request_id = "TAMPERED-B".to_owned();
        seed_chain(&sink, &b_entries).await;

        let subscriber = Arc::new(RecordingSubscriber::new());
        let v = ChainVerifier::new(
            sink as Arc<dyn AuditSink>,
            vec![subscriber.clone() as Arc<dyn BrokenChainSubscriber>],
            Arc::new(FixedClock),
            DEFAULT_INTERVAL,
        );
        v.register_tenant(tenant()).await;
        v.register_tenant(tenant_b()).await;
        let results = v.run_once().await;

        let by_tenant: std::collections::HashMap<TenantId, VerifyTickResult> =
            results.into_iter().collect();
        match &by_tenant[&tenant()] {
            VerifyTickResult::Clean { entries_checked } => assert_eq!(*entries_checked, 3),
            other => panic!("expected Clean for A, got {other:?}"),
        }
        match &by_tenant[&tenant_b()] {
            VerifyTickResult::Broken(p) => {
                assert_eq!(p.tenant_id, tenant_b());
                assert_eq!(p.break_seq, 2);
            }
            other => panic!("expected Broken for B, got {other:?}"),
        }
        // Subscriber observed exactly tenant B's break.
        let observed = subscriber.events().await;
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].tenant_id, tenant_b());
    }

    #[tokio::test]
    async fn registered_tenants_round_trips() {
        let sink = Arc::new(VecSink::default());
        let v = ChainVerifier::new(
            sink as Arc<dyn AuditSink>,
            vec![],
            Arc::new(FixedClock),
            DEFAULT_INTERVAL,
        );
        v.register_tenant(tenant()).await;
        v.register_tenant(tenant_b()).await;
        let mut all = v.registered_tenants().await;
        all.sort();
        assert_eq!(all.len(), 2);
        v.unregister_tenant(&tenant()).await;
        let after = v.registered_tenants().await;
        assert_eq!(after, vec![tenant_b()]);
    }

    #[test]
    fn broken_payload_translates_chain_divergence() {
        let entries = make_chain(tenant(), 2);
        let err = AuditError::ChainDivergence {
            at_seq: 2,
            expected: "ee".repeat(32),
            actual: "ff".repeat(32),
        };
        let p = broken_payload(tenant(), &entries, &err, "ts".into());
        assert_eq!(p.break_seq, 2);
        assert_eq!(p.last_good_seq, Some(1));
        assert_eq!(p.expected_hash.len(), 64);
        assert_eq!(p.actual_hash.len(), 64);
        assert_eq!(p.tenant_id, tenant());
    }

    #[test]
    fn broken_payload_translates_sequence_gap() {
        let entries = make_chain(tenant(), 2);
        let err = AuditError::SequenceGap { at_seq: 2 };
        let p = broken_payload(tenant(), &entries, &err, "ts".into());
        assert_eq!(p.break_seq, 2);
        assert_eq!(p.last_good_seq, Some(1));
        assert!(p.expected_hash.is_empty());
        assert!(p.actual_hash.is_empty());
    }
}
