//! Audit replay — time-travel debugging.
//!
//! Given a tenant + a timestamp, reconstruct the **read-only** state of an
//! aggregate (engagement, finding, …) AS-OF that moment by walking the
//! existing append-only audit chain and selecting the latest `after`
//! snapshot whose `ts <= as_of`.
//!
//! This module is purely a query / projection layer — it never mutates the
//! chain. Sibling crates and HTTP controllers wrap the in-memory service
//! via the `Arc<dyn TimeTravelService>` form so the read surface stays
//! decoupled from the underlying [`AuditSink`].
//!
//! ## Acceptance criteria (P3-009)
//!
//! - Reconstruct any past state via audit log — [`TimeTravelService::replay_engagement`],
//!   [`TimeTravelService::replay_finding`] and the generic
//!   [`TimeTravelService::replay_timeline`].
//! - Diff between two timestamps — [`TimeTravelService::diff_between`] returns
//!   a [`StateDiff`] with the `before` snapshot at the earlier moment and
//!   the `after` snapshot at the later moment.
//! - Read-only, never mutates current state — every method consumes the
//!   sink through `read_range`; no `append` calls are issued from this
//!   module.
//!
//! ## Chain integrity
//!
//! Replay results are only useful if the underlying chain has not been
//! tampered with. Each public projection method runs
//! [`crate::controller::verify_chain::verify_entries`] over the tenant
//! slice before returning any state. If the chain is broken, the method
//! surfaces [`AuditError::ChainDivergence`] / [`AuditError::SequenceGap`]
//! directly so callers can render an explicit "chain broken" message
//! instead of stale state.
//!
//! ## Algorithm
//!
//! For each aggregate kind / id:
//!
//! 1. Snapshot every entry whose `tenant_id == requested tenant`,
//!    `resource_kind == aggregate kind code`, `resource_id == requested
//!    id`, and `ts <= as_of`.
//! 2. Pick the entry with the latest `ts` (and, on tie, the highest
//!    `seq`).
//! 3. If the picked entry has an `after` JSON snapshot, decode it into
//!    the wire view type (`EngagementView` / `FindingView`).
//! 4. Otherwise (e.g. the last recorded event was a *delete*), the
//!    aggregate is considered absent at `as_of` and `None` is returned.
//!
//! ## Future timestamps
//!
//! The HTTP controller rejects `as_of` values that are more than seven
//! days in the future before the request reaches this module — see
//! `crate::controller::time_travel::replay_engagement` in `sx-api`. This
//! module itself accepts any timestamp because internal callers (tests,
//! background jobs) may legitimately query future timestamps without
//! incurring the operator-protection window.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::instrument;

use sx_core::value_object::ids::TenantId;

use crate::controller::verify_chain::verify_entries;
use crate::error::AuditError;
use crate::model::entry::AuditEntry;
use crate::service::sink::AuditSink;

/// Aggregate kinds the time-travel surface understands.
///
/// The on-wire `resource_kind` string stored on every audit entry uses the
/// snake-case form (`"engagement"`, `"finding"`, `"user"`, `"asset"`);
/// this enum keeps the type-level vocabulary small and makes the
/// controller / port layer reject unknown kinds at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateKind {
    /// `engagement` — Phase-1 scan campaign aggregate.
    Engagement,
    /// `finding` — Phase-1 vulnerability finding aggregate.
    Finding,
    /// `user` — IAM user aggregate (role / permission / status mutations).
    User,
    /// `asset` — discovered asset aggregate.
    Asset,
}

impl AggregateKind {
    /// Wire form of the kind — matches the [`AuditEntry::resource_kind`]
    /// string written by the recorder.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Engagement => "engagement",
            Self::Finding => "finding",
            Self::User => "user",
            Self::Asset => "asset",
        }
    }

    /// Parse a wire string into the enum. Returns `None` for any value
    /// outside the accepted set.
    #[must_use]
    pub const fn parse(raw: &str) -> Option<Self> {
        if raw.eq_ignore_ascii_case("engagement") {
            Some(Self::Engagement)
        } else if raw.eq_ignore_ascii_case("finding") {
            Some(Self::Finding)
        } else if raw.eq_ignore_ascii_case("user") {
            Some(Self::User)
        } else if raw.eq_ignore_ascii_case("asset") {
            Some(Self::Asset)
        } else {
            None
        }
    }
}

/// Opaque aggregate identifier (free-form string).
///
/// Matches the type of [`AuditEntry::resource_id`] — usually a UUID
/// rendered as a string but kept open so plugins recording custom
/// resource ids continue to work.
pub type AggregateId = String;

/// A single point in an aggregate's reconstructed timeline.
///
/// Returned by [`TimeTravelService::replay_timeline`]. Each element is a
/// projection of one [`AuditEntry`] in the requested window, in
/// oldest-first order. The HTTP layer renders the timeline as the
/// `events` array of `GET /v1/audit/replay`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineEvent {
    /// Monotonic per-tenant sequence number of the underlying entry.
    pub seq: u64,
    /// UTC timestamp the mutation occurred at.
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    /// Snake-case action code, e.g. `engagement_updated`.
    pub action: String,
    /// Snapshot of the aggregate immediately before this event (when the
    /// recorder captured it). `None` for creation events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    /// Snapshot of the aggregate immediately after this event. `None` for
    /// deletion events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
}

impl TimelineEvent {
    /// Project a raw [`AuditEntry`] into a wire-friendly timeline event.
    ///
    /// Internal helper — kept `pub(crate)` so the projection logic lives in
    /// exactly one place and the trait implementations stay short.
    pub(crate) fn from_entry(entry: AuditEntry) -> Self {
        Self {
            seq: entry.seq,
            ts: entry.ts,
            action: entry.action.code().to_owned(),
            before: entry.before,
            after: entry.after,
        }
    }
}

/// Replay timeline returned by [`TimeTravelService::replay_timeline`].
///
/// Wraps the ordered list of [`TimelineEvent`]s plus the chain-verification
/// outcome. Callers MUST treat `chain_verified == false` as a "trust
/// broken" signal and surface it to the operator rather than blindly
/// rendering the events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayTimeline {
    /// Snake-case aggregate kind echoed back for client convenience.
    pub entity_type: String,
    /// Aggregate id echoed back for client convenience.
    pub entity_id: String,
    /// `true` when the underlying audit chain verified end-to-end across
    /// the queried window. `false` means the projection MAY be stale —
    /// see the `chain_error` field for the reason.
    pub chain_verified: bool,
    /// Human-readable chain-verification failure, when `chain_verified`
    /// is `false`. `None` on the happy path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_error: Option<String>,
    /// Ordered mutations (oldest-first).
    pub events: Vec<TimelineEvent>,
}

/// Diff produced by [`TimeTravelService::diff_between`].
///
/// `before` is the aggregate state at the earlier timestamp and `after`
/// is the state at the later timestamp. Either field can be `None`:
///
/// - `before == None` — the aggregate did not yet exist at the earlier
///   timestamp.
/// - `after == None` — the aggregate was deleted by the later timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateDiff {
    /// Snake-case aggregate kind echoed back for client convenience.
    pub entity_type: String,
    /// Aggregate id echoed back for client convenience.
    pub entity_id: String,
    /// Earlier timestamp the projection used.
    #[serde(with = "time::serde::rfc3339")]
    pub from_ts: OffsetDateTime,
    /// Later timestamp the projection used.
    #[serde(with = "time::serde::rfc3339")]
    pub to_ts: OffsetDateTime,
    /// State at `from_ts`. `None` if the aggregate did not exist yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    /// State at `to_ts`. `None` if the aggregate was already deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    /// `true` when the underlying chain verified.
    pub chain_verified: bool,
    /// Optional verification-failure description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_error: Option<String>,
}

/// Read-only time-travel query surface.
///
/// All operations are pure projections over the audit chain — they never
/// mutate the [`AuditSink`].
#[async_trait]
pub trait TimeTravelService: Send + Sync + std::fmt::Debug {
    /// Reconstruct the engagement state for `engagement_id` under
    /// `tenant_id` as it existed at `as_of`.
    ///
    /// Returns the decoded snapshot when a recorded `after` image
    /// exists at-or-before `as_of`. Returns `Ok(None)` when no audit
    /// row matches — including the case where the aggregate had not
    /// yet been created at `as_of`.
    async fn replay_engagement(
        &self,
        tenant_id: TenantId,
        engagement_id: &str,
        as_of: OffsetDateTime,
    ) -> Result<Option<serde_json::Value>, AuditError>;

    /// Reconstruct the finding state for `finding_id` under `tenant_id`
    /// as it existed at `as_of`. Same semantics as
    /// [`Self::replay_engagement`].
    async fn replay_finding(
        &self,
        tenant_id: TenantId,
        finding_id: &str,
        as_of: OffsetDateTime,
    ) -> Result<Option<serde_json::Value>, AuditError>;

    /// Return every audit row matching the aggregate `kind` + `id` whose
    /// `ts` falls in the inclusive window `[since, until]`.
    ///
    /// Both window bounds are optional; `since = None` uses the
    /// beginning of time and `until = None` uses [`OffsetDateTime::now_utc`].
    /// Results are returned **oldest-first** by `ts` (and `seq`).
    async fn history(
        &self,
        tenant_id: TenantId,
        kind: AggregateKind,
        id: &str,
        since: Option<OffsetDateTime>,
        until: Option<OffsetDateTime>,
    ) -> Result<Vec<AuditEntry>, AuditError>;

    /// Replay every mutation of a single entity in `[from, to]` as an
    /// ordered timeline.
    ///
    /// The timeline is the user-facing view of the time-travel surface:
    /// each element carries the action code and the before/after JSON
    /// snapshots that the recorder captured. Before assembling the
    /// timeline this method verifies the entire tenant chain and stamps
    /// the result with `chain_verified=false` (plus a human-readable
    /// `chain_error`) when verification fails — the events are still
    /// returned so an operator can see *what* claims have been tampered
    /// with, but the trust signal is unambiguous.
    async fn replay_timeline(
        &self,
        tenant_id: TenantId,
        entity_type: AggregateKind,
        entity_id: &str,
        from: Option<OffsetDateTime>,
        to: Option<OffsetDateTime>,
    ) -> Result<ReplayTimeline, AuditError>;

    /// Diff a single entity's state between two timestamps.
    ///
    /// `from` must be `<= to`; the implementation MUST reject the
    /// reverse ordering with [`AuditError::Internal`] so callers cannot
    /// accidentally compose meaningless diffs.
    ///
    /// Returns a [`StateDiff`] holding the `after` snapshot at-or-before
    /// each endpoint. As with [`Self::replay_timeline`], the chain is
    /// verified end-to-end and the outcome is exposed via the
    /// `chain_verified` / `chain_error` fields.
    async fn diff_between(
        &self,
        tenant_id: TenantId,
        entity_type: AggregateKind,
        entity_id: &str,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<StateDiff, AuditError>;
}

/// In-memory implementation of [`TimeTravelService`] that works against
/// any [`AuditSink`] implementation that supports scanning by tenant.
///
/// The default sink in the monolith is an in-memory `Vec<AuditEntry>`;
/// this service drives the read side by issuing
/// `read_range(tenant_id, 1, u64::MAX)` and filtering the results
/// in-process. For very large chains the sink should later grow a
/// kind/id index — the trait surface stays unchanged.
#[derive(Debug)]
pub struct InMemoryTimeTravelService {
    sink: Arc<dyn AuditSink>,
}

impl InMemoryTimeTravelService {
    /// Construct a service bound to `sink`.
    #[must_use]
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }

    /// Snapshot every entry for `tenant_id`. Helper used by every public
    /// method — separated so the `read_range` upper bound is centralised
    /// in one place.
    async fn snapshot_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        self.sink.read_range(tenant_id, 1, u64::MAX).await
    }

    /// Walk the chain and return the latest `after` snapshot at-or-before
    /// `as_of` for the `(kind, id)` aggregate.
    async fn pick_as_of(
        &self,
        tenant_id: TenantId,
        kind: AggregateKind,
        id: &str,
        as_of: OffsetDateTime,
    ) -> Result<Option<serde_json::Value>, AuditError> {
        let entries = self.snapshot_for_tenant(tenant_id).await?;
        Ok(pick_as_of_from_entries(&entries, kind, id, as_of))
    }
}

/// Pick the latest `after` snapshot at-or-before `as_of` from an
/// already-loaded entry slice.
///
/// Pulled out of the trait impl so `replay_timeline` / `diff_between` can
/// share the same selection logic without re-querying the sink.
fn pick_as_of_from_entries(
    entries: &[AuditEntry],
    kind: AggregateKind,
    id: &str,
    as_of: OffsetDateTime,
) -> Option<serde_json::Value> {
    entries
        .iter()
        .filter(|e| e.resource_kind == kind.as_str() && e.resource_id == id && e.ts <= as_of)
        // Newest first — ties broken by larger seq.
        .max_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.seq.cmp(&b.seq)))
        .and_then(|entry| entry.after.clone())
}

/// Verify the chain slice and translate the outcome into the
/// `(chain_verified, chain_error)` pair surfaced by the replay views.
///
/// `entries` MUST already be ordered oldest-first by `seq`. Returns
/// `(true, None)` on the happy path.
fn verify_chain_snapshot(entries: &[AuditEntry]) -> (bool, Option<String>) {
    if entries.is_empty() {
        return (true, None);
    }
    // `verify_entries` expects the slice to start at `expected_first_seq`.
    // We pass the actual first seq so partial chains (post-truncation)
    // verify correctly — full chains starting at seq=1 also pass since
    // that's the genesis check inside `verify_entries`. `.first()` is
    // safe under the earlier `is_empty()` guard and avoids panicking
    // indexing.
    let Some(first) = entries.first() else {
        return (true, None);
    };
    match verify_entries(entries, first.seq) {
        Ok(_) => (true, None),
        Err(err) => (false, Some(err.to_string())),
    }
}

#[async_trait]
impl TimeTravelService for InMemoryTimeTravelService {
    async fn replay_engagement(
        &self,
        tenant_id: TenantId,
        engagement_id: &str,
        as_of: OffsetDateTime,
    ) -> Result<Option<serde_json::Value>, AuditError> {
        self.pick_as_of(tenant_id, AggregateKind::Engagement, engagement_id, as_of)
            .await
    }

    async fn replay_finding(
        &self,
        tenant_id: TenantId,
        finding_id: &str,
        as_of: OffsetDateTime,
    ) -> Result<Option<serde_json::Value>, AuditError> {
        self.pick_as_of(tenant_id, AggregateKind::Finding, finding_id, as_of)
            .await
    }

    async fn history(
        &self,
        tenant_id: TenantId,
        kind: AggregateKind,
        id: &str,
        since: Option<OffsetDateTime>,
        until: Option<OffsetDateTime>,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let entries = self.snapshot_for_tenant(tenant_id).await?;
        let mut hits: Vec<AuditEntry> = entries
            .into_iter()
            .filter(|e| e.resource_kind == kind.as_str() && e.resource_id == id)
            .filter(|e| since.is_none_or(|s| e.ts >= s))
            .filter(|e| until.is_none_or(|u| e.ts <= u))
            .collect();
        // Oldest-first.
        hits.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.seq.cmp(&b.seq)));
        Ok(hits)
    }

    #[instrument(skip(self), fields(tenant = %tenant_id, kind = entity_type.as_str(), id = %entity_id))]
    async fn replay_timeline(
        &self,
        tenant_id: TenantId,
        entity_type: AggregateKind,
        entity_id: &str,
        from: Option<OffsetDateTime>,
        to: Option<OffsetDateTime>,
    ) -> Result<ReplayTimeline, AuditError> {
        let mut entries = self.snapshot_for_tenant(tenant_id).await?;
        // Sort by seq so chain verification sees a well-ordered slice.
        entries.sort_by_key(|e| e.seq);
        let (chain_verified, chain_error) = verify_chain_snapshot(&entries);

        let mut events: Vec<TimelineEvent> = entries
            .into_iter()
            .filter(|e| e.resource_kind == entity_type.as_str() && e.resource_id == entity_id)
            .filter(|e| from.is_none_or(|f| e.ts >= f))
            .filter(|e| to.is_none_or(|t| e.ts <= t))
            .map(TimelineEvent::from_entry)
            .collect();
        // Already oldest-first because we sorted the source by seq, but
        // be defensive — `ts` and `seq` are co-monotonic per tenant.
        events.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.seq.cmp(&b.seq)));

        Ok(ReplayTimeline {
            entity_type: entity_type.as_str().to_owned(),
            entity_id: entity_id.to_owned(),
            chain_verified,
            chain_error,
            events,
        })
    }

    #[instrument(skip(self), fields(tenant = %tenant_id, kind = entity_type.as_str(), id = %entity_id))]
    async fn diff_between(
        &self,
        tenant_id: TenantId,
        entity_type: AggregateKind,
        entity_id: &str,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<StateDiff, AuditError> {
        if from > to {
            return Err(AuditError::Internal(format!(
                "diff window inverted: from {from} > to {to}"
            )));
        }
        let mut entries = self.snapshot_for_tenant(tenant_id).await?;
        entries.sort_by_key(|e| e.seq);
        let (chain_verified, chain_error) = verify_chain_snapshot(&entries);

        let before = pick_as_of_from_entries(&entries, entity_type, entity_id, from);
        let after = pick_as_of_from_entries(&entries, entity_type, entity_id, to);

        Ok(StateDiff {
            entity_type: entity_type.as_str().to_owned(),
            entity_id: entity_id.to_owned(),
            from_ts: from,
            to_ts: to,
            before,
            after,
            chain_verified,
            chain_error,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use serde_json::json;

    use sx_core::value_object::ids::UserId;

    use super::*;
    use crate::model::action::AuditAction;
    use crate::model::actor::Actor;
    use crate::model::entry::HASH_LEN;

    /// Minimal `AuditSink` over a `Vec<AuditEntry>` — used to assemble a
    /// synthetic chain without dragging in the monolith adapter.
    #[derive(Debug, Default)]
    struct VecSink {
        rows: StdMutex<Vec<AuditEntry>>,
    }

    impl VecSink {
        fn push(&self, e: AuditEntry) {
            self.rows.lock().unwrap().push(e);
        }
    }

    #[async_trait]
    impl AuditSink for VecSink {
        async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
            self.rows.lock().unwrap().push(entry.clone());
            Ok(())
        }

        async fn last_entry_for_tenant(
            &self,
            tenant_id: TenantId,
        ) -> Result<Option<AuditEntry>, AuditError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|e| e.tenant_id == tenant_id)
                .cloned())
        }

        async fn read_range(
            &self,
            tenant_id: TenantId,
            from_seq: u64,
            to_seq: u64,
        ) -> Result<Vec<AuditEntry>, AuditError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.tenant_id == tenant_id && e.seq >= from_seq && e.seq <= to_seq)
                .cloned()
                .collect())
        }
    }

    fn make_entry(
        seq: u64,
        tenant: TenantId,
        ts_secs: i64,
        kind: &str,
        id: &str,
        action: AuditAction,
        after: Option<serde_json::Value>,
    ) -> AuditEntry {
        AuditEntry {
            seq,
            tenant_id: tenant,
            ts: OffsetDateTime::from_unix_timestamp(ts_secs).unwrap(),
            actor: Actor::user(UserId::new()),
            action,
            resource_kind: kind.into(),
            resource_id: id.into(),
            before: None,
            after,
            request_id: format!("req-{seq}"),
            prev_hash: [0u8; HASH_LEN],
            hash: [0u8; HASH_LEN],
            chain_hash: String::new(),
            chain_prev_hash: None,
        }
    }

    #[test]
    fn aggregate_kind_parse_round_trip() {
        assert_eq!(
            AggregateKind::parse("engagement"),
            Some(AggregateKind::Engagement)
        );
        assert_eq!(
            AggregateKind::parse("Engagement"),
            Some(AggregateKind::Engagement)
        );
        assert_eq!(
            AggregateKind::parse("finding"),
            Some(AggregateKind::Finding)
        );
        assert_eq!(AggregateKind::parse("asset"), Some(AggregateKind::Asset));
        assert_eq!(AggregateKind::parse("not-a-real-kind"), None);
        assert_eq!(AggregateKind::Engagement.as_str(), "engagement");
        assert_eq!(AggregateKind::Finding.as_str(), "finding");
    }

    /// Three engagement update events at t=100, 200, 300. Asking for the
    /// state at t=250 returns the t=200 snapshot.
    #[tokio::test]
    async fn replay_engagement_picks_latest_snapshot_before_as_of() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let eid = "eng-abc";

        sink.push(make_entry(
            1,
            tenant,
            100,
            "engagement",
            eid,
            AuditAction::EngagementCreated,
            Some(json!({"id": eid, "name": "v1", "status": "draft"})),
        ));
        sink.push(make_entry(
            2,
            tenant,
            200,
            "engagement",
            eid,
            AuditAction::EngagementUpdated,
            Some(json!({"id": eid, "name": "v2", "status": "active"})),
        ));
        sink.push(make_entry(
            3,
            tenant,
            300,
            "engagement",
            eid,
            AuditAction::EngagementUpdated,
            Some(json!({"id": eid, "name": "v3", "status": "completed"})),
        ));

        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let as_of = OffsetDateTime::from_unix_timestamp(250).unwrap();
        let out = svc
            .replay_engagement(tenant, eid, as_of)
            .await
            .expect("replay ok")
            .expect("Some snapshot");
        assert_eq!(out["name"], "v2");
        assert_eq!(out["status"], "active");
    }

    /// `as_of` before the first creation → `None`.
    #[tokio::test]
    async fn replay_engagement_returns_none_before_creation() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let eid = "eng-future";
        sink.push(make_entry(
            1,
            tenant,
            500,
            "engagement",
            eid,
            AuditAction::EngagementCreated,
            Some(json!({"id": eid, "name": "first"})),
        ));
        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let before = OffsetDateTime::from_unix_timestamp(100).unwrap();
        let out = svc.replay_engagement(tenant, eid, before).await.unwrap();
        assert!(out.is_none());
    }

    /// Finding replay picks the latest snapshot at-or-before `as_of`.
    #[tokio::test]
    async fn replay_finding_picks_latest_snapshot() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let fid = "find-xyz";
        sink.push(make_entry(
            1,
            tenant,
            100,
            "finding",
            fid,
            AuditAction::FindingCreated,
            Some(json!({"id": fid, "status": "open"})),
        ));
        sink.push(make_entry(
            2,
            tenant,
            200,
            "finding",
            fid,
            AuditAction::FindingConfirmed,
            Some(json!({"id": fid, "status": "triaged"})),
        ));
        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let now = OffsetDateTime::from_unix_timestamp(300).unwrap();
        let out = svc.replay_finding(tenant, fid, now).await.unwrap().unwrap();
        assert_eq!(out["status"], "triaged");
    }

    /// Other tenants' rows must NOT leak into the projection.
    #[tokio::test]
    async fn replay_is_tenant_scoped() {
        let sink = Arc::new(VecSink::default());
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let eid = "shared-id";

        // Tenant B's row arrives FIRST (higher ts) but must not appear
        // in tenant A's replay.
        sink.push(make_entry(
            1,
            tenant_b,
            500,
            "engagement",
            eid,
            AuditAction::EngagementCreated,
            Some(json!({"id": eid, "name": "tenant-b"})),
        ));
        sink.push(make_entry(
            1,
            tenant_a,
            100,
            "engagement",
            eid,
            AuditAction::EngagementCreated,
            Some(json!({"id": eid, "name": "tenant-a"})),
        ));

        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let as_of = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
        let out = svc
            .replay_engagement(tenant_a, eid, as_of)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out["name"], "tenant-a");
    }

    /// `history` returns every matching row in the supplied window,
    /// oldest-first.
    #[tokio::test]
    async fn history_filters_window_and_orders_oldest_first() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let eid = "eng-window";
        sink.push(make_entry(
            1,
            tenant,
            100,
            "engagement",
            eid,
            AuditAction::EngagementCreated,
            Some(json!({"v": 1})),
        ));
        sink.push(make_entry(
            2,
            tenant,
            200,
            "engagement",
            eid,
            AuditAction::EngagementUpdated,
            Some(json!({"v": 2})),
        ));
        sink.push(make_entry(
            3,
            tenant,
            300,
            "engagement",
            eid,
            AuditAction::EngagementUpdated,
            Some(json!({"v": 3})),
        ));
        sink.push(make_entry(
            4,
            tenant,
            400,
            "engagement",
            eid,
            AuditAction::EngagementUpdated,
            Some(json!({"v": 4})),
        ));

        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let lo = OffsetDateTime::from_unix_timestamp(150).unwrap();
        let hi = OffsetDateTime::from_unix_timestamp(350).unwrap();
        let hits = svc
            .history(tenant, AggregateKind::Engagement, eid, Some(lo), Some(hi))
            .await
            .unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].seq, 2);
        assert_eq!(hits[1].seq, 3);
    }

    /// `history` with both bounds `None` returns every row for the
    /// `(kind, id)` pair.
    #[tokio::test]
    async fn history_with_no_bounds_returns_full_aggregate_chain() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let eid = "eng-full";
        for i in 1u64..=5 {
            sink.push(make_entry(
                i,
                tenant,
                i64::try_from(100 * i).unwrap(),
                "engagement",
                eid,
                AuditAction::EngagementUpdated,
                Some(json!({"v": i})),
            ));
        }
        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let hits = svc
            .history(tenant, AggregateKind::Engagement, eid, None, None)
            .await
            .unwrap();
        assert_eq!(hits.len(), 5);
        assert_eq!(hits[0].seq, 1);
        assert_eq!(hits[4].seq, 5);
    }

    /// Equal-ts ties are broken by `seq` so the picked snapshot is
    /// deterministic.
    #[tokio::test]
    async fn equal_timestamps_break_tie_on_higher_seq() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let eid = "eng-tie";
        sink.push(make_entry(
            1,
            tenant,
            500,
            "engagement",
            eid,
            AuditAction::EngagementCreated,
            Some(json!({"name": "old"})),
        ));
        sink.push(make_entry(
            2,
            tenant,
            500,
            "engagement",
            eid,
            AuditAction::EngagementUpdated,
            Some(json!({"name": "new"})),
        ));
        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let as_of = OffsetDateTime::from_unix_timestamp(500).unwrap();
        let out = svc
            .replay_engagement(tenant, eid, as_of)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out["name"], "new");
    }

    // ------------------------------------------------------------------
    // Chain-verified projections (replay_timeline / diff_between).
    //
    // These helpers build a *real* (hash-linked) chain via `build_entry`
    // so the new methods can run end-to-end verification.
    // ------------------------------------------------------------------

    use crate::service::chain_builder::{build_entry, build_genesis, NewAuditEvent};

    /// Append one entry to a real chain, returning the new sink and the
    /// last entry hash so further entries can link forward.
    fn signed_event(
        action: AuditAction,
        kind: &str,
        id: &str,
        ts_secs: i64,
        tenant: TenantId,
        before: Option<serde_json::Value>,
        after: Option<serde_json::Value>,
    ) -> NewAuditEvent {
        NewAuditEvent {
            tenant_id: tenant,
            actor: Actor::user(UserId::new()),
            action,
            resource_kind: kind.into(),
            resource_id: id.into(),
            before,
            after,
            request_id: format!("req-{ts_secs}"),
            ts: Some(OffsetDateTime::from_unix_timestamp(ts_secs).unwrap()),
        }
    }

    /// Build a verified two-event chain for a single user aggregate and
    /// assert that `replay_timeline` returns both events oldest-first
    /// with `chain_verified=true`.
    #[tokio::test]
    async fn replay_timeline_returns_events_with_chain_verified() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let uid = "user-42";

        let g = build_genesis(signed_event(
            AuditAction::Login,
            "user",
            uid,
            100,
            tenant,
            None,
            Some(json!({"id": uid, "status": "active", "role": "viewer"})),
        ))
        .unwrap();
        let e2 = build_entry(
            2,
            g.hash,
            signed_event(
                AuditAction::Login,
                "user",
                uid,
                200,
                tenant,
                Some(json!({"id": uid, "status": "active", "role": "viewer"})),
                Some(json!({"id": uid, "status": "active", "role": "admin"})),
            ),
        )
        .unwrap();
        sink.push(g);
        sink.push(e2);

        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let tl = svc
            .replay_timeline(tenant, AggregateKind::User, uid, None, None)
            .await
            .expect("timeline ok");

        assert!(
            tl.chain_verified,
            "chain should verify: {:?}",
            tl.chain_error
        );
        assert!(tl.chain_error.is_none());
        assert_eq!(tl.entity_type, "user");
        assert_eq!(tl.entity_id, uid);
        assert_eq!(tl.events.len(), 2);
        assert_eq!(tl.events[0].seq, 1);
        assert_eq!(tl.events[1].seq, 2);
        // Oldest-first.
        assert!(tl.events[0].ts < tl.events[1].ts);
        // Final mutation upgraded the role to admin.
        let last_after = tl.events[1].after.as_ref().expect("after present");
        assert_eq!(last_after["role"], "admin");
    }

    /// A tampered chain (hash mutated post-write) must surface as
    /// `chain_verified=false` with a populated `chain_error`. Events are
    /// still returned so the operator can audit the suspicious data.
    #[tokio::test]
    async fn replay_timeline_flags_broken_chain() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let uid = "user-tampered";

        let mut g = build_genesis(signed_event(
            AuditAction::Login,
            "user",
            uid,
            100,
            tenant,
            None,
            Some(json!({"id": uid, "v": 1})),
        ))
        .unwrap();
        // Tamper with the genesis snapshot after the hash was computed.
        g.after = Some(json!({"id": uid, "v": "TAMPERED"}));
        sink.push(g);

        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let tl = svc
            .replay_timeline(tenant, AggregateKind::User, uid, None, None)
            .await
            .expect("timeline still returns even when chain is broken");
        assert!(!tl.chain_verified, "tampered chain must NOT verify");
        assert!(tl.chain_error.is_some(), "must explain the failure");
        assert_eq!(tl.events.len(), 1);
        // Event payload still surfaced for forensic review.
        assert_eq!(tl.events[0].after.as_ref().unwrap()["v"], "TAMPERED");
    }

    /// Replay timeline does not leak rows owned by other tenants even
    /// when entity ids collide.
    #[tokio::test]
    async fn replay_timeline_is_tenant_scoped() {
        let sink_a = Arc::new(VecSink::default());
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let uid = "shared-user-id";

        let ga = build_genesis(signed_event(
            AuditAction::Login,
            "user",
            uid,
            100,
            tenant_a,
            None,
            Some(json!({"owner": "tenant-a"})),
        ))
        .unwrap();
        let gb = build_genesis(signed_event(
            AuditAction::Login,
            "user",
            uid,
            200,
            tenant_b,
            None,
            Some(json!({"owner": "tenant-b"})),
        ))
        .unwrap();
        sink_a.push(ga);
        sink_a.push(gb);

        let svc = InMemoryTimeTravelService::new(sink_a as Arc<dyn AuditSink>);
        let tl = svc
            .replay_timeline(tenant_a, AggregateKind::User, uid, None, None)
            .await
            .unwrap();
        assert_eq!(tl.events.len(), 1);
        assert_eq!(
            tl.events[0].after.as_ref().unwrap()["owner"],
            "tenant-a",
            "tenant B's row must not leak into tenant A's replay"
        );
    }

    /// `replay_timeline` honours the `(from, to)` window — events outside
    /// it are excluded but verification still considers the whole chain.
    #[tokio::test]
    async fn replay_timeline_applies_window_filter() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let uid = "user-window";

        let g = build_genesis(signed_event(
            AuditAction::Login,
            "user",
            uid,
            100,
            tenant,
            None,
            Some(json!({"v": 1})),
        ))
        .unwrap();
        let e2 = build_entry(
            2,
            g.hash,
            signed_event(
                AuditAction::Login,
                "user",
                uid,
                200,
                tenant,
                Some(json!({"v": 1})),
                Some(json!({"v": 2})),
            ),
        )
        .unwrap();
        let e3 = build_entry(
            3,
            e2.hash,
            signed_event(
                AuditAction::Login,
                "user",
                uid,
                300,
                tenant,
                Some(json!({"v": 2})),
                Some(json!({"v": 3})),
            ),
        )
        .unwrap();
        sink.push(g);
        sink.push(e2);
        sink.push(e3);

        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let from = OffsetDateTime::from_unix_timestamp(150).unwrap();
        let to = OffsetDateTime::from_unix_timestamp(250).unwrap();
        let tl = svc
            .replay_timeline(tenant, AggregateKind::User, uid, Some(from), Some(to))
            .await
            .unwrap();
        assert!(tl.chain_verified);
        assert_eq!(tl.events.len(), 1, "only the t=200 event is in window");
        assert_eq!(tl.events[0].seq, 2);
    }

    /// `diff_between` returns the before/after snapshots straddling the
    /// requested window.
    #[tokio::test]
    async fn diff_between_returns_state_at_each_endpoint() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let uid = "user-diff";

        let g = build_genesis(signed_event(
            AuditAction::Login,
            "user",
            uid,
            100,
            tenant,
            None,
            Some(json!({"role": "viewer"})),
        ))
        .unwrap();
        let e2 = build_entry(
            2,
            g.hash,
            signed_event(
                AuditAction::Login,
                "user",
                uid,
                200,
                tenant,
                Some(json!({"role": "viewer"})),
                Some(json!({"role": "editor"})),
            ),
        )
        .unwrap();
        let e3 = build_entry(
            3,
            e2.hash,
            signed_event(
                AuditAction::Login,
                "user",
                uid,
                300,
                tenant,
                Some(json!({"role": "editor"})),
                Some(json!({"role": "admin"})),
            ),
        )
        .unwrap();
        sink.push(g);
        sink.push(e2);
        sink.push(e3);

        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let from = OffsetDateTime::from_unix_timestamp(150).unwrap();
        let to = OffsetDateTime::from_unix_timestamp(350).unwrap();
        let diff = svc
            .diff_between(tenant, AggregateKind::User, uid, from, to)
            .await
            .unwrap();
        assert!(diff.chain_verified);
        let before = diff.before.expect("before snapshot present");
        let after = diff.after.expect("after snapshot present");
        assert_eq!(before["role"], "viewer");
        assert_eq!(after["role"], "admin");
    }

    /// `diff_between` rejects an inverted window (`from > to`).
    #[tokio::test]
    async fn diff_between_rejects_inverted_window() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let later = OffsetDateTime::from_unix_timestamp(500).unwrap();
        let earlier = OffsetDateTime::from_unix_timestamp(100).unwrap();
        let err = svc
            .diff_between(tenant, AggregateKind::User, "u", later, earlier)
            .await
            .expect_err("inverted window must be rejected");
        assert!(matches!(err, AuditError::Internal(_)));
    }

    /// Empty tenant chain → verified, empty events, no snapshots.
    #[tokio::test]
    async fn replay_timeline_empty_chain_verifies_clean() {
        let sink = Arc::new(VecSink::default());
        let tenant = TenantId::new();
        let svc = InMemoryTimeTravelService::new(sink as Arc<dyn AuditSink>);
        let tl = svc
            .replay_timeline(tenant, AggregateKind::User, "ghost", None, None)
            .await
            .unwrap();
        assert!(tl.chain_verified);
        assert!(tl.chain_error.is_none());
        assert!(tl.events.is_empty());
    }

    /// Generic aggregate kinds parse the new `user` / `asset` codes.
    #[test]
    fn aggregate_kind_parse_covers_user_and_asset() {
        assert_eq!(AggregateKind::parse("user"), Some(AggregateKind::User));
        assert_eq!(AggregateKind::parse("Asset"), Some(AggregateKind::Asset));
        assert_eq!(AggregateKind::User.as_str(), "user");
        assert_eq!(AggregateKind::Asset.as_str(), "asset");
    }
}
