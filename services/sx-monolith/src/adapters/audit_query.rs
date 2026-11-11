//! Audit-query adapter — backs the `GET /v1/audit/search` and
//! `GET /v1/audit/export` endpoints.
//!
//! ## Topology
//!
//! The adapter owns a single [`InMemoryAuditBufferSink`] which doubles as
//! both an `sx_audit::AuditSink` (so the `RecordAuditEventUseCase` can
//! append into it) and as the read surface for the
//! [`sx_api::port::AuditQueryPort`] implementation:
//!
//! ```text
//!   RecordAuditEventUseCase ──append──▶ InMemoryAuditBufferSink ◀──snapshot── AuditQueryAdapter
//!                                              (Mutex<Vec<AuditEntry>>)
//! ```
//!
//! Sharing one `Arc<InMemoryAuditBufferSink>` keeps the audit write path
//! and the audit read endpoints consistent without a separate replication
//! layer. The same buffer is also handed to the
//! [`AuditQueryBundle::sink`] field so the composition root can plug it
//! into the recorder.
//!
//! ## Filter semantics
//!
//! Filters are applied at projection time inside [`AuditQueryAdapter::search`].
//! All filters are AND-combined:
//!
//! - `since` — inclusive RFC 3339 lower-bound on `ts`. Parsed once; bad
//!   strings surface as [`Phase3PortError::Invalid`].
//! - `action` — exact match on the [`AuditAction::code`] string.
//! - `actor` — exact match on the projected `kind:id` actor string
//!   (snake-case kind).
//!
//! Results are sorted **newest-first** by `ts`.
//!
//! ## Export cap
//!
//! [`AuditQueryAdapter::export_ndjson`] caps the output at
//! [`MAX_EXPORT_ENTRIES`] entries. Each entry is serialised with
//! `serde_json::to_string` (compact form) and joined with `\n`.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::{AuditQueryPort, AuditReplayPort, Phase3PortError};
use sx_api::view::audit_view::{
    AuditDiffQuery, AuditDiffResponse, AuditEntryView, AuditReplayQuery, AuditReplayResponse,
    AuditSearchQuery, AuditSearchResponse, AuditTimelineEventView, MAX_EXPORT_ENTRIES,
};
#[cfg(test)]
use sx_audit::model::action::AuditAction;
use sx_audit::model::actor::{Actor, ActorKind};
use sx_audit::model::entry::AuditEntry;
use sx_audit::prelude::{AuditError, AuditSink};
use sx_audit::time_travel::{AggregateKind, InMemoryTimeTravelService, TimeTravelService};
use sx_core::value_object::ids::TenantId;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex;

/// Bundle exposing the audit-query trait object the composition root stuffs
/// into [`sx_api::AppState`], plus the concrete buffer sink the audit
/// recorder writes through.
///
/// Both handles share the same underlying `Mutex<Vec<AuditEntry>>` so a
/// freshly-recorded audit row is visible to the read endpoints
/// immediately.
#[derive(Clone)]
pub(crate) struct AuditQueryBundle {
    /// HTTP-facing port wired into the API surface.
    pub(crate) audit_query: Arc<dyn AuditQueryPort>,
    /// Audit-replay (time-travel) HTTP-facing port. Backs the
    /// `GET /v1/audit/replay` and `GET /v1/audit/diff` endpoints (P3-009).
    pub(crate) audit_replay: Arc<dyn AuditReplayPort>,
    /// Sink the recorder + chain verifier append/read through. Shares the
    /// same underlying store as `audit_query`, so a freshly-recorded row is
    /// visible to the read endpoints immediately. In-memory (dev) or the
    /// durable Postgres store when the DB is enabled.
    pub(crate) sink: Arc<dyn AuditSink>,
}

impl std::fmt::Debug for AuditQueryBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditQueryBundle").finish_non_exhaustive()
    }
}

/// Build the audit-query/replay bundle. When the DB is enabled the trail is
/// durable (Postgres) and the hash chain survives restart; otherwise it is an
/// in-memory buffer (dev quick-start). The query adapter, replay service,
/// recorder, and chain verifier all share the one store.
///
/// Pure (no I/O) — safe to call synchronously from `build_app_state`.
pub(crate) fn build(postgres: Option<(PgPool, u64)>) -> AuditQueryBundle {
    // Build the one store, then take an `AuditSink` view (recorder / replay /
    // verifier) and an `AuditReadAll` view (query adapter) of the same object.
    let (sink, source): (Arc<dyn AuditSink>, Arc<dyn AuditReadAll>) =
        if let Some((pool, stmt_timeout_ms)) = postgres {
            let store = Arc::new(PgAuditStore::new(pool, stmt_timeout_ms));
            (Arc::clone(&store) as Arc<dyn AuditSink>, store)
        } else {
            let buf = Arc::new(InMemoryAuditBufferSink::new());
            (Arc::clone(&buf) as Arc<dyn AuditSink>, buf)
        };
    let audit_query: Arc<dyn AuditQueryPort> = Arc::new(AuditQueryAdapter {
        source: Arc::clone(&source),
    });
    // Audit-replay reuses the same store so freshly-recorded mutations are
    // observable through the time-travel surface immediately.
    let audit_replay: Arc<dyn AuditReplayPort> = Arc::new(AuditReplayAdapter {
        service: Arc::new(InMemoryTimeTravelService::new(Arc::clone(&sink))),
    });
    AuditQueryBundle {
        audit_query,
        audit_replay,
        sink,
    }
}

/// Thread-safe in-memory audit sink.
///
/// Implements [`AuditSink`] so the `sx-audit` recorder can write into it,
/// and exposes a [`Self::snapshot`] read surface the query adapter uses.
#[derive(Debug, Default)]
pub(crate) struct InMemoryAuditBufferSink {
    inner: Mutex<Vec<AuditEntry>>,
}

impl InMemoryAuditBufferSink {
    /// Construct an empty buffer.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Return a cloned snapshot of every entry currently in the buffer.
    /// Ordering matches insertion order (oldest-first).
    pub(crate) async fn snapshot(&self) -> Vec<AuditEntry> {
        self.inner.lock().await.clone()
    }

    /// Append a row directly. Test-only helper that bypasses the
    /// `AuditSink` `seq` invariant — used by the in-module unit tests to
    /// hydrate a buffer without spinning up `RecordAuditEventUseCase`.
    #[cfg(test)]
    pub(crate) async fn push_for_test(&self, entry: AuditEntry) {
        self.inner.lock().await.push(entry);
    }
}

#[async_trait]
impl AuditSink for InMemoryAuditBufferSink {
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let mut guard = self.inner.lock().await;
        // Enforce per-tenant monotonic seq.
        let expected = guard
            .iter()
            .rev()
            .find(|e| e.tenant_id == entry.tenant_id)
            .map_or(1u64, |last| last.seq.saturating_add(1));
        if entry.seq != expected {
            return Err(AuditError::Sink(format!(
                "out-of-order seq: expected {expected}, got {}",
                entry.seq
            )));
        }
        guard.push(entry.clone());
        Ok(())
    }

    async fn last_entry_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<AuditEntry>, AuditError> {
        let guard = self.inner.lock().await;
        Ok(guard
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
        let guard = self.inner.lock().await;
        Ok(guard
            .iter()
            .filter(|e| e.tenant_id == tenant_id && e.seq >= from_seq && e.seq <= to_seq)
            .cloned()
            .collect())
    }
}

/// Cross-tenant bulk read of the audit trail, for the (tenant-agnostic)
/// `GET /v1/audit/search` + `/export` surface.
///
/// The `AuditSink` trait is deliberately per-tenant (append / last-entry /
/// read-range). The search/export port, by contrast, carries no tenant id —
/// it reads across the whole trail (an admin surface, gated by `audit:read`
/// at the HTTP layer; this is the pre-existing in-memory behaviour, preserved
/// here). This monolith-local trait adds just that bulk read so the query
/// adapter works over either the in-memory buffer or the durable Postgres
/// store without widening the shared `sx_audit::AuditSink` trait (which has
/// a dozen implementations across the workspace).
#[async_trait]
pub(crate) trait AuditReadAll: Send + Sync + std::fmt::Debug {
    async fn read_all(&self) -> Result<Vec<AuditEntry>, AuditError>;
}

#[async_trait]
impl AuditReadAll for InMemoryAuditBufferSink {
    async fn read_all(&self) -> Result<Vec<AuditEntry>, AuditError> {
        Ok(self.snapshot().await)
    }
}

/// Durable Postgres-backed audit sink + bulk reader.
///
/// The composition root bound the tamper-evident audit trail to an in-memory
/// buffer, so every audit entry — and the per-tenant hash chain that makes
/// the log tamper-evident — was lost on a monolith restart. When
/// `database.enabled` this store persists the trail instead, and the
/// hash-chain resumes seamlessly across a restart because the recorder reads
/// `last_entry_for_tenant` (now from Postgres) before chaining the next
/// entry.
///
/// Each [`AuditEntry`] is stored losslessly as JSONB in `audit_entries`,
/// keyed by `(tenant_id, seq)`, with a `ts` projection for ordering. The
/// per-tenant monotonic-seq invariant is enforced both by the recorder's
/// per-tenant mutex (read-then-append) and by the `(tenant_id, seq)` primary
/// key (a cross-process race loses on the duplicate key).
///
/// Cross-tenant `read_all` (the admin search surface) reads every tenant's
/// rows, so — like the other IAM stores in this program — the table is NOT
/// under tenant RLS; the per-tenant methods carry an explicit `tenant_id`
/// predicate.
pub(crate) struct PgAuditStore {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgAuditStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgAuditStore").finish_non_exhaustive()
    }
}

impl PgAuditStore {
    pub(crate) const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    fn sink_err(e: impl std::fmt::Display) -> AuditError {
        AuditError::Sink(format!("pg audit store: {e}"))
    }

    async fn set_timeout(&self, tx: &mut sqlx::PgConnection) -> Result<(), AuditError> {
        let bounded = self.stmt_timeout_ms.clamp(1, 60_000);
        sqlx::query(&format!("SET LOCAL statement_timeout = {bounded}"))
            .execute(&mut *tx)
            .await
            .map(|_| ())
            .map_err(Self::sink_err)
    }

    fn decode(row: &sqlx::postgres::PgRow) -> Result<AuditEntry, AuditError> {
        row.try_get::<Json<AuditEntry>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::sink_err)
    }
}

#[async_trait]
impl AuditSink for PgAuditStore {
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let seq = i64::try_from(entry.seq)
            .map_err(|_| AuditError::Sink(format!("seq {} exceeds i64", entry.seq)))?;
        let mut tx = self.pool.begin().await.map_err(Self::sink_err)?;
        self.set_timeout(&mut tx).await?;
        // Enforce the per-tenant monotonic-seq invariant (the recorder's
        // per-tenant mutex serialises read-then-append within a process; the
        // PK guards cross-process races).
        let last: Option<i64> =
            sqlx::query("SELECT max(seq) AS m FROM audit_entries WHERE tenant_id = $1")
                .bind(*entry.tenant_id.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .map_err(Self::sink_err)?
                .try_get::<Option<i64>, _>("m")
                .map_err(Self::sink_err)?;
        let expected = last.map_or(1, |s| s.saturating_add(1));
        if seq != expected {
            return Err(AuditError::Sink(format!(
                "out-of-order seq: expected {expected}, got {seq}"
            )));
        }
        sqlx::query(
            "INSERT INTO audit_entries (tenant_id, seq, ts, aggregate) VALUES ($1, $2, $3, $4)",
        )
        .bind(*entry.tenant_id.as_uuid())
        .bind(seq)
        .bind(entry.ts)
        .bind(Json(entry))
        .execute(&mut *tx)
        .await
        .map_err(Self::sink_err)?;
        tx.commit().await.map_err(Self::sink_err)
    }

    async fn last_entry_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<AuditEntry>, AuditError> {
        let mut tx = self.pool.begin().await.map_err(Self::sink_err)?;
        self.set_timeout(&mut tx).await?;
        let row = sqlx::query(
            "SELECT aggregate FROM audit_entries WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(*tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(Self::sink_err)?;
        tx.commit().await.map_err(Self::sink_err)?;
        row.as_ref().map(Self::decode).transpose()
    }

    async fn read_range(
        &self,
        tenant_id: TenantId,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let from = i64::try_from(from_seq).unwrap_or(0);
        let to = i64::try_from(to_seq).unwrap_or(i64::MAX);
        let mut tx = self.pool.begin().await.map_err(Self::sink_err)?;
        self.set_timeout(&mut tx).await?;
        let rows = sqlx::query(
            "SELECT aggregate FROM audit_entries \
             WHERE tenant_id = $1 AND seq >= $2 AND seq <= $3 ORDER BY seq ASC",
        )
        .bind(*tenant_id.as_uuid())
        .bind(from)
        .bind(to)
        .fetch_all(&mut *tx)
        .await
        .map_err(Self::sink_err)?;
        tx.commit().await.map_err(Self::sink_err)?;
        rows.iter().map(Self::decode).collect()
    }
}

#[async_trait]
impl AuditReadAll for PgAuditStore {
    async fn read_all(&self) -> Result<Vec<AuditEntry>, AuditError> {
        let mut tx = self.pool.begin().await.map_err(Self::sink_err)?;
        self.set_timeout(&mut tx).await?;
        let rows = sqlx::query("SELECT aggregate FROM audit_entries ORDER BY ts ASC")
            .fetch_all(&mut *tx)
            .await
            .map_err(Self::sink_err)?;
        tx.commit().await.map_err(Self::sink_err)?;
        rows.iter().map(Self::decode).collect()
    }
}

/// Concrete [`AuditQueryPort`] implementation backed by any [`AuditReadAll`]
/// source (the in-memory buffer or the durable Postgres store).
#[derive(Debug)]
pub(crate) struct AuditQueryAdapter {
    pub(crate) source: Arc<dyn AuditReadAll>,
}

#[async_trait]
impl AuditQueryPort for AuditQueryAdapter {
    async fn search(
        &self,
        query: AuditSearchQuery,
    ) -> Result<AuditSearchResponse, Phase3PortError> {
        let since_dt = parse_optional_rfc3339(query.since.as_deref())?;
        let limit = query.effective_limit() as usize;

        let snapshot = self
            .source
            .read_all()
            .await
            .map_err(|e| Phase3PortError::Internal(format!("audit read: {e}")))?;
        let mut filtered: Vec<AuditEntry> = snapshot
            .into_iter()
            .filter(|e| {
                filter_entry(
                    e,
                    since_dt.as_ref(),
                    query.action.as_deref(),
                    query.actor.as_deref(),
                )
            })
            .collect();

        // Newest-first.
        filtered.sort_by(|a, b| b.ts.cmp(&a.ts));

        let total_matching = filtered.len();
        let truncated: Vec<AuditEntry> = filtered.into_iter().take(limit).collect();
        let has_more = total_matching > truncated.len();

        let items = truncated
            .into_iter()
            .map(project_entry)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(AuditSearchResponse { items, has_more })
    }

    async fn export_ndjson(&self, since: Option<String>) -> Result<Vec<u8>, Phase3PortError> {
        let since_dt = parse_optional_rfc3339(since.as_deref())?;
        let snapshot = self
            .source
            .read_all()
            .await
            .map_err(|e| Phase3PortError::Internal(format!("audit read: {e}")))?;

        let mut filtered: Vec<AuditEntry> = snapshot
            .into_iter()
            .filter(|e| filter_entry(e, since_dt.as_ref(), None, None))
            .collect();
        // Oldest-first for exports so an operator-driven re-import preserves
        // chain order.
        filtered.sort_by(|a, b| a.ts.cmp(&b.ts));

        if filtered.len() > MAX_EXPORT_ENTRIES {
            filtered.truncate(MAX_EXPORT_ENTRIES);
        }

        let mut out: Vec<u8> = Vec::with_capacity(filtered.len() * 256);
        for entry in filtered {
            let view = project_entry(entry)?;
            let line = serde_json::to_string(&view)
                .map_err(|e| Phase3PortError::Internal(format!("ndjson encode: {e}")))?;
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        Ok(out)
    }
}

/// Parse an optional RFC 3339 string; emits [`Phase3PortError::Invalid`]
/// when present-but-malformed.
fn parse_optional_rfc3339(s: Option<&str>) -> Result<Option<OffsetDateTime>, Phase3PortError> {
    match s {
        None => Ok(None),
        Some(raw) => OffsetDateTime::parse(raw, &Rfc3339)
            .map(Some)
            .map_err(|e| Phase3PortError::Invalid(format!("malformed since: {e}"))),
    }
}

/// Apply the AND-combined `since` / `action` / `actor` filters.
fn filter_entry(
    entry: &AuditEntry,
    since: Option<&OffsetDateTime>,
    action: Option<&str>,
    actor: Option<&str>,
) -> bool {
    if let Some(since) = since {
        if entry.ts < *since {
            return false;
        }
    }
    if let Some(action_filter) = action {
        if entry.action.code() != action_filter {
            return false;
        }
    }
    if let Some(actor_filter) = actor {
        if project_actor(&entry.actor) != actor_filter {
            return false;
        }
    }
    true
}

/// Project a [`AuditEntry`] into the wire view.
fn project_entry(entry: AuditEntry) -> Result<AuditEntryView, Phase3PortError> {
    let ts = entry
        .ts
        .format(&Rfc3339)
        .map_err(|e| Phase3PortError::Internal(format!("format ts: {e}")))?;
    Ok(AuditEntryView {
        ts,
        action: entry.action.code().to_owned(),
        actor: project_actor(&entry.actor),
        resource_kind: entry.resource_kind,
        resource_id: entry.resource_id,
        request_id: entry.request_id,
        tenant_id: entry.tenant_id.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Audit-replay (time-travel debugging) adapter — P3-009
// ---------------------------------------------------------------------------

/// Concrete [`AuditReplayPort`] implementation that delegates to an
/// [`InMemoryTimeTravelService`].
///
/// The adapter is responsible for:
///
/// - Parsing wire timestamps + entity-kind strings.
/// - Tenant scoping — the bearer-token tenant is the only allowed scope;
///   any mismatch surfaces as [`Phase3PortError::Forbidden`].
/// - Projecting the domain [`sx_audit::time_travel::ReplayTimeline`] /
///   [`sx_audit::time_travel::StateDiff`] into the public wire DTOs.
#[derive(Debug)]
pub(crate) struct AuditReplayAdapter {
    service: Arc<dyn TimeTravelService>,
}

#[async_trait]
impl AuditReplayPort for AuditReplayAdapter {
    async fn replay(
        &self,
        tenant_id: &str,
        query: AuditReplayQuery,
    ) -> Result<AuditReplayResponse, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        let kind = parse_aggregate_kind(&query.entity_type)?;
        let from = parse_optional_rfc3339(query.from.as_deref())?;
        let to = parse_optional_rfc3339(query.to.as_deref())?;

        let timeline = self
            .service
            .replay_timeline(tenant, kind, &query.entity_id, from, to)
            .await
            .map_err(|err| Phase3PortError::Internal(format!("replay: {err}")))?;

        let events: Vec<AuditTimelineEventView> = timeline
            .events
            .into_iter()
            .map(|event| {
                let ts = event
                    .ts
                    .format(&Rfc3339)
                    .map_err(|e| Phase3PortError::Internal(format!("format ts: {e}")))?;
                Ok(AuditTimelineEventView {
                    seq: event.seq,
                    ts,
                    action: event.action,
                    before: event.before,
                    after: event.after,
                })
            })
            .collect::<Result<Vec<_>, Phase3PortError>>()?;

        Ok(AuditReplayResponse {
            entity_type: timeline.entity_type,
            entity_id: timeline.entity_id,
            chain_verified: timeline.chain_verified,
            chain_error: timeline.chain_error,
            events,
        })
    }

    async fn diff(
        &self,
        tenant_id: &str,
        query: AuditDiffQuery,
    ) -> Result<AuditDiffResponse, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        let kind = parse_aggregate_kind(&query.entity_type)?;
        let from = parse_required_rfc3339(&query.from, "from")?;
        let to = parse_required_rfc3339(&query.to, "to")?;
        if from > to {
            return Err(Phase3PortError::Invalid(format!(
                "diff window inverted: from {from} > to {to}"
            )));
        }

        let diff = self
            .service
            .diff_between(tenant, kind, &query.entity_id, from, to)
            .await
            .map_err(|err| Phase3PortError::Internal(format!("diff: {err}")))?;

        let from_ts = diff
            .from_ts
            .format(&Rfc3339)
            .map_err(|e| Phase3PortError::Internal(format!("format from_ts: {e}")))?;
        let to_ts = diff
            .to_ts
            .format(&Rfc3339)
            .map_err(|e| Phase3PortError::Internal(format!("format to_ts: {e}")))?;

        Ok(AuditDiffResponse {
            entity_type: diff.entity_type,
            entity_id: diff.entity_id,
            from_ts,
            to_ts,
            before: diff.before,
            after: diff.after,
            chain_verified: diff.chain_verified,
            chain_error: diff.chain_error,
        })
    }
}

/// Parse the bearer-token tenant id into the strongly-typed [`TenantId`].
///
/// Surfaces [`Phase3PortError::Forbidden`] when the bearer token carries
/// a malformed tenant id — defence-in-depth against the auth layer
/// stamping a bogus claim into the request.
fn parse_tenant(raw: &str) -> Result<TenantId, Phase3PortError> {
    raw.parse::<TenantId>()
        .map_err(|err| Phase3PortError::Forbidden(format!("invalid tenant claim: {err}")))
}

/// Parse the wire `entity_type` into the [`AggregateKind`] enum.
fn parse_aggregate_kind(raw: &str) -> Result<AggregateKind, Phase3PortError> {
    AggregateKind::parse(raw)
        .ok_or_else(|| Phase3PortError::Invalid(format!("unknown entity_type: {raw}")))
}

/// Parse a required RFC 3339 timestamp; emits
/// [`Phase3PortError::Invalid`] when the string is malformed.
fn parse_required_rfc3339(s: &str, field: &str) -> Result<OffsetDateTime, Phase3PortError> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|e| Phase3PortError::Invalid(format!("malformed {field}: {e}")))
}

/// Project an [`Actor`] into the wire `kind:id` form.
fn project_actor(actor: &Actor) -> String {
    let kind = match actor.kind {
        ActorKind::User => "user",
        ActorKind::Service => "service",
        ActorKind::System => "system",
    };
    format!("{kind}:{}", actor.id)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use sx_audit::model::entry::HASH_LEN;
    use sx_core::value_object::ids::UserId;

    fn make_entry(seq: u64, action: AuditAction, ts_secs: i64, tenant: TenantId) -> AuditEntry {
        AuditEntry {
            seq,
            tenant_id: tenant,
            ts: OffsetDateTime::from_unix_timestamp(ts_secs).unwrap(),
            actor: Actor::user(UserId::new()),
            action,
            resource_kind: "engagement".into(),
            resource_id: format!("res-{seq}"),
            before: None,
            after: None,
            request_id: format!("req-{seq}"),
            prev_hash: [0u8; HASH_LEN],
            hash: [0u8; HASH_LEN],
            chain_hash: String::new(),
            chain_prev_hash: None,
        }
    }

    fn tenant() -> TenantId {
        TenantId::new()
    }

    /// Build an in-memory bundle for tests, returning the concrete buffer
    /// handle too so tests can seed entries via `push_for_test`.
    fn build_in_memory_for_test() -> (AuditQueryBundle, Arc<InMemoryAuditBufferSink>) {
        let buf = Arc::new(InMemoryAuditBufferSink::new());
        let audit_query: Arc<dyn AuditQueryPort> = Arc::new(AuditQueryAdapter {
            source: Arc::clone(&buf) as Arc<dyn AuditReadAll>,
        });
        let audit_replay: Arc<dyn AuditReplayPort> = Arc::new(AuditReplayAdapter {
            service: Arc::new(InMemoryTimeTravelService::new(
                Arc::clone(&buf) as Arc<dyn AuditSink>
            )),
        });
        let bundle = AuditQueryBundle {
            audit_query,
            audit_replay,
            sink: Arc::clone(&buf) as Arc<dyn AuditSink>,
        };
        (bundle, buf)
    }

    /// Durability proof against a real Postgres: the `PgAuditStore` persists
    /// the hash chain, enforces per-tenant monotonic `seq`, and — crucially —
    /// a *fresh store (restart-equivalent)* resumes the chain: `last_entry`
    /// returns the persisted head (hash intact) so the recorder would chain
    /// the next entry onto it, and `read_range` returns the full chain.
    ///
    /// Gated on `TEST_DATABASE_URL` (silent no-op in CI; workspace live-DB
    /// fixture convention). `audit_entries` has no tenant FK.
    #[tokio::test]
    async fn pg_audit_store_chain_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tid = tenant();
        // Distinct hash bytes so we can assert the head's hash round-trips.
        let mut e1 = make_entry(1, AuditAction::Login, 100, tid);
        e1.hash = [0x11; HASH_LEN];
        let mut e2 = make_entry(2, AuditAction::Logout, 200, tid);
        e2.prev_hash = [0x11; HASH_LEN];
        e2.hash = [0x22; HASH_LEN];

        {
            let pool = PgPool::connect(&url).await.expect("connect");
            let store = PgAuditStore::new(pool, 15_000);
            store.append(&e1).await.expect("append genesis");
            // Out-of-order seq is rejected (seq 1 again when 2 is expected).
            assert!(
                store.append(&e1).await.is_err(),
                "replayed/out-of-order seq must be rejected"
            );
            store.append(&e2).await.expect("append seq 2");
            let last = store
                .last_entry_for_tenant(tid)
                .await
                .expect("last_entry")
                .expect("has head");
            assert_eq!(last.seq, 2);
            assert_eq!(last.hash, [0x22; HASH_LEN]);
        }

        // Fresh store == a fresh process. In-memory state would be gone here.
        {
            let pool = PgPool::connect(&url).await.expect("reconnect");
            let store = PgAuditStore::new(pool, 15_000);
            // The chain head survived, with its hash intact — the recorder
            // would chain the next entry onto this.
            let head = store
                .last_entry_for_tenant(tid)
                .await
                .expect("last_entry after restart")
                .expect("head survived restart");
            assert_eq!(head.seq, 2);
            assert_eq!(head.hash, [0x22; HASH_LEN]);
            // And a seq-3 entry chained onto the persisted head is accepted.
            let mut e3 = make_entry(3, AuditAction::Login, 300, tid);
            e3.prev_hash = head.hash;
            e3.hash = [0x33; HASH_LEN];
            store
                .append(&e3)
                .await
                .expect("chain continues after restart");
            let range = store.read_range(tid, 1, 3).await.expect("read_range");
            assert_eq!(range.len(), 3);
            assert_eq!(range[0].seq, 1);
            assert_eq!(range[2].prev_hash, [0x22; HASH_LEN]);
        }
    }

    /// Adapter filters by `since` (inclusive lower bound).
    #[tokio::test]
    async fn search_filters_by_since() {
        let (bundle, buf) = build_in_memory_for_test();
        let t = tenant();
        // ts = 100, 200, 300
        buf.push_for_test(make_entry(1, AuditAction::Login, 100, t))
            .await;
        buf.push_for_test(make_entry(2, AuditAction::Login, 200, t))
            .await;
        buf.push_for_test(make_entry(3, AuditAction::Logout, 300, t))
            .await;

        let since = OffsetDateTime::from_unix_timestamp(200)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        let resp = bundle
            .audit_query
            .search(AuditSearchQuery {
                since: Some(since),
                ..AuditSearchQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(resp.items.len(), 2);
        // Newest-first.
        assert_eq!(resp.items[0].action, "logout");
        assert_eq!(resp.items[1].action, "login");
        assert!(!resp.has_more);
    }

    /// Adapter filters by exact `action`.
    #[tokio::test]
    async fn search_filters_by_action() {
        let (bundle, buf) = build_in_memory_for_test();
        let t = tenant();
        buf.push_for_test(make_entry(1, AuditAction::Login, 100, t))
            .await;
        buf.push_for_test(make_entry(2, AuditAction::Logout, 200, t))
            .await;
        buf.push_for_test(make_entry(3, AuditAction::Login, 300, t))
            .await;

        let resp = bundle
            .audit_query
            .search(AuditSearchQuery {
                action: Some("login".into()),
                ..AuditSearchQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(resp.items.len(), 2);
        assert!(resp.items.iter().all(|e| e.action == "login"));
    }

    /// Adapter filters by exact `actor` (`kind:id`).
    #[tokio::test]
    async fn search_filters_by_actor() {
        let (bundle, buf) = build_in_memory_for_test();
        let t = tenant();
        let user_a = UserId::new();
        let user_b = UserId::new();
        let mut e1 = make_entry(1, AuditAction::Login, 100, t);
        e1.actor = Actor::user(user_a);
        let mut e2 = make_entry(2, AuditAction::Login, 200, t);
        e2.actor = Actor::user(user_b);
        buf.push_for_test(e1).await;
        buf.push_for_test(e2).await;

        let target = format!("user:{user_a}");
        let resp = bundle
            .audit_query
            .search(AuditSearchQuery {
                actor: Some(target.clone()),
                ..AuditSearchQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].actor, target);
    }

    /// `limit` truncates and sets `has_more=true` when more match.
    #[tokio::test]
    async fn search_caps_at_limit_and_sets_has_more() {
        let (bundle, buf) = build_in_memory_for_test();
        let t = tenant();
        for i in 1i64..=5 {
            buf.push_for_test(make_entry(
                u64::try_from(i).unwrap(),
                AuditAction::Login,
                100 + i,
                t,
            ))
            .await;
        }
        let resp = bundle
            .audit_query
            .search(AuditSearchQuery {
                limit: Some(2),
                ..AuditSearchQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(resp.items.len(), 2);
        assert!(resp.has_more);
    }

    /// Export emits exactly one NDJSON line per entry, terminated by `\n`.
    #[tokio::test]
    async fn export_streams_one_ndjson_line_per_entry() {
        let (bundle, buf) = build_in_memory_for_test();
        let t = tenant();
        buf.push_for_test(make_entry(1, AuditAction::Login, 100, t))
            .await;
        buf.push_for_test(make_entry(2, AuditAction::Logout, 200, t))
            .await;

        let body = bundle.audit_query.export_ndjson(None).await.unwrap();
        let text = String::from_utf8(body).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line must parse as a complete AuditEntryView.
        for line in lines {
            let v: AuditEntryView = serde_json::from_str(line).unwrap();
            assert!(!v.action.is_empty());
        }
        // Body ends with newline.
        assert!(text.ends_with('\n'));
    }

    /// Export respects the [`MAX_EXPORT_ENTRIES`] cap.
    #[tokio::test]
    async fn export_caps_at_max_entries() {
        let (bundle, buf) = build_in_memory_for_test();
        let t = tenant();
        // Insert MAX_EXPORT_ENTRIES + 5 entries.
        let total = i64::try_from(MAX_EXPORT_ENTRIES).unwrap() + 5;
        for i in 1i64..=total {
            buf.push_for_test(make_entry(
                u64::try_from(i).unwrap(),
                AuditAction::Login,
                100 + i,
                t,
            ))
            .await;
        }
        let body = bundle.audit_query.export_ndjson(None).await.unwrap();
        #[allow(clippy::naive_bytecount)]
        let line_count = body.iter().filter(|b| **b == b'\n').count();
        assert_eq!(line_count, MAX_EXPORT_ENTRIES);
    }

    /// Malformed `since` surfaces as [`Phase3PortError::Invalid`].
    #[tokio::test]
    async fn search_rejects_malformed_since() {
        let (bundle, _buf) = build_in_memory_for_test();
        let err = bundle
            .audit_query
            .search(AuditSearchQuery {
                since: Some("not-a-timestamp".into()),
                ..AuditSearchQuery::default()
            })
            .await
            .expect_err("malformed since should be rejected");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    /// Concurrent search calls are safe (shared `Arc<Mutex<...>>`).
    #[tokio::test]
    async fn concurrent_search_is_safe() {
        let (bundle, buf) = build_in_memory_for_test();
        let t = tenant();
        for i in 1i64..=20 {
            buf.push_for_test(make_entry(
                u64::try_from(i).unwrap(),
                AuditAction::Login,
                100 + i,
                t,
            ))
            .await;
        }
        let port = Arc::clone(&bundle.audit_query);
        let mut handles = Vec::with_capacity(8);
        for _ in 0..8 {
            let port = Arc::clone(&port);
            handles.push(tokio::spawn(async move {
                let resp = port.search(AuditSearchQuery::default()).await.unwrap();
                assert_eq!(resp.items.len(), 20);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    /// `project_actor` round-trip — verifies `kind:id` format for every
    /// actor variant.
    #[test]
    fn project_actor_emits_kind_colon_id() {
        let u = Actor::user(UserId::new());
        let s = Actor::service("worker");
        let sys = Actor::system();
        assert!(project_actor(&u).starts_with("user:"));
        assert_eq!(project_actor(&s), "service:worker");
        assert_eq!(project_actor(&sys), "system:system");
    }

    // ------------------------------------------------------------------
    // Audit-replay (time-travel) adapter tests — P3-009
    // ------------------------------------------------------------------

    use serde_json::json;
    use sx_audit::prelude::{build_entry, build_genesis, NewAuditEvent};

    /// Build a `NewAuditEvent` payload at a specific unix timestamp; the
    /// helper exists so the replay adapter tests stay readable.
    fn signed(
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

    /// `replay` returns events oldest-first with `chain_verified=true` for
    /// a well-formed two-event chain.
    #[tokio::test]
    async fn replay_returns_ordered_events_for_intact_chain() {
        let (bundle, buf) = build_in_memory_for_test();
        let tenant = tenant();
        let eid = "eng-1";

        let g = build_genesis(signed(
            AuditAction::EngagementCreated,
            "engagement",
            eid,
            100,
            tenant,
            None,
            Some(json!({"name": "v1"})),
        ))
        .unwrap();
        let e2 = build_entry(
            2,
            g.hash,
            signed(
                AuditAction::EngagementUpdated,
                "engagement",
                eid,
                200,
                tenant,
                Some(json!({"name": "v1"})),
                Some(json!({"name": "v2"})),
            ),
        )
        .unwrap();
        buf.push_for_test(g).await;
        buf.push_for_test(e2).await;

        let resp = bundle
            .audit_replay
            .replay(
                &tenant.to_string(),
                AuditReplayQuery {
                    entity_type: "engagement".into(),
                    entity_id: eid.into(),
                    from: None,
                    to: None,
                },
            )
            .await
            .unwrap();
        assert!(
            resp.chain_verified,
            "expected verified chain: {:?}",
            resp.chain_error
        );
        assert!(resp.chain_error.is_none());
        assert_eq!(resp.events.len(), 2);
        assert_eq!(resp.events[0].seq, 1);
        assert_eq!(resp.events[1].seq, 2);
        // Final post-image surfaced into the wire view.
        assert_eq!(resp.events[1].after.as_ref().unwrap()["name"], "v2");
    }

    /// Cross-tenant replay MUST NOT leak rows from another tenant even
    /// when the entity id collides. The bearer-token tenant is the only
    /// allowed scope.
    #[tokio::test]
    async fn replay_rejects_cross_tenant_lookup() {
        let (bundle, buf) = build_in_memory_for_test();
        let tenant_a = tenant();
        let tenant_b = tenant();
        let eid = "shared-eid";

        // Hydrate a row only for tenant B.
        let g = build_genesis(signed(
            AuditAction::EngagementCreated,
            "engagement",
            eid,
            100,
            tenant_b,
            None,
            Some(json!({"owner": "tenant-b"})),
        ))
        .unwrap();
        buf.push_for_test(g).await;

        // Query the SAME entity id as tenant A — must come back empty.
        let resp = bundle
            .audit_replay
            .replay(
                &tenant_a.to_string(),
                AuditReplayQuery {
                    entity_type: "engagement".into(),
                    entity_id: eid.into(),
                    from: None,
                    to: None,
                },
            )
            .await
            .unwrap();
        assert!(resp.chain_verified);
        assert!(
            resp.events.is_empty(),
            "tenant B's row must NOT leak into tenant A's replay; got {:?}",
            resp.events
        );
    }

    /// A tampered chain surfaces with `chain_verified=false` and a
    /// populated `chain_error`; the events are still returned so the
    /// operator can audit *which* rows are suspicious.
    #[tokio::test]
    async fn replay_flags_tampered_chain_explicitly() {
        let (bundle, buf) = build_in_memory_for_test();
        let tenant = tenant();
        let eid = "eng-tampered";

        let mut g = build_genesis(signed(
            AuditAction::EngagementCreated,
            "engagement",
            eid,
            100,
            tenant,
            None,
            Some(json!({"name": "real"})),
        ))
        .unwrap();
        // Tamper the post-image AFTER the hash was computed — verification
        // must reject the row.
        g.after = Some(json!({"name": "TAMPERED"}));
        buf.push_for_test(g).await;

        let resp = bundle
            .audit_replay
            .replay(
                &tenant.to_string(),
                AuditReplayQuery {
                    entity_type: "engagement".into(),
                    entity_id: eid.into(),
                    from: None,
                    to: None,
                },
            )
            .await
            .unwrap();
        assert!(
            !resp.chain_verified,
            "tampered chain must fail verification"
        );
        assert!(resp.chain_error.is_some());
        assert_eq!(resp.events.len(), 1);
        assert_eq!(
            resp.events[0].after.as_ref().unwrap()["name"],
            "TAMPERED",
            "events still surface for forensic review",
        );
    }

    /// Unknown `entity_type` is rejected as a 422.
    #[tokio::test]
    async fn replay_rejects_unknown_entity_type() {
        let (bundle, _buf) = build_in_memory_for_test();
        let err = bundle
            .audit_replay
            .replay(
                &tenant().to_string(),
                AuditReplayQuery {
                    entity_type: "spaceship".into(),
                    entity_id: "x".into(),
                    from: None,
                    to: None,
                },
            )
            .await
            .expect_err("unknown entity_type must be rejected");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    /// A malformed bearer-token tenant id is rejected as `Forbidden`.
    #[tokio::test]
    async fn replay_rejects_malformed_tenant_claim() {
        let (bundle, _buf) = build_in_memory_for_test();
        let err = bundle
            .audit_replay
            .replay(
                "not-a-uuid",
                AuditReplayQuery {
                    entity_type: "engagement".into(),
                    entity_id: "x".into(),
                    from: None,
                    to: None,
                },
            )
            .await
            .expect_err("malformed tenant must be rejected");
        assert!(matches!(err, Phase3PortError::Forbidden(_)));
    }

    /// `diff` rejects an inverted window (`from > to`).
    #[tokio::test]
    async fn diff_rejects_inverted_window() {
        let (bundle, _buf) = build_in_memory_for_test();
        let later = OffsetDateTime::from_unix_timestamp(500)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        let earlier = OffsetDateTime::from_unix_timestamp(100)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        let err = bundle
            .audit_replay
            .diff(
                &tenant().to_string(),
                AuditDiffQuery {
                    entity_type: "engagement".into(),
                    entity_id: "e".into(),
                    from: later,
                    to: earlier,
                },
            )
            .await
            .expect_err("inverted window must be rejected");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    /// `diff` returns before/after snapshots for the requested endpoints.
    #[tokio::test]
    async fn diff_returns_before_and_after_snapshots() {
        let (bundle, buf) = build_in_memory_for_test();
        let tenant = tenant();
        let eid = "eng-diff";

        let g = build_genesis(signed(
            AuditAction::EngagementCreated,
            "engagement",
            eid,
            100,
            tenant,
            None,
            Some(json!({"status": "draft"})),
        ))
        .unwrap();
        let e2 = build_entry(
            2,
            g.hash,
            signed(
                AuditAction::EngagementUpdated,
                "engagement",
                eid,
                300,
                tenant,
                Some(json!({"status": "draft"})),
                Some(json!({"status": "active"})),
            ),
        )
        .unwrap();
        buf.push_for_test(g).await;
        buf.push_for_test(e2).await;

        let from = OffsetDateTime::from_unix_timestamp(150)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        let to = OffsetDateTime::from_unix_timestamp(400)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        let resp = bundle
            .audit_replay
            .diff(
                &tenant.to_string(),
                AuditDiffQuery {
                    entity_type: "engagement".into(),
                    entity_id: eid.into(),
                    from,
                    to,
                },
            )
            .await
            .unwrap();
        assert!(resp.chain_verified);
        assert_eq!(
            resp.before.as_ref().unwrap()["status"],
            "draft",
            "before snapshot picks the genesis row at t=100"
        );
        assert_eq!(
            resp.after.as_ref().unwrap()["status"],
            "active",
            "after snapshot picks the t=300 row"
        );
    }
}
