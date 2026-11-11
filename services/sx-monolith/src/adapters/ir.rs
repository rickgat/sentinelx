//! IR playbooks adapter (P3-004).
//!
//! Wires the in-memory [`InMemoryIrPlaybookService`] from
//! [`sx_ir_playbooks`] behind the [`IrPlaybooksPort`] HTTP trait. The
//! adapter is responsible for:
//!
//! 1. Holding a process-lifetime instance of the in-memory service so
//!    incident state survives across HTTP calls.
//! 2. Translating domain errors ([`sx_ir_playbooks::IrPlaybookError`])
//!    into the HTTP port's [`IrPlaybookPortError`] taxonomy.
//! 3. Projecting domain types ([`Incident`], [`Playbook`]) onto the
//!    wire DTOs ([`IncidentView`], [`PlaybookView`]).
//! 4. Parsing the wire-side `status` string into the domain enum
//!    [`StepStatus`] (validation past the HTTP boundary).
//!
//! ## Tenant scoping
//!
//! Every call forwards `tenant_id` verbatim to the underlying service.
//! Cross-tenant reads collapse to [`IrPlaybookPortError::NotFound`] so
//! a foreign caller cannot enumerate incident ids that belong to
//! another tenant.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::{IrPlaybookPortError, IrPlaybooksPort};
use sx_api::view::ir_view::{
    IncidentStepView, IncidentView, ListPlaybooksResponse, PlaybookStepView, PlaybookView,
    StepAuditView,
};
use sx_audit::chain_verifier::{AuditChainBrokenPayload, BrokenChainSubscriber};
use sx_ir_playbooks::service::{OpenIncident, StepUpdate};
use sx_ir_playbooks::{
    builtin_catalog, is_legal_incident_transition, is_legal_step_transition, AuditChainBrokenEvent,
    AutoFireOutcome, InMemoryIrPlaybookService, Incident, IncidentState, IrPhase, IrPlaybookError,
    IrPlaybookService, Playbook, StepAuditEntry, StepAuditKind, StepStatus,
    AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID, AUTO_FIRE_ACTOR, AUTO_FIRE_SEVERITY,
};
use sx_storage::prelude::TenantId as StorageTenantId;
use sx_storage::tenant_context::TenantContext;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// Bundle handed to the composition root.
pub(crate) struct IrBundle {
    /// HTTP-facing port.
    pub(crate) port: Arc<dyn IrPlaybooksPort>,
    /// Auto-fire subscriber forwarded into the audit chain verifier so
    /// `audit.chain.broken` events automatically open an
    /// `audit_chain_compromise` incident.
    pub(crate) chain_broken_subscriber: Arc<dyn BrokenChainSubscriber>,
    /// IR service handle — kept so the drill simulator (P-CRIT-002) can
    /// drive the state machine without crossing the HTTP layer.
    #[allow(dead_code)] // production wiring lands when the drill API HTTP route is exposed
    pub(crate) service: Arc<dyn IrPlaybookService>,
}

/// Build the bundle. Incidents are durable (Postgres) when the DB is enabled
/// — so an open incident and its step-audit trail survive a monolith restart
/// — else in-memory (dev quick-start). The built-in playbook catalog is
/// static either way.
pub(crate) fn build(postgres: Option<(PgPool, u64)>) -> IrBundle {
    let service: Arc<dyn IrPlaybookService> = match postgres {
        Some((pool, stmt_timeout_ms)) => Arc::new(PgIrPlaybookService::new(pool, stmt_timeout_ms)),
        None => Arc::new(InMemoryIrPlaybookService::new()),
    };
    let port: Arc<dyn IrPlaybooksPort> = Arc::new(IrAdapter {
        service: Arc::clone(&service),
    });
    let chain_broken_subscriber: Arc<dyn BrokenChainSubscriber> = Arc::new(ChainBrokenAutoFire {
        service: Arc::clone(&service),
    });
    IrBundle {
        port,
        chain_broken_subscriber,
        service,
    }
}

/// Subscriber adapter that bridges
/// [`AuditChainBrokenPayload`](sx_audit::chain_verifier::AuditChainBrokenPayload)
/// from the audit chain verifier into the IR auto-fire surface.
#[derive(Debug)]
struct ChainBrokenAutoFire {
    service: Arc<dyn IrPlaybookService>,
}

#[async_trait]
impl BrokenChainSubscriber for ChainBrokenAutoFire {
    async fn on_broken(&self, payload: &AuditChainBrokenPayload) {
        let evt = AuditChainBrokenEvent {
            tenant_id: payload.tenant_id.to_string(),
            expected_hash: payload.expected_hash.clone(),
            actual_hash: payload.actual_hash.clone(),
            last_good_seq: payload.last_good_seq,
            break_seq: payload.break_seq,
            detected_at: payload.detected_at.clone(),
        };
        match self.service.auto_fire_audit_chain_compromise(evt).await {
            Ok(outcome) => {
                tracing::error!(
                    target: "monolith.ir.auto_fire",
                    tenant = %payload.tenant_id,
                    incident = %outcome.incident.id,
                    deduplicated = outcome.deduplicated,
                    break_seq = payload.break_seq,
                    "audit.chain.broken IR auto-fire dispatched"
                );
            }
            Err(err) => {
                tracing::error!(
                    target: "monolith.ir.auto_fire",
                    tenant = %payload.tenant_id,
                    break_seq = payload.break_seq,
                    error = %err,
                    "audit.chain.broken IR auto-fire FAILED — manual escalation required"
                );
            }
        }
    }
}

/// In-process IR-playbooks adapter.
struct IrAdapter {
    service: Arc<dyn IrPlaybookService>,
}

impl std::fmt::Debug for IrAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrAdapter").finish_non_exhaustive()
    }
}

#[async_trait]
impl IrPlaybooksPort for IrAdapter {
    async fn list_playbooks(
        &self,
        tenant_id: &str,
    ) -> Result<ListPlaybooksResponse, IrPlaybookPortError> {
        let pbs = self
            .service
            .list_playbooks(tenant_id)
            .await
            .map_err(map_err)?;
        Ok(ListPlaybooksResponse {
            items: pbs.iter().map(project_playbook).collect(),
        })
    }

    async fn open_incident(
        &self,
        tenant_id: &str,
        actor: &str,
        playbook_id: &str,
        title: &str,
        severity: Option<&str>,
    ) -> Result<IncidentView, IrPlaybookPortError> {
        let req = OpenIncident {
            playbook_id: playbook_id.to_owned(),
            title: title.to_owned(),
            severity: severity.map(str::to_owned),
        };
        let inc = self
            .service
            .open_incident(tenant_id, actor, req)
            .await
            .map_err(map_err)?;
        Ok(project_incident(&inc))
    }

    async fn get_incident(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<IncidentView, IrPlaybookPortError> {
        let inc = self
            .service
            .get_incident(tenant_id, incident_id)
            .await
            .map_err(map_err)?;
        Ok(project_incident(&inc))
    }

    async fn update_step(
        &self,
        tenant_id: &str,
        actor: &str,
        incident_id: &str,
        step_id: &str,
        status: Option<&str>,
        owner: Option<&str>,
        reason: Option<&str>,
        evidence: Option<&str>,
    ) -> Result<IncidentView, IrPlaybookPortError> {
        let status_enum = status.map(parse_status).transpose()?;
        let update = StepUpdate {
            status: status_enum,
            owner: owner.map(str::to_owned),
            reason: reason.map(str::to_owned),
            evidence: evidence.map(str::to_owned),
        };
        let inc = self
            .service
            .update_step(tenant_id, actor, incident_id, step_id, update)
            .await
            .map_err(map_err)?;
        Ok(project_incident(&inc))
    }
}

// ---------------------------------------------------------------------------
// Durable Postgres-backed IR service (incidents survive restart)
// ---------------------------------------------------------------------------

/// Postgres-backed [`IrPlaybookService`].
///
/// The composition root bound IR to the in-memory service, so every open
/// incident and its step-audit trail was lost on a monolith restart (and
/// invisible across instances) — including `audit_chain_compromise`
/// incidents auto-fired on a tamper-evidence break. This persists incidents.
///
/// The built-in playbook *catalog* is static (loaded from
/// [`builtin_catalog`]), so only incidents are durable. Each [`Incident`]
/// aggregate (steps + step-audit trail) is stored as JSONB in `ir_incidents`
/// keyed by `(tenant_id, incident_id)`, with `playbook_id` + `state`
/// projections for the auto-fire dedup scan. The lifecycle logic mirrors
/// `InMemoryIrPlaybookService`, but every read-modify-write runs inside a
/// transaction over a `SELECT … FOR UPDATE` row lock, so concurrent step
/// patches serialise at the database (stronger than the in-memory mutex).
///
/// Keyed by a globally-unique incident id and filtered explicitly by tenant,
/// the table is intentionally not under tenant RLS (same rationale as the
/// other id-keyed stores in this program).
struct PgIrPlaybookService {
    pool: PgPool,
    stmt_timeout_ms: u64,
    catalog: Vec<Playbook>,
}

impl std::fmt::Debug for PgIrPlaybookService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgIrPlaybookService")
            .finish_non_exhaustive()
    }
}

impl PgIrPlaybookService {
    fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
            catalog: builtin_catalog().unwrap_or_default(),
        }
    }

    fn find_playbook(&self, id: &str) -> Option<&Playbook> {
        self.catalog.iter().find(|p| p.id == id)
    }

    fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
    }

    fn internal(e: impl std::fmt::Display) -> IrPlaybookError {
        IrPlaybookError::Internal(format!("ir incident store: {e}"))
    }

    fn parse_tenant(tenant_id: &str) -> Result<Uuid, IrPlaybookError> {
        Uuid::parse_str(tenant_id.trim())
            .map_err(|e| IrPlaybookError::Invalid(format!("tenant_id not a uuid: {e}")))
    }

    /// Open a transaction with the tenant RLS GUC applied (the `ir_incidents`
    /// table is `ENABLE`+`FORCE ROW LEVEL SECURITY`, keyed on
    /// `app_current_tenant()`), plus a statement timeout.
    async fn begin_tenant(
        &self,
        tenant_uuid: Uuid,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, IrPlaybookError> {
        let mut tx = self.pool.begin().await.map_err(Self::internal)?;
        TenantContext::apply(
            &mut tx,
            StorageTenantId::from_uuid(tenant_uuid),
            self.stmt_timeout_ms,
        )
        .await
        .map_err(Self::internal)?;
        Ok(tx)
    }

    fn decode(row: &sqlx::postgres::PgRow) -> Result<Incident, IrPlaybookError> {
        row.try_get::<Json<Incident>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::internal)
    }

    /// Persist a freshly-opened incident into `ir_incidents`. The projection
    /// columns (playbook_id, state, title, severity, steps) satisfy the
    /// table's CHECK constraints + back the auto-fire dedup scan; `aggregate`
    /// is the lossless read source (incl. the step-audit trail).
    async fn insert(
        &self,
        tx: &mut sqlx::PgConnection,
        inc: &Incident,
    ) -> Result<(), IrPlaybookError> {
        let id = Uuid::parse_str(&inc.id).map_err(Self::internal)?;
        let tenant = Self::parse_tenant(&inc.tenant_id)?;
        sqlx::query(
            "INSERT INTO ir_incidents \
                 (id, tenant_id, playbook_id, state, title, severity, steps, \
                  opened_at, updated_at, aggregate) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::timestamptz, $10)",
        )
        .bind(id)
        .bind(tenant)
        .bind(&inc.playbook_id)
        .bind(inc.state.as_str())
        .bind(&inc.title)
        .bind(inc.severity.as_deref())
        .bind(Json(&inc.steps))
        .bind(&inc.opened_at)
        .bind(&inc.updated_at)
        .bind(Json(inc))
        .execute(&mut *tx)
        .await
        .map_err(Self::internal)?;
        Ok(())
    }
}

#[async_trait]
impl IrPlaybookService for PgIrPlaybookService {
    async fn list_playbooks(&self, _tenant_id: &str) -> Result<Vec<Playbook>, IrPlaybookError> {
        Ok(self.catalog.clone())
    }

    async fn open_incident(
        &self,
        tenant_id: &str,
        actor: &str,
        req: OpenIncident,
    ) -> Result<Incident, IrPlaybookError> {
        if tenant_id.is_empty() {
            return Err(IrPlaybookError::Invalid("tenant_id empty".into()));
        }
        if actor.is_empty() {
            return Err(IrPlaybookError::Invalid("actor empty".into()));
        }
        if req.title.is_empty() {
            return Err(IrPlaybookError::Invalid("title empty".into()));
        }
        let tenant_uuid = Self::parse_tenant(tenant_id)?;
        let pb = self
            .find_playbook(&req.playbook_id)
            .ok_or(IrPlaybookError::NotFound)?;
        let now = Self::now_rfc3339();
        let inc = Incident::open(
            Uuid::now_v7().to_string(),
            tenant_id.to_owned(),
            pb,
            req.title,
            req.severity,
            &now,
        );
        let mut tx = self.begin_tenant(tenant_uuid).await?;
        self.insert(&mut tx, &inc).await?;
        tx.commit().await.map_err(Self::internal)?;
        Ok(inc)
    }

    async fn get_incident(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<Incident, IrPlaybookError> {
        let tenant_uuid = Self::parse_tenant(tenant_id)?;
        // A malformed incident id cannot match a row — surface NotFound
        // rather than a decode error (mirrors the in-memory lookup miss).
        let Ok(inc_uuid) = Uuid::parse_str(incident_id.trim()) else {
            return Err(IrPlaybookError::NotFound);
        };
        let mut tx = self.begin_tenant(tenant_uuid).await?;
        // RLS confines the row to the calling tenant; the id predicate picks
        // the incident.
        let row = sqlx::query("SELECT aggregate FROM ir_incidents WHERE id = $1")
            .bind(inc_uuid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        let row = row.ok_or(IrPlaybookError::NotFound)?;
        Self::decode(&row)
    }

    #[allow(clippy::too_many_lines)] // single-transaction patch handler, mirrors the in-memory service
    async fn update_step(
        &self,
        tenant_id: &str,
        actor: &str,
        incident_id: &str,
        step_id: &str,
        update: StepUpdate,
    ) -> Result<Incident, IrPlaybookError> {
        if actor.is_empty() {
            return Err(IrPlaybookError::Invalid("actor empty".into()));
        }
        let tenant_uuid = Self::parse_tenant(tenant_id)?;
        let Ok(inc_uuid) = Uuid::parse_str(incident_id.trim()) else {
            return Err(IrPlaybookError::NotFound);
        };
        let now = Self::now_rfc3339();
        let mut tx = self.begin_tenant(tenant_uuid).await?;
        // Row-lock the incident for the whole read-modify-write.
        let row = sqlx::query("SELECT aggregate FROM ir_incidents WHERE id = $1 FOR UPDATE")
            .bind(inc_uuid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::internal)?;
        let mut inc = Self::decode(&row.ok_or(IrPlaybookError::NotFound)?)?;

        if matches!(inc.state, IncidentState::Closed) {
            return Err(IrPlaybookError::IllegalIncidentTransition(
                "incident is closed".into(),
            ));
        }
        let mut new_audit: Vec<StepAuditEntry> = Vec::new();

        // -- Status update --------------------------------------------
        if let Some(new_status) = update.status {
            let step = inc.step_mut(step_id).ok_or(IrPlaybookError::NotFound)?;
            let from = step.status;
            if !is_legal_step_transition(from, new_status) {
                return Err(IrPlaybookError::IllegalStepTransition(format!(
                    "{} -> {}",
                    from.as_str(),
                    new_status.as_str()
                )));
            }
            if matches!(new_status, StepStatus::Skipped)
                && update.reason.as_deref().unwrap_or("").is_empty()
            {
                return Err(IrPlaybookError::Invalid(
                    "skipped status requires a non-empty reason".into(),
                ));
            }
            if from != new_status {
                step.status = new_status;
                step.reason.clone_from(&update.reason);
                step.updated_at.clone_from(&now);
                new_audit.push(StepAuditEntry::step_status(
                    Uuid::now_v7().to_string(),
                    step_id.to_owned(),
                    actor.to_owned(),
                    from,
                    new_status,
                    update.reason.clone(),
                    now.clone(),
                ));
            }
        }

        // -- Owner update ---------------------------------------------
        if let Some(owner) = update.owner.clone() {
            let step = inc.step_mut(step_id).ok_or(IrPlaybookError::NotFound)?;
            if step.owner.as_deref() != Some(owner.as_str()) {
                step.owner = Some(owner);
                step.updated_at.clone_from(&now);
                new_audit.push(StepAuditEntry::owner_change(
                    Uuid::now_v7().to_string(),
                    step_id.to_owned(),
                    actor.to_owned(),
                    update.reason.clone(),
                    now.clone(),
                ));
            }
        }

        // -- Evidence append ------------------------------------------
        if let Some(uri) = update.evidence {
            if !uri.is_empty() {
                let step = inc.step_mut(step_id).ok_or(IrPlaybookError::NotFound)?;
                step.evidence.push(uri.clone());
                step.updated_at.clone_from(&now);
                new_audit.push(StepAuditEntry::evidence(
                    Uuid::now_v7().to_string(),
                    step_id.to_owned(),
                    actor.to_owned(),
                    uri,
                    now.clone(),
                ));
            }
        }

        // -- Rollup ----------------------------------------------------
        let prev_state = inc.state;
        let next_state = inc.rollup_state();
        if prev_state != next_state {
            if !is_legal_incident_transition(prev_state, next_state) {
                return Err(IrPlaybookError::IllegalIncidentTransition(format!(
                    "{} -> {}",
                    prev_state.as_str(),
                    next_state.as_str()
                )));
            }
            inc.state = next_state;
            new_audit.push(StepAuditEntry::incident_state(
                Uuid::now_v7().to_string(),
                actor.to_owned(),
                prev_state,
                next_state,
                now.clone(),
            ));
        }

        if new_audit.is_empty() {
            // No-op patch — nothing to persist.
            tx.commit().await.map_err(Self::internal)?;
            return Ok(inc);
        }
        inc.audit.extend(new_audit);
        inc.updated_at = now;
        sqlx::query(
            "UPDATE ir_incidents \
             SET state = $2, steps = $3, updated_at = $4::timestamptz, aggregate = $5 \
             WHERE id = $1",
        )
        .bind(inc_uuid)
        .bind(inc.state.as_str())
        .bind(Json(&inc.steps))
        .bind(&inc.updated_at)
        .bind(Json(&inc))
        .execute(&mut *tx)
        .await
        .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        Ok(inc)
    }

    async fn auto_fire_audit_chain_compromise(
        &self,
        event: AuditChainBrokenEvent,
    ) -> Result<AutoFireOutcome, IrPlaybookError> {
        if event.tenant_id.is_empty() {
            return Err(IrPlaybookError::Invalid("tenant_id empty".into()));
        }
        let tenant_uuid = Self::parse_tenant(&event.tenant_id)?;
        let mut tx = self.begin_tenant(tenant_uuid).await?;
        // Dedupe: an already-open audit_chain_compromise incident for this
        // tenant short-circuits. RLS scopes the scan to the tenant; the
        // `(tenant_id, state, ...)` index backs the predicate.
        let existing = sqlx::query(
            "SELECT aggregate FROM ir_incidents \
             WHERE playbook_id = $1 AND state <> $2 \
             ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID)
        .bind(IncidentState::Closed.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(Self::internal)?;
        if let Some(row) = existing {
            let inc = Self::decode(&row)?;
            tx.commit().await.map_err(Self::internal)?;
            return Ok(AutoFireOutcome {
                incident: inc,
                deduplicated: true,
            });
        }

        let pb = self
            .find_playbook(AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID)
            .ok_or_else(|| {
                IrPlaybookError::Internal(format!(
                    "catalog missing builtin playbook '{AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID}'"
                ))
            })?;
        let now = Self::now_rfc3339();
        let title = format!(
            "audit chain broken at seq {} (tenant {})",
            event.break_seq, event.tenant_id
        );
        let mut inc = Incident::open(
            Uuid::now_v7().to_string(),
            event.tenant_id.clone(),
            pb,
            title,
            Some(AUTO_FIRE_SEVERITY.to_owned()),
            &now,
        );
        // Stamp the structured break event onto the first preparation step's
        // evidence so the IR commander sees the break tuple on triage.
        let payload_json = serde_json::to_string(&event).map_err(|e| {
            IrPlaybookError::Internal(format!("audit.chain.broken payload serialise: {e}"))
        })?;
        if let Some(first_prep) = inc
            .steps
            .iter_mut()
            .find(|s| matches!(s.phase, IrPhase::Preparation))
        {
            first_prep
                .evidence
                .push(format!("audit.chain.broken:{payload_json}"));
        }
        self.insert(&mut tx, &inc).await?;
        tx.commit().await.map_err(Self::internal)?;
        tracing::error!(
            target: "ir.auto_fire",
            tenant = %event.tenant_id,
            incident = %inc.id,
            playbook = %AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID,
            break_seq = event.break_seq,
            actor = AUTO_FIRE_ACTOR,
            severity = AUTO_FIRE_SEVERITY,
            "audit chain broken: IR incident auto-fired (durable)"
        );
        Ok(AutoFireOutcome {
            incident: inc,
            deduplicated: false,
        })
    }
}

fn map_err(err: IrPlaybookError) -> IrPlaybookPortError {
    match err {
        IrPlaybookError::NotFound => IrPlaybookPortError::NotFound,
        IrPlaybookError::IllegalStepTransition(m) => IrPlaybookPortError::IllegalStepTransition(m),
        IrPlaybookError::IllegalIncidentTransition(m) => {
            IrPlaybookPortError::IllegalIncidentTransition(m)
        }
        IrPlaybookError::Invalid(m) => IrPlaybookPortError::Invalid(m),
        IrPlaybookError::Internal(m) => IrPlaybookPortError::Internal(m),
    }
}

fn parse_status(raw: &str) -> Result<StepStatus, IrPlaybookPortError> {
    match raw {
        "todo" => Ok(StepStatus::Todo),
        "in_progress" => Ok(StepStatus::InProgress),
        "done" => Ok(StepStatus::Done),
        "skipped" => Ok(StepStatus::Skipped),
        other => Err(IrPlaybookPortError::Invalid(format!(
            "unknown status: {other}"
        ))),
    }
}

fn project_playbook(pb: &Playbook) -> PlaybookView {
    PlaybookView {
        id: pb.id.clone(),
        name: pb.name.clone(),
        summary: pb.summary.clone(),
        steps: pb
            .steps
            .iter()
            .map(|s| PlaybookStepView {
                id: s.id.clone(),
                phase: s.phase.as_str().to_owned(),
                title: s.title.clone(),
                description: s.description.clone(),
                default_owner_role: s.default_owner_role.clone(),
                evidence_hints: s.evidence_hints.clone(),
            })
            .collect(),
    }
}

fn project_incident(inc: &Incident) -> IncidentView {
    IncidentView {
        id: inc.id.clone(),
        tenant_id: inc.tenant_id.clone(),
        playbook_id: inc.playbook_id.clone(),
        state: project_incident_state(inc.state).to_owned(),
        title: inc.title.clone(),
        severity: inc.severity.clone(),
        steps: inc
            .steps
            .iter()
            .map(|s| IncidentStepView {
                step_id: s.step_id.clone(),
                phase: s.phase.as_str().to_owned(),
                title: s.title.clone(),
                description: s.description.clone(),
                owner: s.owner.clone(),
                status: s.status.as_str().to_owned(),
                reason: s.reason.clone(),
                evidence: s.evidence.clone(),
                updated_at: s.updated_at.clone(),
            })
            .collect(),
        audit: inc.audit.iter().map(project_audit).collect(),
        opened_at: inc.opened_at.clone(),
        updated_at: inc.updated_at.clone(),
    }
}

const fn project_incident_state(s: IncidentState) -> &'static str {
    s.as_str()
}

fn project_audit(row: &StepAuditEntry) -> StepAuditView {
    StepAuditView {
        id: row.id.clone(),
        kind: project_audit_kind(row.kind).to_owned(),
        step_id: row.step_id.clone(),
        actor: row.actor.clone(),
        from_status: row.from_status.map(|s| s.as_str().to_owned()),
        to_status: row.to_status.map(|s| s.as_str().to_owned()),
        from_incident_state: row.from_incident_state.map(|s| s.as_str().to_owned()),
        to_incident_state: row.to_incident_state.map(|s| s.as_str().to_owned()),
        note: row.note.clone(),
        at: row.at.clone(),
    }
}

const fn project_audit_kind(k: StepAuditKind) -> &'static str {
    k.as_str()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tenant_a() -> &'static str {
        "00000000-0000-0000-0000-00000000000a"
    }
    fn tenant_b() -> &'static str {
        "00000000-0000-0000-0000-00000000000b"
    }

    #[tokio::test]
    async fn lists_builtin_catalog() {
        let b = build(None);
        let res = b.port.list_playbooks(tenant_a()).await.unwrap();
        let ids: Vec<&str> = res.items.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "ransomware",
                "data_exfiltration",
                "credential_compromise",
                "insider_threat",
                "audit_chain_compromise"
            ]
        );
        // Every projection covers every phase string.
        for pb in &res.items {
            for phase in [
                "preparation",
                "detection_analysis",
                "containment_eradication_recovery",
                "post_incident_activity",
            ] {
                assert!(
                    pb.steps.iter().any(|s| s.phase == phase),
                    "playbook {} missing phase {}",
                    pb.id,
                    phase
                );
            }
        }
    }

    #[tokio::test]
    async fn open_then_get_round_trips() {
        let b = build(None);
        let inc = b
            .port
            .open_incident(tenant_a(), "alice", "ransomware", "demo", Some("high"))
            .await
            .unwrap();
        assert_eq!(inc.state, "open");
        assert_eq!(inc.tenant_id, tenant_a());
        let fetched = b.port.get_incident(tenant_a(), &inc.id).await.unwrap();
        assert_eq!(fetched.id, inc.id);
    }

    #[tokio::test]
    async fn tenant_isolation_blocks_foreign_reads() {
        let b = build(None);
        let inc = b
            .port
            .open_incident(tenant_a(), "alice", "ransomware", "demo", None)
            .await
            .unwrap();
        let err = b
            .port
            .get_incident(tenant_b(), &inc.id)
            .await
            .expect_err("must reject");
        assert!(matches!(err, IrPlaybookPortError::NotFound));
    }

    #[tokio::test]
    async fn legal_status_transition_audited() {
        let b = build(None);
        let inc = b
            .port
            .open_incident(tenant_a(), "alice", "ransomware", "demo", None)
            .await
            .unwrap();
        let first = inc.steps[0].step_id.clone();
        let updated = b
            .port
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &first,
                Some("in_progress"),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(updated
            .audit
            .iter()
            .any(|r| r.kind == "step_status_changed"));
        assert!(updated
            .audit
            .iter()
            .any(|r| r.kind == "incident_state_changed"));
        assert_eq!(updated.state, "in_progress");
    }

    #[tokio::test]
    async fn illegal_status_transition_rejected() {
        let b = build(None);
        let inc = b
            .port
            .open_incident(tenant_a(), "alice", "ransomware", "demo", None)
            .await
            .unwrap();
        let first = inc.steps[0].step_id.clone();
        let err = b
            .port
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &first,
                Some("done"),
                None,
                None,
                None,
            )
            .await
            .expect_err("must reject");
        assert!(matches!(err, IrPlaybookPortError::IllegalStepTransition(_)));
    }

    #[tokio::test]
    async fn unknown_status_label_rejected() {
        let b = build(None);
        let inc = b
            .port
            .open_incident(tenant_a(), "alice", "ransomware", "demo", None)
            .await
            .unwrap();
        let first = inc.steps[0].step_id.clone();
        let err = b
            .port
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &first,
                Some("blocked"),
                None,
                None,
                None,
            )
            .await
            .expect_err("must reject");
        assert!(matches!(err, IrPlaybookPortError::Invalid(_)));
    }

    /// Durability proof against a real Postgres: open an incident → advance a
    /// step (audited) → *fresh service (restart-equivalent)* → the incident,
    /// its advanced state, and its audit trail survive → auto-fire opens an
    /// `audit_chain_compromise` incident and a second auto-fire deduplicates
    /// against the persisted open incident.
    ///
    /// Gated on `TEST_DATABASE_URL` (silent no-op in CI; workspace live-DB
    /// fixture convention).
    #[tokio::test]
    async fn pg_ir_incident_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = uuid::Uuid::new_v4().to_string();

        let incident_id;
        let first_step;
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            // `ir_incidents.tenant_id` FKs `tenants(id)`; create a fresh,
            // isolated tenant for this run (tenants is not under RLS).
            sqlx::query("INSERT INTO tenants (id, name, slug, tier) VALUES ($1::uuid, 'IR live test', $2, 'starter')")
                .bind(&tenant)
                .bind(format!("ir-live-{tenant}"))
                .execute(&pool)
                .await
                .expect("seed tenant");
            let svc = PgIrPlaybookService::new(pool, 15_000);
            let inc = svc
                .open_incident(
                    &tenant,
                    "alice",
                    OpenIncident {
                        playbook_id: "ransomware".into(),
                        title: "live drill".into(),
                        severity: Some("high".into()),
                    },
                )
                .await
                .expect("open");
            assert_eq!(inc.state, IncidentState::Open);
            incident_id = inc.id.clone();
            first_step = inc.steps[0].step_id.clone();
            let advanced = svc
                .update_step(
                    &tenant,
                    "alice",
                    &incident_id,
                    &first_step,
                    StepUpdate {
                        status: Some(StepStatus::InProgress),
                        owner: None,
                        reason: None,
                        evidence: None,
                    },
                )
                .await
                .expect("advance step");
            assert_eq!(advanced.state, IncidentState::InProgress);
            assert!(!advanced.audit.is_empty());
        }

        // Fresh service == a fresh process. In-memory state would be gone.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let svc = PgIrPlaybookService::new(pool, 15_000);
            let got = svc
                .get_incident(&tenant, &incident_id)
                .await
                .expect("incident survived restart");
            assert_eq!(got.state, IncidentState::InProgress, "state survived");
            assert!(
                got.audit
                    .iter()
                    .any(|a| a.step_id.as_deref() == Some(first_step.as_str())),
                "step audit survived restart"
            );

            // Auto-fire opens a compromise incident; a second call dedups
            // against the persisted open incident.
            let event = AuditChainBrokenEvent {
                tenant_id: tenant.clone(),
                expected_hash: "aa".into(),
                actual_hash: "bb".into(),
                last_good_seq: Some(4),
                break_seq: 5,
                detected_at: "2026-11-07T00:00:00Z".into(),
            };
            let first = svc
                .auto_fire_audit_chain_compromise(event.clone())
                .await
                .expect("auto-fire");
            assert!(!first.deduplicated, "first auto-fire opens a new incident");
            let second = svc
                .auto_fire_audit_chain_compromise(event)
                .await
                .expect("auto-fire dedup");
            assert!(
                second.deduplicated,
                "second auto-fire dedups on persisted incident"
            );
            assert_eq!(second.incident.id, first.incident.id);
        }
    }
}
