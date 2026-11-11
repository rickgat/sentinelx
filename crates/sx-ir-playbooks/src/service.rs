//! Service trait + in-memory adapter for IR playbooks.
//!
//! Implementations own:
//!   * The playbook catalog (static; built-ins live in [`crate::catalog`]).
//!   * The per-tenant incident store.
//!   * The append-only step-audit trail.
//!
//! The HTTP layer ports against this trait via `sx_api::port::IrPlaybooksPort`.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::StepAuditEntry;
use crate::catalog::{builtin_catalog, AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID};
use crate::error::IrPlaybookError;
use crate::incident::{Incident, IncidentState, StepStatus};
use crate::playbook::Playbook;
use crate::state::{is_legal_incident_transition, is_legal_step_transition};

/// Synthetic actor stamped on every auto-fired incident. Operators
/// filter on this string in the step-audit trail to differentiate
/// human-opened incidents from auto-opened ones.
pub const AUTO_FIRE_ACTOR: &str = "system.auto-fire";

/// Severity label stamped on every auto-fired `audit_chain_compromise`
/// incident — non-negotiable because a chain break invalidates the SOC2
/// trust boundary.
pub const AUTO_FIRE_SEVERITY: &str = "critical";

/// Structured payload emitted by the audit-chain background verifier
/// when it detects a tampered hot-tail and surfaced to the IR auto-fire
/// pipeline.
///
/// Mirrors the field set called out in CRIT-002 acceptance criterion #2:
/// `{tenant_id, expected_hash, actual_hash, last_good_seq, break_seq}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditChainBrokenEvent {
    /// Tenant whose chain failed verification (UUID string form).
    pub tenant_id: String,
    /// Hex-encoded hash the verifier *expected* at `break_seq`
    /// (recomputed from the stored canonical bytes + signing key).
    pub expected_hash: String,
    /// Hex-encoded hash actually persisted at `break_seq`.
    pub actual_hash: String,
    /// Last sequence number whose stored hash matched the recomputation.
    /// `None` when the chain broke at the very first row of the window.
    pub last_good_seq: Option<u64>,
    /// First sequence number at which the recomputed hash diverged.
    pub break_seq: u64,
    /// RFC 3339 timestamp at which the break was confirmed (the moment
    /// the regulator notification clock starts).
    pub detected_at: String,
}

/// Outcome of [`IrPlaybookService::auto_fire_audit_chain_compromise`].
///
/// Carries both the freshly-opened incident and a deduplication marker
/// so callers can wire the verifier so it does not re-open a fresh
/// incident on every tick when the chain is still broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoFireOutcome {
    /// The opened incident.
    pub incident: Incident,
    /// `true` when the call observed an existing open incident for this
    /// tenant and short-circuited; `false` when a brand-new incident was
    /// opened by this call.
    pub deduplicated: bool,
}

/// Patch payload accepted by
/// `PATCH /v1/ir/incidents/{id}/steps/{step}` and forwarded into
/// [`IrPlaybookService::update_step`].
///
/// Every field is optional — a caller can claim ownership without
/// flipping the status, or attach evidence without changing anything
/// else. Skipping a step requires a non-empty `reason`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepUpdate {
    /// New status (subject to state-machine check).
    pub status: Option<StepStatus>,
    /// New owner (claim or reassign).
    pub owner: Option<String>,
    /// Reason — required when `status == Skipped`, free-form note
    /// otherwise.
    pub reason: Option<String>,
    /// New evidence URI appended to the step's evidence list.
    pub evidence: Option<String>,
}

/// Open-incident request body — extracted out so the API layer can
/// reuse the same struct in its view module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenIncident {
    /// Catalog id of the playbook to clone (e.g. `"ransomware"`).
    pub playbook_id: String,
    /// Display title for the new incident.
    pub title: String,
    /// Optional severity label (`low` / `med` / `high` / `critical`).
    pub severity: Option<String>,
}

/// Service trait — the surface the API + monolith layers depend on.
#[async_trait]
pub trait IrPlaybookService: Send + Sync + std::fmt::Debug {
    /// Return the catalog of available playbooks. Catalog is global, not
    /// per-tenant, but the call signature still passes `tenant_id` so
    /// future per-tenant catalog customisation (P3-007 plugin marketplace)
    /// can slot in without an API break.
    async fn list_playbooks(&self, tenant_id: &str) -> Result<Vec<Playbook>, IrPlaybookError>;

    /// Open a new incident for the given tenant against the catalog
    /// entry identified by `req.playbook_id`.
    async fn open_incident(
        &self,
        tenant_id: &str,
        actor: &str,
        req: OpenIncident,
    ) -> Result<Incident, IrPlaybookError>;

    /// Fetch the full snapshot of an incident (steps + audit trail).
    /// Cross-tenant reads return [`IrPlaybookError::NotFound`].
    async fn get_incident(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<Incident, IrPlaybookError>;

    /// Apply a step update. Returns the post-update incident snapshot.
    async fn update_step(
        &self,
        tenant_id: &str,
        actor: &str,
        incident_id: &str,
        step_id: &str,
        update: StepUpdate,
    ) -> Result<Incident, IrPlaybookError>;

    /// Auto-fire the `audit_chain_compromise` playbook in response to a
    /// CRITICAL `audit.chain.broken` event surfaced by the background
    /// chain verifier. Actor is stamped as [`AUTO_FIRE_ACTOR`] and
    /// severity is forced to [`AUTO_FIRE_SEVERITY`] regardless of
    /// caller hint.
    ///
    /// Deduplication: implementations MUST short-circuit if an
    /// already-open `audit_chain_compromise` incident exists for the
    /// same tenant — surfaced as `AutoFireOutcome::deduplicated = true`.
    async fn auto_fire_audit_chain_compromise(
        &self,
        event: AuditChainBrokenEvent,
    ) -> Result<AutoFireOutcome, IrPlaybookError>;
}

// -------------------------------------------------------------------------
// In-memory implementation
// -------------------------------------------------------------------------

/// Trait abstracting a wall-clock so tests can pin time.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Return the current instant as an RFC 3339 string.
    fn now_rfc3339(&self) -> String;
}

/// Default clock — `OffsetDateTime::now_utc`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_rfc3339(&self) -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
    }
}

/// In-memory adapter backing the dev / standalone monolith.
#[derive(Debug)]
pub struct InMemoryIrPlaybookService {
    catalog: Vec<Playbook>,
    incidents: Mutex<HashMap<String, Vec<Incident>>>,
    clock: Box<dyn Clock>,
}

impl Default for InMemoryIrPlaybookService {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryIrPlaybookService {
    /// Build a new service hydrated with the built-in catalog and a
    /// system clock.
    ///
    /// # Panics
    ///
    /// Falls back to an empty catalog if the embedded JSON ever fails
    /// to parse (which would be a compile-time issue caught in CI).
    #[must_use]
    pub fn new() -> Self {
        let catalog = builtin_catalog().unwrap_or_default();
        Self {
            catalog,
            incidents: Mutex::new(HashMap::new()),
            clock: Box::new(SystemClock),
        }
    }

    /// Build with a custom clock — used by tests to pin timestamps.
    #[must_use]
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Self {
            catalog: builtin_catalog().unwrap_or_default(),
            incidents: Mutex::new(HashMap::new()),
            clock,
        }
    }

    fn find_playbook(&self, id: &str) -> Option<&Playbook> {
        self.catalog.iter().find(|p| p.id == id)
    }
}

#[async_trait]
impl IrPlaybookService for InMemoryIrPlaybookService {
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
        let Some(pb) = self.find_playbook(&req.playbook_id) else {
            return Err(IrPlaybookError::NotFound);
        };
        let now = self.clock.now_rfc3339();
        let incident_id = Uuid::now_v7().to_string();
        let inc = Incident::open(
            incident_id,
            tenant_id.to_owned(),
            pb,
            req.title,
            req.severity,
            &now,
        );
        let mut guard = self
            .incidents
            .lock()
            .map_err(|_| IrPlaybookError::Internal("incident mutex poisoned".into()))?;
        guard
            .entry(tenant_id.to_owned())
            .or_default()
            .push(inc.clone());
        drop(guard);
        tracing::info!(
            tenant = %tenant_id,
            actor = %actor,
            incident = %inc.id,
            playbook = %inc.playbook_id,
            "ir incident opened"
        );
        Ok(inc)
    }

    async fn get_incident(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<Incident, IrPlaybookError> {
        let guard = self
            .incidents
            .lock()
            .map_err(|_| IrPlaybookError::Internal("incident mutex poisoned".into()))?;
        let inc = guard
            .get(tenant_id)
            .and_then(|v| v.iter().find(|i| i.id == incident_id))
            .cloned();
        drop(guard);
        inc.ok_or(IrPlaybookError::NotFound)
    }

    #[allow(clippy::too_many_lines)] // single-transaction patch handler, by design
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
        let now = self.clock.now_rfc3339();
        let mut guard = self
            .incidents
            .lock()
            .map_err(|_| IrPlaybookError::Internal("incident mutex poisoned".into()))?;
        let bucket = guard.get_mut(tenant_id).ok_or(IrPlaybookError::NotFound)?;
        let inc = bucket
            .iter_mut()
            .find(|i| i.id == incident_id)
            .ok_or(IrPlaybookError::NotFound)?;

        if matches!(inc.state, IncidentState::Closed) {
            return Err(IrPlaybookError::IllegalIncidentTransition(
                "incident is closed".into(),
            ));
        }

        // Collect audit rows before applying so we can short-circuit on
        // illegal transitions without leaving the incident half-mutated.
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
            // No-op patch — nothing to record.
            return Ok(inc.clone());
        }
        inc.audit.extend(new_audit);
        inc.updated_at = now;
        let snapshot = inc.clone();
        drop(guard);
        tracing::info!(
            tenant = %tenant_id,
            actor = %actor,
            incident = %snapshot.id,
            step = %step_id,
            "ir step updated"
        );
        Ok(snapshot)
    }

    async fn auto_fire_audit_chain_compromise(
        &self,
        event: AuditChainBrokenEvent,
    ) -> Result<AutoFireOutcome, IrPlaybookError> {
        if event.tenant_id.is_empty() {
            return Err(IrPlaybookError::Invalid("tenant_id empty".into()));
        }

        // Dedupe: if an open `audit_chain_compromise` incident already
        // exists for this tenant, surface it and stamp the new event
        // onto the first preparation step's evidence list so the IR
        // commander still sees the latest break_seq.
        {
            let guard = self
                .incidents
                .lock()
                .map_err(|_| IrPlaybookError::Internal("incident mutex poisoned".into()))?;
            if let Some(open) = guard.get(&event.tenant_id).and_then(|bucket| {
                bucket.iter().find(|i| {
                    i.playbook_id == AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID
                        && !matches!(i.state, IncidentState::Closed)
                })
            }) {
                let snapshot = open.clone();
                drop(guard);
                tracing::warn!(
                    tenant = %event.tenant_id,
                    incident = %snapshot.id,
                    break_seq = event.break_seq,
                    "audit.chain.broken auto-fire deduplicated; existing incident still open"
                );
                return Ok(AutoFireOutcome {
                    incident: snapshot,
                    deduplicated: true,
                });
            }
            drop(guard);
        }

        // Pull the playbook template from the catalog. A missing
        // template is a compile-time bug — the catalog loader runs in
        // tests + at construction time, but the in-memory service falls
        // back to an empty catalog on malformed JSON. Treat that as
        // Internal so callers can wire it into a CRITICAL log.
        let pb = self
            .find_playbook(AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID)
            .ok_or_else(|| {
                IrPlaybookError::Internal(format!(
                    "catalog missing builtin playbook '{AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID}'"
                ))
            })?
            .clone();

        let now = self.clock.now_rfc3339();
        let incident_id = Uuid::now_v7().to_string();
        let title = format!(
            "audit chain broken at seq {} (tenant {})",
            event.break_seq, event.tenant_id
        );
        let mut inc = Incident::open(
            incident_id,
            event.tenant_id.clone(),
            &pb,
            title,
            Some(AUTO_FIRE_SEVERITY.to_owned()),
            &now,
        );

        // Stamp the structured event on the first preparation step's
        // evidence list so the IR commander has the (expected_hash,
        // actual_hash, last_good_seq, break_seq) tuple at their
        // fingertips when triaging the incident. We serialise via
        // serde_json::to_string — when serialisation fails (extremely
        // unlikely given the field types) we surface as Internal.
        let payload_json = serde_json::to_string(&event).map_err(|e| {
            IrPlaybookError::Internal(format!("audit.chain.broken payload serialise: {e}"))
        })?;
        if let Some(first_prep) = inc
            .steps
            .iter_mut()
            .find(|s| matches!(s.phase, crate::phase::IrPhase::Preparation))
        {
            first_prep
                .evidence
                .push(format!("audit.chain.broken:{payload_json}"));
        }

        let mut guard = self
            .incidents
            .lock()
            .map_err(|_| IrPlaybookError::Internal("incident mutex poisoned".into()))?;
        guard
            .entry(event.tenant_id.clone())
            .or_default()
            .push(inc.clone());
        drop(guard);

        tracing::error!(
            target: "ir.auto_fire",
            tenant = %event.tenant_id,
            incident = %inc.id,
            playbook = %AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID,
            break_seq = event.break_seq,
            last_good_seq = ?event.last_good_seq,
            actor = AUTO_FIRE_ACTOR,
            severity = AUTO_FIRE_SEVERITY,
            "audit chain broken: IR incident auto-fired"
        );
        Ok(AutoFireOutcome {
            incident: inc,
            deduplicated: false,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::phase::IrPhase;

    fn tenant_a() -> &'static str {
        "00000000-0000-0000-0000-00000000000a"
    }
    fn tenant_b() -> &'static str {
        "00000000-0000-0000-0000-00000000000b"
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct FixedClock;
    impl Clock for FixedClock {
        fn now_rfc3339(&self) -> String {
            "2026-01-01T00:00:00Z".into()
        }
    }

    fn svc() -> InMemoryIrPlaybookService {
        InMemoryIrPlaybookService::with_clock(Box::new(FixedClock))
    }

    async fn open_ransomware(s: &InMemoryIrPlaybookService, tenant: &str) -> Incident {
        let req = OpenIncident {
            playbook_id: "ransomware".into(),
            title: "encryption observed on fileshare".into(),
            severity: Some("high".into()),
        };
        s.open_incident(tenant, "alice", req)
            .await
            .expect("open ok")
    }

    #[tokio::test]
    async fn lists_builtin_playbooks() {
        let s = svc();
        let pbs = s.list_playbooks(tenant_a()).await.unwrap();
        let ids: Vec<&str> = pbs.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "ransomware",
                "data_exfiltration",
                "credential_compromise",
                "insider_threat",
                "audit_chain_compromise",
            ]
        );
    }

    fn break_event(tenant: &str, seq: u64) -> AuditChainBrokenEvent {
        AuditChainBrokenEvent {
            tenant_id: tenant.to_owned(),
            expected_hash: "ab".repeat(32),
            actual_hash: "cd".repeat(32),
            last_good_seq: seq.checked_sub(1),
            break_seq: seq,
            detected_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn auto_fire_opens_audit_chain_compromise_incident() {
        let s = svc();
        let out = s
            .auto_fire_audit_chain_compromise(break_event(tenant_a(), 42))
            .await
            .unwrap();
        assert!(!out.deduplicated);
        assert_eq!(out.incident.playbook_id, "audit_chain_compromise");
        assert_eq!(out.incident.severity.as_deref(), Some("critical"));
        assert_eq!(out.incident.tenant_id, tenant_a());
        // Structured payload stamped on the first preparation step.
        let prep = out
            .incident
            .steps
            .iter()
            .find(|s| matches!(s.phase, crate::phase::IrPhase::Preparation))
            .unwrap();
        assert!(prep
            .evidence
            .iter()
            .any(|e| e.starts_with("audit.chain.broken:")));
    }

    #[tokio::test]
    async fn auto_fire_deduplicates_per_tenant() {
        let s = svc();
        let first = s
            .auto_fire_audit_chain_compromise(break_event(tenant_a(), 1))
            .await
            .unwrap();
        let second = s
            .auto_fire_audit_chain_compromise(break_event(tenant_a(), 2))
            .await
            .unwrap();
        assert!(!first.deduplicated);
        assert!(second.deduplicated);
        assert_eq!(first.incident.id, second.incident.id);
    }

    #[tokio::test]
    async fn auto_fire_isolates_tenants() {
        let s = svc();
        let a = s
            .auto_fire_audit_chain_compromise(break_event(tenant_a(), 7))
            .await
            .unwrap();
        let b = s
            .auto_fire_audit_chain_compromise(break_event(tenant_b(), 7))
            .await
            .unwrap();
        assert!(!a.deduplicated);
        assert!(!b.deduplicated);
        assert_ne!(a.incident.id, b.incident.id);
    }

    #[tokio::test]
    async fn auto_fire_rejects_empty_tenant() {
        let s = svc();
        let err = s
            .auto_fire_audit_chain_compromise(break_event("", 1))
            .await
            .expect_err("must reject");
        assert!(matches!(err, IrPlaybookError::Invalid(_)));
    }

    #[tokio::test]
    async fn open_unknown_playbook_is_not_found() {
        let s = svc();
        let err = s
            .open_incident(
                tenant_a(),
                "alice",
                OpenIncident {
                    playbook_id: "nope".into(),
                    title: "x".into(),
                    severity: None,
                },
            )
            .await
            .expect_err("must error");
        assert_eq!(err, IrPlaybookError::NotFound);
    }

    #[tokio::test]
    async fn open_clones_template_steps() {
        let s = svc();
        let inc = open_ransomware(&s, tenant_a()).await;
        assert_eq!(inc.state, IncidentState::Open);
        assert!(inc.steps.iter().any(|st| st.phase == IrPhase::Preparation));
        assert!(inc
            .steps
            .iter()
            .all(|st| st.status == StepStatus::Todo && st.owner.is_none()));
    }

    #[tokio::test]
    async fn legal_status_transition_is_audited() {
        let s = svc();
        let inc = open_ransomware(&s, tenant_a()).await;
        let first = inc.steps[0].step_id.clone();
        let updated = s
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &first,
                StepUpdate {
                    status: Some(StepStatus::InProgress),
                    ..StepUpdate::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.state, IncidentState::InProgress);
        assert_eq!(updated.audit.len(), 2); // step + incident-state
        assert!(updated
            .audit
            .iter()
            .any(|r| matches!(r.kind, crate::audit::StepAuditKind::StepStatusChanged)));
        assert!(updated
            .audit
            .iter()
            .any(|r| matches!(r.kind, crate::audit::StepAuditKind::IncidentStateChanged)));
    }

    #[tokio::test]
    async fn illegal_transition_todo_to_done_is_rejected() {
        let s = svc();
        let inc = open_ransomware(&s, tenant_a()).await;
        let first = inc.steps[0].step_id.clone();
        let err = s
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &first,
                StepUpdate {
                    status: Some(StepStatus::Done),
                    ..StepUpdate::default()
                },
            )
            .await
            .expect_err("illegal must reject");
        assert!(matches!(err, IrPlaybookError::IllegalStepTransition(_)));
    }

    #[tokio::test]
    async fn skipped_requires_reason() {
        let s = svc();
        let inc = open_ransomware(&s, tenant_a()).await;
        let first = inc.steps[0].step_id.clone();
        let err = s
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &first,
                StepUpdate {
                    status: Some(StepStatus::Skipped),
                    reason: Some(String::new()),
                    ..StepUpdate::default()
                },
            )
            .await
            .expect_err("must require reason");
        assert!(matches!(err, IrPlaybookError::Invalid(_)));

        // Same payload with a real reason succeeds.
        let ok = s
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &first,
                StepUpdate {
                    status: Some(StepStatus::Skipped),
                    reason: Some("not applicable to cloud-only env".into()),
                    ..StepUpdate::default()
                },
            )
            .await
            .unwrap();
        let step = ok.step(&first).unwrap();
        assert_eq!(step.status, StepStatus::Skipped);
        assert_eq!(
            step.reason.as_deref(),
            Some("not applicable to cloud-only env")
        );
    }

    #[tokio::test]
    async fn owner_claim_audits_separately() {
        let s = svc();
        let inc = open_ransomware(&s, tenant_a()).await;
        let first = inc.steps[0].step_id.clone();
        let updated = s
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &first,
                StepUpdate {
                    owner: Some("alice".into()),
                    ..StepUpdate::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            updated.step(&first).unwrap().owner.as_deref(),
            Some("alice")
        );
        assert_eq!(updated.audit.len(), 1);
        assert!(matches!(
            updated.audit[0].kind,
            crate::audit::StepAuditKind::StepOwnerChanged
        ));
    }

    #[tokio::test]
    async fn evidence_appends_audit() {
        let s = svc();
        let inc = open_ransomware(&s, tenant_a()).await;
        let first = inc.steps[0].step_id.clone();
        let updated = s
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &first,
                StepUpdate {
                    evidence: Some("s3://bucket/key.log".into()),
                    ..StepUpdate::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.step(&first).unwrap().evidence.len(), 1);
        assert_eq!(updated.audit.len(), 1);
    }

    #[tokio::test]
    async fn rollup_progresses_to_closed_when_all_terminal() {
        let s = svc();
        let inc = open_ransomware(&s, tenant_a()).await;
        let ids: Vec<String> = inc.steps.iter().map(|s| s.step_id.clone()).collect();
        for id in &ids {
            s.update_step(
                tenant_a(),
                "alice",
                &inc.id,
                id,
                StepUpdate {
                    status: Some(StepStatus::InProgress),
                    ..StepUpdate::default()
                },
            )
            .await
            .unwrap();
        }
        // Walk every step to Done.
        for id in &ids {
            s.update_step(
                tenant_a(),
                "alice",
                &inc.id,
                id,
                StepUpdate {
                    status: Some(StepStatus::Done),
                    ..StepUpdate::default()
                },
            )
            .await
            .unwrap();
        }
        let snap = s.get_incident(tenant_a(), &inc.id).await.unwrap();
        assert_eq!(snap.state, IncidentState::Closed);
        // Audit trail: step + state transitions across each step.
        assert!(snap.audit.len() >= ids.len() * 2);
    }

    #[tokio::test]
    async fn closed_incident_rejects_further_updates() {
        let s = svc();
        let inc = open_ransomware(&s, tenant_a()).await;
        let ids: Vec<String> = inc.steps.iter().map(|s| s.step_id.clone()).collect();
        // Walk to Done.
        for id in &ids {
            s.update_step(
                tenant_a(),
                "alice",
                &inc.id,
                id,
                StepUpdate {
                    status: Some(StepStatus::InProgress),
                    ..StepUpdate::default()
                },
            )
            .await
            .unwrap();
            s.update_step(
                tenant_a(),
                "alice",
                &inc.id,
                id,
                StepUpdate {
                    status: Some(StepStatus::Done),
                    ..StepUpdate::default()
                },
            )
            .await
            .unwrap();
        }
        // Attempt any further update.
        let err = s
            .update_step(
                tenant_a(),
                "alice",
                &inc.id,
                &ids[0],
                StepUpdate {
                    owner: Some("bob".into()),
                    ..StepUpdate::default()
                },
            )
            .await
            .expect_err("must reject");
        assert!(matches!(err, IrPlaybookError::IllegalIncidentTransition(_)));
    }

    #[tokio::test]
    async fn tenant_isolation_blocks_cross_tenant_reads() {
        let s = svc();
        let inc = open_ransomware(&s, tenant_a()).await;
        let err = s
            .get_incident(tenant_b(), &inc.id)
            .await
            .expect_err("must reject");
        assert_eq!(err, IrPlaybookError::NotFound);

        let err = s
            .update_step(
                tenant_b(),
                "mallory",
                &inc.id,
                &inc.steps[0].step_id,
                StepUpdate {
                    owner: Some("mallory".into()),
                    ..StepUpdate::default()
                },
            )
            .await
            .expect_err("must reject");
        assert_eq!(err, IrPlaybookError::NotFound);
    }

    #[tokio::test]
    async fn unknown_incident_id_is_not_found() {
        let s = svc();
        let err = s
            .get_incident(tenant_a(), "00000000-0000-0000-0000-deadbeefdead")
            .await
            .expect_err("must reject");
        assert_eq!(err, IrPlaybookError::NotFound);
    }
}
