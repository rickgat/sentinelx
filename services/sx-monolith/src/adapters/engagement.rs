//! Engagement + kill-switch adapter.
//!
//! Wires `sx-engagement`'s real use cases behind the `sx-api` ports:
//! - [`EngagementServicePort`] is fronted by [`CreateEngagementUseCase`]
//!   and an in-memory [`EngagementRepository`].
//! - [`KillSwitchPort`] wraps the real [`InMemoryKillSwitch`] so triggering
//!   the switch from the API and querying it both hit the same instance.
//!
//! ## Repository visibility
//!
//! [`EngagementBundle`] now also exposes the underlying
//! [`InMemoryEngagementRepository`] as `repo` so that sibling adapters
//! (currently: the discovery adapter) can look up engagements by id without
//! routing through the API-level service port.
//!
//! ### Why expose the in-memory repo specifically?
//!
//! The Postgres `EngagementRepository` impl is not yet wired into the
//! monolith — the in-memory store is the source of truth for Phase 1.5
//! development. Once `postgres::build` returns an
//! `Arc<dyn EngagementRepository>` of its own, the composition root will
//! swap it in and pass it everywhere the in-memory one is used today.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sx_api::port::{
    EngagementPortError, EngagementServicePort, EngagementTransitionPort, KillSwitchPort,
    KillSwitchTrigger,
};
use sx_api::view::engagement_view::{CreateEngagementView, EngagementView, UpdateEngagementView};
use sx_core::value_object::ids::{EngagementId, TenantId};
use sx_engagement::controller::create_engagement::CreateEngagementUseCase;
use sx_engagement::controller::trigger_kill_switch::TriggerKillSwitchUseCase;
use sx_engagement::model::engagement::{Engagement, EngagementStatus};
use sx_engagement::model::intensity::ScanIntensity;
use sx_engagement::model::scope_target::ScopeTarget;
use sx_engagement::port::EngagementRepository;
use sx_engagement::service::clock::SystemClock;
use sx_engagement::service::kill_switch::{
    InMemoryKillSwitch, KillReason, KillSwitch, KillSwitchScope,
};
use sx_engagement::view::CreateEngagementRequest;
use sx_engagement::EngagementError;
use time::OffsetDateTime;

/// Bundle of ready-to-plug-in engagement trait objects.
pub(crate) struct EngagementBundle {
    /// `sx-api`-facing engagement service.
    pub service: Arc<dyn EngagementServicePort>,
    /// `sx-api`-facing engagement state-transition port (pause / resume /
    /// abort / complete).
    pub transitions: Arc<dyn EngagementTransitionPort>,
    /// `sx-api`-facing kill-switch port.
    pub kill_switch: Arc<dyn KillSwitchPort>,
    /// Shared handle to the in-memory engagement repository. Exposed so
    /// other adapters (e.g. discovery) can `find_by_id` engagements without
    /// going through [`EngagementServicePort`].
    pub repo: Arc<dyn EngagementRepository>,
    /// Shared handle to the kill switch driving the bundle. Re-exposed so
    /// the discovery adapter wires the *same* switch the API trips.
    pub kill_switch_concrete: Arc<dyn KillSwitch>,
}

/// Build the engagement bundle. The repository is process-local; the kill
/// switch may be Redis-backed when `external_kill_switch` is `Some`,
/// otherwise an in-process [`InMemoryKillSwitch`] is used.
pub(crate) fn build(
    external_kill_switch: Option<Arc<dyn KillSwitch>>,
    repo: Arc<dyn EngagementRepository>,
) -> EngagementBundle {
    let clock = Arc::new(SystemClock);
    let create_uc = Arc::new(CreateEngagementUseCase::new(
        Arc::clone(&repo),
        Arc::clone(&clock) as Arc<dyn sx_engagement::service::clock::Clock>,
    ));
    let kill_switch: Arc<dyn KillSwitch> = external_kill_switch
        .unwrap_or_else(|| Arc::new(InMemoryKillSwitch::new()) as Arc<dyn KillSwitch>);
    let trigger_uc = Arc::new(TriggerKillSwitchUseCase::new(Arc::clone(&kill_switch)));

    let transitions: Arc<dyn EngagementTransitionPort> = Arc::new(EngagementTransitionAdapter {
        repo: Arc::clone(&repo),
    });

    EngagementBundle {
        service: Arc::new(EngagementAdapter {
            create_uc,
            repo: Arc::clone(&repo),
        }),
        transitions,
        kill_switch: Arc::new(KillSwitchAdapter {
            trigger: trigger_uc,
            inner: Arc::clone(&kill_switch),
        }),
        repo: Arc::clone(&repo),
        kill_switch_concrete: kill_switch,
    }
}

// ----- EngagementServicePort impl ----------------------------------------

struct EngagementAdapter {
    create_uc: Arc<CreateEngagementUseCase>,
    repo: Arc<dyn EngagementRepository>,
}

#[async_trait]
impl EngagementServicePort for EngagementAdapter {
    async fn create(
        &self,
        tenant_id: &str,
        req: CreateEngagementView,
    ) -> Result<EngagementView, EngagementPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let scope = parse_scope(&req.scopes)?;
        if scope.is_empty() {
            return Err(EngagementPortError::Invalid("scope is empty".into()));
        }
        let now = OffsetDateTime::now_utc();
        // Default window: now → +24h. The View has no window field today; the
        // request body schema in Phase 1.5 will carry explicit dates.
        let window_end = now + Duration::from_secs(60 * 60 * 24);

        let request = CreateEngagementRequest {
            tenant_id: tenant,
            name: req.name,
            scope,
            window_start: now,
            window_end,
            max_intensity: ScanIntensity::PassiveValidation,
        };
        let resp = self.create_uc.execute(request).await.map_err(domain_err)?;
        let engagement = self
            .repo
            .find_by_id(tenant, resp.engagement_id)
            .await
            .map_err(|e| EngagementPortError::Internal(e.to_string()))?
            .ok_or_else(|| {
                EngagementPortError::Internal("engagement disappeared after create".into())
            })?;
        Ok(to_view(&engagement, req.description))
    }

    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<EngagementView>, EngagementPortError> {
        let tenant = parse_tenant(tenant_id)?;
        Ok(self
            .repo
            .list(tenant, offset, limit)
            .await
            .map_err(|e| EngagementPortError::Internal(e.to_string()))?
            .into_iter()
            .map(|e| to_view(&e, None))
            .collect())
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<EngagementView, EngagementPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let eid = parse_engagement_id(id)?;
        let maybe = self
            .repo
            .find_by_id(tenant, eid)
            .await
            .map_err(|e| EngagementPortError::Internal(e.to_string()))?;
        maybe
            .map(|e| to_view(&e, None))
            .ok_or(EngagementPortError::NotFound)
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: &str,
        _req: UpdateEngagementView,
    ) -> Result<EngagementView, EngagementPortError> {
        // Phase 1.5 will expose status transition + name patch use cases.
        let tenant = parse_tenant(tenant_id)?;
        let eid = parse_engagement_id(id)?;
        self.repo
            .find_by_id(tenant, eid)
            .await
            .map_err(|e| EngagementPortError::Internal(e.to_string()))?
            .map(|e| to_view(&e, None))
            .ok_or(EngagementPortError::NotFound)
    }
}

// ----- KillSwitchPort impl ------------------------------------------------

struct KillSwitchAdapter {
    trigger: Arc<TriggerKillSwitchUseCase>,
    inner: Arc<dyn KillSwitch>,
}

#[async_trait]
impl KillSwitchPort for KillSwitchAdapter {
    async fn trip(&self, _trigger: KillSwitchTrigger) -> Result<(), EngagementPortError> {
        self.trigger
            .execute(KillSwitchScope::Global, KillReason::Manual)
            .await
            .map_err(domain_err)
    }

    async fn is_tripped(&self) -> Result<bool, EngagementPortError> {
        self.inner
            .is_tripped(KillSwitchScope::Global)
            .await
            .map_err(domain_err)
    }
}

// ----- EngagementTransitionPort impl --------------------------------------

/// Drives the four operator-triggered FSM transitions
/// (`pause` / `resume` / `abort` / `complete`) over the in-memory engagement
/// store.
///
/// The adapter reads the live aggregate, applies
/// [`Engagement::transition_to`], and persists the result. Illegal edges
/// surface from the domain as
/// [`EngagementError::InvalidStateTransition`] which this adapter maps onto
/// [`EngagementPortError::Forbidden`] — the HTTP layer renders that as
/// `403 Forbidden`.
struct EngagementTransitionAdapter {
    repo: Arc<dyn EngagementRepository>,
}

impl EngagementTransitionAdapter {
    /// Shared transition driver: load the engagement, attempt the FSM edge,
    /// persist, return the projection.
    async fn run_transition(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        target: EngagementStatus,
    ) -> Result<EngagementView, EngagementPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let eid = parse_engagement_id(engagement_id)?;
        let mut engagement = self
            .repo
            .find_by_id(tenant, eid)
            .await
            .map_err(domain_err)?
            .ok_or(EngagementPortError::NotFound)?;
        let now = OffsetDateTime::now_utc();
        engagement
            .transition_to(target, now)
            .map_err(transition_err)?;
        self.repo.update(&engagement).await.map_err(domain_err)?;
        Ok(to_view(&engagement, None))
    }
}

#[async_trait]
impl EngagementTransitionPort for EngagementTransitionAdapter {
    async fn activate(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<EngagementView, EngagementPortError> {
        // The domain FSM allows Draft → Active (the "start" operation).
        // Unlike `resume` we do NOT require a prior Paused state; the raw
        // `transition_to` rejects any other source edge as
        // `InvalidStateTransition` → 403.
        self.run_transition(tenant_id, engagement_id, EngagementStatus::Active)
            .await
    }

    async fn pause(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<EngagementView, EngagementPortError> {
        self.run_transition(tenant_id, engagement_id, EngagementStatus::Paused)
            .await
    }

    async fn resume(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<EngagementView, EngagementPortError> {
        // The domain FSM allows both Draft → Active (the "start"
        // operation) and Paused → Active (the "resume" operation). For
        // the resume port we tighten this — only a previously-paused
        // engagement may be resumed; starting a Draft engagement is a
        // distinct operation handled by its own controller.
        let tenant = parse_tenant(tenant_id)?;
        let eid = parse_engagement_id(engagement_id)?;
        let current = self
            .repo
            .find_by_id(tenant, eid)
            .await
            .map_err(domain_err)?
            .ok_or(EngagementPortError::NotFound)?;
        if current.status != EngagementStatus::Paused {
            return Err(EngagementPortError::Forbidden);
        }
        self.run_transition(tenant_id, engagement_id, EngagementStatus::Active)
            .await
    }

    async fn abort(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        reason: &str,
    ) -> Result<EngagementView, EngagementPortError> {
        // The reason is forwarded for auditing only. The HTTP surface
        // already enforced `1..=2000` chars via `EngagementAbortRequest`,
        // but we defend in depth in case a future caller bypasses the
        // controller (e.g. a sibling adapter calling this port directly).
        let trimmed = reason.trim();
        if trimmed.is_empty() {
            return Err(EngagementPortError::Invalid(
                "abort reason must not be empty".into(),
            ));
        }
        if trimmed.len() > 2_000 {
            return Err(EngagementPortError::Invalid(
                "abort reason exceeds 2000 chars".into(),
            ));
        }
        // Phase 1.5: the in-memory engagement aggregate has no audit field
        // for the reason yet; record it on the tracing span so the operator
        // can correlate the abort with the audit pipeline once it lands.
        tracing::info!(
            tenant_id = %tenant_id,
            engagement_id = %engagement_id,
            reason_chars = trimmed.len(),
            "engagement abort requested"
        );
        self.run_transition(tenant_id, engagement_id, EngagementStatus::Aborted)
            .await
    }

    async fn complete(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<EngagementView, EngagementPortError> {
        self.run_transition(tenant_id, engagement_id, EngagementStatus::Completed)
            .await
    }
}

/// Map domain errors raised during a transition.
///
/// `InvalidStateTransition` is the FSM-violation signal — surface it as
/// [`EngagementPortError::Forbidden`] so the HTTP layer renders `403`.
fn transition_err(e: EngagementError) -> EngagementPortError {
    match e {
        EngagementError::InvalidStateTransition { from, to } => {
            // The port's `Forbidden` variant does not carry a payload, so
            // we surface the detail via `Conflict` semantics in logs but
            // still map onto `Forbidden` per the spec ("State-machine
            // violations → 403 Forbidden with descriptive message"). The
            // descriptive message lives on the tracing span.
            tracing::warn!(
                from = %from,
                to = %to,
                "engagement state-machine transition rejected"
            );
            EngagementPortError::Forbidden
        }
        other => domain_err(other),
    }
}

// ----- In-memory EngagementRepository ------------------------------------

#[derive(Debug, Default)]
pub(crate) struct InMemoryEngagementRepository {
    rows: Mutex<HashMap<(TenantId, EngagementId), Engagement>>,
}

impl InMemoryEngagementRepository {
    pub(crate) fn list(&self, tenant: TenantId, offset: u64, limit: u32) -> Vec<Engagement> {
        let Ok(g) = self.rows.lock() else {
            return Vec::new();
        };
        g.iter()
            .filter(|((t, _), _)| *t == tenant)
            .map(|(_, e)| e.clone())
            .skip(offset as usize)
            .take(limit as usize)
            .collect()
    }

    /// Insert a pre-built [`Engagement`] directly into the store. Used by
    /// the demo seeder (`adapters::seed`) at startup. Silently no-ops if
    /// the mutex is poisoned — see [`crate::adapters::repository::InMemoryAssets::seed_one`]
    /// for the rationale.
    pub(crate) fn seed_one(&self, engagement: Engagement) {
        if let Ok(mut g) = self.rows.lock() {
            g.insert((engagement.tenant_id, engagement.id), engagement);
        }
    }

    /// Emptiness probe used by the demo-seed gate in
    /// [`crate::adapters::build_app_state`]. Returns `true` when the
    /// repository holds zero engagement rows across all tenants. A
    /// poisoned mutex is treated as "non-empty" so the gate fails closed
    /// — re-running the seeder against an unknown state would be worse
    /// than skipping it.
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.lock().is_ok_and(|g| g.is_empty())
    }
}

#[async_trait]
impl EngagementRepository for InMemoryEngagementRepository {
    async fn create(&self, engagement: &Engagement) -> Result<(), EngagementError> {
        let mut g = self
            .rows
            .lock()
            .map_err(|_| EngagementError::internal("repo poisoned"))?;
        g.insert((engagement.tenant_id, engagement.id), engagement.clone());
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: EngagementId,
    ) -> Result<Option<Engagement>, EngagementError> {
        let g = self
            .rows
            .lock()
            .map_err(|_| EngagementError::internal("repo poisoned"))?;
        Ok(g.get(&(tenant_id, id)).cloned())
    }

    async fn update(&self, engagement: &Engagement) -> Result<(), EngagementError> {
        let mut g = self
            .rows
            .lock()
            .map_err(|_| EngagementError::internal("repo poisoned"))?;
        if g.contains_key(&(engagement.tenant_id, engagement.id)) {
            g.insert((engagement.tenant_id, engagement.id), engagement.clone());
            Ok(())
        } else {
            Err(EngagementError::Repository("not found".into()))
        }
    }

    async fn list(
        &self,
        tenant_id: TenantId,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<Engagement>, EngagementError> {
        // Inherent `list` (Vec) shadows the trait method here, so this is
        // not recursive.
        Ok(self.list(tenant_id, offset, limit))
    }
}

// ----- Conversion helpers -------------------------------------------------

fn parse_tenant(s: &str) -> Result<TenantId, EngagementPortError> {
    let id = uuid::Uuid::from_str(s)
        .map_err(|_| EngagementPortError::Invalid("invalid tenant id".into()))?;
    Ok(TenantId::from_uuid(id))
}

fn parse_engagement_id(s: &str) -> Result<EngagementId, EngagementPortError> {
    let id = uuid::Uuid::from_str(s)
        .map_err(|_| EngagementPortError::Invalid("invalid engagement id".into()))?;
    Ok(EngagementId::from_uuid(id))
}

fn parse_scope(scopes: &[String]) -> Result<Vec<ScopeTarget>, EngagementPortError> {
    let mut out = Vec::with_capacity(scopes.len());
    for s in scopes {
        let target = if let Ok(net) = s.parse::<ipnet::IpNet>() {
            ScopeTarget::Cidr(net)
        } else if let Ok(url) = url::Url::parse(s) {
            ScopeTarget::Url(url)
        } else {
            ScopeTarget::Domain(s.clone())
        };
        out.push(target);
    }
    Ok(out)
}

fn to_view(e: &Engagement, description: Option<String>) -> EngagementView {
    EngagementView {
        id: e.id.to_string(),
        tenant_id: e.tenant_id.to_string(),
        name: e.name.clone(),
        description,
        scopes: e.scope.iter().map(scope_to_string).collect(),
        status: status_to_string(e.status).to_owned(),
        created_at: e.created_at.to_string(),
        updated_at: e.updated_at.to_string(),
    }
}

fn scope_to_string(t: &ScopeTarget) -> String {
    match t {
        ScopeTarget::Cidr(net) => net.to_string(),
        ScopeTarget::IpV4(ip) => ip.to_string(),
        ScopeTarget::IpV6(ip) => ip.to_string(),
        ScopeTarget::Domain(d) => d.clone(),
        ScopeTarget::Url(u) => u.to_string(),
        ScopeTarget::Arn(a) | ScopeTarget::RepoUrl(a) => a.clone(),
    }
}

const fn status_to_string(s: EngagementStatus) -> &'static str {
    match s {
        EngagementStatus::Draft => "draft",
        EngagementStatus::Active => "active",
        EngagementStatus::Paused => "paused",
        EngagementStatus::Completed => "completed",
        EngagementStatus::Aborted => "aborted",
    }
}

fn domain_err(e: EngagementError) -> EngagementPortError {
    match e {
        EngagementError::InvalidInput(m) => EngagementPortError::Invalid(m),
        EngagementError::Repository(m) => EngagementPortError::Dependency(m),
        EngagementError::Internal(m) => EngagementPortError::Internal(m),
        other => EngagementPortError::Internal(other.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_engagement::model::window::TimeWindow;

    fn fixed_tenant() -> TenantId {
        TenantId::from_uuid(uuid::Uuid::parse_str("01010101-0101-0101-0101-010101010101").unwrap())
    }

    fn fixed_engagement_id() -> EngagementId {
        EngagementId::from_uuid(
            uuid::Uuid::parse_str("e0000001-0000-0000-0000-000000000000").unwrap(),
        )
    }

    fn sample_engagement() -> Engagement {
        let now = OffsetDateTime::UNIX_EPOCH;
        let window = TimeWindow::new(now, now + time::Duration::hours(2)).unwrap();
        Engagement::new_draft(
            fixed_engagement_id(),
            fixed_tenant(),
            "Seeded Pentest",
            vec![ScopeTarget::Domain("example.com".into())],
            window,
            ScanIntensity::SafeInteractive,
            now,
        )
        .unwrap()
    }

    #[test]
    fn inmemory_engagement_seed_one_appears_in_list() {
        let repo = InMemoryEngagementRepository::default();
        repo.seed_one(sample_engagement());
        let items = repo.list(fixed_tenant(), 0, 100);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, fixed_engagement_id());
        assert_eq!(items[0].name, "Seeded Pentest");
    }

    /// SX-REVIEW-002 / M2 — the demo-seed gate in
    /// [`crate::adapters::build_app_state`] uses `is_empty()` to decide
    /// whether to call `seed::run`. A fresh repository must report
    /// empty so the gate proceeds; once `seed_one` lands a row it
    /// must report non-empty so a second boot is a no-op. This test
    /// pins both halves of that contract.
    #[test]
    fn is_empty_flips_after_seed_one() {
        let repo = InMemoryEngagementRepository::default();
        assert!(
            repo.is_empty(),
            "fresh InMemoryEngagementRepository must report empty so \
             the demo seed gate proceeds on first boot",
        );
        repo.seed_one(sample_engagement());
        assert!(
            !repo.is_empty(),
            "after a single seed_one the repository must report \
             non-empty so the demo seed gate short-circuits on \
             subsequent boots",
        );
    }

    // -----------------------------------------------------------------
    // EngagementTransitionAdapter — state-machine matrix
    //
    // We exercise each starting state (Draft, Active, Paused, Completed,
    // Aborted) against each operator transition (pause / resume / abort /
    // complete). Valid edges return `EngagementView`; invalid edges
    // surface as `EngagementPortError::Forbidden`.
    // -----------------------------------------------------------------

    /// Construct an [`EngagementTransitionAdapter`] backed by an in-memory
    /// repo containing a single engagement pinned to the given starting
    /// status.
    fn adapter_at(status: EngagementStatus) -> (EngagementTransitionAdapter, String, String) {
        let repo = Arc::new(InMemoryEngagementRepository::default());
        let mut e = sample_engagement();
        // Mutate the status field on the aggregate without going through
        // `transition_to` — we want a seeded fixture, not a domain event.
        e.status = status;
        repo.seed_one(e);
        let adapter = EngagementTransitionAdapter {
            repo: Arc::clone(&repo) as Arc<dyn EngagementRepository>,
        };
        (
            adapter,
            fixed_tenant().to_string(),
            fixed_engagement_id().to_string(),
        )
    }

    #[tokio::test]
    async fn pause_from_active_succeeds() {
        let (adapter, tenant, id) = adapter_at(EngagementStatus::Active);
        let view = adapter.pause(&tenant, &id).await.expect("pause active");
        assert_eq!(view.status, "paused");
    }

    #[tokio::test]
    async fn pause_from_draft_is_forbidden() {
        let (adapter, tenant, id) = adapter_at(EngagementStatus::Draft);
        let err = adapter.pause(&tenant, &id).await.unwrap_err();
        assert!(matches!(err, EngagementPortError::Forbidden));
    }

    #[tokio::test]
    async fn pause_from_paused_is_forbidden() {
        let (adapter, tenant, id) = adapter_at(EngagementStatus::Paused);
        assert!(matches!(
            adapter.pause(&tenant, &id).await.unwrap_err(),
            EngagementPortError::Forbidden
        ));
    }

    #[tokio::test]
    async fn pause_from_terminal_states_is_forbidden() {
        for s in [EngagementStatus::Completed, EngagementStatus::Aborted] {
            let (adapter, tenant, id) = adapter_at(s);
            assert!(matches!(
                adapter.pause(&tenant, &id).await.unwrap_err(),
                EngagementPortError::Forbidden
            ));
        }
    }

    #[tokio::test]
    async fn resume_from_paused_succeeds() {
        let (adapter, tenant, id) = adapter_at(EngagementStatus::Paused);
        let view = adapter.resume(&tenant, &id).await.expect("resume paused");
        assert_eq!(view.status, "active");
    }

    #[tokio::test]
    async fn resume_from_non_paused_is_forbidden() {
        for s in [
            EngagementStatus::Draft,
            EngagementStatus::Active,
            EngagementStatus::Completed,
            EngagementStatus::Aborted,
        ] {
            let (adapter, tenant, id) = adapter_at(s);
            assert!(matches!(
                adapter.resume(&tenant, &id).await.unwrap_err(),
                EngagementPortError::Forbidden
            ));
        }
    }

    #[tokio::test]
    async fn complete_from_active_succeeds() {
        let (adapter, tenant, id) = adapter_at(EngagementStatus::Active);
        let view = adapter.complete(&tenant, &id).await.expect("complete");
        assert_eq!(view.status, "completed");
    }

    #[tokio::test]
    async fn complete_from_non_active_is_forbidden() {
        for s in [
            EngagementStatus::Draft,
            EngagementStatus::Paused,
            EngagementStatus::Completed,
            EngagementStatus::Aborted,
        ] {
            let (adapter, tenant, id) = adapter_at(s);
            assert!(matches!(
                adapter.complete(&tenant, &id).await.unwrap_err(),
                EngagementPortError::Forbidden
            ));
        }
    }

    #[tokio::test]
    async fn abort_from_draft_active_paused_succeeds() {
        for s in [
            EngagementStatus::Draft,
            EngagementStatus::Active,
            EngagementStatus::Paused,
        ] {
            let (adapter, tenant, id) = adapter_at(s);
            let view = adapter
                .abort(&tenant, &id, "kill it")
                .await
                .expect("abort allowed");
            assert_eq!(view.status, "aborted");
        }
    }

    #[tokio::test]
    async fn abort_from_terminal_states_is_forbidden() {
        for s in [EngagementStatus::Completed, EngagementStatus::Aborted] {
            let (adapter, tenant, id) = adapter_at(s);
            assert!(matches!(
                adapter.abort(&tenant, &id, "x").await.unwrap_err(),
                EngagementPortError::Forbidden
            ));
        }
    }

    #[tokio::test]
    async fn abort_rejects_empty_reason() {
        let (adapter, tenant, id) = adapter_at(EngagementStatus::Active);
        let err = adapter.abort(&tenant, &id, "   ").await.unwrap_err();
        assert!(matches!(err, EngagementPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn abort_rejects_overlong_reason() {
        let (adapter, tenant, id) = adapter_at(EngagementStatus::Active);
        let big = "x".repeat(2_001);
        let err = adapter.abort(&tenant, &id, &big).await.unwrap_err();
        assert!(matches!(err, EngagementPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn transitions_against_missing_engagement_are_not_found() {
        let repo = Arc::new(InMemoryEngagementRepository::default());
        let adapter = EngagementTransitionAdapter {
            repo: Arc::clone(&repo) as Arc<dyn EngagementRepository>,
        };
        let tenant = fixed_tenant().to_string();
        let id = fixed_engagement_id().to_string();
        assert!(matches!(
            adapter.pause(&tenant, &id).await.unwrap_err(),
            EngagementPortError::NotFound
        ));
        assert!(matches!(
            adapter.resume(&tenant, &id).await.unwrap_err(),
            EngagementPortError::NotFound
        ));
        assert!(matches!(
            adapter.complete(&tenant, &id).await.unwrap_err(),
            EngagementPortError::NotFound
        ));
        assert!(matches!(
            adapter.abort(&tenant, &id, "r").await.unwrap_err(),
            EngagementPortError::NotFound
        ));
    }

    #[tokio::test]
    async fn invalid_uuid_tenant_is_invalid() {
        let (adapter, _, id) = adapter_at(EngagementStatus::Active);
        let err = adapter.pause("not-a-uuid", &id).await.unwrap_err();
        assert!(matches!(err, EngagementPortError::Invalid(_)));
    }
}
