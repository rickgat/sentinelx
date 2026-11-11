#![allow(dead_code)] // Wired into AppState by the reconcile pass; see module RECONCILE notes.
//! Cyber-digital-twin adapter.
//!
//! Owns the per-`(tenant, engagement)` in-memory [`sx_twin::Twin`] store
//! that backs the [`TwinPort`] trait declared in
//! `sx-api`. The HTTP surface never sees a `Twin` directly — it goes
//! through this adapter, which:
//!
//! 1. Looks up the requested engagement's twin under a `Mutex` guard.
//! 2. Projects the [`sx_twin::Twin`] into a wire-friendly
//!    [`TwinStateView`] (string-typed asset uuids + lowercase enum
//!    labels).
//! 3. Returns an **empty** [`TwinStateView`] when no twin has been seeded
//!    yet — the read endpoint is allowed to be called before any
//!    discovery / BAS run has populated the twin (a `404` would force the
//!    UI to special-case unseeded engagements for no reason).
//!
//! ## Seeding strategy ([`TwinBundle::seed_from_findings`])
//!
//! The adapter exposes a synchronous helper that synthesises a twin from
//! the existing assets+findings repositories already wired into the
//! monolith. The rules are intentionally simple — no graph topology is
//! invented; the twin starts as a node-set with the right risk markers:
//!
//! - **Assets**: every [`AssetView`] in `tenant_id` whose `engagement_id`
//!   matches becomes a [`sx_twin::state::AssetState`]. The asset's
//!   uuid is preserved via [`sx_twin::state::AssetId::from_uuid`] so the
//!   twin and the production repositories share id space. The
//!   AssetView's free-form `kind` string is mapped onto the closed
//!   [`sx_twin::state::AssetKind`] enum via [`map_asset_kind`].
//! - **Suspected markers**: every [`FindingView`] in the same tenant with
//!   `severity ∈ {high, critical}` marks its target asset as
//!   [`CompromiseState::Suspected`]. `Suspected` is **not** the same as
//!   `Compromised` — the seed never moves an asset directly into the
//!   compromised set; that transition is reserved for the tick
//!   simulator.
//! - **Edges**: the seed does not synthesise edges. Edge discovery
//!   belongs to `sx-graph`'s knowledge graph and is wired through a
//!   separate Phase-3.5+ pass.
//!
//! The seed is **idempotent**: calling [`TwinBundle::seed_from_findings`]
//! twice for the same `(tenant, engagement)` replaces the prior twin
//! wholesale.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sx_api::port::{AssetRepositoryPort, FindingRepositoryPort, Phase3PortError, TwinPort};
use sx_api::view::asset_view::AssetView;
use sx_api::view::twin_view::{TwinAssetView, TwinEdgeView, TwinStateView};
use sx_core::value_object::ids::{EngagementId, TenantId};
use sx_twin::state::{AssetId, AssetKind, AssetState, CompromiseState};
use sx_twin::twin::Twin;
use tracing::info;
use uuid::Uuid;

/// Maximum page size used when paging through the upstream asset /
/// finding repositories during a seed. Picked to match the existing
/// monolith adapters (see [`super::phase3::ReportAdapter`]).
const SEED_PAGE_LIMIT: u32 = 200;

/// Bundle returned by [`build`].
pub(crate) struct TwinBundle {
    /// Trait-object façade plumbed into `AppState`.
    pub twin: Arc<dyn TwinPort>,
    /// Concrete handle retained so the composition root can call
    /// [`TwinAdapter::seed_from_findings`] for in-memory demo flows.
    pub adapter: Arc<TwinAdapter>,
}

impl TwinBundle {
    /// Synthesise a [`Twin`] from the in-process asset + finding
    /// repositories and store it under `(tenant_id, engagement_id)`.
    ///
    /// This is a thin convenience wrapper over
    /// [`TwinAdapter::seed_from_findings`] so callers do not have to
    /// reach through the bundle's `adapter` field.
    pub(crate) async fn seed_from_findings(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        assets: &Arc<dyn AssetRepositoryPort>,
        findings: &Arc<dyn FindingRepositoryPort>,
    ) -> Result<usize, Phase3PortError> {
        self.adapter
            .seed_from_findings(tenant_id, engagement_id, assets, findings)
            .await
    }
}

/// Construct an empty store with no seeded twins.
#[allow(dead_code)] // wired into AppState by the next-turn reconcile pass
pub(crate) fn build(
    _assets: Arc<dyn AssetRepositoryPort>,
    _findings: Arc<dyn FindingRepositoryPort>,
) -> TwinBundle {
    // `assets` + `findings` are accepted in the function signature so the
    // composition root in `adapters/mod.rs` can wire them through without
    // a second plumbing pass once the reconcile lands. The adapter does
    // not retain them today — `seed_from_findings` accepts the ports
    // explicitly so test code can inject stubs without rebuilding the
    // bundle.
    let adapter = Arc::new(TwinAdapter::new());
    info!(
        target = "adapters.twin.built",
        backend = "in_memory",
        "twin bundle constructed",
    );
    TwinBundle {
        twin: Arc::clone(&adapter) as Arc<dyn TwinPort>,
        adapter,
    }
}

/// In-memory `(tenant, engagement)` → [`Twin`] store.
pub(crate) struct TwinAdapter {
    twins: Mutex<HashMap<(TenantId, EngagementId), Twin>>,
}

impl TwinAdapter {
    /// Build an empty adapter.
    pub(crate) fn new() -> Self {
        Self {
            twins: Mutex::new(HashMap::new()),
        }
    }

    /// Replace (or insert) the twin bound to `(tenant_id, engagement_id)`
    /// by walking the in-process asset + finding repositories.
    ///
    /// Returns the number of asset rows imported. See module-level docs
    /// for the seed rules.
    pub(crate) async fn seed_from_findings(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        assets: &Arc<dyn AssetRepositoryPort>,
        findings: &Arc<dyn FindingRepositoryPort>,
    ) -> Result<usize, Phase3PortError> {
        let tenant_key = parse_tenant_id(tenant_id)?;
        let engagement_key = parse_engagement_id(engagement_id)?;

        let asset_rows = assets
            .list(tenant_id, 0, SEED_PAGE_LIMIT)
            .await
            .map_err(map_engagement_error)?;
        let finding_rows = findings
            .list(tenant_id, 0, SEED_PAGE_LIMIT)
            .await
            .map_err(map_engagement_error)?;

        let mut twin = Twin::new();
        let mut imported = 0usize;

        // Index asset views by uuid so we can later look up the
        // corresponding twin id when promoting a finding to a Suspected
        // marker.
        let mut asset_index: HashMap<String, AssetId> = HashMap::new();
        for view in asset_rows
            .into_iter()
            .filter(|a| a.engagement_id == engagement_id)
        {
            if let Some(state) = view_to_asset_state(&view) {
                let id = state.id;
                if twin.add_asset(state).is_ok() {
                    let _ = asset_index.insert(view.id.clone(), id);
                    imported += 1;
                }
            }
        }

        // Walk findings AFTER the asset pass so we never try to flip a
        // node that was not registered.
        for finding in finding_rows {
            if !severity_is_high_or_above(&finding.severity) {
                continue;
            }
            let Some(asset_id) = asset_index.get(&finding.asset_id).copied() else {
                continue;
            };
            // Suspected is the seed's strongest marker — the simulator
            // promotes Suspected → Compromised when the tick algorithm
            // observes a corroborating event. We mirror that here by
            // mutating the asset state directly.
            if let Some(state) = twin.assets.get_mut(&asset_id) {
                state.compromise_state = CompromiseState::Suspected;
            }
        }

        let mut guard = self
            .twins
            .lock()
            .map_err(|_| Phase3PortError::Internal("twin store lock poisoned".to_owned()))?;
        let _ = guard.insert((tenant_key, engagement_key), twin);
        Ok(imported)
    }
}

#[async_trait]
impl TwinPort for TwinAdapter {
    async fn get(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<TwinStateView, Phase3PortError> {
        let tenant_key = parse_tenant_id(tenant_id)?;
        let engagement_key = parse_engagement_id(engagement_id)?;
        let guard = self
            .twins
            .lock()
            .map_err(|_| Phase3PortError::Internal("twin store lock poisoned".to_owned()))?;
        match guard.get(&(tenant_key, engagement_key)) {
            Some(twin) => Ok(project_twin(twin)),
            None => Ok(empty_view()),
        }
    }
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

fn empty_view() -> TwinStateView {
    TwinStateView {
        assets: vec![],
        edges: vec![],
        compromised_ids: vec![],
    }
}

fn project_twin(twin: &Twin) -> TwinStateView {
    let mut assets: Vec<TwinAssetView> = twin
        .assets
        .values()
        .map(|state| TwinAssetView {
            id: state.id.to_string(),
            kind: kind_str(state.kind).to_owned(),
            identifier: state.id.to_string(),
            risk_score: state.risk_score,
            compromise_state: compromise_str(state.compromise_state).to_owned(),
        })
        .collect();
    assets.sort_by(|a, b| a.id.cmp(&b.id));

    let mut edges: Vec<TwinEdgeView> = twin
        .edges
        .iter()
        .map(|e| TwinEdgeView {
            from: e.from.to_string(),
            to: e.to.to_string(),
            exploit_probability: e.exploit_probability,
        })
        .collect();
    edges.sort_by(|a, b| (a.from.as_str(), a.to.as_str()).cmp(&(b.from.as_str(), b.to.as_str())));

    let mut compromised_ids: Vec<String> =
        twin.compromised.iter().map(ToString::to_string).collect();
    compromised_ids.sort();

    TwinStateView {
        assets,
        edges,
        compromised_ids,
    }
}

fn kind_str(kind: AssetKind) -> &'static str {
    match kind {
        AssetKind::Host => "host",
        AssetKind::Network => "network",
        AssetKind::Identity => "identity",
        AssetKind::Application => "application",
        AssetKind::Data => "data",
        _ => "other",
    }
}

fn compromise_str(state: CompromiseState) -> &'static str {
    match state {
        CompromiseState::Suspected => "suspected",
        CompromiseState::Compromised => "compromised",
        CompromiseState::Contained => "contained",
        _ => "healthy",
    }
}

fn view_to_asset_state(view: &AssetView) -> Option<AssetState> {
    let uuid = Uuid::parse_str(&view.id).ok()?;
    let id = AssetId::from_uuid(uuid);
    let kind = map_asset_kind(&view.kind);
    Some(AssetState::new(id, kind, 0.0))
}

fn map_asset_kind(raw: &str) -> AssetKind {
    match raw.trim().to_ascii_lowercase().as_str() {
        "host" | "server" | "workstation" | "vm" => AssetKind::Host,
        "network" | "router" | "switch" | "firewall" => AssetKind::Network,
        "identity" | "user" | "service_account" => AssetKind::Identity,
        "application" | "service" | "app" | "url" => AssetKind::Application,
        "data" | "database" | "bucket" | "share" => AssetKind::Data,
        _ => AssetKind::Other,
    }
}

fn severity_is_high_or_above(severity: &str) -> bool {
    matches!(
        severity.trim().to_ascii_lowercase().as_str(),
        "high" | "critical"
    )
}

fn parse_tenant_id(raw: &str) -> Result<TenantId, Phase3PortError> {
    TenantId::from_str(raw).map_err(|e| Phase3PortError::Invalid(format!("invalid tenant_id: {e}")))
}

fn parse_engagement_id(raw: &str) -> Result<EngagementId, Phase3PortError> {
    EngagementId::from_str(raw)
        .map_err(|e| Phase3PortError::Invalid(format!("invalid engagement_id: {e}")))
}

fn map_engagement_error(err: sx_api::port::EngagementPortError) -> Phase3PortError {
    use sx_api::port::EngagementPortError as E;
    match err {
        E::NotFound => Phase3PortError::NotFound,
        E::Forbidden => Phase3PortError::Forbidden("forbidden".to_owned()),
        E::Conflict(msg) | E::Invalid(msg) => Phase3PortError::Invalid(msg),
        E::Dependency(msg) => Phase3PortError::Dependency(msg),
        E::Internal(msg) => Phase3PortError::Internal(msg),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    use sx_api::port::{AssetRepositoryPort, EngagementPortError, FindingRepositoryPort};
    use sx_api::view::asset_view::AssetView;
    use sx_api::view::finding_view::FindingView;

    // --- Stub repositories ------------------------------------------------

    #[derive(Debug, Default)]
    struct StubAssets {
        rows: Vec<AssetView>,
    }

    #[async_trait]
    impl AssetRepositoryPort for StubAssets {
        async fn list(
            &self,
            tenant_id: &str,
            _offset: u64,
            _limit: u32,
        ) -> Result<Vec<AssetView>, EngagementPortError> {
            Ok(self
                .rows
                .iter()
                .filter(|a| a.tenant_id == tenant_id)
                .cloned()
                .collect())
        }

        async fn get(&self, _tenant_id: &str, _id: &str) -> Result<AssetView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
    }

    #[derive(Debug, Default)]
    struct StubFindings {
        rows: Vec<FindingView>,
    }

    #[async_trait]
    impl FindingRepositoryPort for StubFindings {
        async fn list(
            &self,
            tenant_id: &str,
            _offset: u64,
            _limit: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            Ok(self
                .rows
                .iter()
                .filter(|f| f.tenant_id == tenant_id)
                .cloned()
                .collect())
        }

        async fn get(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }

        async fn update_status(
            &self,
            _tenant_id: &str,
            _id: &str,
            _new_status: &str,
            _comment: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }

        async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
            Ok(view)
        }
    }

    fn asset_view(
        asset_uuid: Uuid,
        tenant: &str,
        engagement: &str,
        kind: &str,
        identifier: &str,
    ) -> AssetView {
        AssetView {
            id: asset_uuid.to_string(),
            tenant_id: tenant.to_owned(),
            engagement_id: engagement.to_owned(),
            kind: kind.to_owned(),
            identifier: identifier.to_owned(),
            source: "manual".into(),
            first_seen: "2026-05-29T00:00:00Z".into(),
            last_seen: "2026-05-29T00:00:00Z".into(),
            criticality: None,
        }
    }

    fn finding_view(
        finding_uuid: &str,
        tenant: &str,
        asset_uuid: Uuid,
        severity: &str,
    ) -> FindingView {
        FindingView {
            id: finding_uuid.to_owned(),
            tenant_id: tenant.to_owned(),
            asset_id: asset_uuid.to_string(),
            severity: severity.to_owned(),
            status: "open".into(),
            title: "t".into(),
            description: "d".into(),
            cvss: None,
            cve_id: None,
            first_seen: "2026-05-29T00:00:00Z".into(),
            last_seen: "2026-05-29T00:00:00Z".into(),
            metadata: None,
        }
    }

    fn arc_assets(rows: Vec<AssetView>) -> Arc<dyn AssetRepositoryPort> {
        Arc::new(StubAssets { rows })
    }

    fn arc_findings(rows: Vec<FindingView>) -> Arc<dyn FindingRepositoryPort> {
        Arc::new(StubFindings { rows })
    }

    // --- Tests ------------------------------------------------------------

    #[tokio::test]
    async fn get_returns_empty_view_for_unknown_engagement() {
        let adapter = TwinAdapter::new();
        let tenant = TenantId::new().to_string();
        let engagement = EngagementId::new().to_string();
        let view = adapter.get(&tenant, &engagement).await.unwrap();
        assert!(view.assets.is_empty());
        assert!(view.edges.is_empty());
        assert!(view.compromised_ids.is_empty());
    }

    #[tokio::test]
    async fn build_returns_empty_store() {
        let assets = arc_assets(vec![]);
        let findings = arc_findings(vec![]);
        let bundle = build(Arc::clone(&assets), Arc::clone(&findings));
        let tenant = TenantId::new().to_string();
        let engagement = EngagementId::new().to_string();
        let view = bundle.twin.get(&tenant, &engagement).await.unwrap();
        assert!(view.assets.is_empty());
    }

    #[tokio::test]
    async fn seed_from_findings_produces_non_empty_twin() {
        let tenant = TenantId::new().to_string();
        let engagement = EngagementId::new().to_string();
        let asset_uuid = Uuid::new_v4();
        let assets = arc_assets(vec![asset_view(
            asset_uuid,
            &tenant,
            &engagement,
            "host",
            "host-1",
        )]);
        let findings = arc_findings(vec![]);

        let adapter = TwinAdapter::new();
        let imported = adapter
            .seed_from_findings(&tenant, &engagement, &assets, &findings)
            .await
            .unwrap();
        assert_eq!(imported, 1);

        let view = adapter.get(&tenant, &engagement).await.unwrap();
        assert_eq!(view.assets.len(), 1);
        assert_eq!(view.assets[0].kind, "host");
        assert_eq!(view.assets[0].compromise_state, "healthy");
        assert!(view.compromised_ids.is_empty());
    }

    #[tokio::test]
    async fn seed_promotes_high_severity_finding_to_suspected() {
        let tenant = TenantId::new().to_string();
        let engagement = EngagementId::new().to_string();
        let asset_uuid = Uuid::new_v4();
        let assets = arc_assets(vec![asset_view(
            asset_uuid,
            &tenant,
            &engagement,
            "host",
            "host-1",
        )]);
        let findings = arc_findings(vec![
            finding_view("f-1", &tenant, asset_uuid, "high"),
            finding_view("f-2", &tenant, asset_uuid, "low"),
        ]);

        let adapter = TwinAdapter::new();
        adapter
            .seed_from_findings(&tenant, &engagement, &assets, &findings)
            .await
            .unwrap();

        let view = adapter.get(&tenant, &engagement).await.unwrap();
        assert_eq!(view.assets.len(), 1);
        // Suspected marker — not Compromised.
        assert_eq!(view.assets[0].compromise_state, "suspected");
        // Suspected does NOT add to the compromised set.
        assert!(view.compromised_ids.is_empty());
    }

    #[tokio::test]
    async fn seed_ignores_other_engagements() {
        let tenant = TenantId::new().to_string();
        let target_engagement = EngagementId::new().to_string();
        let other_engagement = EngagementId::new().to_string();
        let asset_a = Uuid::new_v4();
        let asset_b = Uuid::new_v4();
        let assets = arc_assets(vec![
            asset_view(asset_a, &tenant, &target_engagement, "host", "host-a"),
            asset_view(asset_b, &tenant, &other_engagement, "host", "host-b"),
        ]);
        let findings = arc_findings(vec![]);

        let adapter = TwinAdapter::new();
        let imported = adapter
            .seed_from_findings(&tenant, &target_engagement, &assets, &findings)
            .await
            .unwrap();
        assert_eq!(
            imported, 1,
            "only the target engagement's asset is imported"
        );
    }

    #[tokio::test]
    async fn invalid_tenant_id_is_unprocessable() {
        let adapter = TwinAdapter::new();
        let engagement = EngagementId::new().to_string();
        let err = adapter.get("not-a-uuid", &engagement).await.unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_get_from_four_tasks_is_consistent() {
        let tenant = TenantId::new().to_string();
        let engagement = EngagementId::new().to_string();
        let asset_uuid = Uuid::new_v4();
        let assets = arc_assets(vec![asset_view(
            asset_uuid,
            &tenant,
            &engagement,
            "host",
            "host-1",
        )]);
        let findings = arc_findings(vec![finding_view("f-1", &tenant, asset_uuid, "critical")]);

        let adapter = Arc::new(TwinAdapter::new());
        adapter
            .seed_from_findings(&tenant, &engagement, &assets, &findings)
            .await
            .unwrap();

        let mut handles = Vec::new();
        for _ in 0..4 {
            let a = Arc::clone(&adapter);
            let t = tenant.clone();
            let e = engagement.clone();
            handles.push(tokio::spawn(async move { a.get(&t, &e).await }));
        }
        for h in handles {
            let view = h.await.unwrap().unwrap();
            assert_eq!(view.assets.len(), 1);
            assert_eq!(view.assets[0].compromise_state, "suspected");
        }
    }

    #[test]
    fn map_asset_kind_handles_canonical_strings() {
        assert!(matches!(map_asset_kind("host"), AssetKind::Host));
        assert!(matches!(map_asset_kind("DATABASE"), AssetKind::Data));
        assert!(matches!(map_asset_kind("identity"), AssetKind::Identity));
        assert!(matches!(map_asset_kind("router"), AssetKind::Network));
        assert!(matches!(map_asset_kind("url"), AssetKind::Application));
        assert!(matches!(map_asset_kind(""), AssetKind::Other));
        assert!(matches!(map_asset_kind("squid"), AssetKind::Other));
    }

    #[test]
    fn severity_predicate_matches_only_high_and_critical() {
        assert!(severity_is_high_or_above("high"));
        assert!(severity_is_high_or_above("CRITICAL"));
        assert!(!severity_is_high_or_above("medium"));
        assert!(!severity_is_high_or_above("info"));
    }
}
