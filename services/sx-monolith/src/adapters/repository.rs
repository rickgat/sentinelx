//! In-memory repository adapters.
//!
//! These satisfy the read-side ports declared by `sx-api` and are designed
//! to be swapped one-for-one with the `Pg<X>Repository` adapters from
//! `sx-storage` once a real database connection is part of the boot path.
//!
//! Each store starts empty. Provisioning data is intentionally left to a
//! future Phase 1.5 admin controller.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sx_api::port::{
    AssetRepositoryPort, EngagementPortError, FindingRepositoryPort, TenantRepositoryPort,
    TenantSummaryView,
};
use sx_api::view::asset_view::AssetView;
use sx_api::view::finding_view::FindingView;

/// Bundle of repository trait objects passed to `AppState`.
pub(crate) struct RepositoryBundle {
    pub assets: Arc<dyn AssetRepositoryPort>,
    pub findings: Arc<dyn FindingRepositoryPort>,
    pub tenants: Arc<dyn TenantRepositoryPort>,
    /// Concrete handles to the in-memory stores. Exposed so the demo
    /// seeder (`adapters::seed`) can call `seed_one` without downcasting
    /// from the trait-object façades above.
    pub assets_concrete: Arc<InMemoryAssets>,
    pub findings_concrete: Arc<InMemoryFindings>,
    pub tenants_concrete: Arc<InMemoryTenants>,
}

/// Build the in-memory repository bundle.
pub(crate) fn build() -> RepositoryBundle {
    let assets = Arc::new(InMemoryAssets::default());
    let findings = Arc::new(InMemoryFindings::default());
    let tenants = Arc::new(InMemoryTenants::default());
    RepositoryBundle {
        assets: Arc::clone(&assets) as Arc<dyn AssetRepositoryPort>,
        findings: Arc::clone(&findings) as Arc<dyn FindingRepositoryPort>,
        tenants: Arc::clone(&tenants) as Arc<dyn TenantRepositoryPort>,
        assets_concrete: assets,
        findings_concrete: findings,
        tenants_concrete: tenants,
    }
}

#[derive(Debug, Default)]
pub(crate) struct InMemoryAssets {
    rows: Mutex<HashMap<(String, String), AssetView>>,
}

impl InMemoryAssets {
    /// Insert a pre-built [`AssetView`] directly into the store. Used by the
    /// demo seeder (`adapters::seed`) at startup. Silently no-ops when the
    /// internal mutex is poisoned — the seeder runs before any HTTP traffic
    /// so the only realistic cause of poisoning would be a panic in another
    /// seed step, which we let the higher-level error path handle.
    pub(crate) fn seed_one(&self, view: AssetView) {
        if let Ok(mut g) = self.rows.lock() {
            let key = (view.tenant_id.clone(), view.id.clone());
            g.insert(key, view);
        }
    }

    /// Insert a new [`AssetView`] for `tenant_id` with the supplied
    /// `engagement_id` / `kind` / `identifier` / `source`. Idempotent on
    /// the `(tenant_id, engagement_id, identifier)` tuple — a duplicate
    /// surfaces as [`EngagementPortError::Conflict`].
    ///
    /// The asset id is minted from `uuid::Uuid::now_v7()` so the wire id
    /// is monotonic and the in-memory adapter does not require a wiring
    /// callback.
    pub(crate) fn insert_new(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        kind: &str,
        identifier: &str,
        source: &str,
    ) -> Result<AssetView, sx_api::port::EngagementPortError> {
        let mut g = self.rows.lock().map_err(|_| {
            sx_api::port::EngagementPortError::Internal("assets lock poisoned".into())
        })?;
        // Conflict on the same (tenant, engagement, identifier) tuple —
        // this keeps the create endpoint idempotent on duplicate input.
        let dup = g.values().any(|v| {
            v.tenant_id == tenant_id
                && v.engagement_id == engagement_id
                && v.identifier == identifier
        });
        if dup {
            return Err(sx_api::port::EngagementPortError::Conflict(
                "asset already exists for (engagement_id, identifier)".into(),
            ));
        }
        let id = uuid::Uuid::now_v7().to_string();
        let now = current_rfc3339();
        let view = AssetView {
            id: id.clone(),
            tenant_id: tenant_id.to_owned(),
            engagement_id: engagement_id.to_owned(),
            kind: kind.to_owned(),
            identifier: identifier.to_owned(),
            source: source.to_owned(),
            first_seen: now.clone(),
            last_seen: now,
            // The in-memory repo has no notion of criticality —
            // callers that want to test scoring on a specific
            // criticality patch the field after construction.
            criticality: None,
        };
        g.insert((tenant_id.to_owned(), id), view.clone());
        Ok(view)
    }

    /// Apply a partial update. `kind` / `identifier` / `source` are
    /// preserved when `None`. Bumps `last_seen` to the call-time clock.
    pub(crate) fn patch(
        &self,
        tenant_id: &str,
        id: &str,
        kind: Option<&str>,
        identifier: Option<&str>,
        source: Option<&str>,
    ) -> Result<AssetView, sx_api::port::EngagementPortError> {
        let mut g = self.rows.lock().map_err(|_| {
            sx_api::port::EngagementPortError::Internal("assets lock poisoned".into())
        })?;
        let key = (tenant_id.to_owned(), id.to_owned());
        let Some(view) = g.get_mut(&key) else {
            return Err(sx_api::port::EngagementPortError::NotFound);
        };
        if let Some(k) = kind {
            view.kind = k.to_owned();
        }
        if let Some(i) = identifier {
            view.identifier = i.to_owned();
        }
        if let Some(s) = source {
            view.source = s.to_owned();
        }
        view.last_seen = current_rfc3339();
        Ok(view.clone())
    }

    /// Remove the asset identified by `(tenant_id, id)`. Returns
    /// [`sx_api::port::EngagementPortError::NotFound`] when the row is
    /// absent.
    pub(crate) fn remove(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<(), sx_api::port::EngagementPortError> {
        let mut g = self.rows.lock().map_err(|_| {
            sx_api::port::EngagementPortError::Internal("assets lock poisoned".into())
        })?;
        if g.remove(&(tenant_id.to_owned(), id.to_owned())).is_some() {
            Ok(())
        } else {
            Err(sx_api::port::EngagementPortError::NotFound)
        }
    }
}

/// Current wall-clock projected to an RFC 3339 UTC string. Lives here
/// rather than in a shared util so the in-memory adapter has zero new
/// dependencies — both `time::OffsetDateTime` and `time::format_description`
/// are already pulled in transitively via the workspace.
fn current_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[async_trait]
impl AssetRepositoryPort for InMemoryAssets {
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<AssetView>, EngagementPortError> {
        let Ok(g) = self.rows.lock() else {
            return Err(EngagementPortError::Internal("assets lock poisoned".into()));
        };
        Ok(g.iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, v)| v.clone())
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<AssetView, EngagementPortError> {
        let Ok(g) = self.rows.lock() else {
            return Err(EngagementPortError::Internal("assets lock poisoned".into()));
        };
        g.get(&(tenant_id.to_owned(), id.to_owned()))
            .cloned()
            .ok_or(EngagementPortError::NotFound)
    }
}

#[derive(Debug, Default)]
pub(crate) struct InMemoryFindings {
    rows: Mutex<HashMap<(String, String), FindingView>>,
}

impl InMemoryFindings {
    /// Insert a pre-built [`FindingView`] directly into the store. Used by the
    /// demo seeder. See [`InMemoryAssets::seed_one`] for the poisoning policy.
    pub(crate) fn seed_one(&self, view: FindingView) {
        if let Ok(mut g) = self.rows.lock() {
            let key = (view.tenant_id.clone(), view.id.clone());
            g.insert(key, view);
        }
    }
}

#[async_trait]
impl FindingRepositoryPort for InMemoryFindings {
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<FindingView>, EngagementPortError> {
        let Ok(g) = self.rows.lock() else {
            return Err(EngagementPortError::Internal(
                "findings lock poisoned".into(),
            ));
        };
        Ok(g.iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, v)| v.clone())
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
        let Ok(g) = self.rows.lock() else {
            return Err(EngagementPortError::Internal(
                "findings lock poisoned".into(),
            ));
        };
        g.get(&(tenant_id.to_owned(), id.to_owned()))
            .cloned()
            .ok_or(EngagementPortError::NotFound)
    }

    async fn update_status(
        &self,
        tenant_id: &str,
        id: &str,
        new_status: &str,
        _comment: Option<&str>,
    ) -> Result<FindingView, EngagementPortError> {
        let mut g = self
            .rows
            .lock()
            .map_err(|_| EngagementPortError::Internal("findings lock poisoned".into()))?;
        match g.get_mut(&(tenant_id.to_owned(), id.to_owned())) {
            Some(view) => {
                view.status = new_status.to_owned();
                Ok(view.clone())
            }
            None => Err(EngagementPortError::NotFound),
        }
    }

    /// Insert a finding into the in-memory store.
    ///
    /// Idempotency: keyed by `(tenant_id, id)`. On a collision the
    /// previous entry is **overwritten** (last-write-wins) — the SAML
    /// attack observer (TOP5-#3-P2-004) relies on this so a flood of
    /// XSW attempts keyed by `(tenant, kind, idp, day_bucket)` collapses
    /// to a single row. The returned view is the freshly-inserted one
    /// — never an error. Emitters that need first-write-wins semantics
    /// MUST probe `get` first.
    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
        let mut g = self
            .rows
            .lock()
            .map_err(|_| EngagementPortError::Internal("findings lock poisoned".into()))?;
        let key = (view.tenant_id.clone(), view.id.clone());
        g.insert(key, view.clone());
        Ok(view)
    }
}

#[derive(Debug, Default)]
pub(crate) struct InMemoryTenants {
    rows: Mutex<HashMap<String, TenantSummaryView>>,
}

impl InMemoryTenants {
    /// Insert a pre-built [`TenantSummaryView`] directly into the store. Used
    /// by the demo seeder. See [`InMemoryAssets::seed_one`] for the poisoning
    /// policy.
    pub(crate) fn seed_one(&self, view: TenantSummaryView) {
        if let Ok(mut g) = self.rows.lock() {
            g.insert(view.id.clone(), view);
        }
    }

    /// Insert a new tenant row keyed by `slug` uniqueness. Returns
    /// [`EngagementPortError::Conflict`] when the slug is already taken.
    ///
    /// The tenant id is minted from `uuid::Uuid::now_v7()` so the wire
    /// id is monotonic and the in-memory adapter does not require a
    /// wiring callback.
    pub(crate) fn insert_new(
        &self,
        slug: &str,
        name: &str,
    ) -> Result<TenantSummaryView, EngagementPortError> {
        let mut g = self
            .rows
            .lock()
            .map_err(|_| EngagementPortError::Internal("tenants lock poisoned".into()))?;
        if g.values().any(|v| v.slug == slug) {
            return Err(EngagementPortError::Conflict("tenant exists".into()));
        }
        let id = uuid::Uuid::now_v7().to_string();
        let view = TenantSummaryView {
            id: id.clone(),
            name: name.to_owned(),
            slug: slug.to_owned(),
            is_active: true,
        };
        g.insert(id, view.clone());
        Ok(view)
    }

    /// Apply a partial update to the tenant identified by `id`. `name` /
    /// `is_active` are preserved when `None`. Returns
    /// [`EngagementPortError::NotFound`] when the id is unknown.
    pub(crate) fn patch(
        &self,
        id: &str,
        name: Option<&str>,
        is_active: Option<bool>,
    ) -> Result<TenantSummaryView, EngagementPortError> {
        let mut g = self
            .rows
            .lock()
            .map_err(|_| EngagementPortError::Internal("tenants lock poisoned".into()))?;
        let Some(view) = g.get_mut(id) else {
            return Err(EngagementPortError::NotFound);
        };
        if let Some(n) = name {
            view.name = n.to_owned();
        }
        if let Some(a) = is_active {
            view.is_active = a;
        }
        Ok(view.clone())
    }

    /// Remove the tenant identified by `id`. Returns
    /// [`EngagementPortError::NotFound`] when the row is absent.
    pub(crate) fn remove(&self, id: &str) -> Result<(), EngagementPortError> {
        let mut g = self
            .rows
            .lock()
            .map_err(|_| EngagementPortError::Internal("tenants lock poisoned".into()))?;
        if g.remove(id).is_some() {
            Ok(())
        } else {
            Err(EngagementPortError::NotFound)
        }
    }

    /// Snapshot the current row count. Used by adapter tests to assert
    /// list-after-delete semantics without exposing the inner map.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.rows.lock().map(|g| g.len()).unwrap_or(0)
    }
}

#[async_trait]
impl TenantRepositoryPort for InMemoryTenants {
    async fn get(&self, id: &str) -> Result<TenantSummaryView, EngagementPortError> {
        let Ok(g) = self.rows.lock() else {
            return Err(EngagementPortError::Internal(
                "tenants lock poisoned".into(),
            ));
        };
        g.get(id).cloned().ok_or(EngagementPortError::NotFound)
    }

    async fn list_tenants(
        &self,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<TenantSummaryView>, EngagementPortError> {
        let Ok(g) = self.rows.lock() else {
            return Err(EngagementPortError::Internal(
                "tenants lock poisoned".into(),
            ));
        };
        // Stable order by id so paging is deterministic across calls.
        let mut rows: Vec<TenantSummaryView> = g.values().cloned().collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";

    fn asset_view(id: &str) -> AssetView {
        AssetView {
            id: id.to_owned(),
            tenant_id: TENANT.to_owned(),
            engagement_id: "e0000001-0000-0000-0000-000000000000".to_owned(),
            kind: "host".to_owned(),
            identifier: "api.example".to_owned(),
            source: "manual".to_owned(),
            first_seen: "2026-05-01T00:00:00Z".to_owned(),
            last_seen: "2026-05-29T00:00:00Z".to_owned(),
            criticality: None,
        }
    }

    fn finding_view(id: &str, asset_id: &str) -> FindingView {
        FindingView {
            id: id.to_owned(),
            tenant_id: TENANT.to_owned(),
            asset_id: asset_id.to_owned(),
            severity: "high".to_owned(),
            status: "open".to_owned(),
            title: "demo".to_owned(),
            description: "demo finding".to_owned(),
            cvss: Some(7.0),
            cve_id: None,
            first_seen: "2026-05-15T00:00:00Z".to_owned(),
            last_seen: "2026-05-29T00:00:00Z".to_owned(),
            metadata: None,
        }
    }

    #[tokio::test]
    async fn inmemory_assets_seed_one_appears_in_list() {
        let store = InMemoryAssets::default();
        store.seed_one(asset_view("a0000001-0000-0000-0000-000000000000"));
        let items = store.list(TENANT, 0, 100).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "a0000001-0000-0000-0000-000000000000");
    }

    #[tokio::test]
    async fn inmemory_findings_seed_one_appears_in_list() {
        let store = InMemoryFindings::default();
        store.seed_one(finding_view(
            "f0000001-0000-0000-0000-000000000000",
            "a0000001-0000-0000-0000-000000000000",
        ));
        let items = store.list(TENANT, 0, 100).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "f0000001-0000-0000-0000-000000000000");
    }

    #[tokio::test]
    async fn inmemory_findings_insert_round_trips_via_get() {
        let store = InMemoryFindings::default();
        let view = finding_view(
            "f0000001-0000-0000-0000-000000000000",
            "a0000001-0000-0000-0000-000000000000",
        );
        let persisted = store.insert(view.clone()).await.unwrap();
        assert_eq!(persisted.id, view.id);
        let got = store
            .get(TENANT, "f0000001-0000-0000-0000-000000000000")
            .await
            .unwrap();
        assert_eq!(got.id, view.id);
    }

    #[tokio::test]
    async fn inmemory_findings_insert_is_idempotent_on_tenant_id_pair() {
        let store = InMemoryFindings::default();
        let view = finding_view(
            "f0000001-0000-0000-0000-000000000000",
            "a0000001-0000-0000-0000-000000000000",
        );
        store.insert(view.clone()).await.unwrap();
        // Re-fire — emitter inside its dedup window.
        store.insert(view.clone()).await.unwrap();
        let items = store.list(TENANT, 0, 100).await.unwrap();
        assert_eq!(items.len(), 1, "re-insert must not duplicate the row");
    }

    #[tokio::test]
    async fn inmemory_tenants_seed_one_appears_via_get() {
        let store = InMemoryTenants::default();
        store.seed_one(TenantSummaryView {
            id: TENANT.to_owned(),
            name: "Default Tenant".to_owned(),
            slug: "default".to_owned(),
            is_active: true,
        });
        let view = store.get(TENANT).await.unwrap();
        assert_eq!(view.name, "Default Tenant");
    }
}
