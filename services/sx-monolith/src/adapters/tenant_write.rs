//! Concrete adapter behind [`sx_api::port::TenantWritePort`].
//!
//! Wraps the existing in-memory tenant store ([`InMemoryTenants`]) so the
//! HTTP surface can issue `POST` / `PATCH` / `DELETE` against the same
//! rows the read-only [`sx_api::port::TenantRepositoryPort`] iterates.
//! The read and write halves share one mutex inside the concrete store,
//! so a delete observed by the write port is observable by the next
//! `GET /v1/tenants/me` query.
//!
//! ## Why a bundle
//!
//! The composition root in [`crate::adapters::mod`] picks each port off a
//! single struct so the wiring stays uniform across adapters (asset
//! writes, BAS, collab, ...). [`TenantWriteBundle::build`] is the only
//! entry point — it takes the concrete in-memory store and exposes a
//! single trait object.
//!
//! ## Slug-uniqueness contract
//!
//! Duplicate slugs surface as [`Phase3PortError::Invalid`] carrying the
//! sentinel `"tenant exists"` (mirroring the marker on the
//! [`sx_api::controller::tenants`] side). The HTTP controller translates
//! that into `409 Conflict`. Every other underlying
//! [`EngagementPortError`] is translated into the closest matching
//! [`Phase3PortError`] variant.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{EngagementPortError, Phase3PortError, TenantSummaryView, TenantWritePort};
use sx_api::view::tenant_view::{CreateTenantRequest, UpdateTenantRequest};

use crate::adapters::repository::InMemoryTenants;

/// Sentinel string the adapter returns inside
/// [`Phase3PortError::Invalid`] to signal a slug-uniqueness collision.
/// Must stay byte-for-byte identical to
/// `sx_api::controller::tenants::DUPLICATE_TENANT_MARKER` so the
/// controller's idempotency-detection arm matches.
const DUPLICATE_TENANT_MARKER: &str = "tenant exists";

/// Bundle exposing the single write-side trait object.
pub(crate) struct TenantWriteBundle {
    /// Trait object plugged into [`sx_api::AppState::tenant_write`].
    pub write: Arc<dyn TenantWritePort>,
}

impl TenantWriteBundle {
    /// Build the bundle from the concrete in-memory store.
    pub(crate) fn build(store: Arc<InMemoryTenants>) -> Self {
        let adapter = InMemoryTenantWriteAdapter { store };
        Self {
            write: Arc::new(adapter),
        }
    }

    /// Build the bundle from an already-constructed write port — used by the
    /// composition root to plug in the Postgres-backed adapter when the DB is
    /// enabled.
    pub(crate) fn from_port(write: Arc<dyn TenantWritePort>) -> Self {
        Self { write }
    }
}

/// In-memory implementation of [`TenantWritePort`] over [`InMemoryTenants`].
///
/// The adapter is intentionally thin — every method delegates to the
/// concrete store, which owns the mutex. Underlying
/// [`EngagementPortError`] values are translated into the closest
/// matching [`Phase3PortError`] so the HTTP layer reuses
/// [`sx_api::controller::map_phase3`].
struct InMemoryTenantWriteAdapter {
    store: Arc<InMemoryTenants>,
}

#[async_trait]
impl TenantWritePort for InMemoryTenantWriteAdapter {
    async fn create(&self, req: CreateTenantRequest) -> Result<TenantSummaryView, Phase3PortError> {
        self.store
            .insert_new(&req.slug, &req.name)
            .map_err(translate_error)
    }

    async fn update(
        &self,
        id: &str,
        req: UpdateTenantRequest,
    ) -> Result<TenantSummaryView, Phase3PortError> {
        self.store
            .patch(id, req.name.as_deref(), req.is_active)
            .map_err(translate_error)
    }

    async fn delete(&self, id: &str) -> Result<(), Phase3PortError> {
        self.store.remove(id).map_err(translate_error)
    }
}

/// Translate an [`EngagementPortError`] (the store's native error type)
/// into the [`Phase3PortError`] surface expected by
/// [`TenantWritePort`]. The store reports slug collisions as
/// [`EngagementPortError::Conflict`]; we collapse that into
/// [`Phase3PortError::Invalid`] with the
/// [`DUPLICATE_TENANT_MARKER`] sentinel so the controller's idempotency
/// arm fires.
fn translate_error(err: EngagementPortError) -> Phase3PortError {
    match err {
        EngagementPortError::NotFound => Phase3PortError::NotFound,
        EngagementPortError::Forbidden => Phase3PortError::Forbidden("forbidden".into()),
        EngagementPortError::Conflict(_) => {
            Phase3PortError::Invalid(DUPLICATE_TENANT_MARKER.into())
        }
        EngagementPortError::Invalid(m) => Phase3PortError::Invalid(m),
        EngagementPortError::Dependency(m) => Phase3PortError::Dependency(m),
        EngagementPortError::Internal(m) => Phase3PortError::Internal(m),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn create_req(slug: &str, name: &str) -> CreateTenantRequest {
        CreateTenantRequest {
            slug: slug.to_owned(),
            name: name.to_owned(),
        }
    }

    #[tokio::test]
    async fn create_returns_persisted_projection() {
        let store = Arc::new(InMemoryTenants::default());
        let bundle = TenantWriteBundle::build(Arc::clone(&store));
        let view = bundle
            .write
            .create(create_req("acme", "Acme Corp"))
            .await
            .expect("create ok");
        assert_eq!(view.slug, "acme");
        assert_eq!(view.name, "Acme Corp");
        assert!(view.is_active);
        assert!(!view.id.is_empty());
    }

    #[tokio::test]
    async fn duplicate_slug_surfaces_as_invalid_marker() {
        let store = Arc::new(InMemoryTenants::default());
        let bundle = TenantWriteBundle::build(Arc::clone(&store));
        bundle
            .write
            .create(create_req("acme", "Acme Corp"))
            .await
            .expect("first create ok");
        let err = bundle
            .write
            .create(create_req("acme", "Acme Two"))
            .await
            .expect_err("duplicate must fail");
        match err {
            Phase3PortError::Invalid(m) => assert_eq!(m, "tenant exists"),
            other => panic!("expected Invalid(\"tenant exists\"), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_preserves_untouched_fields() {
        let store = Arc::new(InMemoryTenants::default());
        let bundle = TenantWriteBundle::build(Arc::clone(&store));
        let created = bundle
            .write
            .create(create_req("acme", "Acme Corp"))
            .await
            .expect("create ok");
        let patch = UpdateTenantRequest {
            name: Some("Acme Renamed".to_owned()),
            is_active: None,
        };
        let updated = bundle
            .write
            .update(&created.id, patch)
            .await
            .expect("update ok");
        assert_eq!(updated.name, "Acme Renamed");
        // slug + is_active preserved verbatim from the create call.
        assert_eq!(updated.slug, "acme");
        assert!(updated.is_active);
    }

    #[tokio::test]
    async fn update_missing_returns_not_found() {
        let store = Arc::new(InMemoryTenants::default());
        let bundle = TenantWriteBundle::build(Arc::clone(&store));
        let patch = UpdateTenantRequest {
            name: Some("renamed".to_owned()),
            is_active: None,
        };
        let err = bundle
            .write
            .update("missing-id", patch)
            .await
            .expect_err("must be NotFound");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn update_flips_is_active_only() {
        let store = Arc::new(InMemoryTenants::default());
        let bundle = TenantWriteBundle::build(Arc::clone(&store));
        let created = bundle
            .write
            .create(create_req("acme", "Acme Corp"))
            .await
            .expect("create ok");
        let patch = UpdateTenantRequest {
            name: None,
            is_active: Some(false),
        };
        let updated = bundle
            .write
            .update(&created.id, patch)
            .await
            .expect("update ok");
        assert_eq!(updated.name, "Acme Corp"); // preserved
        assert!(!updated.is_active);
    }

    #[tokio::test]
    async fn delete_removes_row_and_subsequent_delete_is_not_found() {
        let store = Arc::new(InMemoryTenants::default());
        let bundle = TenantWriteBundle::build(Arc::clone(&store));
        let created = bundle
            .write
            .create(create_req("acme", "Acme Corp"))
            .await
            .expect("create ok");
        assert_eq!(store.len(), 1);
        bundle.write.delete(&created.id).await.expect("delete ok");
        assert_eq!(store.len(), 0);
        let err = bundle
            .write
            .delete(&created.id)
            .await
            .expect_err("second delete must be NotFound");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn delete_missing_returns_not_found() {
        let store = Arc::new(InMemoryTenants::default());
        let bundle = TenantWriteBundle::build(Arc::clone(&store));
        let err = bundle
            .write
            .delete("missing-id")
            .await
            .expect_err("must be NotFound");
        assert!(matches!(err, Phase3PortError::NotFound));
    }
}
