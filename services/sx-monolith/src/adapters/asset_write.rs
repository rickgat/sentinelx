//! Concrete adapter behind [`sx_api::port::AssetWritePort`].
//!
//! Wraps the existing in-memory asset store ([`InMemoryAssets`]) so the
//! HTTP surface can issue `POST` / `PATCH` / `DELETE` against the same
//! rows the read-only [`AssetRepositoryPort`] iterates. The read and
//! write halves share one mutex inside the concrete store, so a delete
//! observed by the write port is observable by the next read port query.
//!
//! ## Why a bundle
//!
//! The composition root in [`crate::adapters::mod`] picks each port off a
//! single struct so the wiring stays uniform across adapters (BAS,
//! collab, admin, ...). [`AssetWriteBundle::build`] is the only entry
//! point — it takes the concrete in-memory store and exposes a single
//! trait object.
//!
//! ## Pg vs. in-memory
//!
//! Phase 1.5 wires the in-memory store unconditionally. When the
//! Postgres pool is live, callers fall through to the read-only
//! `PgAssetsAdapter` for `GET` queries; the write-side will be promoted
//! to a Postgres-backed implementation in a subsequent phase. Until then
//! `POST` / `PATCH` / `DELETE` operate against the in-memory store even
//! on Postgres deployments — surfaced as a wiring note in the
//! composition-root reconcile log.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{AssetWritePort, EngagementPortError};
use sx_api::view::asset_view::{AssetView, CreateAssetRequest, UpdateAssetRequest};

use crate::adapters::repository::InMemoryAssets;

/// Bundle exposing the single write-side trait object.
pub(crate) struct AssetWriteBundle {
    /// Trait object plugged into [`sx_api::AppState::asset_write`].
    pub write: Arc<dyn AssetWritePort>,
}

impl AssetWriteBundle {
    /// Build the bundle from the concrete in-memory store.
    pub(crate) fn build(store: Arc<InMemoryAssets>) -> Self {
        let adapter = InMemoryAssetWriteAdapter { store };
        Self {
            write: Arc::new(adapter),
        }
    }

    /// Build the bundle from an already-constructed write port — used by the
    /// composition root to plug in the Postgres-backed adapter when the DB is
    /// enabled.
    pub(crate) fn from_port(write: Arc<dyn AssetWritePort>) -> Self {
        Self { write }
    }
}

/// In-memory implementation of [`AssetWritePort`] over [`InMemoryAssets`].
///
/// The adapter is intentionally thin — every method delegates to the
/// concrete store, which owns the mutex. Errors propagate as
/// [`EngagementPortError`] verbatim.
struct InMemoryAssetWriteAdapter {
    store: Arc<InMemoryAssets>,
}

#[async_trait]
impl AssetWritePort for InMemoryAssetWriteAdapter {
    async fn create(
        &self,
        tenant_id: &str,
        req: CreateAssetRequest,
    ) -> Result<AssetView, EngagementPortError> {
        self.store.insert_new(
            tenant_id,
            &req.engagement_id,
            &req.kind,
            &req.identifier,
            &req.source,
        )
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: &str,
        req: UpdateAssetRequest,
    ) -> Result<AssetView, EngagementPortError> {
        self.store.patch(
            tenant_id,
            id,
            req.kind.as_deref(),
            req.identifier.as_deref(),
            req.source.as_deref(),
        )
    }

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), EngagementPortError> {
        self.store.remove(tenant_id, id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";
    const ENGAGEMENT: &str = "e0000001-0000-0000-0000-000000000000";

    fn create_req(identifier: &str) -> CreateAssetRequest {
        CreateAssetRequest {
            engagement_id: ENGAGEMENT.to_owned(),
            kind: "host".to_owned(),
            identifier: identifier.to_owned(),
            source: "manual".to_owned(),
        }
    }

    #[tokio::test]
    async fn create_then_get_round_trip() {
        let store = Arc::new(InMemoryAssets::default());
        let bundle = AssetWriteBundle::build(Arc::clone(&store));
        let view = bundle
            .write
            .create(TENANT, create_req("api.example"))
            .await
            .expect("create ok");
        assert_eq!(view.tenant_id, TENANT);
        assert_eq!(view.engagement_id, ENGAGEMENT);
        assert_eq!(view.kind, "host");
        assert_eq!(view.identifier, "api.example");
        assert_eq!(view.source, "manual");
    }

    #[tokio::test]
    async fn duplicate_create_is_conflict() {
        let store = Arc::new(InMemoryAssets::default());
        let bundle = AssetWriteBundle::build(Arc::clone(&store));
        bundle
            .write
            .create(TENANT, create_req("api.example"))
            .await
            .expect("first create ok");
        let err = bundle
            .write
            .create(TENANT, create_req("api.example"))
            .await
            .expect_err("duplicate must fail");
        assert!(matches!(err, EngagementPortError::Conflict(_)));
    }

    #[tokio::test]
    async fn update_preserves_untouched_fields() {
        let store = Arc::new(InMemoryAssets::default());
        let bundle = AssetWriteBundle::build(Arc::clone(&store));
        let created = bundle
            .write
            .create(TENANT, create_req("api.example"))
            .await
            .expect("create ok");
        let patch = UpdateAssetRequest {
            kind: Some("domain".to_owned()),
            identifier: None,
            source: None,
        };
        let updated = bundle
            .write
            .update(TENANT, &created.id, patch)
            .await
            .expect("update ok");
        assert_eq!(updated.kind, "domain");
        // identifier and source preserved verbatim from the create call.
        assert_eq!(updated.identifier, "api.example");
        assert_eq!(updated.source, "manual");
    }

    #[tokio::test]
    async fn update_missing_returns_not_found() {
        let store = Arc::new(InMemoryAssets::default());
        let bundle = AssetWriteBundle::build(Arc::clone(&store));
        let patch = UpdateAssetRequest {
            kind: Some("host".to_owned()),
            identifier: None,
            source: None,
        };
        let err = bundle
            .write
            .update(TENANT, "missing-id", patch)
            .await
            .expect_err("must be NotFound");
        assert!(matches!(err, EngagementPortError::NotFound));
    }

    #[tokio::test]
    async fn delete_missing_returns_not_found() {
        let store = Arc::new(InMemoryAssets::default());
        let bundle = AssetWriteBundle::build(Arc::clone(&store));
        let err = bundle
            .write
            .delete(TENANT, "missing-id")
            .await
            .expect_err("must be NotFound");
        assert!(matches!(err, EngagementPortError::NotFound));
    }

    #[tokio::test]
    async fn concurrent_create_and_delete_safe() {
        let store = Arc::new(InMemoryAssets::default());
        let bundle = AssetWriteBundle::build(Arc::clone(&store));
        // create then delete from two different tasks; the mutex
        // serialises the writes so neither operation panics.
        let created = bundle
            .write
            .create(TENANT, create_req("api.example"))
            .await
            .expect("create ok");
        let asset_id = created.id.clone();
        let w1 = Arc::clone(&bundle.write);
        let w2 = Arc::clone(&bundle.write);
        let t1 = tokio::spawn(async move {
            // Best-effort second create — should fail with Conflict, never
            // panic, never poison the mutex.
            let _ = w1.create(TENANT, create_req("api.example")).await;
        });
        let t2 = tokio::spawn(async move {
            // First-or-second delete — at most one wins.
            let _ = w2.delete(TENANT, &asset_id).await;
        });
        let _ = t1.await;
        let _ = t2.await;
        // Either the row is gone (delete won the race) or still present
        // (delete lost the race) — in both cases the adapter is healthy.
        let second_delete = bundle.write.delete(TENANT, &created.id).await;
        assert!(
            matches!(second_delete, Ok(()) | Err(EngagementPortError::NotFound)),
            "unexpected error from second delete: {second_delete:?}"
        );
    }
}
