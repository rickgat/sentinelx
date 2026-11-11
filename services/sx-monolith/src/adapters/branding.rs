//! Per-tenant report branding adapter (P2-002 MSSP white-label).
//!
//! Holds an in-memory, tenant-scoped [`BrandConfig`] store that is shared
//! between two callers:
//!
//! * the HTTP [`BrandingPort`] (`GET`/`PUT /v1/reports/branding`), and
//! * the report renderer, which calls [`BrandingStore::get`] and applies
//!   the result via `ReportContext::with_branding` before rendering.
//!
//! In-memory-first per the project norm; a Postgres-backed store can swap
//! in behind the same [`BrandingStore`] trait without touching callers.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sx_api::port::{BrandingPort, BrandingPortError};
use sx_api::view::branding_view::{validate_hex_color, BrandingView, SetBrandingRequest};
use sx_report::model::branding::{BrandConfig, MAX_LOGO_BYTES};

/// Shared per-tenant branding store. Object-safe + async so both an
/// in-memory map and a Postgres-backed table satisfy it behind one trait.
#[async_trait]
pub(crate) trait BrandingStore: Send + Sync + std::fmt::Debug {
    /// Branding for `tenant_id`, or [`BrandConfig::default`] when unset.
    async fn get(&self, tenant_id: &str) -> BrandConfig;
    /// Replace the branding for `tenant_id`.
    async fn set(&self, tenant_id: &str, cfg: BrandConfig);
}

/// In-memory [`BrandingStore`].
#[derive(Default)]
pub(crate) struct InMemoryBrandingStore {
    inner: Mutex<HashMap<String, BrandConfig>>,
}

impl std::fmt::Debug for InMemoryBrandingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryBrandingStore")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl BrandingStore for InMemoryBrandingStore {
    async fn get(&self, tenant_id: &str) -> BrandConfig {
        self.inner
            .lock()
            .map(|g| g.get(tenant_id).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    async fn set(&self, tenant_id: &str, cfg: BrandConfig) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(tenant_id.to_owned(), cfg);
        }
    }
}

/// Postgres-backed [`BrandingStore`] (#1 persistence). One row per tenant in
/// `report_branding`, tenant-isolated via RLS (`TenantContext::apply`). On
/// any error the read falls back to the default brand and the write logs —
/// branding must never take down report rendering or the API.
pub(crate) struct PgBrandingStore {
    pool: sqlx::PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgBrandingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgBrandingStore").finish_non_exhaustive()
    }
}

impl PgBrandingStore {
    pub(crate) fn new(pool: sqlx::PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    async fn get_inner(&self, tenant_id: &str) -> Result<Option<BrandConfig>, String> {
        use sqlx::Row as _;
        let uuid = uuid::Uuid::from_str(tenant_id).map_err(|e| format!("bad tenant id: {e}"))?;
        let tid = sx_storage::prelude::TenantId::from_uuid(uuid);
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        sx_storage::tenant_context::TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(|e| e.to_string())?;
        let row = sqlx::query(
            "SELECT logo_png, primary_color_hex, cover_md, footer_md \
             FROM report_branding WHERE tenant_id = $1",
        )
        .bind(tid.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(row.map(|r| BrandConfig {
            logo_png: r.get::<Option<Vec<u8>>, _>("logo_png"),
            primary_color_hex: r.get::<String, _>("primary_color_hex"),
            cover_md: r.get::<Option<String>, _>("cover_md"),
            footer_md: r.get::<Option<String>, _>("footer_md"),
        }))
    }

    async fn set_inner(&self, tenant_id: &str, cfg: &BrandConfig) -> Result<(), String> {
        let uuid = uuid::Uuid::from_str(tenant_id).map_err(|e| format!("bad tenant id: {e}"))?;
        let tid = sx_storage::prelude::TenantId::from_uuid(uuid);
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        sx_storage::tenant_context::TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(|e| e.to_string())?;
        sqlx::query(
            "INSERT INTO report_branding \
                 (tenant_id, logo_png, primary_color_hex, cover_md, footer_md, updated_at) \
             VALUES ($1, $2, $3, $4, $5, now()) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
                 logo_png = EXCLUDED.logo_png, \
                 primary_color_hex = EXCLUDED.primary_color_hex, \
                 cover_md = EXCLUDED.cover_md, \
                 footer_md = EXCLUDED.footer_md, \
                 updated_at = now()",
        )
        .bind(tid.as_uuid())
        .bind(cfg.logo_png.as_deref())
        .bind(&cfg.primary_color_hex)
        .bind(cfg.cover_md.as_deref())
        .bind(cfg.footer_md.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[async_trait]
impl BrandingStore for PgBrandingStore {
    async fn get(&self, tenant_id: &str) -> BrandConfig {
        match self.get_inner(tenant_id).await {
            Ok(Some(cfg)) => cfg,
            Ok(None) => BrandConfig::default(),
            Err(e) => {
                tracing::warn!(target: "adapters.branding.pg", error = %e, "branding read failed; using default");
                BrandConfig::default()
            }
        }
    }

    async fn set(&self, tenant_id: &str, cfg: BrandConfig) {
        if let Err(e) = self.set_inner(tenant_id, &cfg).await {
            tracing::warn!(target: "adapters.branding.pg", error = %e, "branding write failed");
        }
    }
}

/// Bundle handed to the composition root.
pub(crate) struct BrandingBundle {
    /// HTTP-facing port bound onto `AppState`. The shared store is owned by
    /// the composition root (passed to both this bundle and the report
    /// adapter), so the bundle only needs to expose the port.
    pub branding: Arc<dyn BrandingPort>,
}

impl std::fmt::Debug for BrandingBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrandingBundle").finish_non_exhaustive()
    }
}

/// Build the branding bundle over the supplied store (in-memory for dev,
/// [`PgBrandingStore`] when Postgres is enabled).
pub(crate) fn build(store: Arc<dyn BrandingStore>) -> BrandingBundle {
    let branding: Arc<dyn BrandingPort> = Arc::new(BrandingAdapter { store });
    BrandingBundle { branding }
}

/// Projects a [`BrandConfig`] onto the wire view (logo re-encoded base64).
fn to_view(cfg: &BrandConfig) -> BrandingView {
    BrandingView {
        logo_png_base64: cfg.logo_png.as_ref().map(|b| B64.encode(b)),
        primary_color_hex: cfg.primary_color_hex.clone(),
        cover_md: cfg.cover_md.clone(),
        footer_md: cfg.footer_md.clone(),
    }
}

/// `BrandingPort` implementation over the shared branding store.
#[derive(Debug)]
struct BrandingAdapter {
    store: Arc<dyn BrandingStore>,
}

#[async_trait]
impl BrandingPort for BrandingAdapter {
    async fn get(&self, tenant_id: &str) -> Result<BrandingView, BrandingPortError> {
        Ok(to_view(&self.store.get(tenant_id).await))
    }

    async fn set(
        &self,
        tenant_id: &str,
        _actor: &str,
        req: SetBrandingRequest,
    ) -> Result<BrandingView, BrandingPortError> {
        // Defence in depth: re-validate the colour even though the wire
        // extractor already did (the port can be called from elsewhere).
        validate_hex_color(&req.primary_color_hex)
            .map_err(|_| BrandingPortError::Invalid("primary_color_hex must be #RRGGBB".into()))?;

        let logo_png = match req.logo_png_base64 {
            Some(ref s) if !s.is_empty() => {
                let bytes = B64.decode(s.as_bytes()).map_err(|e| {
                    BrandingPortError::Invalid(format!("logo is not valid base64: {e}"))
                })?;
                if bytes.len() > MAX_LOGO_BYTES {
                    return Err(BrandingPortError::Invalid(format!(
                        "logo exceeds {MAX_LOGO_BYTES} bytes (got {})",
                        bytes.len()
                    )));
                }
                // PNG magic number guard so a wrong file type is rejected early.
                if !bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
                    return Err(BrandingPortError::Invalid(
                        "logo must be a PNG image".into(),
                    ));
                }
                Some(bytes)
            }
            _ => None,
        };

        let cfg = BrandConfig {
            logo_png,
            primary_color_hex: req.primary_color_hex,
            footer_md: req.footer_md,
            cover_md: req.cover_md,
        };
        self.store.set(tenant_id, cfg.clone()).await;
        Ok(to_view(&cfg))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sx_report::model::branding::DEFAULT_PRIMARY_COLOR_HEX;

    const TENANT: &str = "t-demo";
    // 1x1 transparent PNG.
    const PNG_B64: &str =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

    #[tokio::test]
    async fn default_branding_when_unset() {
        let b = build(Arc::new(InMemoryBrandingStore::default()));
        let v = b.branding.get(TENANT).await.unwrap();
        assert_eq!(v.primary_color_hex, DEFAULT_PRIMARY_COLOR_HEX);
        assert!(v.logo_png_base64.is_none());
    }

    #[tokio::test]
    async fn set_then_get_round_trips_and_reaches_store() {
        let store = Arc::new(InMemoryBrandingStore::default());
        let b = build(Arc::clone(&store) as Arc<dyn BrandingStore>);
        let req = SetBrandingRequest {
            logo_png_base64: Some(PNG_B64.to_owned()),
            primary_color_hex: "#0A1B2C".to_owned(),
            cover_md: Some("# Acme Corp".to_owned()),
            footer_md: Some("confidential".to_owned()),
        };
        let v = b.branding.set(TENANT, "operator-1", req).await.unwrap();
        assert_eq!(v.primary_color_hex, "#0A1B2C");
        assert!(v.logo_png_base64.is_some());
        // The report renderer reads the SAME store.
        let cfg = store.get(TENANT).await;
        assert_eq!(cfg.primary_color_hex, "#0A1B2C");
        assert!(cfg.logo_png.is_some());
        assert_eq!(cfg.cover_md.as_deref(), Some("# Acme Corp"));
    }

    #[tokio::test]
    async fn rejects_bad_colour() {
        let b = build(Arc::new(InMemoryBrandingStore::default()));
        let req = SetBrandingRequest {
            logo_png_base64: None,
            primary_color_hex: "red".to_owned(),
            cover_md: None,
            footer_md: None,
        };
        assert!(b.branding.set(TENANT, "u", req).await.is_err());
    }

    #[tokio::test]
    async fn rejects_non_png_logo() {
        let b = build(Arc::new(InMemoryBrandingStore::default()));
        let req = SetBrandingRequest {
            logo_png_base64: Some(B64.encode(b"not a png")),
            primary_color_hex: "#112233".to_owned(),
            cover_md: None,
            footer_md: None,
        };
        let err = b.branding.set(TENANT, "u", req).await.unwrap_err();
        assert!(matches!(err, BrandingPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn tenants_are_isolated() {
        let b = build(Arc::new(InMemoryBrandingStore::default()));
        let req = SetBrandingRequest {
            logo_png_base64: None,
            primary_color_hex: "#445566".to_owned(),
            cover_md: None,
            footer_md: None,
        };
        b.branding.set("tenant-a", "u", req).await.unwrap();
        // tenant-b still sees defaults.
        let vb = b.branding.get("tenant-b").await.unwrap();
        assert_eq!(vb.primary_color_hex, DEFAULT_PRIMARY_COLOR_HEX);
    }
}
