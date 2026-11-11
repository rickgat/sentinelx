//! Credentialed vulnerability-scanner ingest adapter (P0-002).
//!
//! Wraps the parser/dedup/registry pipeline from `sx-vuln-ingest`. Import
//! receipts (which tenant imported what, when, with what asset/finding
//! counts) back `GET /v1/vuln/imports`. In dev they live in an in-memory
//! ring buffer (cap 1000, newest-first); when the database is enabled they
//! are persisted to the pre-existing `vuln_imports` table (FORCE-RLS) so
//! the import history survives a restart. The wire-shape and port surface
//! are identical across both backends.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sqlx::{PgPool, Row as _};
use sx_api::port::{Phase3PortError, VulnIngestPort};
use sx_api::view::vuln_ingest_view::{VulnImportResponse, VulnImportView};
use sx_storage::domain::value_object::TenantId;
use sx_storage::tenant_context::TenantContext;
use sx_vuln_ingest::{InMemoryVulnIngestService, SourceFormat, VulnIngestError, VulnIngestService};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// Adapter holding the parser service plus the receipt store — an
/// in-memory ring in dev, or the Postgres `vuln_imports` table when the DB
/// is enabled.
pub(crate) struct VulnIngestAdapter {
    service: Arc<dyn VulnIngestService>,
    rows: Mutex<Vec<VulnImportView>>,
    /// `Some` when the DB is enabled — the durable home of import receipts.
    store: Option<Arc<PgVulnImportStore>>,
}

impl std::fmt::Debug for VulnIngestAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VulnIngestAdapter")
            .field("rows_len", &self.rows.lock().map(|r| r.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl VulnIngestAdapter {
    /// Maximum receipts retained in memory before oldest rows are evicted.
    pub(crate) const CAP: usize = 1000;

    pub(crate) fn new() -> Self {
        Self {
            service: Arc::new(InMemoryVulnIngestService::default()),
            rows: Mutex::new(Vec::new()),
            store: None,
        }
    }

    /// Durable variant — receipts persist to the `vuln_imports` table.
    /// Selected by the composition root when the database is enabled.
    pub(crate) fn new_pg(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            service: Arc::new(InMemoryVulnIngestService::default()),
            rows: Mutex::new(Vec::new()),
            store: Some(Arc::new(PgVulnImportStore {
                pool,
                stmt_timeout_ms,
            })),
        }
    }

    fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
    }

    fn map_err(err: VulnIngestError) -> Phase3PortError {
        match err {
            VulnIngestError::UnsupportedFormat(m)
            | VulnIngestError::UnrecognisedShape(m)
            | VulnIngestError::MissingField(m) => Phase3PortError::Invalid(m),
            VulnIngestError::PayloadTooLarge { actual, max } => {
                Phase3PortError::Invalid(format!("payload too large: {actual} > {max}"))
            }
            VulnIngestError::Xml(m) => Phase3PortError::Invalid(format!("xml: {m}")),
            VulnIngestError::Internal(m) => Phase3PortError::Internal(m),
        }
    }
}

#[async_trait]
impl VulnIngestPort for VulnIngestAdapter {
    async fn import(
        &self,
        tenant_id: &str,
        source: &str,
        payload: &[u8],
    ) -> Result<VulnImportResponse, Phase3PortError> {
        let fmt = SourceFormat::parse(source)
            .ok_or_else(|| Phase3PortError::Invalid(format!("unsupported source: {source}")))?;
        let report = self
            .service
            .import(tenant_id, fmt, payload)
            .await
            .map_err(Self::map_err)?;

        let asset_count = u32::try_from(report.asset_count).unwrap_or(u32::MAX);
        let finding_count = u32::try_from(report.finding_count).unwrap_or(u32::MAX);
        let duplicates_dropped = u32::try_from(report.duplicates_dropped).unwrap_or(u32::MAX);
        let parse_errors = u32::try_from(report.parse_errors).unwrap_or(u32::MAX);

        let status = if report.parse_errors > 0 {
            "partial"
        } else {
            "ok"
        };

        let view = VulnImportView {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_owned(),
            source: fmt.as_str().to_owned(),
            asset_count,
            finding_count,
            ingested_at: Self::now_rfc3339(),
            status: status.to_owned(),
        };

        // Durable store when the DB is enabled; otherwise the in-memory
        // ring. The receipt is the only persisted artefact — the parsed
        // findings are folded into the main findings table by the
        // pipeline above.
        if let Some(store) = &self.store {
            store.insert(&view).await?;
        } else {
            let mut guard = self
                .rows
                .lock()
                .map_err(|_| Phase3PortError::Internal("vuln_ingest rows poisoned".into()))?;
            guard.insert(0, view.clone());
            if guard.len() > Self::CAP {
                guard.truncate(Self::CAP);
            }
        }

        Ok(VulnImportResponse {
            import: view,
            duplicates_dropped,
            parse_errors,
        })
    }

    async fn list(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<VulnImportView>, Phase3PortError> {
        if let Some(store) = &self.store {
            return store.list(tenant_id, limit).await;
        }
        let guard = self
            .rows
            .lock()
            .map_err(|_| Phase3PortError::Internal("vuln_ingest rows poisoned".into()))?;
        let capped = limit.min(Self::CAP);
        let out: Vec<VulnImportView> = guard
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .take(capped)
            .cloned()
            .collect();
        Ok(out)
    }
}

/// Postgres store for vuln-import receipts — the pre-existing
/// `vuln_imports` table (FORCE-RLS on `app_current_tenant()`). The receipt
/// is small, append-only and read often, so the full history is retained
/// (no in-memory-style cap); `list` applies the caller's limit.
struct PgVulnImportStore {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgVulnImportStore {
    fn err(e: impl std::fmt::Display) -> Phase3PortError {
        Phase3PortError::Internal(format!("vuln import store: {e}"))
    }

    fn tenant_uuid(tenant_id: &str) -> Result<Uuid, Phase3PortError> {
        Uuid::parse_str(tenant_id)
            .map_err(|e| Phase3PortError::Invalid(format!("tenant id not a uuid: {e}")))
    }

    async fn begin(
        &self,
        tenant: Uuid,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, Phase3PortError> {
        let mut tx = self.pool.begin().await.map_err(Self::err)?;
        TenantContext::apply(&mut tx, TenantId::from_uuid(tenant), self.stmt_timeout_ms)
            .await
            .map_err(Self::err)?;
        Ok(tx)
    }

    async fn insert(&self, view: &VulnImportView) -> Result<(), Phase3PortError> {
        let tenant = Self::tenant_uuid(&view.tenant_id)?;
        let id = Uuid::parse_str(&view.id)
            .map_err(|e| Phase3PortError::Invalid(format!("import id not a uuid: {e}")))?;
        let ingested_at = OffsetDateTime::parse(&view.ingested_at, &Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let asset_count = i32::try_from(view.asset_count).unwrap_or(i32::MAX);
        let finding_count = i32::try_from(view.finding_count).unwrap_or(i32::MAX);
        let mut tx = self.begin(tenant).await?;
        sqlx::query(
            "INSERT INTO vuln_imports \
                 (id, tenant_id, source, asset_count, finding_count, ingested_at, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(tenant)
        .bind(&view.source)
        .bind(asset_count)
        .bind(finding_count)
        .bind(ingested_at)
        .bind(&view.status)
        .execute(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)
    }

    async fn list(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<VulnImportView>, Phase3PortError> {
        let tenant = Self::tenant_uuid(tenant_id)?;
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut tx = self.begin(tenant).await?;
        let rows = sqlx::query(
            "SELECT id, source, asset_count, finding_count, ingested_at, status \
             FROM vuln_imports \
             WHERE tenant_id = $1 \
             ORDER BY ingested_at DESC \
             LIMIT $2",
        )
        .bind(tenant)
        .bind(lim)
        .fetch_all(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        rows.into_iter()
            .map(|r| {
                let ingested: OffsetDateTime = r.try_get("ingested_at").map_err(Self::err)?;
                let asset_count: i32 = r.try_get("asset_count").map_err(Self::err)?;
                let finding_count: i32 = r.try_get("finding_count").map_err(Self::err)?;
                Ok(VulnImportView {
                    id: r.try_get::<Uuid, _>("id").map_err(Self::err)?.to_string(),
                    tenant_id: tenant_id.to_owned(),
                    source: r.try_get("source").map_err(Self::err)?,
                    asset_count: u32::try_from(asset_count).unwrap_or(0),
                    finding_count: u32::try_from(finding_count).unwrap_or(0),
                    ingested_at: ingested.format(&Rfc3339).unwrap_or_default(),
                    status: r.try_get("status").map_err(Self::err)?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const NESSUS_FIXTURE: &str = r#"<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="t">
    <ReportHost name="10.0.0.1">
      <ReportItem pluginID="51192" pluginName="SSL Expired" severity="3">
        <description>d</description><solution>s</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"#;

    #[tokio::test]
    async fn import_records_receipt_and_list_returns_it() {
        let a = VulnIngestAdapter::new();
        let resp = a
            .import("tenant-a", "nessus", NESSUS_FIXTURE.as_bytes())
            .await
            .unwrap();
        assert_eq!(resp.import.tenant_id, "tenant-a");
        assert_eq!(resp.import.source, "nessus");
        assert_eq!(resp.import.asset_count, 1);
        assert_eq!(resp.import.finding_count, 1);
        assert_eq!(resp.import.status, "ok");

        let items = a.list("tenant-a", 10).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].source, "nessus");
    }

    #[tokio::test]
    async fn list_is_tenant_scoped() {
        let a = VulnIngestAdapter::new();
        a.import("tenant-a", "nessus", NESSUS_FIXTURE.as_bytes())
            .await
            .unwrap();
        a.import("tenant-b", "nessus", NESSUS_FIXTURE.as_bytes())
            .await
            .unwrap();
        let a_items = a.list("tenant-a", 10).await.unwrap();
        let b_items = a.list("tenant-b", 10).await.unwrap();
        assert_eq!(a_items.len(), 1);
        assert_eq!(b_items.len(), 1);
        assert_ne!(a_items[0].id, b_items[0].id);
    }

    #[tokio::test]
    async fn unsupported_source_is_rejected() {
        let a = VulnIngestAdapter::new();
        let err = a
            .import("t", "qualys", NESSUS_FIXTURE.as_bytes())
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn malformed_xml_is_rejected() {
        let a = VulnIngestAdapter::new();
        let err = a.import("t", "nessus", b"<garbage/>").await.unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn list_clamps_to_cap() {
        let a = VulnIngestAdapter::new();
        a.import("t", "nessus", NESSUS_FIXTURE.as_bytes())
            .await
            .unwrap();
        let items = a.list("t", usize::MAX).await.unwrap();
        assert!(items.len() <= VulnIngestAdapter::CAP);
    }

    /// Durability proof against a real Postgres: an import receipt written
    /// for a freshly-seeded tenant survives a *fresh adapter (restart-
    /// equivalent)* and is tenant-scoped on read-back. Gated on
    /// `TEST_DATABASE_URL` (silent no-op in CI).
    #[tokio::test]
    async fn pg_vuln_import_receipt_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = uuid::Uuid::new_v4();
        let tenant_s = tenant.to_string();

        // Seed the tenant (RLS policies need the GUC tenant to exist for a
        // clean cascade on cleanup; the table has no FK but we tidy up).
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, tier) VALUES ($1, $2, $3, 'starter') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(tenant)
            .bind(format!("vi-{tenant}"))
            .bind(format!("vi-{tenant}"))
            .execute(&pool)
            .await
            .expect("seed tenant");
        }

        // First process: import a Nessus report → receipt persisted.
        let import_id = {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let a = VulnIngestAdapter::new_pg(pool, 15_000);
            let resp = a
                .import(&tenant_s, "nessus", NESSUS_FIXTURE.as_bytes())
                .await
                .expect("import");
            assert_eq!(resp.import.status, "ok");
            resp.import.id
        };

        // Fresh adapter == a fresh process. An in-memory ring would be empty.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let a = VulnIngestAdapter::new_pg(pool, 15_000);
            let items = a.list(&tenant_s, 10).await.expect("list");
            assert_eq!(items.len(), 1, "receipt survived restart");
            assert_eq!(items[0].id, import_id);
            assert_eq!(items[0].source, "nessus");
            assert_eq!(items[0].asset_count, 1);
            assert_eq!(items[0].finding_count, 1);

            // Another tenant sees nothing (RLS + predicate).
            let other = uuid::Uuid::new_v4().to_string();
            let empty = a.list(&other, 10).await.expect("list other");
            assert!(empty.is_empty(), "receipts are tenant-scoped");
        }

        // Cleanup. vuln_imports is FORCE-RLS with no FK to tenants, so the
        // receipts must be deleted inside a tenant-scoped tx (the GUC must
        // be set for RLS to permit the delete); the tenants row is not
        // under RLS.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let mut tx = pool.begin().await.expect("begin cleanup");
            sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
                .bind(tenant.to_string())
                .execute(&mut *tx)
                .await
                .expect("set tenant guc");
            sqlx::query("DELETE FROM vuln_imports WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&mut *tx)
                .await
                .expect("cleanup receipts");
            tx.commit().await.expect("commit cleanup");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup tenant");
        }
    }
}
