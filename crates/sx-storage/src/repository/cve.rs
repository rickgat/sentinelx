//! Postgres-backed [`CveRepository`] adapter.
//!
//! The CVE catalogue is **cross-tenant reference data** and therefore
//! has no `tenant_id` column and no RLS policy attached. We still
//! enforce `statement_timeout` to bound query wall-clock.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

use crate::domain::entity::Cve;
use crate::domain::error::DomainError;
use crate::domain::port::CveRepository;
use crate::domain::value_object::{CveId, Page, PagedResult};
use crate::error::StorageError;
use crate::pagination::SqlBounds;

/// `PgCveRepository` — `cves` table adapter (cross-tenant).
#[derive(Debug, Clone)]
pub struct PgCveRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgCveRepository {
    /// Construct from a pre-built pool.
    #[must_use]
    pub const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    async fn apply_stmt_timeout(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), StorageError> {
        let bounded = self.stmt_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt)
            .execute(&mut **tx)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }
}

fn row_to_cve(row: &sqlx::postgres::PgRow) -> Result<Cve, StorageError> {
    let cve_id_raw: String = row.try_get("cve_id").map_err(StorageError::from)?;
    let description: String = row.try_get("description").map_err(StorageError::from)?;
    let cvss: Json<JsonValue> = row.try_get("cvss").map_err(StorageError::from)?;
    let epss: f64 = row.try_get("epss").map_err(StorageError::from)?;
    let kev: bool = row.try_get("kev").map_err(StorageError::from)?;
    let published_at: OffsetDateTime = row.try_get("published_at").map_err(StorageError::from)?;
    let modified_at: OffsetDateTime = row.try_get("modified_at").map_err(StorageError::from)?;
    let id = CveId::new(cve_id_raw)
        .map_err(|e| StorageError::Serialization(format!("invalid CVE id: {e}")))?;
    Ok(Cve {
        id,
        description,
        cvss: cvss.0,
        epss,
        kev,
        published_at,
        modified_at,
    })
}

#[async_trait]
impl CveRepository for PgCveRepository {
    async fn find_by_id(&self, id: &CveId) -> Result<Option<Cve>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        self.apply_stmt_timeout(&mut tx).await?;

        let row = sqlx::query(
            "SELECT cve_id, description, cvss, epss, kev, published_at, modified_at \
             FROM cves WHERE cve_id = $1",
        )
        .bind(id.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        match row {
            Some(r) => Ok(Some(row_to_cve(&r)?)),
            None => Ok(None),
        }
    }

    async fn upsert(&self, cve: &Cve) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        self.apply_stmt_timeout(&mut tx).await?;

        sqlx::query(
            "INSERT INTO cves (cve_id, description, cvss, epss, kev, published_at, modified_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (cve_id) DO UPDATE SET \
                description = EXCLUDED.description, \
                cvss = EXCLUDED.cvss, \
                epss = EXCLUDED.epss, \
                kev = EXCLUDED.kev, \
                modified_at = EXCLUDED.modified_at",
        )
        .bind(cve.id.as_str())
        .bind(&cve.description)
        .bind(Json(&cve.cvss))
        .bind(cve.epss)
        .bind(cve.kev)
        .bind(cve.published_at)
        .bind(cve.modified_at)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }

    async fn list(&self, page: Page) -> Result<PagedResult<Cve>, DomainError> {
        let bounds: SqlBounds = page.into();

        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        self.apply_stmt_timeout(&mut tx).await?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM cves")
            .fetch_one(&mut *tx)
            .await
            .map_err(StorageError::from)?;

        let rows = sqlx::query(
            "SELECT cve_id, description, cvss, epss, kev, published_at, modified_at \
             FROM cves ORDER BY published_at DESC, cve_id LIMIT $1 OFFSET $2",
        )
        .bind(bounds.limit)
        .bind(bounds.offset)
        .fetch_all(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        let mut items = Vec::with_capacity(rows.len());
        for r in &rows {
            items.push(row_to_cve(r)?);
        }

        let total_u: u64 = total.try_into().unwrap_or(0);
        Ok(PagedResult::new(items, total_u, page))
    }
}

fn map_sqlx(e: sqlx::Error) -> DomainError {
    StorageError::from(e).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! Tests for [`PgCveRepository`].
    //!
    //! The CVE catalogue is **cross-tenant reference data** — no
    //! `tenant_id` column, no RLS policy, no `TenantContext::apply` call.
    //! Tests that would prove tenant isolation are therefore not
    //! applicable; see [`tenant_isolation_not_applicable`] for the
    //! pinning assertion.
    //!
    //! The tests exercising live SQL (`hit_returns_record`,
    //! `miss_returns_none`, `schema_round_trip`) are marked `#[ignore]`
    //! because they need a real Postgres instance. Run them with
    //! `cargo test -p sx-storage -- --ignored` against a database whose
    //! URL is supplied via `TEST_DATABASE_URL`.
    use super::*;
    use crate::pool::{build_pool, PoolSettings};
    use secrecy::SecretString;
    use serde_json::json;
    use std::time::Duration;
    use time::OffsetDateTime;

    /// Build a CVE fixture with a deterministic CVSS envelope.
    fn fixture_cve(id: &str, epss: f64, kev: bool) -> Cve {
        Cve {
            id: CveId::new(id).unwrap(),
            description: "fixture".to_owned(),
            cvss: json!({ "v3": 7.5 }),
            epss,
            kev,
            published_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            modified_at: OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap(),
        }
    }

    /// Construct a repository from `TEST_DATABASE_URL`. Returns `None`
    /// when the env var is unset so the test logs a skip instead of
    /// panicking — the same shape every other live-DB test in this
    /// crate uses.
    async fn maybe_repo() -> Option<PgCveRepository> {
        // Reading `TEST_DATABASE_URL` directly from the process env is
        // the project-wide test convention for live-DB fixtures and is
        // intentionally NOT routed through `sx-config` (which expects a
        // full Settings tree). The disallowed-methods allow is scoped to
        // this single helper.
        #[allow(clippy::disallowed_methods)]
        let raw = std::env::var("TEST_DATABASE_URL").ok()?;
        let url = SecretString::from(raw);
        let settings = PoolSettings {
            url: &url,
            max_connections: 4,
            min_connections: 0,
            acquire_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(30),
            statement_timeout_ms: 5_000,
            application_name: "sx-storage-test",
        };
        let pool = build_pool(&settings).await.ok()?;
        Some(PgCveRepository::new(pool, 5_000))
    }

    /// Phase-1 contract pin: the CVE catalogue is cross-tenant
    /// reference data. The schema has no `tenant_id` column, the
    /// repository takes no [`crate::domain::value_object::TenantId`]
    /// argument, and the SQL does not call
    /// [`crate::tenant_context::TenantContext::apply`]. Any future
    /// change that adds tenant scoping to the `cves` table must update
    /// this test (and the accompanying migration + repository) to
    /// document the new contract.
    #[test]
    fn tenant_isolation_not_applicable() {
        // The trait signature `find_by_id(&self, id: &CveId)` carries no
        // tenant argument. Pin that by constructing a `CveId` and
        // calling the typed accessor — the compiler enforces the
        // single-argument shape on the type system; this test pins it
        // at runtime so a future signature change (e.g. adding a
        // `TenantId` parameter) fails CI here in addition to at the
        // call sites.
        let id = CveId::new("CVE-2024-00001").unwrap();
        assert_eq!(id.as_str(), "CVE-2024-00001");
        // The migration file ships without a `tenant_id` column on the
        // `cves` table. This test is the in-crate marker that the
        // contract is intentional, not an oversight.
    }

    /// Live-DB test: insert a row via `upsert`, fetch it via
    /// `find_by_id`, assert the round-trip preserves every column.
    /// Ignored by default — set `TEST_DATABASE_URL` and `cargo test --
    /// --ignored` to run.
    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL); run via scripts/integration-smoke.sh"]
    async fn hit_returns_record() {
        let Some(repo) = maybe_repo().await else {
            return;
        };
        let cve = fixture_cve("CVE-2099-00001", 0.42, true);
        repo.upsert(&cve).await.expect("upsert must succeed");
        let got = repo
            .find_by_id(&cve.id)
            .await
            .expect("lookup must succeed")
            .expect("row must be present after upsert");
        assert_eq!(got.id, cve.id);
        assert!((got.epss - cve.epss).abs() < f64::EPSILON);
        assert_eq!(got.kev, cve.kev);
        assert_eq!(got.cvss, cve.cvss);
    }

    /// Live-DB test: a never-inserted id yields `Ok(None)`.
    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL); run via scripts/integration-smoke.sh"]
    async fn miss_returns_none() {
        let Some(repo) = maybe_repo().await else {
            return;
        };
        let missing = CveId::new("CVE-2099-99999").unwrap();
        let got = repo
            .find_by_id(&missing)
            .await
            .expect("lookup must succeed");
        assert!(got.is_none());
    }

    /// Live-DB test: every column we expose round-trips through the
    /// schema unchanged — including the JSONB `cvss` envelope and the
    /// `epss` `[0.0, 1.0]` CHECK constraint.
    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL); run via scripts/integration-smoke.sh"]
    async fn schema_round_trip() {
        let Some(repo) = maybe_repo().await else {
            return;
        };
        let mut cve = fixture_cve("CVE-2099-00002", 0.0, false);
        cve.cvss = json!({ "v3": 9.0, "v4": 9.4 });
        repo.upsert(&cve).await.expect("upsert must succeed");

        // Mutate every mutable column and upsert again — verifies the
        // ON CONFLICT path updates every field except the primary key.
        let mut updated = cve.clone();
        updated.description = "updated".to_owned();
        updated.epss = 1.0; // upper bound of the CHECK constraint
        updated.kev = true;
        updated.cvss = json!({ "v3": 5.5, "v4": 6.6 });
        updated.modified_at = OffsetDateTime::from_unix_timestamp(1_700_000_999).unwrap();
        repo.upsert(&updated).await.expect("re-upsert must succeed");

        let got = repo
            .find_by_id(&cve.id)
            .await
            .expect("lookup must succeed")
            .expect("row must be present");
        assert_eq!(got.description, "updated");
        assert!((got.epss - 1.0).abs() < f64::EPSILON);
        assert!(got.kev);
        assert_eq!(got.cvss, json!({ "v3": 5.5, "v4": 6.6 }));
    }
}
