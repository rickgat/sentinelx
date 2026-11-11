//! Postgres-backed [`TenantRepository`] adapter.

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::entity::Tenant;
use crate::domain::error::DomainError;
use crate::domain::port::TenantRepository;
use crate::domain::value_object::TenantId;
use crate::error::StorageError;

/// `PgTenantRepository` — `tenants` table adapter.
///
/// `tenants` is the *only* table not under RLS (it is itself the
/// tenant authority), so no tenant context is set here; isolation is
/// instead enforced by the application layer (only platform admins
/// reach this repository).
#[derive(Debug, Clone)]
pub struct PgTenantRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgTenantRepository {
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

fn row_to_tenant(row: &sqlx::postgres::PgRow) -> Result<Tenant, StorageError> {
    let id: Uuid = row.try_get("id").map_err(StorageError::from)?;
    let name: String = row.try_get("name").map_err(StorageError::from)?;
    let slug: String = row.try_get("slug").map_err(StorageError::from)?;
    let tier: String = row.try_get("tier").map_err(StorageError::from)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(StorageError::from)?;
    let deleted_at: Option<OffsetDateTime> =
        row.try_get("deleted_at").map_err(StorageError::from)?;
    Ok(Tenant {
        id: TenantId::from_uuid(id),
        name,
        slug,
        tier,
        created_at,
        deleted_at,
    })
}

#[async_trait]
impl TenantRepository for PgTenantRepository {
    async fn find_by_id(&self, id: TenantId) -> Result<Option<Tenant>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        self.apply_stmt_timeout(&mut tx).await?;

        let row = sqlx::query(
            "SELECT id, name, slug, tier, created_at, deleted_at \
             FROM tenants WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        match row {
            Some(r) => Ok(Some(row_to_tenant(&r)?)),
            None => Ok(None),
        }
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Tenant>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        self.apply_stmt_timeout(&mut tx).await?;

        let row = sqlx::query(
            "SELECT id, name, slug, tier, created_at, deleted_at \
             FROM tenants WHERE slug = $1 AND deleted_at IS NULL",
        )
        .bind(slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        match row {
            Some(r) => Ok(Some(row_to_tenant(&r)?)),
            None => Ok(None),
        }
    }

    async fn save(&self, tenant: &Tenant) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        self.apply_stmt_timeout(&mut tx).await?;

        sqlx::query(
            "INSERT INTO tenants (id, name, slug, tier, created_at, deleted_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO UPDATE SET \
                name = EXCLUDED.name, \
                slug = EXCLUDED.slug, \
                tier = EXCLUDED.tier, \
                deleted_at = EXCLUDED.deleted_at",
        )
        .bind(tenant.id.as_uuid())
        .bind(&tenant.name)
        .bind(&tenant.slug)
        .bind(&tenant.tier)
        .bind(tenant.created_at)
        .bind(tenant.deleted_at)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }

    async fn soft_delete(&self, id: TenantId) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        self.apply_stmt_timeout(&mut tx).await?;

        let affected = sqlx::query(
            "UPDATE tenants SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id.as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?
        .rows_affected();

        tx.commit().await.map_err(StorageError::from)?;

        if affected == 0 {
            return Err(DomainError::NotFound {
                entity: TenantId::entity_name(),
                id: id.to_string(),
            });
        }
        Ok(())
    }
}

fn map_sqlx(e: sqlx::Error) -> DomainError {
    StorageError::from(e).into()
}
