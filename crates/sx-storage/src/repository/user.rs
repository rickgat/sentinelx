//! Postgres-backed [`UserRepository`] adapter.

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::entity::User;
use crate::domain::error::DomainError;
use crate::domain::port::UserRepository;
use crate::domain::value_object::{Page, PagedResult, TenantId, UserId};
use crate::error::StorageError;
use crate::pagination::SqlBounds;
use crate::tenant_context::TenantContext;

/// `PgUserRepository` — `users` table adapter (RLS-enabled).
#[derive(Debug, Clone)]
pub struct PgUserRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgUserRepository {
    /// Construct from a pre-built pool.
    #[must_use]
    pub const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }
}

fn row_to_user(row: &sqlx::postgres::PgRow) -> Result<User, StorageError> {
    let id: Uuid = row.try_get("id").map_err(StorageError::from)?;
    let tenant_id: Uuid = row.try_get("tenant_id").map_err(StorageError::from)?;
    let email: String = row.try_get("email").map_err(StorageError::from)?;
    let password_hash: String = row.try_get("password_hash").map_err(StorageError::from)?;
    let display_name: String = row.try_get("display_name").map_err(StorageError::from)?;
    let is_active: bool = row.try_get("is_active").map_err(StorageError::from)?;
    let mfa_enrolled: bool = row.try_get("mfa_enrolled").map_err(StorageError::from)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(StorageError::from)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(StorageError::from)?;
    Ok(User {
        id: UserId::from_uuid(id),
        tenant_id: TenantId::from_uuid(tenant_id),
        email,
        password_hash,
        display_name,
        is_active,
        mfa_enrolled,
        created_at,
        updated_at,
    })
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: UserId,
    ) -> Result<Option<User>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT id, tenant_id, email::text AS email, password_hash, display_name, \
                    is_active, mfa_enrolled, created_at, updated_at \
             FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        match row {
            Some(r) => Ok(Some(row_to_user(&r)?)),
            None => Ok(None),
        }
    }

    async fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT id, tenant_id, email::text AS email, password_hash, display_name, \
                    is_active, mfa_enrolled, created_at, updated_at \
             FROM users WHERE email = $1::citext AND tenant_id = $2",
        )
        .bind(email)
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        match row {
            Some(r) => Ok(Some(row_to_user(&r)?)),
            None => Ok(None),
        }
    }

    async fn save(&self, user: &User) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, user.tenant_id, self.stmt_timeout_ms).await?;

        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash, display_name, \
                                is_active, mfa_enrolled, created_at, updated_at) \
             VALUES ($1, $2, $3::citext, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO UPDATE SET \
                email = EXCLUDED.email, \
                password_hash = EXCLUDED.password_hash, \
                display_name = EXCLUDED.display_name, \
                is_active = EXCLUDED.is_active, \
                mfa_enrolled = EXCLUDED.mfa_enrolled, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind(user.id.as_uuid())
        .bind(user.tenant_id.as_uuid())
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(&user.display_name)
        .bind(user.is_active)
        .bind(user.mfa_enrolled)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: TenantId,
        page: Page,
    ) -> Result<PagedResult<User>, DomainError> {
        let bounds: SqlBounds = page.into();

        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM users WHERE tenant_id = $1")
                .bind(tenant_id.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .map_err(StorageError::from)?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, email::text AS email, password_hash, display_name, \
                    is_active, mfa_enrolled, created_at, updated_at \
             FROM users WHERE tenant_id = $1 \
             ORDER BY created_at, id LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id.as_uuid())
        .bind(bounds.limit)
        .bind(bounds.offset)
        .fetch_all(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        let mut items = Vec::with_capacity(rows.len());
        for r in &rows {
            items.push(row_to_user(r)?);
        }

        let total_u: u64 = total.try_into().unwrap_or(0);
        Ok(PagedResult::new(items, total_u, page))
    }
}

fn map_sqlx(e: sqlx::Error) -> DomainError {
    StorageError::from(e).into()
}
