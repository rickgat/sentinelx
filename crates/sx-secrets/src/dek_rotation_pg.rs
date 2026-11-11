//! Postgres-backed [`RotationProgressStore`] and [`RotationPolicyStore`]
//! implementations.
//!
//! Both adapters follow the same pattern as [`crate::dek_pg::PgDekStore`]:
//! every operation runs inside a short transaction whose first
//! statement applies the tenant-scoped GUC (`app.current_tenant_id`)
//! and a `statement_timeout` bound. RLS therefore guarantees that a
//! buggy caller cannot enumerate another tenant's rows even when the
//! application logic is wrong.
//!
//! The scheduler's `list_all` runs without a tenant context — by design
//! it must see every policy row to evaluate `is_due`. It therefore runs
//! under a service role with `BYPASSRLS` set; see
//! `docs/operations/dek-rotation.md` for the bootstrap recipe.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use crate::dek::TenantId;
use crate::dek_rotation::{
    DekRotationError, RotationCheckpoint, RotationJobStatus, RotationPolicyRow,
    RotationPolicyStore, RotationProgressStore,
};

/// Default `statement_timeout` (ms) applied to every rotation
/// progress / policy transaction when the caller does not override.
const DEFAULT_STMT_TIMEOUT_MS: u64 = 5_000;

/// Postgres-backed [`RotationProgressStore`].
#[derive(Debug, Clone)]
pub struct PgRotationProgressStore {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgRotationProgressStore {
    /// Construct from a pre-built pool with the default statement
    /// timeout.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self {
            pool,
            stmt_timeout_ms: DEFAULT_STMT_TIMEOUT_MS,
        }
    }

    /// Construct with an explicit statement timeout (ms).
    #[must_use]
    pub const fn with_statement_timeout(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    /// Borrow the underlying pool.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn apply_tenant_context(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: TenantId,
        stmt_timeout_ms: u64,
    ) -> Result<(), DekRotationError> {
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut **tx)
            .await
            .map_err(DekRotationError::store)?;
        let bounded = stmt_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt)
            .execute(&mut **tx)
            .await
            .map_err(DekRotationError::store)?;
        Ok(())
    }
}

#[async_trait]
impl RotationProgressStore for PgRotationProgressStore {
    async fn upsert(&self, checkpoint: &RotationCheckpoint) -> Result<(), DekRotationError> {
        let version_i32 = i32::try_from(checkpoint.target_dek_version)
            .map_err(|e| DekRotationError::store(format!("target_dek_version: {e}")))?;
        let total_i64 = i64::try_from(checkpoint.total_rows)
            .map_err(|e| DekRotationError::store(format!("total_rows: {e}")))?;
        let processed_i64 = i64::try_from(checkpoint.processed_rows)
            .map_err(|e| DekRotationError::store(format!("processed_rows: {e}")))?;

        let mut tx = self.pool.begin().await.map_err(DekRotationError::store)?;
        Self::apply_tenant_context(&mut tx, checkpoint.tenant_id, self.stmt_timeout_ms).await?;

        // Atomically validate state transition: if a row exists and the
        // current status cannot transition to the new one, reject.
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT status FROM dek_rotation_progress \
             WHERE tenant_id = $1 AND target_dek_version = $2",
        )
        .bind(checkpoint.tenant_id.as_uuid())
        .bind(version_i32)
        .fetch_optional(&mut *tx)
        .await
        .map_err(DekRotationError::store)?;

        if let Some(existing_str) = existing {
            if let Some(existing) = RotationJobStatus::parse(&existing_str) {
                if existing != checkpoint.status && !existing.can_transition_to(checkpoint.status) {
                    return Err(DekRotationError::IllegalTransition {
                        from: existing,
                        to: checkpoint.status,
                    });
                }
            }
        }

        sqlx::query(
            "INSERT INTO dek_rotation_progress \
             (tenant_id, target_dek_version, last_processed_row_id, total_rows, \
              processed_rows, started_at, last_checkpoint_at, status, last_error) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (tenant_id, target_dek_version) DO UPDATE SET \
                 last_processed_row_id = EXCLUDED.last_processed_row_id, \
                 total_rows            = EXCLUDED.total_rows, \
                 processed_rows        = EXCLUDED.processed_rows, \
                 last_checkpoint_at    = EXCLUDED.last_checkpoint_at, \
                 status                = EXCLUDED.status, \
                 last_error            = EXCLUDED.last_error",
        )
        .bind(checkpoint.tenant_id.as_uuid())
        .bind(version_i32)
        .bind(&checkpoint.last_processed_row_id)
        .bind(total_i64)
        .bind(processed_i64)
        .bind(checkpoint.started_at)
        .bind(checkpoint.last_checkpoint_at)
        .bind(checkpoint.status.as_str())
        .bind(&checkpoint.last_error)
        .execute(&mut *tx)
        .await
        .map_err(DekRotationError::store)?;

        tx.commit().await.map_err(DekRotationError::store)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant_id: TenantId,
        target_dek_version: u32,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError> {
        let version_i32 = i32::try_from(target_dek_version)
            .map_err(|e| DekRotationError::store(format!("target_dek_version: {e}")))?;
        let mut tx = self.pool.begin().await.map_err(DekRotationError::store)?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.stmt_timeout_ms).await?;
        let row = sqlx::query(
            "SELECT tenant_id, target_dek_version, last_processed_row_id, \
                    total_rows, processed_rows, started_at, last_checkpoint_at, \
                    status, last_error \
             FROM dek_rotation_progress \
             WHERE tenant_id = $1 AND target_dek_version = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(version_i32)
        .fetch_optional(&mut *tx)
        .await
        .map_err(DekRotationError::store)?;
        tx.commit().await.map_err(DekRotationError::store)?;
        row.as_ref().map(checkpoint_from_row).transpose()
    }

    async fn latest_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError> {
        let mut tx = self.pool.begin().await.map_err(DekRotationError::store)?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.stmt_timeout_ms).await?;
        let row = sqlx::query(
            "SELECT tenant_id, target_dek_version, last_processed_row_id, \
                    total_rows, processed_rows, started_at, last_checkpoint_at, \
                    status, last_error \
             FROM dek_rotation_progress \
             WHERE tenant_id = $1 \
             ORDER BY target_dek_version DESC \
             LIMIT 1",
        )
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(DekRotationError::store)?;
        tx.commit().await.map_err(DekRotationError::store)?;
        row.as_ref().map(checkpoint_from_row).transpose()
    }
}

fn checkpoint_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<RotationCheckpoint, DekRotationError> {
    let tenant_uuid: uuid::Uuid = row.try_get("tenant_id").map_err(DekRotationError::store)?;
    let version_i32: i32 = row
        .try_get("target_dek_version")
        .map_err(DekRotationError::store)?;
    let last_processed: Option<String> = row
        .try_get("last_processed_row_id")
        .map_err(DekRotationError::store)?;
    let total_i64: i64 = row.try_get("total_rows").map_err(DekRotationError::store)?;
    let processed_i64: i64 = row
        .try_get("processed_rows")
        .map_err(DekRotationError::store)?;
    let started_at: DateTime<Utc> = row.try_get("started_at").map_err(DekRotationError::store)?;
    let last_checkpoint_at: DateTime<Utc> = row
        .try_get("last_checkpoint_at")
        .map_err(DekRotationError::store)?;
    let status_str: String = row.try_get("status").map_err(DekRotationError::store)?;
    let last_error: Option<String> = row.try_get("last_error").map_err(DekRotationError::store)?;

    let target_dek_version = u32::try_from(version_i32)
        .map_err(|e| DekRotationError::store(format!("target_dek_version: {e}")))?;
    let total_rows = u64::try_from(total_i64)
        .map_err(|e| DekRotationError::store(format!("total_rows: {e}")))?;
    let processed_rows = u64::try_from(processed_i64)
        .map_err(|e| DekRotationError::store(format!("processed_rows: {e}")))?;
    let status = RotationJobStatus::parse(&status_str)
        .ok_or_else(|| DekRotationError::store(format!("unknown status `{status_str}` from DB")))?;

    Ok(RotationCheckpoint {
        tenant_id: TenantId::new(tenant_uuid),
        target_dek_version,
        last_processed_row_id: last_processed,
        total_rows,
        processed_rows,
        started_at,
        last_checkpoint_at,
        status,
        last_error,
    })
}

/// Postgres-backed [`RotationPolicyStore`].
#[derive(Debug, Clone)]
pub struct PgRotationPolicyStore {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgRotationPolicyStore {
    /// Construct from a pre-built pool with the default statement
    /// timeout.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self {
            pool,
            stmt_timeout_ms: DEFAULT_STMT_TIMEOUT_MS,
        }
    }

    /// Construct with an explicit statement timeout (ms).
    #[must_use]
    pub const fn with_statement_timeout(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    /// Borrow the underlying pool.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn apply_tenant_context(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: TenantId,
        stmt_timeout_ms: u64,
    ) -> Result<(), DekRotationError> {
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut **tx)
            .await
            .map_err(DekRotationError::store)?;
        let bounded = stmt_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt)
            .execute(&mut **tx)
            .await
            .map_err(DekRotationError::store)?;
        Ok(())
    }
}

#[async_trait]
impl RotationPolicyStore for PgRotationPolicyStore {
    async fn get(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationPolicyRow>, DekRotationError> {
        let mut tx = self.pool.begin().await.map_err(DekRotationError::store)?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.stmt_timeout_ms).await?;
        let row = sqlx::query(
            "SELECT tenant_id, cadence_days, last_rotated_at, updated_at \
             FROM dek_rotation_policy \
             WHERE tenant_id = $1",
        )
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(DekRotationError::store)?;
        tx.commit().await.map_err(DekRotationError::store)?;
        row.as_ref().map(policy_row_from_row).transpose()
    }

    async fn upsert(&self, row: &RotationPolicyRow) -> Result<(), DekRotationError> {
        let mut tx = self.pool.begin().await.map_err(DekRotationError::store)?;
        Self::apply_tenant_context(&mut tx, row.tenant_id, self.stmt_timeout_ms).await?;
        sqlx::query(
            "INSERT INTO dek_rotation_policy \
             (tenant_id, cadence_days, last_rotated_at, updated_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
                 cadence_days     = EXCLUDED.cadence_days, \
                 last_rotated_at  = EXCLUDED.last_rotated_at, \
                 updated_at       = EXCLUDED.updated_at",
        )
        .bind(row.tenant_id.as_uuid())
        .bind(row.cadence_days)
        .bind(row.last_rotated_at)
        .bind(row.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(DekRotationError::store)?;
        tx.commit().await.map_err(DekRotationError::store)?;
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<RotationPolicyRow>, DekRotationError> {
        // The scheduler runs under BYPASSRLS — no tenant context is
        // applied here. Operators MUST ensure the role on this pool
        // carries BYPASSRLS (see docs/operations/dek-rotation.md).
        let mut tx = self.pool.begin().await.map_err(DekRotationError::store)?;
        let bounded = self.stmt_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt)
            .execute(&mut *tx)
            .await
            .map_err(DekRotationError::store)?;
        let rows = sqlx::query(
            "SELECT tenant_id, cadence_days, last_rotated_at, updated_at \
             FROM dek_rotation_policy",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(DekRotationError::store)?;
        tx.commit().await.map_err(DekRotationError::store)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(policy_row_from_row(&row)?);
        }
        Ok(out)
    }
}

fn policy_row_from_row(row: &sqlx::postgres::PgRow) -> Result<RotationPolicyRow, DekRotationError> {
    let tenant_uuid: uuid::Uuid = row.try_get("tenant_id").map_err(DekRotationError::store)?;
    let cadence_days: i32 = row
        .try_get("cadence_days")
        .map_err(DekRotationError::store)?;
    let last_rotated_at: Option<DateTime<Utc>> = row
        .try_get("last_rotated_at")
        .map_err(DekRotationError::store)?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(DekRotationError::store)?;
    Ok(RotationPolicyRow {
        tenant_id: TenantId::new(tenant_uuid),
        cadence_days,
        last_rotated_at,
        updated_at,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    //! Live-DB tests are gated by `#[ignore]` because they require
    //! Postgres on `TEST_DATABASE_URL` with the rotation migration
    //! applied. The constructor tests run unconditionally and verify
    //! the lazy-pool no-I/O contract.

    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn new_does_not_perform_io() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy must not perform I/O");
        let progress = PgRotationProgressStore::new(pool.clone());
        assert_eq!(progress.stmt_timeout_ms, DEFAULT_STMT_TIMEOUT_MS);
        let policy = PgRotationPolicyStore::with_statement_timeout(pool, 1_000);
        assert_eq!(policy.stmt_timeout_ms, 1_000);
    }
}
