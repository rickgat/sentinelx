//! Per-transaction Postgres tenant context.
//!
//! Establishes two transaction-local GUCs at the start of every
//! repository operation:
//!
//! 1. `app.current_tenant_id` — consumed by all RLS policies (see
//!    `migrations/20260101000010_enable_rls.sql`).
//! 2. `statement_timeout` — bounds query wall-clock time at the
//!    server side as a cheap `DoS` defence.
//!
//! Both are scoped with `set_config(..., true)` / `SET LOCAL` so they
//! evaporate at `COMMIT` / `ROLLBACK`. This means the policy is
//! impossible to forget across pooled-connection reuse.

use sqlx::{Postgres, Transaction};

use crate::domain::value_object::TenantId;
use crate::error::StorageError;

/// Marker type carrying the tenant-context helpers as associated
/// functions.
#[derive(Debug, Clone, Copy)]
pub struct TenantContext;

impl TenantContext {
    /// Apply `app.current_tenant_id` and `statement_timeout` to the
    /// open transaction. Must be called as the **first** statement of
    /// every repository transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Query`] if either `SET` call fails.
    pub async fn apply(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: TenantId,
        statement_timeout_ms: u64,
    ) -> Result<(), StorageError> {
        // `set_config(..., true)` is the function form of `SET LOCAL`.
        // It accepts a `text` parameter and is therefore safely
        // parameterised.
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut **tx)
            .await
            .map_err(StorageError::from)?;

        // `SET LOCAL statement_timeout` does NOT accept a `$1`
        // placeholder; it requires a literal. We bound the input to a
        // safe integer range and format it directly. There is no SQL
        // injection vector because the input type is `u64`.
        let bounded = statement_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt)
            .execute(&mut **tx)
            .await
            .map_err(StorageError::from)?;

        Ok(())
    }
}
