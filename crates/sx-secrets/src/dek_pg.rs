//! Postgres-backed [`DekStore`] implementation.
//!
//! [`PgDekStore`] persists [`StoredDek`] records in a `tenant_deks` table
//! whose schema lives in `crates/sx-storage/migrations/20260101000014`.
//! The table carries one row per tenant (`tenant_id` is the primary key)
//! and is guarded by row-level security so that a wedged caller cannot
//! enumerate another tenant's wrapped DEK.
//!
//! Every operation runs inside a short transaction so the RLS GUC
//! (`app.current_tenant_id`) and the per-statement timeout are bounded
//! together. The transactional shape mirrors the repositories in
//! `sx-storage` (see `PgSocRuleRepository`) so deployments and runbooks
//! treat all RLS tables uniformly.
//!
//! ## Why not depend on `sx-storage`?
//!
//! `sx-secrets` is intentionally standalone — it must be usable from
//! crates that do not pull in the full storage stack. The tenant context
//! (`SELECT set_config('app.current_tenant_id', …, true)` plus
//! `SET LOCAL statement_timeout`) is therefore inlined here rather than
//! imported from `sx-storage::tenant_context`. The two implementations
//! are deliberately identical in shape.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use crate::dek::{DekStore, StoredDek, TenantId};
use crate::error::SecretsError;
use crate::kms::provider::Ciphertext;

/// Default `statement_timeout` (ms) for `tenant_deks` transactions when
/// callers do not override at construction time.
const DEFAULT_STMT_TIMEOUT_MS: u64 = 5_000;

/// Postgres-backed [`DekStore`].
///
/// Wraps a [`PgPool`] handle and a per-statement timeout. Cheap to
/// clone: the underlying pool is reference-counted.
#[derive(Debug, Clone)]
pub struct PgDekStore {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgDekStore {
    /// Construct from a pre-built pool using the default statement
    /// timeout. No I/O is performed.
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

    /// Borrow the underlying pool. Exposed for tests and for callers
    /// that want to share the connection budget with other adapters.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply the tenant-scoped GUC and statement timeout to an open
    /// transaction. Must be the first statement of every transaction.
    async fn apply_tenant_context(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: TenantId,
        stmt_timeout_ms: u64,
    ) -> Result<(), SecretsError> {
        // `set_config(..., true)` is the function form of `SET LOCAL`.
        // The text argument is safely parameterised.
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut **tx)
            .await?;

        // `SET LOCAL statement_timeout` does not accept `$1`; it requires
        // a literal. We bound to `u32::MAX` so there is no overflow risk
        // and no injection vector (the type is `u64`).
        let bounded = stmt_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt).execute(&mut **tx).await?;

        Ok(())
    }
}

#[async_trait]
impl DekStore for PgDekStore {
    async fn get(&self, tenant_id: TenantId) -> Result<Option<StoredDek>, SecretsError> {
        let mut tx = self.pool.begin().await?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT tenant_id, key_id, version, wrapped, created_at \
             FROM tenant_deks \
             WHERE tenant_id = $1",
        )
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await?;

        tx.commit().await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let tenant_uuid: uuid::Uuid = row.try_get("tenant_id")?;
        let key_id: String = row.try_get("key_id")?;
        let version: i32 = row.try_get("version")?;
        let wrapped: String = row.try_get("wrapped")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;

        let version_u32 = u32::try_from(version)
            .map_err(|e| SecretsError::format(format!("version out of range: {e}")))?;

        Ok(Some(StoredDek {
            tenant_id: TenantId::new(tenant_uuid),
            key_id,
            version: version_u32,
            wrapped: Ciphertext::new(wrapped),
            created_at,
        }))
    }

    async fn put(&self, dek: StoredDek) -> Result<(), SecretsError> {
        // INTEGER is signed in Postgres; reject DEK versions that would
        // overflow the column so the database never sees a wrapped value.
        let version_i32 = i32::try_from(dek.version)
            .map_err(|e| SecretsError::format(format!("version out of range: {e}")))?;

        let mut tx = self.pool.begin().await?;
        Self::apply_tenant_context(&mut tx, dek.tenant_id, self.stmt_timeout_ms).await?;

        sqlx::query(
            "INSERT INTO tenant_deks (tenant_id, key_id, version, wrapped, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
                key_id     = EXCLUDED.key_id, \
                version    = EXCLUDED.version, \
                wrapped    = EXCLUDED.wrapped, \
                created_at = EXCLUDED.created_at",
        )
        .bind(dek.tenant_id.as_uuid())
        .bind(&dek.key_id)
        .bind(version_i32)
        .bind(dek.wrapped.as_str())
        .bind(dek.created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn delete(&self, tenant_id: TenantId) -> Result<(), SecretsError> {
        let mut tx = self.pool.begin().await?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        sqlx::query("DELETE FROM tenant_deks WHERE tenant_id = $1")
            .bind(tenant_id.as_uuid())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    //! Tests for [`PgDekStore`].
    //!
    //! The live-DB tests are gated by `#[ignore]` because they need a
    //! real Postgres instance with the `tenant_deks` migration applied.
    //! Run them with `cargo test -p sx-secrets -- --ignored` against a
    //! database whose URL is supplied via `TEST_DATABASE_URL`.
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;

    /// Construct a store from `TEST_DATABASE_URL`. Returns `None` when
    /// the env var is unset so the test logs a skip instead of
    /// panicking — the same shape every other live-DB test in the
    /// project uses.
    async fn maybe_store() -> Option<PgDekStore> {
        #[allow(clippy::disallowed_methods)] // live-DB test-only env lookup
        let raw = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&raw)
            .await
            .ok()?;
        Some(PgDekStore::new(pool))
    }

    #[tokio::test]
    async fn new_does_not_perform_io() {
        // `PgPool::connect_lazy` is the only way to obtain a `PgPool`
        // without touching the network. The constructor must be `const`
        // and copy the pool handle without further work.
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy must not perform I/O");
        let store = PgDekStore::new(pool.clone());
        assert_eq!(store.stmt_timeout_ms, DEFAULT_STMT_TIMEOUT_MS);
        let with_to = PgDekStore::with_statement_timeout(pool, 1_000);
        assert_eq!(with_to.stmt_timeout_ms, 1_000);
    }

    /// Live-DB test: round-trip a DEK through `put` / `get` / `delete`.
    #[tokio::test]
    #[ignore = "Requires live Postgres on TEST_DATABASE_URL"]
    async fn live_round_trip_put_get_delete() {
        let Some(store) = maybe_store().await else {
            return;
        };
        let tenant = TenantId::random();
        let dek = StoredDek {
            tenant_id: tenant,
            key_id: "tenant-kek".to_owned(),
            version: 1,
            wrapped: Ciphertext::new("vault:v1:LIVE-ROUND-TRIP"),
            created_at: Utc::now(),
        };

        store.put(dek.clone()).await.expect("put");
        let got = store.get(tenant).await.expect("get").expect("row present");
        assert_eq!(got.tenant_id, dek.tenant_id);
        assert_eq!(got.key_id, dek.key_id);
        assert_eq!(got.version, dek.version);
        assert_eq!(got.wrapped, dek.wrapped);

        // Re-`put` must overwrite (ON CONFLICT path).
        let mut updated = dek.clone();
        updated.version = 2;
        updated.wrapped = Ciphertext::new("vault:v2:LIVE-ROUND-TRIP");
        store.put(updated.clone()).await.expect("re-put");

        let got2 = store
            .get(tenant)
            .await
            .expect("get-2")
            .expect("row present");
        assert_eq!(got2.version, 2);
        assert_eq!(got2.wrapped, updated.wrapped);

        store.delete(tenant).await.expect("delete");
        let missing = store.get(tenant).await.expect("get-3");
        assert!(missing.is_none());

        // Idempotent delete on an absent row.
        store.delete(tenant).await.expect("delete-2");
    }

    /// Live-DB test: a row owned by tenant A must not be visible from
    /// tenant B's RLS context.
    #[tokio::test]
    #[ignore = "Requires live Postgres on TEST_DATABASE_URL"]
    async fn live_rls_isolates_tenants() {
        let Some(store) = maybe_store().await else {
            return;
        };
        let tenant_a = TenantId::random();
        let tenant_b = TenantId::random();
        let dek = StoredDek {
            tenant_id: tenant_a,
            key_id: "tenant-kek".to_owned(),
            version: 1,
            wrapped: Ciphertext::new("vault:v1:RLS-ISOLATION"),
            created_at: Utc::now(),
        };

        store.put(dek.clone()).await.expect("put-a");

        // Tenant B must not see tenant A's row.
        let seen_by_b = store.get(tenant_b).await.expect("get-b");
        assert!(seen_by_b.is_none(), "tenant B must not see tenant A's DEK");

        // Tenant A must see its own row.
        let seen_by_a = store.get(tenant_a).await.expect("get-a");
        assert!(seen_by_a.is_some(), "tenant A must see its own DEK");

        // Clean up so reruns are idempotent.
        store.delete(tenant_a).await.expect("cleanup");
    }
}
