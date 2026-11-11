//! Postgres-backed adapters wiring `sx-storage` into the `sx-api` ports.
//!
//! This module is the composition glue between
//! [`sx_storage`]'s [`sqlx::PgPool`] / repository helpers and the read-side
//! repository ports declared in [`sx_api::port`]:
//! [`sx_api::port::TenantRepositoryPort`],
//! [`sx_api::port::AssetRepositoryPort`] and
//! [`sx_api::port::FindingRepositoryPort`].
//!
//! ## Responsibilities
//!
//! 1. Build a validated [`sqlx::PgPool`] from
//!    [`sx_config::DatabaseConfig`] via [`sx_storage::pool::build_pool`].
//! 2. Run pending sqlx migrations at boot when
//!    [`sx_config::DatabaseConfig::migrate_on_start`] is `true`.
//! 3. Idempotently seed a bootstrap tenant + admin user when
//!    [`sx_config::schema::bootstrap::BootstrapConfig::enabled`] is `true`.
//! 4. Provide three repository adapters that wrap every query in a
//!    transaction with the tenant-scoped RLS GUC set via
//!    [`sx_storage::tenant_context::TenantContext::apply`].
//!
//! ## Error mapping
//!
//! Every `sqlx::Error` is translated into
//! [`sx_api::port::EngagementPortError`] via [`map_sqlx_error`]:
//! - [`sqlx::Error::RowNotFound`] → [`EngagementPortError::NotFound`].
//! - Postgres `23505` (unique violation) → [`EngagementPortError::Conflict`].
//! - Pool errors → [`EngagementPortError::Dependency`].
//! - Anything else → [`EngagementPortError::Internal`].
//!
//! ## Security posture
//!
//! - Every tenant-scoped query opens a transaction, calls
//!   [`sx_storage::tenant_context::TenantContext::apply`] (which sets the
//!   `app.current_tenant_id` GUC consumed by RLS policies), runs the
//!   parameterised query, then commits. RLS provides defence-in-depth on
//!   top of the explicit `WHERE tenant_id = $1` predicate.
//! - All identifiers cross the boundary as strings and are parsed into
//!   [`Uuid`] before binding so malformed input fails fast with
//!   [`EngagementPortError::Invalid`].
//!
//! The `dead_code` allowance below is temporary: every public item in
//! this module is consumed once the composition root (`adapters/mod.rs`)
//! is updated to call [`build`] in `build_app_state`. Until that wiring
//! lands the workspace's `-D warnings` policy would otherwise reject the
//! crate.

#![allow(dead_code)]

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row, Transaction};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use sx_api::port::{
    AssetRepositoryPort, AssetWritePort, EngagementPortError, FindingRepositoryPort,
    Phase3PortError, TenantRepositoryPort, TenantSummaryView, TenantWritePort,
};
use sx_api::view::asset_view::{AssetView, CreateAssetRequest, UpdateAssetRequest};
use sx_api::view::finding_view::FindingView;
use sx_api::view::tenant_view::{CreateTenantRequest, UpdateTenantRequest};
use sx_config::schema::bootstrap::BootstrapConfig;
use sx_config::DatabaseConfig;
use sx_storage::domain::value_object::TenantId;
use sx_storage::pool::{build_pool, PoolSettings};
use sx_storage::tenant_context::TenantContext;

/// Application name reported to Postgres on every connection. Surfaces in
/// `pg_stat_activity` for traceability.
const APPLICATION_NAME: &str = "sx-monolith";

/// Postgres SQLSTATE for `unique_violation`.
const PG_UNIQUE_VIOLATION: &str = "23505";

/// Postgres SQLSTATE for `query_canceled` (`statement_timeout` fired).
const PG_QUERY_CANCELED: &str = "57014";

/// Postgres SQLSTATE for `foreign_key_violation`.
const PG_FK_VIOLATION: &str = "23503";

/// Bundle returned by [`build`] containing the live pool and all three
/// trait-object repository adapters ready to drop into
/// [`sx_api::state::AppState`].
pub(crate) struct PostgresBundle {
    /// Tenant projection adapter.
    pub tenants: Arc<dyn TenantRepositoryPort>,
    /// Asset projection adapter.
    pub assets: Arc<dyn AssetRepositoryPort>,
    /// Finding projection + status update adapter.
    pub findings: Arc<dyn FindingRepositoryPort>,
    /// The live connection pool, retained so callers can share it with
    /// sibling adapters (engagement, audit, …).
    pub pool: PgPool,
}

/// Build the Postgres composition bundle.
///
/// Steps:
/// 1. Construct a validated [`sqlx::PgPool`] via
///    [`sx_storage::pool::build_pool`].
/// 2. If [`DatabaseConfig::migrate_on_start`] is `true`, apply pending
///    migrations from `crates/sx-storage/migrations`.
/// 3. If [`BootstrapConfig::enabled`] is `true`, seed the bootstrap
///    tenant + admin user idempotently.
/// 4. Return the bundle of adapters wrapping the pool.
///
/// # Errors
///
/// Returns an `anyhow::Error` annotated with [`anyhow::Context`] for any
/// of:
/// - Pool construction failure (invalid URL, connection refused, …).
/// - Migration failure (syntax error in a `*.sql` file, version mismatch).
/// - Seed failure (constraint violation, network blip).
pub(crate) async fn build(
    db_cfg: &DatabaseConfig,
    bootstrap_cfg: &BootstrapConfig,
) -> anyhow::Result<PostgresBundle> {
    let pool = build_pool_from_cfg(db_cfg).await?;
    maybe_run_migrations(&pool, db_cfg).await?;
    maybe_seed_bootstrap(&pool, bootstrap_cfg, db_cfg.statement_timeout_ms).await?;
    Ok(assemble_bundle(pool, db_cfg.statement_timeout_ms))
}

/// Build the pool from the [`DatabaseConfig`] section, emitting a
/// `tracing` event describing the pool parameters.
async fn build_pool_from_cfg(db_cfg: &DatabaseConfig) -> anyhow::Result<PgPool> {
    tracing::info!(
        max_connections = db_cfg.max_connections,
        min_connections = db_cfg.min_connections,
        statement_timeout_ms = db_cfg.statement_timeout_ms,
        migrate_on_start = db_cfg.migrate_on_start,
        "building postgres pool",
    );

    let settings = PoolSettings {
        url: &db_cfg.url,
        max_connections: db_cfg.max_connections,
        min_connections: db_cfg.min_connections,
        acquire_timeout: db_cfg.acquire_timeout,
        idle_timeout: db_cfg.idle_timeout,
        statement_timeout_ms: db_cfg.statement_timeout_ms,
        application_name: APPLICATION_NAME,
    };

    build_pool(&settings)
        .await
        .map_err(|e| anyhow::anyhow!("failed to build postgres pool: {e}"))
}

/// Run pending migrations when `migrate_on_start` is set; otherwise log
/// and skip.
#[allow(clippy::cognitive_complexity)]
async fn maybe_run_migrations(pool: &PgPool, db_cfg: &DatabaseConfig) -> anyhow::Result<()> {
    if db_cfg.migrate_on_start {
        tracing::info!("running pending sqlx migrations");
        run_migrations(pool).await?;
        tracing::info!("sqlx migrations complete");
    } else {
        tracing::debug!("migrate_on_start = false, skipping migration runner");
    }
    Ok(())
}

/// Seed the bootstrap tenant when `bootstrap.enabled` is set; otherwise
/// log and skip.
///
/// Note: the bootstrap **admin user** is seeded by the IAM bundle (see
/// `crate::adapters::iam::seed_bootstrap_admin`) via the
/// `PgIamUserRepository` adapter so the in-memory and Postgres paths
/// share one code path. This function only ensures the tenant row exists
/// (FK precondition for the user insert).
async fn maybe_seed_bootstrap(
    pool: &PgPool,
    bootstrap_cfg: &BootstrapConfig,
    stmt_timeout_ms: u64,
) -> anyhow::Result<()> {
    if bootstrap_cfg.enabled {
        tracing::info!(
            tenant_slug = %bootstrap_cfg.admin_tenant_slug,
            "bootstrap tenant seed enabled",
        );
        seed_bootstrap_tenant(pool, bootstrap_cfg, stmt_timeout_ms).await?;
    } else {
        tracing::debug!("bootstrap.enabled = false, skipping tenant seed");
    }
    Ok(())
}

/// Wrap the pool in the three trait-object adapters and pack them into a
/// [`PostgresBundle`].
fn assemble_bundle(pool: PgPool, stmt_timeout_ms: u64) -> PostgresBundle {
    let tenants: Arc<dyn TenantRepositoryPort> = Arc::new(PgTenantsAdapter {
        pool: pool.clone(),
        stmt_timeout_ms,
    });
    let assets: Arc<dyn AssetRepositoryPort> = Arc::new(PgAssetsAdapter {
        pool: pool.clone(),
        stmt_timeout_ms,
    });
    let findings: Arc<dyn FindingRepositoryPort> = Arc::new(PgFindingsAdapter {
        pool: pool.clone(),
        stmt_timeout_ms,
    });
    PostgresBundle {
        tenants,
        assets,
        findings,
        pool,
    }
}

/// Apply pending sqlx migrations bundled under `crates/sx-storage/migrations`.
///
/// The path is resolved at compile time relative to this file
/// (`services/sx-monolith/src/adapters/postgres.rs`).
async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    let migrator = sqlx::migrate!("../../crates/sx-storage/migrations");
    migrator
        .run(pool)
        .await
        .map_err(|e| anyhow::anyhow!("sqlx migration failed: {e}"))
}

/// Idempotently insert the bootstrap tenant row.
///
/// Uses `ON CONFLICT … DO NOTHING` on the natural unique key (`slug`) so
/// repeated boots are no-ops. The bootstrap admin USER is seeded later
/// by the IAM layer via the unified `PgIamUserRepository` path so the
/// in-memory and Postgres branches share a single seeding code path.
///
/// The `tenants` table is not under RLS so no `TenantContext::apply` is
/// needed here — only a `SET LOCAL statement_timeout` for parity with
/// the rest of the adapter.
async fn seed_bootstrap_tenant(
    pool: &PgPool,
    cfg: &BootstrapConfig,
    stmt_timeout_ms: u64,
) -> anyhow::Result<()> {
    let tenant_uuid = cfg.admin_tenant_id.unwrap_or_else(Uuid::now_v7);

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| anyhow::anyhow!("failed to open tenant seed transaction: {e}"))?;

    let bounded = stmt_timeout_ms.min(u64::from(u32::MAX));
    let stmt = format!("SET LOCAL statement_timeout = {bounded}");
    sqlx::query(&stmt)
        .execute(&mut *tx)
        .await
        .map_err(|e| anyhow::anyhow!("failed to set statement_timeout for tenant seed: {e}"))?;

    let tenant_insert = sqlx::query(
        "INSERT INTO tenants (id, name, slug, tier) \
         VALUES ($1, $2, $3, 'enterprise') \
         ON CONFLICT (slug) DO NOTHING",
    )
    .bind(tenant_uuid)
    .bind(&cfg.admin_tenant_name)
    .bind(&cfg.admin_tenant_slug)
    .execute(&mut *tx)
    .await
    .map_err(|e| anyhow::anyhow!("failed to insert bootstrap tenant: {e}"))?;

    let resolved_tenant_id: Uuid =
        sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1 AND deleted_at IS NULL")
            .bind(&cfg.admin_tenant_slug)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| anyhow::anyhow!("failed to resolve bootstrap tenant id: {e}"))?;

    tx.commit()
        .await
        .map_err(|e| anyhow::anyhow!("failed to commit bootstrap tenant seed: {e}"))?;

    tracing::info!(
        tenant_inserted = tenant_insert.rows_affected() == 1,
        tenant_id = %resolved_tenant_id,
        "bootstrap tenant seed complete",
    );

    Ok(())
}

/// Translate any [`sqlx::Error`] into an [`EngagementPortError`] following
/// the convention used across the API layer.
fn map_sqlx_error(err: &sqlx::Error) -> EngagementPortError {
    match err {
        sqlx::Error::RowNotFound => EngagementPortError::NotFound,
        sqlx::Error::Database(db_err) => {
            let code = db_err.code().unwrap_or_default().into_owned();
            if code == PG_UNIQUE_VIOLATION {
                EngagementPortError::Conflict(db_err.message().to_owned())
            } else if code == PG_QUERY_CANCELED {
                EngagementPortError::Dependency(format!("statement timeout: {}", db_err.message()))
            } else {
                EngagementPortError::Internal(format!("{code}: {}", db_err.message()))
            }
        }
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) => {
            EngagementPortError::Dependency(err.to_string())
        }
        _ => EngagementPortError::Internal(err.to_string()),
    }
}

/// Translate [`sx_storage::StorageError`] (returned by
/// [`TenantContext::apply`]) into [`EngagementPortError`].
fn map_storage_error(err: &sx_storage::StorageError) -> EngagementPortError {
    use sx_storage::StorageError;
    match err {
        StorageError::NotFound => EngagementPortError::NotFound,
        StorageError::Conflict(msg) => EngagementPortError::Conflict(msg.clone()),
        StorageError::Connection(msg) => EngagementPortError::Dependency(msg.clone()),
        StorageError::Timeout => EngagementPortError::Dependency("statement timeout".to_owned()),
        StorageError::Query(msg) | StorageError::Serialization(msg) | StorageError::Config(msg) => {
            EngagementPortError::Internal(msg.clone())
        }
    }
}

/// Parse a UUID supplied as a string from the HTTP layer. Maps parse
/// failures to [`EngagementPortError::Invalid`].
fn parse_uuid(field: &str, value: &str) -> Result<Uuid, EngagementPortError> {
    Uuid::parse_str(value)
        .map_err(|_| EngagementPortError::Invalid(format!("{field} is not a valid uuid")))
}

/// Clamp `u32` page limit into an `i64` for sqlx binding.
fn limit_to_i64(limit: u32) -> i64 {
    i64::from(limit)
}

/// Clamp `u64` page offset into an `i64`, saturating at [`i64::MAX`].
fn offset_to_i64(offset: u64) -> i64 {
    i64::try_from(offset).unwrap_or(i64::MAX)
}

/// Begin a transaction and install the tenant GUC + statement timeout.
async fn begin_tenant_tx(
    pool: &PgPool,
    tenant_uuid: Uuid,
    stmt_timeout_ms: u64,
) -> Result<Transaction<'_, Postgres>, EngagementPortError> {
    let mut tx = pool.begin().await.map_err(|e| map_sqlx_error(&e))?;
    TenantContext::apply(&mut tx, TenantId::from_uuid(tenant_uuid), stmt_timeout_ms)
        .await
        .map_err(|e| map_storage_error(&e))?;
    Ok(tx)
}

/// Format an [`OffsetDateTime`] as RFC3339, falling back to an empty
/// string if formatting fails (which never happens for a valid UTC
/// timestamp, but the fallback keeps the error surface clean).
fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tenant adapter
// ---------------------------------------------------------------------------

/// Postgres-backed implementation of [`TenantRepositoryPort`].
#[derive(Debug, Clone)]
struct PgTenantsAdapter {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

#[async_trait]
impl TenantRepositoryPort for PgTenantsAdapter {
    async fn get(&self, id: &str) -> Result<TenantSummaryView, EngagementPortError> {
        let tenant_uuid = parse_uuid("tenant_id", id)?;

        // `tenants` is not under RLS, but we still wrap the query in a
        // transaction and apply a `SET LOCAL statement_timeout` to match
        // the rest of the adapter's behaviour.
        let mut tx = self.pool.begin().await.map_err(|e| map_sqlx_error(&e))?;
        let bounded = self.stmt_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e))?;

        let row = sqlx::query("SELECT id, name, slug, deleted_at FROM tenants WHERE id = $1")
            .bind(tenant_uuid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e))?;

        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;

        let Some(row) = row else {
            return Err(EngagementPortError::NotFound);
        };

        let name: String = row
            .try_get("name")
            .map_err(|e| EngagementPortError::Internal(format!("decode tenants.name: {e}")))?;
        let slug: String = row
            .try_get("slug")
            .map_err(|e| EngagementPortError::Internal(format!("decode tenants.slug: {e}")))?;
        let deleted_at: Option<OffsetDateTime> = row.try_get("deleted_at").map_err(|e| {
            EngagementPortError::Internal(format!("decode tenants.deleted_at: {e}"))
        })?;

        Ok(TenantSummaryView {
            id: tenant_uuid.to_string(),
            name,
            slug,
            is_active: deleted_at.is_none(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tenant write adapter (durable `POST`/`PATCH`/`DELETE /v1/admin/tenants`)
// ---------------------------------------------------------------------------

/// Marker string the adapter returns inside [`Phase3PortError::Invalid`] on a
/// slug collision. Must stay byte-for-byte identical to
/// `sx_api::controller::tenants::DUPLICATE_TENANT_MARKER` so the controller's
/// idempotency arm maps it to `409 Conflict`.
const DUPLICATE_TENANT_MARKER: &str = "tenant exists";

/// Postgres-backed [`TenantWritePort`].
///
/// The composition root previously bound tenant writes to a detached
/// in-memory store even when Postgres was enabled, so a tenant created via
/// `POST /v1/admin/tenants` was invisible to the Postgres-backed read path
/// (`GET /v1/tenants/me`) and lost on restart. This adapter writes to the
/// same `tenants` table the read adapter queries.
///
/// The `tenants.tier` column is `NOT NULL` with a CHECK but the create API
/// (`CreateTenantRequest { slug, name }`) carries no tier, so new tenants
/// default to `'starter'` — the entry tier — until a tier-aware admin flow
/// lands. `delete` is a hard `DELETE` (FK-cascading the tenant's assets /
/// engagements), matching the in-memory port contract.
pub(crate) struct PgTenantWriteAdapter {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgTenantWriteAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTenantWriteAdapter")
            .finish_non_exhaustive()
    }
}

impl PgTenantWriteAdapter {
    pub(crate) const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    async fn begin(&self) -> Result<Transaction<'_, Postgres>, Phase3PortError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| phase3(map_sqlx_error(&e)))?;
        let bounded = self.stmt_timeout_ms.min(u64::from(u32::MAX));
        sqlx::query(&format!("SET LOCAL statement_timeout = {bounded}"))
            .execute(&mut *tx)
            .await
            .map_err(|e| phase3(map_sqlx_error(&e)))?;
        Ok(tx)
    }

    fn row_to_summary(row: &PgRow) -> Result<TenantSummaryView, Phase3PortError> {
        let id: Uuid = row
            .try_get("id")
            .map_err(|e| Phase3PortError::Internal(format!("decode tenants.id: {e}")))?;
        let name: String = row
            .try_get("name")
            .map_err(|e| Phase3PortError::Internal(format!("decode tenants.name: {e}")))?;
        let slug: String = row
            .try_get("slug")
            .map_err(|e| Phase3PortError::Internal(format!("decode tenants.slug: {e}")))?;
        let deleted_at: Option<OffsetDateTime> = row
            .try_get("deleted_at")
            .map_err(|e| Phase3PortError::Internal(format!("decode tenants.deleted_at: {e}")))?;
        Ok(TenantSummaryView {
            id: id.to_string(),
            name,
            slug,
            is_active: deleted_at.is_none(),
        })
    }
}

/// Translate the read-side [`EngagementPortError`] into the
/// [`Phase3PortError`] the write port surfaces, collapsing a unique-slug
/// [`EngagementPortError::Conflict`] into the duplicate-tenant marker.
fn phase3(err: EngagementPortError) -> Phase3PortError {
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

#[async_trait]
impl TenantWritePort for PgTenantWriteAdapter {
    async fn create(&self, req: CreateTenantRequest) -> Result<TenantSummaryView, Phase3PortError> {
        let id = Uuid::new_v4();
        let mut tx = self.begin().await?;
        let row = sqlx::query(
            "INSERT INTO tenants (id, name, slug, tier) VALUES ($1, $2, $3, 'starter') \
             RETURNING id, name, slug, deleted_at",
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.slug)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| phase3(map_sqlx_error(&e)))?;
        tx.commit().await.map_err(|e| phase3(map_sqlx_error(&e)))?;
        Self::row_to_summary(&row)
    }

    async fn update(
        &self,
        id: &str,
        req: UpdateTenantRequest,
    ) -> Result<TenantSummaryView, Phase3PortError> {
        let tenant_uuid = parse_uuid("tenant_id", id).map_err(phase3)?;
        let mut tx = self.begin().await?;
        // `COALESCE` keeps `name` when absent; the `CASE` leaves `deleted_at`
        // untouched when `is_active` is absent, clears it on `true`, and
        // stamps `now()` on `false`.
        let row = sqlx::query(
            "UPDATE tenants SET \
                 name = COALESCE($2, name), \
                 deleted_at = CASE \
                     WHEN $3::boolean IS NULL THEN deleted_at \
                     WHEN $3::boolean THEN NULL \
                     ELSE now() END \
             WHERE id = $1 \
             RETURNING id, name, slug, deleted_at",
        )
        .bind(tenant_uuid)
        .bind(req.name.as_deref())
        .bind(req.is_active)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| phase3(map_sqlx_error(&e)))?;
        tx.commit().await.map_err(|e| phase3(map_sqlx_error(&e)))?;
        let row = row.ok_or(Phase3PortError::NotFound)?;
        Self::row_to_summary(&row)
    }

    async fn delete(&self, id: &str) -> Result<(), Phase3PortError> {
        let tenant_uuid = parse_uuid("tenant_id", id).map_err(phase3)?;
        let mut tx = self.begin().await?;
        let res = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant_uuid)
            .execute(&mut *tx)
            .await
            .map_err(|e| phase3(map_sqlx_error(&e)))?;
        tx.commit().await.map_err(|e| phase3(map_sqlx_error(&e)))?;
        if res.rows_affected() == 0 {
            return Err(Phase3PortError::NotFound);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Asset adapter
// ---------------------------------------------------------------------------

/// Postgres-backed implementation of [`AssetRepositoryPort`].
#[derive(Debug, Clone)]
struct PgAssetsAdapter {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

/// Internal helper translating a single `assets` row to the wire DTO.
fn row_to_asset_view(row: &PgRow) -> Result<AssetView, EngagementPortError> {
    let id: Uuid = row
        .try_get("id")
        .map_err(|e| EngagementPortError::Internal(format!("decode assets.id: {e}")))?;
    let tenant_id: Uuid = row
        .try_get("tenant_id")
        .map_err(|e| EngagementPortError::Internal(format!("decode assets.tenant_id: {e}")))?;
    let engagement_id: Uuid = row
        .try_get("engagement_id")
        .map_err(|e| EngagementPortError::Internal(format!("decode assets.engagement_id: {e}")))?;
    let kind: String = row
        .try_get("kind")
        .map_err(|e| EngagementPortError::Internal(format!("decode assets.kind: {e}")))?;
    let fingerprint: String = row
        .try_get("fingerprint")
        .map_err(|e| EngagementPortError::Internal(format!("decode assets.fingerprint: {e}")))?;
    let exposure: String = row
        .try_get("exposure")
        .map_err(|e| EngagementPortError::Internal(format!("decode assets.exposure: {e}")))?;
    // `assets.criticality` was added with the canonical
    // `AssetCriticality` vocabulary in
    // `20260101000014_assets_criticality_value_object.sql`. The
    // adapter surfaces the raw column string as-is so consumers can
    // call `sx_core::value_object::criticality::parse_criticality`
    // and decide on their own fallback; we treat a NULL or any decode
    // failure as `None` rather than aborting the entire view decode
    // because the field is non-critical metadata.
    let criticality: Option<String> = row.try_get("criticality").ok();
    // The API's free-form `source` is preserved verbatim in `tags.source`
    // by the write path; fall back to the `exposure` enum for legacy rows
    // (seeded demo data, or rows written before the write path was wired)
    // that have no `tags.source`.
    let tags: Option<sqlx::types::Json<serde_json::Value>> = row.try_get("tags").ok();
    let source = tags
        .as_ref()
        .and_then(|t| t.0.get("source").and_then(serde_json::Value::as_str))
        .map_or(exposure, ToOwned::to_owned);
    let created_at: OffsetDateTime = row
        .try_get("created_at")
        .map_err(|e| EngagementPortError::Internal(format!("decode assets.created_at: {e}")))?;
    let updated_at: OffsetDateTime = row
        .try_get("updated_at")
        .map_err(|e| EngagementPortError::Internal(format!("decode assets.updated_at: {e}")))?;

    Ok(AssetView {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        engagement_id: engagement_id.to_string(),
        kind,
        identifier: fingerprint,
        source,
        first_seen: rfc3339(created_at),
        last_seen: rfc3339(updated_at),
        criticality,
    })
}

#[async_trait]
impl AssetRepositoryPort for PgAssetsAdapter {
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<AssetView>, EngagementPortError> {
        let tenant_uuid = parse_uuid("tenant_id", tenant_id)?;
        let mut tx = begin_tenant_tx(&self.pool, tenant_uuid, self.stmt_timeout_ms).await?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, engagement_id, kind, fingerprint, exposure, \
                    criticality, tags, created_at, updated_at \
             FROM assets WHERE tenant_id = $1 \
             ORDER BY created_at DESC, id LIMIT $2 OFFSET $3",
        )
        .bind(tenant_uuid)
        .bind(limit_to_i64(limit))
        .bind(offset_to_i64(offset))
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| map_sqlx_error(&e))?;

        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(row_to_asset_view(row)?);
        }
        Ok(out)
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<AssetView, EngagementPortError> {
        let tenant_uuid = parse_uuid("tenant_id", tenant_id)?;
        let asset_uuid = parse_uuid("asset_id", id)?;
        let mut tx = begin_tenant_tx(&self.pool, tenant_uuid, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT id, tenant_id, engagement_id, kind, fingerprint, exposure, \
                    criticality, tags, created_at, updated_at \
             FROM assets WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_uuid)
        .bind(asset_uuid)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_sqlx_error(&e))?;

        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;

        match row {
            Some(r) => row_to_asset_view(&r),
            None => Err(EngagementPortError::NotFound),
        }
    }
}

// ---------------------------------------------------------------------------
// Asset write adapter (durable POST/PATCH/DELETE /v1/assets)
// ---------------------------------------------------------------------------

/// Columns every asset read projects, shared by the write path's `RETURNING`
/// so [`row_to_asset_view`] decodes a freshly-written row identically to a
/// `GET`.
const ASSET_COLUMNS: &str =
    "id, tenant_id, engagement_id, kind, fingerprint, exposure, criticality, tags, \
     created_at, updated_at";

/// Normalise the API's free-form `kind` to the `assets.kind` CHECK vocabulary
/// (case-insensitive); an unrecognised kind is a `400`.
fn normalize_asset_kind(raw: &str) -> Result<&'static str, EngagementPortError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "host" => Ok("Host"),
        "service" => Ok("Service"),
        "webapp" => Ok("Webapp"),
        "cloud" => Ok("Cloud"),
        "identity" => Ok("Identity"),
        "network" => Ok("Network"),
        "container" => Ok("Container"),
        "dns" => Ok("Dns"),
        other => Err(EngagementPortError::Invalid(format!(
            "unknown asset kind '{other}'; expected one of host, service, webapp, cloud, \
             identity, network, container, dns"
        ))),
    }
}

/// Map the API's free-form `source` onto the `assets.exposure` CHECK
/// vocabulary when it names a known exposure, else `Unknown`. The raw
/// `source` is preserved losslessly in `tags.source`, so this projection is
/// only the best-effort enum view.
fn source_to_exposure(source: &str) -> &'static str {
    match source.trim().to_ascii_lowercase().as_str() {
        "internet" => "Internet",
        "internal" => "Internal",
        "restricted" => "Restricted",
        _ => "Unknown",
    }
}

/// Translate a write error, surfacing a foreign-key violation (a missing
/// engagement / tenant) as `Invalid` rather than an opaque `Internal`.
fn map_asset_write_error(err: &sqlx::Error) -> EngagementPortError {
    if let sqlx::Error::Database(db) = err {
        if db.code().unwrap_or_default() == PG_FK_VIOLATION {
            return EngagementPortError::Invalid(
                "engagement_id does not reference an existing engagement".to_owned(),
            );
        }
    }
    map_sqlx_error(err)
}

/// Postgres-backed implementation of [`AssetWritePort`].
///
/// The composition root bound asset writes to a detached in-memory store even
/// when Postgres was enabled, so a `POST /v1/assets` was invisible to the
/// Postgres-backed read path and lost on restart. This writes to the same
/// `assets` table the read adapter queries, under the same tenant RLS.
///
/// Field mapping (the `assets` table predates the free-form write API):
/// `kind` is normalised to the table's CHECK vocabulary; `identifier` is the
/// `fingerprint`; the free-form `source` is stored verbatim in `tags.source`
/// (lossless round-trip) with the `exposure` enum set to its best-effort
/// match; `criticality` defaults to `production`.
#[derive(Debug, Clone)]
struct PgAssetWriteAdapter {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

#[async_trait]
impl AssetWritePort for PgAssetWriteAdapter {
    async fn create(
        &self,
        tenant_id: &str,
        req: CreateAssetRequest,
    ) -> Result<AssetView, EngagementPortError> {
        let tenant_uuid = parse_uuid("tenant_id", tenant_id)?;
        let engagement_uuid = parse_uuid("engagement_id", &req.engagement_id)?;
        let kind = normalize_asset_kind(&req.kind)?;
        let exposure = source_to_exposure(&req.source);
        let id = Uuid::new_v4();
        let mut tx = begin_tenant_tx(&self.pool, tenant_uuid, self.stmt_timeout_ms).await?;
        let row = sqlx::query(&format!(
            "INSERT INTO assets \
                 (id, tenant_id, engagement_id, kind, fingerprint, exposure, tags) \
             VALUES ($1, $2, $3, $4, $5, $6, jsonb_build_object('source', $7::text)) \
             RETURNING {ASSET_COLUMNS}"
        ))
        .bind(id)
        .bind(tenant_uuid)
        .bind(engagement_uuid)
        .bind(kind)
        .bind(&req.identifier)
        .bind(exposure)
        .bind(&req.source)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_asset_write_error(&e))?;
        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;
        row_to_asset_view(&row)
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: &str,
        req: UpdateAssetRequest,
    ) -> Result<AssetView, EngagementPortError> {
        let tenant_uuid = parse_uuid("tenant_id", tenant_id)?;
        let asset_uuid = parse_uuid("asset_id", id)?;
        // Normalise an updated kind (if supplied) before touching the DB.
        let kind = req.kind.as_deref().map(normalize_asset_kind).transpose()?;
        let exposure = req.source.as_deref().map(source_to_exposure);
        let mut tx = begin_tenant_tx(&self.pool, tenant_uuid, self.stmt_timeout_ms).await?;
        // COALESCE keeps each column when its field is absent; `source`
        // updates both the `exposure` projection and the lossless
        // `tags.source`.
        let row = sqlx::query(&format!(
            "UPDATE assets SET \
                 kind = COALESCE($3, kind), \
                 fingerprint = COALESCE($4, fingerprint), \
                 exposure = COALESCE($5, exposure), \
                 tags = CASE WHEN $6::text IS NULL THEN tags \
                             ELSE jsonb_set(tags, '{{source}}', to_jsonb($6::text)) END, \
                 updated_at = now() \
             WHERE tenant_id = $1 AND id = $2 \
             RETURNING {ASSET_COLUMNS}"
        ))
        .bind(tenant_uuid)
        .bind(asset_uuid)
        .bind(kind)
        .bind(req.identifier.as_deref())
        .bind(exposure)
        .bind(req.source.as_deref())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_asset_write_error(&e))?;
        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;
        row.ok_or(EngagementPortError::NotFound)
            .and_then(|r| row_to_asset_view(&r))
    }

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), EngagementPortError> {
        let tenant_uuid = parse_uuid("tenant_id", tenant_id)?;
        let asset_uuid = parse_uuid("asset_id", id)?;
        let mut tx = begin_tenant_tx(&self.pool, tenant_uuid, self.stmt_timeout_ms).await?;
        let res = sqlx::query("DELETE FROM assets WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_uuid)
            .bind(asset_uuid)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e))?;
        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;
        if res.rows_affected() == 0 {
            return Err(EngagementPortError::NotFound);
        }
        Ok(())
    }
}

/// Build the durable Postgres-backed [`AssetWritePort`], selected by the
/// composition root when the DB is enabled.
pub(crate) fn asset_write_adapter(pool: PgPool, stmt_timeout_ms: u64) -> Arc<dyn AssetWritePort> {
    Arc::new(PgAssetWriteAdapter {
        pool,
        stmt_timeout_ms,
    })
}

// ---------------------------------------------------------------------------
// Finding adapter
// ---------------------------------------------------------------------------

/// Postgres-backed implementation of [`FindingRepositoryPort`].
#[derive(Debug, Clone)]
struct PgFindingsAdapter {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

/// Internal helper translating a single `findings` row to the wire DTO.
///
/// The `findings` schema has no `cvss` column (CVSS lives on the `cves`
/// table) and no `updated_at` column; we project `detected_at` /
/// `triaged_at | resolved_at | detected_at` into the API's `first_seen` /
/// `last_seen` fields.
fn row_to_finding_view(row: &PgRow) -> Result<FindingView, EngagementPortError> {
    let id: Uuid = row
        .try_get("id")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.id: {e}")))?;
    let tenant_id: Uuid = row
        .try_get("tenant_id")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.tenant_id: {e}")))?;
    let asset_id: Uuid = row
        .try_get("asset_id")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.asset_id: {e}")))?;
    let severity: String = row
        .try_get("severity")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.severity: {e}")))?;
    let status: String = row
        .try_get("status")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.status: {e}")))?;
    let title: String = row
        .try_get("title")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.title: {e}")))?;
    let description: String = row
        .try_get("description")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.description: {e}")))?;
    let detected_at: OffsetDateTime = row
        .try_get("detected_at")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.detected_at: {e}")))?;
    let triaged_at: Option<OffsetDateTime> = row
        .try_get("triaged_at")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.triaged_at: {e}")))?;
    let resolved_at: Option<OffsetDateTime> = row
        .try_get("resolved_at")
        .map_err(|e| EngagementPortError::Internal(format!("decode findings.resolved_at: {e}")))?;

    let last_seen_ts = resolved_at.or(triaged_at).unwrap_or(detected_at);

    Ok(FindingView {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        asset_id: asset_id.to_string(),
        severity,
        status,
        title,
        description,
        // The `findings` schema does not carry a per-row CVSS score; the
        // composite risk model derives CVSS from the linked CVE record.
        cvss: None,
        // CVE linkage on the `findings` row is not projected through the
        // current SQL — Phase-3.5 schema work will surface it via a
        // dedicated join. For now this stays `None` and the engagement
        // aggregate flow skips these rows.
        cve_id: None,
        first_seen: rfc3339(detected_at),
        last_seen: rfc3339(last_seen_ts),
        // The `findings` schema does not yet carry a JSON metadata
        // column. Until that lands, every Postgres-sourced row reports
        // `None`, which `extract_factor` collapses to the identity
        // factor — matching the Phase-3.5+2 fallback contract.
        metadata: None,
    })
}

#[async_trait]
impl FindingRepositoryPort for PgFindingsAdapter {
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<FindingView>, EngagementPortError> {
        let tenant_uuid = parse_uuid("tenant_id", tenant_id)?;
        let mut tx = begin_tenant_tx(&self.pool, tenant_uuid, self.stmt_timeout_ms).await?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, engagement_id, asset_id, rule_id, severity, status, \
                    title, description, evidence_refs, detected_at, triaged_at, resolved_at \
             FROM findings WHERE tenant_id = $1 \
             ORDER BY detected_at DESC, id LIMIT $2 OFFSET $3",
        )
        .bind(tenant_uuid)
        .bind(limit_to_i64(limit))
        .bind(offset_to_i64(offset))
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| map_sqlx_error(&e))?;

        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(row_to_finding_view(row)?);
        }
        Ok(out)
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
        let tenant_uuid = parse_uuid("tenant_id", tenant_id)?;
        let finding_uuid = parse_uuid("finding_id", id)?;
        let mut tx = begin_tenant_tx(&self.pool, tenant_uuid, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT id, tenant_id, engagement_id, asset_id, rule_id, severity, status, \
                    title, description, evidence_refs, detected_at, triaged_at, resolved_at \
             FROM findings WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_uuid)
        .bind(finding_uuid)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_sqlx_error(&e))?;

        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;

        match row {
            Some(r) => row_to_finding_view(&r),
            None => Err(EngagementPortError::NotFound),
        }
    }

    async fn update_status(
        &self,
        tenant_id: &str,
        id: &str,
        new_status: &str,
        _comment: Option<&str>,
    ) -> Result<FindingView, EngagementPortError> {
        let tenant_uuid = parse_uuid("tenant_id", tenant_id)?;
        let finding_uuid = parse_uuid("finding_id", id)?;
        let mut tx = begin_tenant_tx(&self.pool, tenant_uuid, self.stmt_timeout_ms).await?;

        // The `findings` table has no `updated_at` column; instead, the
        // schema-level CHECK constraint requires `resolved_at IS NOT NULL`
        // when the new status is one of the terminal ones. We use
        // `COALESCE(resolved_at, now())` to satisfy the constraint
        // idempotently — first resolve sets it, subsequent updates keep
        // the original timestamp. Likewise `triaged_at` is set on first
        // non-`New` transition.
        let row = sqlx::query(
            "UPDATE findings \
             SET status = $3, \
                 triaged_at = CASE \
                    WHEN $3 IN ('New') THEN triaged_at \
                    ELSE COALESCE(triaged_at, now()) \
                 END, \
                 resolved_at = CASE \
                    WHEN $3 IN ('Resolved', 'FalsePositive', 'AcceptedRisk') \
                        THEN COALESCE(resolved_at, now()) \
                    ELSE resolved_at \
                 END \
             WHERE tenant_id = $1 AND id = $2 \
             RETURNING id, tenant_id, engagement_id, asset_id, rule_id, severity, status, \
                       title, description, evidence_refs, detected_at, triaged_at, resolved_at",
        )
        .bind(tenant_uuid)
        .bind(finding_uuid)
        .bind(new_status)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_sqlx_error(&e))?;

        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;

        match row {
            Some(r) => row_to_finding_view(&r),
            None => Err(EngagementPortError::NotFound),
        }
    }

    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
        // Required wire-shape fields parsed first so a bad payload fails
        // fast before we touch the connection pool.
        let tenant_uuid = parse_uuid("tenant_id", &view.tenant_id)?;
        let finding_uuid = parse_uuid("finding_id", &view.id)?;
        let asset_uuid = parse_uuid("asset_id", &view.asset_id)?;

        // FindingView does not carry `engagement_id` / `rule_id` on the
        // wire today — the schema requires both. Emitters that call
        // `insert` MUST stash them in `view.metadata` under the
        // canonical keys defined here. This keeps the trait surface
        // minimal while the storage contract stays explicit.
        let (engagement_uuid, rule_id) = extract_finding_insert_metadata(&view)?;

        // Optional `first_seen` overrides `detected_at` when present and
        // parseable; otherwise we let Postgres default it to `now()`.
        let detected_at = parse_rfc3339_opt(&view.first_seen);

        let mut tx = begin_tenant_tx(&self.pool, tenant_uuid, self.stmt_timeout_ms).await?;

        // Idempotent insert keyed by `findings.id` (PRIMARY KEY) — the
        // schema's `id PRIMARY KEY` is a stricter superset of the
        // contract's `(tenant_id, id)` uniqueness key. On conflict we
        // do nothing and re-read the existing row so re-firing emitters
        // observe the original persisted view, not a clobbered one.
        let row = sqlx::query(
            "WITH inserted AS ( \
                INSERT INTO findings ( \
                    id, tenant_id, engagement_id, asset_id, rule_id, \
                    severity, status, title, description, detected_at \
                ) VALUES ( \
                    $1, $2, $3, $4, $5, \
                    $6, $7, $8, $9, COALESCE($10, now()) \
                ) \
                ON CONFLICT (id) DO NOTHING \
                RETURNING id, tenant_id, engagement_id, asset_id, rule_id, severity, status, \
                          title, description, evidence_refs, detected_at, triaged_at, resolved_at \
            ) \
            SELECT id, tenant_id, engagement_id, asset_id, rule_id, severity, status, \
                   title, description, evidence_refs, detected_at, triaged_at, resolved_at \
            FROM inserted \
            UNION ALL \
            SELECT id, tenant_id, engagement_id, asset_id, rule_id, severity, status, \
                   title, description, evidence_refs, detected_at, triaged_at, resolved_at \
            FROM findings WHERE id = $1 AND tenant_id = $2 \
            LIMIT 1",
        )
        .bind(finding_uuid)
        .bind(tenant_uuid)
        .bind(engagement_uuid)
        .bind(asset_uuid)
        .bind(&rule_id)
        .bind(&view.severity)
        .bind(&view.status)
        .bind(&view.title)
        .bind(&view.description)
        .bind(detected_at)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_sqlx_error(&e))?;

        tx.commit().await.map_err(|e| map_sqlx_error(&e))?;

        match row {
            Some(r) => row_to_finding_view(&r),
            None => Err(EngagementPortError::Internal(
                "insert returned no row from CTE union".to_owned(),
            )),
        }
    }
}

/// Extract the `(engagement_id, rule_id)` pair from a finding view's
/// metadata payload.
///
/// `FindingView` keeps the wire shape narrow and pushes adapter-specific
/// fields into `metadata`. The Postgres `findings` table requires both
/// columns (NOT NULL + FK on `engagement_id`), so the adapter refuses
/// the insert with [`EngagementPortError::Invalid`] when the emitter
/// hasn't populated them.
///
/// The canonical metadata keys are:
/// - `engagement_id` — string-encoded UUID.
/// - `rule_id` — string, 1..=256 chars (matches the SQL CHECK).
fn extract_finding_insert_metadata(
    view: &FindingView,
) -> Result<(Uuid, String), EngagementPortError> {
    let meta = view.metadata.as_ref().ok_or_else(|| {
        EngagementPortError::Invalid(
            "metadata.engagement_id and metadata.rule_id required for finding insert".to_owned(),
        )
    })?;
    let engagement_str = meta
        .get("engagement_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            EngagementPortError::Invalid(
                "metadata.engagement_id required for finding insert".to_owned(),
            )
        })?;
    let engagement_uuid = parse_uuid("engagement_id", engagement_str)?;
    let rule_id = meta
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            EngagementPortError::Invalid("metadata.rule_id required for finding insert".to_owned())
        })?;
    if rule_id.is_empty() || rule_id.len() > 256 {
        return Err(EngagementPortError::Invalid(
            "metadata.rule_id length must be between 1 and 256".to_owned(),
        ));
    }
    Ok((engagement_uuid, rule_id.to_owned()))
}

/// Best-effort RFC 3339 parse — returns `None` on any error so the SQL
/// `COALESCE($10, now())` falls back to the database clock.
fn parse_rfc3339_opt(value: &str) -> Option<OffsetDateTime> {
    if value.is_empty() {
        return None;
    }
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Durability proof against a real Postgres: `POST`-equivalent create
    /// lands a row in the shared `assets` table (previously a detached
    /// in-memory store in DB mode) with the free-form `kind`/`source`
    /// mapped + round-tripped → duplicate → bad engagement (FK) → *fresh
    /// pool (restart-equivalent)* read survives → update → delete.
    ///
    /// Gated on `TEST_DATABASE_URL` (silent no-op in CI; workspace live-DB
    /// fixture convention). Seeds its own tenant + engagement (the `assets`
    /// FKs).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn pg_asset_write_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = Uuid::new_v4();
        let engagement = Uuid::new_v4();

        // --- seed tenant (no RLS) + engagement (under tenant GUC) ---------
        {
            let pool = PgPool::connect(&url).await.expect("connect");
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, tier) VALUES ($1, 'asset wr', $2, 'starter')",
            )
            .bind(tenant)
            .bind(format!("asset-wr-{tenant}"))
            .execute(&pool)
            .await
            .expect("seed tenant");
            let mut tx = begin_tenant_tx(&pool, tenant, 15_000)
                .await
                .expect("tenant tx");
            sqlx::query(
                "INSERT INTO engagements \
                     (id, tenant_id, name, window_start, window_end, status, intensity) \
                 VALUES ($1, $2, 'E', now(), now() + interval '1 day', 'Active', 'standard')",
            )
            .bind(engagement)
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .expect("seed engagement");
            tx.commit().await.expect("commit engagement");
        }

        let asset_id;
        {
            let pool = PgPool::connect(&url).await.expect("connect");
            let wr = PgAssetWriteAdapter {
                pool,
                stmt_timeout_ms: 15_000,
            };
            let view = wr
                .create(
                    &tenant.to_string(),
                    CreateAssetRequest {
                        engagement_id: engagement.to_string(),
                        kind: "host".to_owned(),
                        identifier: "api.example".to_owned(),
                        source: "manual".to_owned(),
                    },
                )
                .await
                .expect("create");
            asset_id = view.id.clone();
            assert_eq!(view.kind, "Host", "kind normalised to the enum");
            assert_eq!(view.identifier, "api.example");
            assert_eq!(
                view.source, "manual",
                "free-form source round-trips via tags"
            );

            // Duplicate fingerprint → Conflict.
            let dup = wr
                .create(
                    &tenant.to_string(),
                    CreateAssetRequest {
                        engagement_id: engagement.to_string(),
                        kind: "host".to_owned(),
                        identifier: "api.example".to_owned(),
                        source: "manual".to_owned(),
                    },
                )
                .await;
            assert!(
                matches!(dup, Err(EngagementPortError::Conflict(_))),
                "dup must conflict"
            );

            // Unknown kind → Invalid (400).
            let bad_kind = wr
                .create(
                    &tenant.to_string(),
                    CreateAssetRequest {
                        engagement_id: engagement.to_string(),
                        kind: "spaceship".to_owned(),
                        identifier: "x".to_owned(),
                        source: "manual".to_owned(),
                    },
                )
                .await;
            assert!(
                matches!(bad_kind, Err(EngagementPortError::Invalid(_))),
                "bad kind → 400"
            );

            // Non-existent engagement → Invalid (FK violation).
            let bad_eng = wr
                .create(
                    &tenant.to_string(),
                    CreateAssetRequest {
                        engagement_id: Uuid::new_v4().to_string(),
                        kind: "host".to_owned(),
                        identifier: "y".to_owned(),
                        source: "manual".to_owned(),
                    },
                )
                .await;
            assert!(
                matches!(bad_eng, Err(EngagementPortError::Invalid(_))),
                "missing engagement → 400"
            );
        }

        // Fresh pool == a fresh process. In-memory state would be gone.
        {
            let pool = PgPool::connect(&url).await.expect("reconnect");
            let rd = PgAssetsAdapter {
                pool: pool.clone(),
                stmt_timeout_ms: 15_000,
            };
            let got = rd
                .get(&tenant.to_string(), &asset_id)
                .await
                .expect("asset survived restart");
            assert_eq!(got.kind, "Host");
            assert_eq!(got.source, "manual", "source survived restart");

            let wr = PgAssetWriteAdapter {
                pool,
                stmt_timeout_ms: 15_000,
            };
            let updated = wr
                .update(
                    &tenant.to_string(),
                    &asset_id,
                    UpdateAssetRequest {
                        kind: Some("dns".to_owned()),
                        identifier: None,
                        source: Some("internet".to_owned()),
                    },
                )
                .await
                .expect("update");
            assert_eq!(updated.kind, "Dns");
            assert_eq!(
                updated.identifier, "api.example",
                "untouched field preserved"
            );
            assert_eq!(updated.source, "internet");

            wr.delete(&tenant.to_string(), &asset_id)
                .await
                .expect("delete");
            assert!(matches!(
                wr.delete(&tenant.to_string(), &asset_id).await,
                Err(EngagementPortError::NotFound)
            ));
        }
    }

    #[test]
    fn parse_uuid_rejects_invalid() {
        let err = parse_uuid("tenant_id", "not-a-uuid").expect_err("must reject");
        assert!(matches!(err, EngagementPortError::Invalid(_)));
    }

    #[test]
    fn parse_uuid_accepts_valid() {
        let u = Uuid::now_v7();
        let got = parse_uuid("tenant_id", &u.to_string()).expect("must accept");
        assert_eq!(got, u);
    }

    #[test]
    fn map_sqlx_row_not_found_is_not_found() {
        let mapped = map_sqlx_error(&sqlx::Error::RowNotFound);
        assert!(matches!(mapped, EngagementPortError::NotFound));
    }

    #[test]
    fn map_sqlx_pool_timed_out_is_dependency() {
        let mapped = map_sqlx_error(&sqlx::Error::PoolTimedOut);
        assert!(matches!(mapped, EngagementPortError::Dependency(_)));
    }

    #[test]
    fn map_storage_not_found_is_not_found() {
        let mapped = map_storage_error(&sx_storage::StorageError::NotFound);
        assert!(matches!(mapped, EngagementPortError::NotFound));
    }

    #[test]
    fn map_storage_conflict_is_conflict() {
        let mapped = map_storage_error(&sx_storage::StorageError::Conflict("dup".to_owned()));
        assert!(matches!(mapped, EngagementPortError::Conflict(_)));
    }

    #[test]
    fn offset_saturates_at_i64_max() {
        let got = offset_to_i64(u64::MAX);
        assert_eq!(got, i64::MAX);
    }

    #[test]
    fn rfc3339_roundtrips() {
        let now = OffsetDateTime::now_utc();
        let s = rfc3339(now);
        assert!(s.contains('T'), "{s} should be RFC3339");
    }
}
