//! Postgres-backed SOC rule repository.
//!
//! `soc_rules` rows persist operator-authored detection rules so the SOC
//! engine can hot-reload them without a redeploy. The repository is
//! intentionally minimal: `list`, `upsert`, and `delete`. Tenant
//! isolation is enforced via Row-Level Security (see the migration), so
//! every operation begins by setting `app.current_tenant_id` on the
//! transaction context.
//!
//! Idempotency on `(tenant_id, rule_id)` is enforced at the database
//! level via a `UNIQUE` constraint and consumed by the `ON CONFLICT`
//! clause of [`PgSocRuleRepository::upsert`].

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::value_object::TenantId;
use crate::error::StorageError;
use crate::tenant_context::TenantContext;

/// Default `statement_timeout` (ms) for SOC-rule transactions when
/// callers do not override at construction time.
const DEFAULT_STMT_TIMEOUT_MS: u64 = 5_000;

/// Row persisted in `soc_rules`.
///
/// The match condition is carried as a raw [`JsonValue`] so the storage
/// layer remains agnostic of the SOC DSL — schema evolution happens at
/// the engine layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocRuleRow {
    /// Surrogate primary key (uuid v7).
    pub id: Uuid,
    /// Owning tenant. RLS-checked.
    pub tenant_id: TenantId,
    /// Operator-chosen stable identifier, unique within the tenant.
    pub rule_id: String,
    /// Human-readable label. Optional.
    pub name: Option<String>,
    /// Severity bucket. One of `low | medium | high | critical`.
    pub severity: String,
    /// Match condition envelope, evaluated by the SOC engine.
    pub when_json: JsonValue,
    /// Optional cool-down between successive firings, in seconds.
    pub throttle_secs: Option<i32>,
    /// Whether the rule should be evaluated by the engine.
    pub enabled: bool,
}

/// `PgSocRuleRepository` — `soc_rules` table adapter (RLS).
#[derive(Debug, Clone)]
pub struct PgSocRuleRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgSocRuleRepository {
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

    /// List every SOC rule for `tenant_id`, ordered by `rule_id`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Repository`] if the underlying query
    /// fails for any reason.
    pub async fn list(&self, tenant_id: TenantId) -> Result<Vec<SocRuleRow>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, rule_id, name, severity, when_json, throttle_secs, enabled \
             FROM soc_rules \
             WHERE tenant_id = $1 \
             ORDER BY rule_id ASC",
        )
        .bind(tenant_id.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(row_to_soc_rule(r)?);
        }
        Ok(out)
    }

    /// Insert or update a SOC rule keyed on `(tenant_id, rule_id)`.
    ///
    /// The caller-supplied `row.tenant_id` is overridden with the
    /// argument `tenant_id` to defend against a wedged caller smuggling
    /// a cross-tenant write. The RLS policy would refuse it anyway, but
    /// the redundant check keeps the error surface as
    /// [`DomainError::Repository`] rather than an opaque RLS rejection.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Repository`] for I/O failures and
    /// [`DomainError::Conflict`] for unique-violation surfaces other
    /// than the expected `(tenant_id, rule_id)` upsert path.
    pub async fn upsert(&self, tenant_id: TenantId, row: SocRuleRow) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        sqlx::query(
            "INSERT INTO soc_rules \
                (id, tenant_id, rule_id, name, severity, when_json, throttle_secs, enabled, \
                 created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now()) \
             ON CONFLICT (tenant_id, rule_id) DO UPDATE SET \
                name          = EXCLUDED.name, \
                severity      = EXCLUDED.severity, \
                when_json     = EXCLUDED.when_json, \
                throttle_secs = EXCLUDED.throttle_secs, \
                enabled       = EXCLUDED.enabled, \
                updated_at    = now()",
        )
        .bind(row.id)
        .bind(tenant_id.as_uuid())
        .bind(&row.rule_id)
        .bind(row.name.as_deref())
        .bind(&row.severity)
        .bind(Json(&row.when_json))
        .bind(row.throttle_secs)
        .bind(row.enabled)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }

    /// Delete the rule identified by `(tenant_id, rule_id)`. A no-op if
    /// the row does not exist — callers wanting strict 404 semantics
    /// should `list` first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Repository`] if the underlying query
    /// fails for any reason.
    pub async fn delete(&self, tenant_id: TenantId, rule_id: &str) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        sqlx::query("DELETE FROM soc_rules WHERE tenant_id = $1 AND rule_id = $2")
            .bind(tenant_id.as_uuid())
            .bind(rule_id)
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }
}

fn row_to_soc_rule(row: &sqlx::postgres::PgRow) -> Result<SocRuleRow, StorageError> {
    let id: Uuid = row.try_get("id").map_err(StorageError::from)?;
    let tenant_id: Uuid = row.try_get("tenant_id").map_err(StorageError::from)?;
    let rule_id: String = row.try_get("rule_id").map_err(StorageError::from)?;
    let name: Option<String> = row.try_get("name").map_err(StorageError::from)?;
    let severity: String = row.try_get("severity").map_err(StorageError::from)?;
    let when_json: Json<JsonValue> = row.try_get("when_json").map_err(StorageError::from)?;
    let throttle_secs: Option<i32> = row.try_get("throttle_secs").map_err(StorageError::from)?;
    let enabled: bool = row.try_get("enabled").map_err(StorageError::from)?;
    Ok(SocRuleRow {
        id,
        tenant_id: TenantId::from_uuid(tenant_id),
        rule_id,
        name,
        severity,
        when_json: when_json.0,
        throttle_secs,
        enabled,
    })
}

fn map_sqlx(e: sqlx::Error) -> DomainError {
    StorageError::from(e).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! Tests for [`PgSocRuleRepository`].
    //!
    //! The live-DB tests (`live_round_trip_upsert_list_delete`,
    //! `live_rls_isolates_tenants`) are gated by `#[ignore]` because they
    //! need a real Postgres instance. Run them with
    //! `cargo test -p sx-storage -- --ignored` against a database whose
    //! URL is supplied via `TEST_DATABASE_URL`.
    use super::*;
    use crate::pool::{build_pool, PoolSettings};
    use secrecy::SecretString;
    use serde_json::json;
    use std::time::Duration;

    /// Build a SOC rule fixture with deterministic field values.
    fn fixture_rule(rule_id: &str, tenant: TenantId) -> SocRuleRow {
        SocRuleRow {
            id: Uuid::now_v7(),
            tenant_id: tenant,
            rule_id: rule_id.to_owned(),
            name: Some(format!("rule {rule_id}")),
            severity: "high".to_owned(),
            when_json: json!({ "all": [{ "event": "auth.failed" }] }),
            throttle_secs: Some(60),
            enabled: true,
        }
    }

    /// Construct a repository from `TEST_DATABASE_URL`. Returns `None`
    /// when the env var is unset so the test logs a skip instead of
    /// panicking — the same shape every other live-DB test in this
    /// crate uses.
    async fn maybe_repo() -> Option<PgSocRuleRepository> {
        // Reading `TEST_DATABASE_URL` directly from the process env is
        // the project-wide test convention for live-DB fixtures and is
        // intentionally NOT routed through `sx-config`.
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
        Some(PgSocRuleRepository::new(pool))
    }

    #[test]
    fn soc_rule_row_json_round_trips() {
        let row = fixture_rule("R-001", TenantId::new());
        let encoded = serde_json::to_string(&row).expect("serialize");
        let decoded: SocRuleRow = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(row, decoded);
        // Ensure the `when_json` envelope survives the round trip without
        // being flattened into a string.
        assert!(decoded.when_json.is_object());
    }

    #[test]
    fn soc_rule_row_preserves_optional_columns() {
        // Explicit `None` on optional columns must round-trip.
        let row = SocRuleRow {
            id: Uuid::now_v7(),
            tenant_id: TenantId::new(),
            rule_id: "R-002".to_owned(),
            name: None,
            severity: "critical".to_owned(),
            when_json: json!(null),
            throttle_secs: None,
            enabled: false,
        };
        let encoded = serde_json::to_string(&row).expect("serialize");
        let decoded: SocRuleRow = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(row, decoded);
        assert!(decoded.name.is_none());
        assert!(decoded.throttle_secs.is_none());
        assert!(!decoded.enabled);
    }

    #[tokio::test]
    async fn new_does_not_perform_io() {
        // `PgPool::connect_lazy` is the only way to obtain a `PgPool`
        // without touching the network. The constructor must be `const`
        // and copy the pool handle without further work. The `const fn`
        // signature already proves no I/O at compile time; this test
        // guards against a future refactor that introduces background
        // work (e.g. spawning a probe task).
        //
        // The Tokio context is supplied so the `PgPool::Drop` path —
        // which schedules a teardown task — finds a runtime; otherwise
        // the test would panic at shutdown unrelated to the SUT.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy must not perform I/O");
        // Default-timeout constructor: assert it picked the documented
        // default without poking the network.
        let repo = PgSocRuleRepository::new(pool.clone());
        assert_eq!(repo.stmt_timeout_ms, DEFAULT_STMT_TIMEOUT_MS);
        // Override-timeout constructor: same shape, custom budget.
        let with_to = PgSocRuleRepository::with_statement_timeout(pool, 1_000);
        assert_eq!(with_to.stmt_timeout_ms, 1_000);
    }

    #[test]
    fn fixture_rule_has_expected_shape() {
        let tenant = TenantId::new();
        let r = fixture_rule("R-001", tenant);
        assert_eq!(r.tenant_id, tenant);
        assert_eq!(r.rule_id, "R-001");
        assert_eq!(r.severity, "high");
        assert!(r.enabled);
        assert_eq!(r.throttle_secs, Some(60));
        assert!(r.when_json.is_object());
    }

    /// Live-DB test: insert via `upsert`, fetch via `list`, mutate and
    /// re-`upsert`, then `delete`. Verifies the full CRUD round trip
    /// against the schema, including the JSONB envelope and the
    /// `ON CONFLICT` update path.
    #[tokio::test]
    #[ignore = "Requires live Postgres on TEST_DATABASE_URL"]
    async fn live_round_trip_upsert_list_delete() {
        let Some(repo) = maybe_repo().await else {
            return;
        };
        // Tenant id must already exist in `tenants` for the FK to hold.
        // The integration-smoke harness pre-seeds a known tenant — we
        // mint a fresh UUID here and assume the harness has wired the
        // FK to be deferrable or that the row exists. If not, the test
        // fails fast with a clear message.
        let tenant = TenantId::new();
        let r = fixture_rule("R-LIVE-01", tenant);

        repo.upsert(tenant, r.clone()).await.expect("upsert");
        let listed = repo.list(tenant).await.expect("list");
        assert!(listed.iter().any(|row| row.rule_id == r.rule_id));

        let mut updated = r.clone();
        updated.severity = "critical".to_owned();
        updated.enabled = false;
        repo.upsert(tenant, updated.clone())
            .await
            .expect("re-upsert");

        let listed2 = repo.list(tenant).await.expect("list-2");
        let found = listed2
            .into_iter()
            .find(|row| row.rule_id == updated.rule_id)
            .expect("row must exist after re-upsert");
        assert_eq!(found.severity, "critical");
        assert!(!found.enabled);

        repo.delete(tenant, &updated.rule_id).await.expect("delete");
        let listed3 = repo.list(tenant).await.expect("list-3");
        assert!(listed3.iter().all(|row| row.rule_id != updated.rule_id));
    }

    /// Live-DB test: a rule owned by tenant A must not appear when
    /// tenant B calls `list`. This pins the RLS policy + tenant-bound
    /// `WHERE` clause working together.
    #[tokio::test]
    #[ignore = "Requires live Postgres on TEST_DATABASE_URL"]
    async fn live_rls_isolates_tenants() {
        let Some(repo) = maybe_repo().await else {
            return;
        };
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let r = fixture_rule("R-RLS-01", tenant_a);

        repo.upsert(tenant_a, r.clone()).await.expect("upsert-a");
        let listed_b = repo.list(tenant_b).await.expect("list-b");
        assert!(
            listed_b.iter().all(|row| row.rule_id != r.rule_id),
            "tenant B must not see tenant A's rule",
        );

        let listed_a = repo.list(tenant_a).await.expect("list-a");
        assert!(
            listed_a.iter().any(|row| row.rule_id == r.rule_id),
            "tenant A must see its own rule",
        );

        // Clean up so subsequent reruns are idempotent.
        repo.delete(tenant_a, &r.rule_id).await.expect("cleanup");
    }
}
