//! Postgres-backed [`ChainHeadSource`] reading from `audit_log`.
//!
//! The HMAC anchor publisher (see [`sx_audit::anchor`]) needs to read
//! the latest chain head for **every** tenant in a single pass so it
//! can write one tamper-evident manifest per tenant. The natural place
//! to enumerate every tenant is the storage layer; this module provides
//! the concrete adapter.
//!
//! # RLS bypass
//!
//! `audit_log` has Row-Level Security enabled with a `tenant_id =
//! current_setting('app.current_tenant_id')` policy (see
//! `migrations/20260101000010_enable_rls.sql`). The anchor publisher is
//! a **system-level** operator — it has no single "current tenant" and
//! must observe heads across the entire table. To do so it issues
//! `SET LOCAL row_security = off` at the start of the read transaction.
//!
//! This is safe because:
//!
//! - The publisher is composed at the monolith root and only ever
//!   bound to a privileged operator role at the database layer.
//! - The read is strictly aggregate (`MAX(seq)` + the matching hash)
//!   and never returns row payloads to a tenant-scoped caller.
//! - `SET LOCAL` is scoped to the transaction; concurrent tenant-scoped
//!   transactions on the same pool keep their own RLS context.
//!
//! # SQL
//!
//! ```sql
//! SELECT a1.tenant_id,
//!        MAX(a1.seq) AS head_seq,
//!        (SELECT encode(a2.hash, 'hex')
//!         FROM audit_log a2
//!         WHERE a2.tenant_id = a1.tenant_id
//!         ORDER BY a2.seq DESC
//!         LIMIT 1) AS head_hash
//! FROM audit_log a1
//! GROUP BY a1.tenant_id;
//! ```
//!
//! Note the actual column name in `audit_log` is `hash` (BYTEA, 32-byte
//! SHA-256). It is hex-encoded server-side so the returned `head_hash`
//! drops straight into [`ChainHead::head_hash`] without further
//! conversion.

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use sx_audit::anchor::{AnchorError, ChainHead, ChainHeadSource};
use sx_core::value_object::ids::TenantId;

/// Default `statement_timeout` (ms) for the anchor read transaction.
///
/// The read is `O(tenants)` after the `(tenant_id, seq DESC)` index
/// scan; 10s gives ample margin even with thousands of tenants.
const DEFAULT_STMT_TIMEOUT_MS: u64 = 10_000;

/// `PgChainHeadSource` — enumerates the latest chain head per tenant.
///
/// The struct is intentionally minimal — a thin wrapper around a
/// [`PgPool`] handle that performs no I/O at construction time. It is
/// `Clone` because [`PgPool`] is `Clone` (handle clone, no new
/// connections).
#[derive(Debug, Clone)]
pub struct PgChainHeadSource {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgChainHeadSource {
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
}

/// SQL the adapter issues. Pulled into a constant so it appears once
/// in the binary and is trivially auditable.
const LIST_HEADS_SQL: &str = "SELECT a1.tenant_id, \
            MAX(a1.seq) AS head_seq, \
            (SELECT encode(a2.hash, 'hex') \
             FROM audit_log a2 \
             WHERE a2.tenant_id = a1.tenant_id \
             ORDER BY a2.seq DESC \
             LIMIT 1) AS head_hash \
     FROM audit_log a1 \
     GROUP BY a1.tenant_id";

#[async_trait]
impl ChainHeadSource for PgChainHeadSource {
    async fn list_chain_heads(&self) -> Result<Vec<ChainHead>, AnchorError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AnchorError::Source(e.to_string()))?;

        // Per-transaction `statement_timeout` so a hung read cannot
        // wedge the publisher loop.
        sqlx::query(&format!(
            "SET LOCAL statement_timeout = {}",
            self.stmt_timeout_ms
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| AnchorError::Source(e.to_string()))?;

        // The publisher runs as a privileged operator role; bypass RLS
        // so MAX(seq) sees every tenant rather than the single tenant
        // a `current_tenant_id` GUC would gate to. Scoped to the
        // transaction by `SET LOCAL`.
        sqlx::query("SET LOCAL row_security = off")
            .execute(&mut *tx)
            .await
            .map_err(|e| AnchorError::Source(e.to_string()))?;

        let rows = sqlx::query(LIST_HEADS_SQL)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| AnchorError::Source(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AnchorError::Source(e.to_string()))?;

        let mut heads = Vec::with_capacity(rows.len());
        for row in &rows {
            let tenant_id: Uuid = row
                .try_get("tenant_id")
                .map_err(|e| AnchorError::Source(e.to_string()))?;
            let head_seq_i64: i64 = row
                .try_get("head_seq")
                .map_err(|e| AnchorError::Source(e.to_string()))?;
            // `head_seq` is a BIGINT (sequence number) — always >= 1 in
            // a valid chain. We clamp at zero defensively so a corrupt
            // row cannot panic the publisher; the publisher itself
            // skips tenants with `head_seq == 0`.
            let head_seq = u64::try_from(head_seq_i64).unwrap_or(0);
            // `encode(hash, 'hex')` returns lowercase hex matching the
            // format produced by `hex::encode(...)` in `sx-audit`.
            let head_hash: String = row
                .try_get("head_hash")
                .map_err(|e| AnchorError::Source(e.to_string()))?;
            heads.push(ChainHead {
                tenant_id: TenantId::from_uuid(tenant_id),
                head_seq,
                head_hash,
            });
        }
        Ok(heads)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Tests for [`PgChainHeadSource`].
    //!
    //! The live-DB tests are gated by `#[ignore]` because they need a
    //! real Postgres instance with `audit_log` and `tenants` migrated.
    //! Run them with `cargo test -p sx-storage -- --ignored` against a
    //! database whose URL is supplied via `TEST_DATABASE_URL`.
    use super::*;
    use crate::pool::{build_pool, PoolSettings};
    use secrecy::SecretString;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;

    /// Build a pool against `TEST_DATABASE_URL` for live integration
    /// tests. Returns `None` when the env var is unset so the test
    /// logs a skip instead of panicking — same shape every other
    /// live-DB test in this crate uses.
    async fn maybe_pool() -> Option<PgPool> {
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
            statement_timeout_ms: 10_000,
            application_name: "sx-storage-test",
        };
        build_pool(&settings).await.ok()
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
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy must not perform I/O");
        let src = PgChainHeadSource::new(pool.clone());
        assert_eq!(src.stmt_timeout_ms, DEFAULT_STMT_TIMEOUT_MS);
        // Override-timeout constructor: same shape, custom budget.
        let with_to = PgChainHeadSource::with_statement_timeout(pool, 1_000);
        assert_eq!(with_to.stmt_timeout_ms, 1_000);
    }

    #[test]
    fn list_heads_sql_is_well_formed() {
        // Trivial structural guard so a typo in the constant fails the
        // test rather than only the live-DB integration run.
        assert!(LIST_HEADS_SQL.contains("FROM audit_log"));
        assert!(LIST_HEADS_SQL.contains("MAX(a1.seq)"));
        assert!(LIST_HEADS_SQL.contains("encode(a2.hash, 'hex')"));
        assert!(LIST_HEADS_SQL.contains("GROUP BY a1.tenant_id"));
    }

    /// Live integration: seed two tenants, three rows total, and assert
    /// the adapter returns one row per tenant with the correct
    /// (max seq, matching hash).
    #[tokio::test]
    #[ignore = "Requires live Postgres on TEST_DATABASE_URL with audit_log seeded"]
    async fn live_list_heads_returns_one_row_per_tenant() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // Two fresh tenant ids so the test is independent of any
        // existing rows in `audit_log`.
        let t1 = TenantId::new();
        let t2 = TenantId::new();

        // Tenants table FK must be satisfied. Insert minimal rows.
        for t in [t1, t2] {
            sqlx::query(
                "INSERT INTO tenants (id, name) VALUES ($1, $2) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(t.as_uuid())
            .bind(format!("anchor-test-{t}"))
            .execute(&pool)
            .await
            .expect("seed tenant");
        }

        // Seed 3 audit rows: t1 at seq=1,2 (head should be seq=2);
        // t2 at seq=1 only. Hashes are deterministic per-row so we can
        // assert the correct one came back.
        let hash_t1_s1 = [0x11u8; 32];
        let hash_t1_s2 = [0x22u8; 32];
        let hash_t2_s1 = [0x33u8; 32];
        for (tenant, seq, hash) in [
            (t1, 1_i64, hash_t1_s1),
            (t1, 2_i64, hash_t1_s2),
            (t2, 1_i64, hash_t2_s1),
        ] {
            sqlx::query(
                "INSERT INTO audit_log \
                    (tenant_id, seq, actor, action, resource_kind, resource_id, hash) \
                 VALUES ($1, $2, '{}'::jsonb, 'test.action', 'test', 'r', $3) \
                 ON CONFLICT (tenant_id, seq) DO NOTHING",
            )
            .bind(tenant.as_uuid())
            .bind(seq)
            .bind(&hash[..])
            .execute(&pool)
            .await
            .expect("seed audit_log row");
        }

        let src = PgChainHeadSource::new(pool.clone());
        let heads = src.list_chain_heads().await.expect("list_chain_heads");

        // The result may include other pre-existing tenants in a shared
        // dev database, so we filter to just our seeded ones.
        let mine: Vec<&ChainHead> = heads
            .iter()
            .filter(|h| h.tenant_id == t1 || h.tenant_id == t2)
            .collect();
        assert_eq!(mine.len(), 2, "expected exactly two tenant heads");

        let h1 = mine
            .iter()
            .find(|h| h.tenant_id == t1)
            .expect("t1 head present");
        assert_eq!(h1.head_seq, 2);
        assert_eq!(h1.head_hash, hex::encode(hash_t1_s2));

        let h2 = mine
            .iter()
            .find(|h| h.tenant_id == t2)
            .expect("t2 head present");
        assert_eq!(h2.head_seq, 1);
        assert_eq!(h2.head_hash, hex::encode(hash_t2_s1));

        // Clean up so subsequent reruns are idempotent.
        for t in [t1, t2] {
            sqlx::query("DELETE FROM audit_log WHERE tenant_id = $1")
                .bind(t.as_uuid())
                .execute(&pool)
                .await
                .expect("cleanup audit_log");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(t.as_uuid())
                .execute(&pool)
                .await
                .expect("cleanup tenants");
        }
    }

    /// Live integration: an empty `audit_log` (in the slice the test
    /// observes) yields an empty `Vec`. We assert no panic and the
    /// returned `Vec` does not contain our freshly minted tenant ids.
    #[tokio::test]
    #[ignore = "Requires live Postgres on TEST_DATABASE_URL with audit_log seeded"]
    async fn live_empty_audit_log_returns_no_rows_for_unseeded_tenant() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let unseen = TenantId::new();
        let src = PgChainHeadSource::new(pool);
        let heads = src.list_chain_heads().await.expect("list_chain_heads");
        assert!(
            heads.iter().all(|h| h.tenant_id != unseen),
            "freshly minted tenant must not appear",
        );
    }

    /// Error-path: pointing the source at a closed pool surfaces the
    /// transport failure as [`AnchorError::Source`] rather than a
    /// panic. This is the contract the publisher relies on.
    #[tokio::test]
    async fn closed_pool_surfaces_source_error() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy must not perform I/O");
        // Close before issuing the query — guarantees the call hits
        // `PoolClosed` rather than waiting on a TCP handshake.
        pool.close().await;
        let src = PgChainHeadSource::new(pool);
        let err = src
            .list_chain_heads()
            .await
            .expect_err("closed pool must error");
        assert!(
            matches!(err, AnchorError::Source(_)),
            "expected AnchorError::Source, got {err:?}",
        );
    }
}
