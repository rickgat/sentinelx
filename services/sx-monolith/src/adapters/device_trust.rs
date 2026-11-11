//! Device-trust adapter — bridges [`sx_device_trust::InMemoryDeviceTrustService`]
//! into [`sx_api::port::DeviceTrustPort`].
//!
//! The adapter is intentionally thin: it owns the in-memory policy +
//! snapshot store and forwards every call to the underlying service.
//! Swapping to a Postgres-backed implementation later is a one-line
//! change in the composition root — the trait surface is identical.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::DeviceTrustPort;
use sx_device_trust::service::{
    evaluate_policy, DeviceTrustDecision, DeviceTrustError, DeviceTrustService, DeviceTrustStatus,
    InMemoryDeviceTrustService, PostureSnapshot,
};
use sx_device_trust::{PostureClaims, PosturePolicy};
use sx_storage::domain::value_object::TenantId;
use sx_storage::tenant_context::TenantContext;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// Bundle returned to the composition root.
pub(crate) struct DeviceTrustBundle {
    /// HTTP-facing device-trust port.
    pub device_trust: Arc<dyn DeviceTrustPort>,
}

/// Build the device-trust adapter. `jwt_secret` is the HMAC secret the
/// posture middleware uses to verify incoming `X-Sentinelx-Device-Posture`
/// headers — for the MVP it is intentionally identical to the session
/// JWT secret so a single config knob covers both signing paths.
pub(crate) fn build(jwt_secret: Vec<u8>) -> DeviceTrustBundle {
    let svc: Arc<dyn DeviceTrustService> = Arc::new(InMemoryDeviceTrustService::new());
    DeviceTrustBundle {
        device_trust: Arc::new(DeviceTrustAdapter { svc, jwt_secret }),
    }
}

/// Build the durable Postgres-backed device-trust adapter. Selected by the
/// composition root when the database is enabled, so per-tenant posture
/// **policy** and the observed-snapshot **audit history** survive a restart
/// instead of resetting to the permissive default on every boot.
///
/// Reuses the pre-existing `device_posture_policy` + `device_posture_snapshots`
/// tables (migration `20270101001100`), both FORCE-RLS on
/// `app_current_tenant()`; every operation runs inside a tenant-scoped
/// transaction via [`TenantContext::apply`].
pub(crate) fn build_pg(
    pool: PgPool,
    stmt_timeout_ms: u64,
    jwt_secret: Vec<u8>,
) -> DeviceTrustBundle {
    let svc: Arc<dyn DeviceTrustService> =
        Arc::new(PgDeviceTrustService::new(pool, stmt_timeout_ms));
    DeviceTrustBundle {
        device_trust: Arc::new(DeviceTrustAdapter { svc, jwt_secret }),
    }
}

/// Concrete [`DeviceTrustPort`] implementation. Holds the service behind a
/// trait object so the in-memory and Postgres backends share one adapter.
#[derive(Debug)]
struct DeviceTrustAdapter {
    svc: Arc<dyn DeviceTrustService>,
    /// HMAC secret shared with the session JWT signer. Held as bytes so
    /// the trait method can hand out a fresh `Vec<u8>` per call.
    jwt_secret: Vec<u8>,
}

#[async_trait]
impl DeviceTrustPort for DeviceTrustAdapter {
    async fn get_policy(&self, tenant_id: &str) -> Result<PosturePolicy, DeviceTrustError> {
        self.svc.get_policy(tenant_id).await
    }

    async fn put_policy(
        &self,
        tenant_id: &str,
        policy: PosturePolicy,
    ) -> Result<PosturePolicy, DeviceTrustError> {
        self.svc.put_policy(tenant_id, policy).await
    }

    async fn evaluate(
        &self,
        tenant_id: &str,
        posture: &PostureClaims,
    ) -> Result<DeviceTrustDecision, DeviceTrustError> {
        self.svc.evaluate(tenant_id, posture).await
    }

    async fn record_snapshot(
        &self,
        tenant_id: &str,
        snapshot: PostureSnapshot,
    ) -> Result<(), DeviceTrustError> {
        self.svc.record_snapshot(tenant_id, snapshot).await
    }

    async fn list_snapshots(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<PostureSnapshot>, DeviceTrustError> {
        self.svc.list_snapshots(tenant_id, limit).await
    }

    fn jwt_secret(&self) -> Vec<u8> {
        self.jwt_secret.clone()
    }
}

/// Postgres-backed [`DeviceTrustService`]. Policy is one JSONB row per
/// tenant (missing → [`PosturePolicy::permissive`], matching the in-memory
/// default); snapshots are an append-only per-tenant log capped at the
/// newest `snapshot_cap` rows. Evaluation reuses the crate's public
/// [`evaluate_policy`] so the verdict logic is byte-identical across
/// backends.
struct PgDeviceTrustService {
    pool: PgPool,
    stmt_timeout_ms: u64,
    snapshot_cap: i64,
}

impl std::fmt::Debug for PgDeviceTrustService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgDeviceTrustService")
            .finish_non_exhaustive()
    }
}

impl PgDeviceTrustService {
    /// Default retained-snapshot cap per tenant — matches
    /// [`InMemoryDeviceTrustService::new`].
    const DEFAULT_SNAPSHOT_CAP: i64 = 500;

    fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
            snapshot_cap: Self::DEFAULT_SNAPSHOT_CAP,
        }
    }

    fn dep(e: impl std::fmt::Display) -> DeviceTrustError {
        DeviceTrustError::Dependency(format!("device-trust store: {e}"))
    }

    fn tenant_uuid(tenant_id: &str) -> Result<Uuid, DeviceTrustError> {
        Uuid::parse_str(tenant_id)
            .map_err(|e| DeviceTrustError::Invalid(format!("tenant id not a uuid: {e}")))
    }

    async fn begin(
        &self,
        tenant_uuid: Uuid,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, DeviceTrustError> {
        let mut tx = self.pool.begin().await.map_err(Self::dep)?;
        TenantContext::apply(
            &mut tx,
            TenantId::from_uuid(tenant_uuid),
            self.stmt_timeout_ms,
        )
        .await
        .map_err(Self::dep)?;
        Ok(tx)
    }
}

/// Map the DB `status` TEXT back to the enum (the column CHECK keeps this
/// total in practice; an unknown value is a schema drift bug).
fn status_from_db(s: &str) -> Result<DeviceTrustStatus, DeviceTrustError> {
    match s {
        "trusted" => Ok(DeviceTrustStatus::Trusted),
        "untrusted" => Ok(DeviceTrustStatus::Untrusted),
        "stale" => Ok(DeviceTrustStatus::Stale),
        other => Err(DeviceTrustError::Internal(format!(
            "unknown device-trust status '{other}'"
        ))),
    }
}

#[async_trait]
impl DeviceTrustService for PgDeviceTrustService {
    async fn get_policy(&self, tenant_id: &str) -> Result<PosturePolicy, DeviceTrustError> {
        let tid = Self::tenant_uuid(tenant_id)?;
        let mut tx = self.begin(tid).await?;
        let row = sqlx::query("SELECT policy FROM device_posture_policy WHERE tenant_id = $1")
            .bind(tid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::dep)?;
        tx.commit().await.map_err(Self::dep)?;
        match row {
            Some(r) => r
                .try_get::<Json<PosturePolicy>, _>("policy")
                .map(|j| j.0)
                .map_err(Self::dep),
            None => Ok(PosturePolicy::permissive()),
        }
    }

    async fn put_policy(
        &self,
        tenant_id: &str,
        policy: PosturePolicy,
    ) -> Result<PosturePolicy, DeviceTrustError> {
        let tid = Self::tenant_uuid(tenant_id)?;
        let mut tx = self.begin(tid).await?;
        sqlx::query(
            "INSERT INTO device_posture_policy (tenant_id, policy, updated_at) \
             VALUES ($1, $2, now()) \
             ON CONFLICT (tenant_id) DO UPDATE SET policy = EXCLUDED.policy, updated_at = now()",
        )
        .bind(tid)
        .bind(Json(&policy))
        .execute(&mut *tx)
        .await
        .map_err(Self::dep)?;
        tx.commit().await.map_err(Self::dep)?;
        Ok(policy)
    }

    async fn evaluate(
        &self,
        tenant_id: &str,
        posture: &PostureClaims,
    ) -> Result<DeviceTrustDecision, DeviceTrustError> {
        let policy = self.get_policy(tenant_id).await?;
        Ok(evaluate_policy(&policy, posture))
    }

    async fn record_snapshot(
        &self,
        tenant_id: &str,
        snapshot: PostureSnapshot,
    ) -> Result<(), DeviceTrustError> {
        let tid = Self::tenant_uuid(tenant_id)?;
        let id = Uuid::parse_str(&snapshot.id)
            .map_err(|e| DeviceTrustError::Invalid(format!("snapshot id not a uuid: {e}")))?;
        let user_id = Uuid::parse_str(&snapshot.user_id)
            .map_err(|e| DeviceTrustError::Invalid(format!("user id not a uuid: {e}")))?;
        let session_id = Uuid::parse_str(&snapshot.session_id)
            .map_err(|e| DeviceTrustError::Invalid(format!("session id not a uuid: {e}")))?;
        // Preserve the caller-supplied observation time; fall back to now()
        // only if the string is not RFC3339 (defensive — the middleware
        // always formats RFC3339).
        let observed_at = OffsetDateTime::parse(&snapshot.observed_at, &Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let mut tx = self.begin(tid).await?;
        sqlx::query(
            "INSERT INTO device_posture_snapshots \
                 (id, tenant_id, user_id, session_id, status, claims, reasons, observed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(tid)
        .bind(user_id)
        .bind(session_id)
        .bind(snapshot.status.as_str())
        .bind(Json(&snapshot.claims))
        .bind(Json(&snapshot.reasons))
        .bind(observed_at)
        .execute(&mut *tx)
        .await
        .map_err(Self::dep)?;
        // Bound the retained log to the newest `snapshot_cap` rows per tenant,
        // mirroring the in-memory ring buffer's eviction.
        sqlx::query(
            "DELETE FROM device_posture_snapshots \
             WHERE tenant_id = $1 AND id NOT IN ( \
                 SELECT id FROM device_posture_snapshots \
                 WHERE tenant_id = $1 \
                 ORDER BY observed_at DESC, id DESC \
                 LIMIT $2 \
             )",
        )
        .bind(tid)
        .bind(self.snapshot_cap)
        .execute(&mut *tx)
        .await
        .map_err(Self::dep)?;
        tx.commit().await.map_err(Self::dep)?;
        Ok(())
    }

    async fn list_snapshots(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<PostureSnapshot>, DeviceTrustError> {
        let tid = Self::tenant_uuid(tenant_id)?;
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut tx = self.begin(tid).await?;
        let rows = sqlx::query(
            "SELECT id, user_id, session_id, status, claims, reasons, observed_at \
             FROM device_posture_snapshots \
             WHERE tenant_id = $1 \
             ORDER BY observed_at DESC, id DESC \
             LIMIT $2",
        )
        .bind(tid)
        .bind(lim)
        .fetch_all(&mut *tx)
        .await
        .map_err(Self::dep)?;
        tx.commit().await.map_err(Self::dep)?;
        rows.into_iter()
            .map(|r| {
                let status_txt: String = r.try_get("status").map_err(Self::dep)?;
                let observed: OffsetDateTime = r.try_get("observed_at").map_err(Self::dep)?;
                Ok(PostureSnapshot {
                    id: r.try_get::<Uuid, _>("id").map_err(Self::dep)?.to_string(),
                    user_id: r
                        .try_get::<Uuid, _>("user_id")
                        .map_err(Self::dep)?
                        .to_string(),
                    session_id: r
                        .try_get::<Uuid, _>("session_id")
                        .map_err(Self::dep)?
                        .to_string(),
                    status: status_from_db(&status_txt)?,
                    claims: r
                        .try_get::<Json<PostureClaims>, _>("claims")
                        .map(|j| j.0)
                        .map_err(Self::dep)?,
                    reasons: r
                        .try_get::<Json<Vec<String>>, _>("reasons")
                        .map(|j| j.0)
                        .map_err(Self::dep)?,
                    observed_at: observed.format(&Rfc3339).unwrap_or_default(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_device_trust::service::DeviceTrustStatus;

    fn tenant() -> &'static str {
        "01010101-0101-0101-0101-010101010101"
    }

    #[tokio::test]
    async fn round_trips_policy() {
        let bundle = build(b"secret".to_vec());
        let p = PosturePolicy::strict_baseline();
        bundle
            .device_trust
            .put_policy(tenant(), p.clone())
            .await
            .unwrap();
        let got = bundle.device_trust.get_policy(tenant()).await.unwrap();
        assert_eq!(got, p);
    }

    #[tokio::test]
    async fn evaluates_against_stored_policy() {
        let bundle = build(b"secret".to_vec());
        bundle
            .device_trust
            .put_policy(tenant(), PosturePolicy::strict_baseline())
            .await
            .unwrap();
        let posture = PostureClaims {
            disk_encrypted: true,
            edr_present: true,
            screen_lock_minutes: Some(5),
            os_name: Some("macOS".into()),
            os_version: Some("14.5.0".into()),
            ..PostureClaims::default()
        };
        let dec = bundle
            .device_trust
            .evaluate(tenant(), &posture)
            .await
            .unwrap();
        assert_eq!(dec.status, DeviceTrustStatus::Trusted);
    }

    #[tokio::test]
    async fn snapshot_record_and_list() {
        let bundle = build(b"secret".to_vec());
        bundle
            .device_trust
            .record_snapshot(
                tenant(),
                PostureSnapshot {
                    id: "00000000-0000-0000-0000-000000000001".into(),
                    user_id: "u".into(),
                    session_id: "s".into(),
                    status: DeviceTrustStatus::Trusted,
                    claims: PostureClaims::default(),
                    reasons: vec![],
                    observed_at: "2026-01-01T00:00:00Z".into(),
                },
            )
            .await
            .unwrap();
        let list = bundle
            .device_trust
            .list_snapshots(tenant(), 10)
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn jwt_secret_is_returned_verbatim() {
        let bundle = build(b"hello-secret".to_vec());
        assert_eq!(bundle.device_trust.jwt_secret(), b"hello-secret".to_vec());
    }

    /// Durability proof against a real Postgres: a strict policy + a posture
    /// snapshot written for a freshly-seeded tenant survive a *fresh pool
    /// (restart-equivalent)*, while an unwritten tenant reads back the
    /// permissive default. Gated on `TEST_DATABASE_URL` (silent no-op in CI;
    /// workspace live-DB fixture convention).
    #[tokio::test]
    async fn pg_device_trust_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };

        let tenant = uuid::Uuid::new_v4();
        let tenant_s = tenant.to_string();
        let user = uuid::Uuid::new_v4().to_string();
        let session = uuid::Uuid::new_v4().to_string();
        let snap_id = uuid::Uuid::new_v4().to_string();

        // Seed the tenant row (FK target for both device-posture tables).
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, tier) VALUES ($1, $2, $3, 'starter') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(tenant)
            .bind(format!("dt-{tenant}"))
            .bind(format!("dt-{tenant}"))
            .execute(&pool)
            .await
            .expect("seed tenant");
        }

        // First process: write policy + one snapshot.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let svc = PgDeviceTrustService::new(pool, 15_000);
            svc.put_policy(&tenant_s, PosturePolicy::strict_baseline())
                .await
                .expect("put policy");
            svc.record_snapshot(
                &tenant_s,
                PostureSnapshot {
                    id: snap_id.clone(),
                    user_id: user.clone(),
                    session_id: session.clone(),
                    status: DeviceTrustStatus::Trusted,
                    claims: PostureClaims::default(),
                    reasons: vec![],
                    observed_at: "2026-01-01T00:00:00Z".into(),
                },
            )
            .await
            .expect("record snapshot");
        }

        // Fresh pool == a fresh process. In-memory state would be gone.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let svc = PgDeviceTrustService::new(pool, 15_000);
            let policy = svc.get_policy(&tenant_s).await.expect("get policy");
            assert_eq!(
                policy,
                PosturePolicy::strict_baseline(),
                "policy survived restart"
            );
            let snaps = svc.list_snapshots(&tenant_s, 10).await.expect("list");
            assert_eq!(snaps.len(), 1, "snapshot survived restart");
            assert_eq!(snaps[0].id, snap_id);
            assert_eq!(snaps[0].status, DeviceTrustStatus::Trusted);

            // An unwritten tenant inherits the permissive default.
            let other = uuid::Uuid::new_v4().to_string();
            let def = svc.get_policy(&other).await.expect("get missing");
            assert_eq!(def, PosturePolicy::permissive());
        }

        // Cleanup (cascades to both device-posture tables).
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup");
        }
    }
}
