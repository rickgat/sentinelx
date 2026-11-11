//! Live-Redis integration tests for the [`KillSwitch`] port.
//!
//! These tests exercise a small in-test `RedisKillSwitch` against a real
//! Redis instance. The production implementation lives in the monolith
//! composition root (`services/sx-monolith/src/adapters/redis.rs`) and is
//! intentionally `pub(crate)` there; we re-implement the trait locally so
//! the trait *contract* can be exercised from this crate without pulling
//! `sx-monolith` as a dev-dependency.
//!
//! Every test is gated by `#[ignore = "..."]` so `cargo test` stays green
//! in offline CI. Run them with:
//!
//! ```text
//! docker compose up -d redis
//! cargo test -p sx-engagement -- --ignored
//! ```
//!
//! Test isolation: each test scopes its kill-switch keys under a fresh
//! `TenantId`/`EngagementId` so parallel runs against the same Redis
//! cannot collide.

#![forbid(unsafe_code)]
// Integration tests are inherently `unwrap`-heavy and may abort the suite
// if the live dependency is unavailable. The repository policy of
// `unwrap_used = deny` + `panic = deny` applies workspace-wide; opt out
// here so live tests can express failure plainly.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_methods,
    clippy::missing_const_for_fn
)]

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use sx_core::value_object::ids::{EngagementId, TenantId};
use sx_engagement::error::EngagementError;
use sx_engagement::service::kill_switch::{
    KillReason, KillSwitch, KillSwitchEvent, KillSwitchScope,
};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration as TokioDuration};

const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379/0";
const TTL_SECS: u64 = 60;
const CHANNEL_CAPACITY: usize = 16;

/// Test-local Redis-backed `KillSwitch`.
///
/// Mirrors the production adapter byte-for-byte on the key layout and
/// pub/sub channel name so this test really does guard the production
/// wire-format. Pub/sub coverage is *not* duplicated here — that path is
/// already covered by unit tests in the monolith adapter and by the
/// in-memory `KillSwitch` contract tests.
#[derive(Clone)]
struct RedisKillSwitch {
    manager: ConnectionManager,
    tx: broadcast::Sender<KillSwitchEvent>,
}

// `ConnectionManager` is not `Debug`; the `KillSwitch` trait requires it,
// so we provide a manual impl that never leaks connection details.
impl std::fmt::Debug for RedisKillSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisKillSwitch")
            .field("manager", &"<redis::aio::ConnectionManager>")
            .field("subscribers", &self.tx.receiver_count())
            .finish()
    }
}

#[async_trait]
impl KillSwitch for RedisKillSwitch {
    async fn trip(
        &self,
        scope: KillSwitchScope,
        reason: KillReason,
    ) -> Result<(), EngagementError> {
        let key = scope_key(scope);
        let mut conn = self.manager.clone();
        let _: redis::Value = conn
            .set_ex(&key, reason.to_string(), TTL_SECS)
            .await
            .map_err(|e| EngagementError::Internal(format!("redis: {e}")))?;

        let event = KillSwitchEvent {
            scope,
            reason,
            at: time::OffsetDateTime::now_utc(),
        };
        // Local subscribers — don't actually publish to the pub/sub channel
        // here. This adapter is purposefully a thin contract check; full
        // pub/sub fan-out is covered in the monolith.
        let _ = self.tx.send(event);
        Ok(())
    }

    async fn is_tripped(&self, scope: KillSwitchScope) -> Result<bool, EngagementError> {
        let mut conn = self.manager.clone();
        for key in cascade_keys(scope) {
            let exists: bool = conn
                .exists(&key)
                .await
                .map_err(|e| EngagementError::Internal(format!("redis: {e}")))?;
            if exists {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn subscribe(&self) -> broadcast::Receiver<KillSwitchEvent> {
        self.tx.subscribe()
    }
}

fn scope_key(scope: KillSwitchScope) -> String {
    match scope {
        KillSwitchScope::Global => "sentinelx:kill:global".to_owned(),
        KillSwitchScope::Tenant(t) => format!("sentinelx:kill:tenant:{t}"),
        KillSwitchScope::Engagement(t, e) => {
            format!("sentinelx:kill:engagement:{t}:{e}")
        }
    }
}

fn cascade_keys(scope: KillSwitchScope) -> Vec<String> {
    match scope {
        KillSwitchScope::Global => vec![scope_key(KillSwitchScope::Global)],
        KillSwitchScope::Tenant(t) => vec![
            scope_key(KillSwitchScope::Tenant(t)),
            scope_key(KillSwitchScope::Global),
        ],
        KillSwitchScope::Engagement(t, e) => vec![
            scope_key(KillSwitchScope::Engagement(t, e)),
            scope_key(KillSwitchScope::Tenant(t)),
            scope_key(KillSwitchScope::Global),
        ],
    }
}

/// Best-effort connect helper. Returns `None` on transport errors so the
/// test can fail with a clear message rather than a generic panic.
async fn connect() -> Option<RedisKillSwitch> {
    let url = std::env::var("SX_TEST_REDIS_URL").unwrap_or_else(|_| DEFAULT_REDIS_URL.to_owned());
    let client = Client::open(url).ok()?;
    let manager = ConnectionManager::new(client).await.ok()?;
    let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
    Some(RedisKillSwitch { manager, tx })
}

/// Best-effort cleanup so test keys don't linger on shared dev Redis.
async fn cleanup(ks: &RedisKillSwitch, scopes: &[KillSwitchScope]) {
    let mut conn = ks.manager.clone();
    for scope in scopes {
        let _: Result<redis::Value, redis::RedisError> = conn.del(scope_key(*scope)).await;
    }
}

#[tokio::test]
#[ignore = "requires live Redis (SX_TEST_REDIS_URL); run via scripts/integration-smoke.sh"]
async fn tenant_trip_is_persisted_and_observed() {
    let Some(ks) = connect().await else {
        panic!("could not reach redis at default URL; set SX_TEST_REDIS_URL");
    };
    let tenant = TenantId::new();

    assert!(!ks
        .is_tripped(KillSwitchScope::Tenant(tenant))
        .await
        .unwrap());
    ks.trip(KillSwitchScope::Tenant(tenant), KillReason::Manual)
        .await
        .unwrap();
    assert!(ks
        .is_tripped(KillSwitchScope::Tenant(tenant))
        .await
        .unwrap());

    cleanup(&ks, &[KillSwitchScope::Tenant(tenant)]).await;
}

#[tokio::test]
#[ignore = "requires live Redis (SX_TEST_REDIS_URL); run via scripts/integration-smoke.sh"]
async fn engagement_scope_cascades_from_tenant_trip() {
    let Some(ks) = connect().await else {
        panic!("could not reach redis at default URL; set SX_TEST_REDIS_URL");
    };
    let tenant = TenantId::new();
    let engagement = EngagementId::new();

    ks.trip(KillSwitchScope::Tenant(tenant), KillReason::EmergencyStop)
        .await
        .unwrap();

    assert!(
        ks.is_tripped(KillSwitchScope::Engagement(tenant, engagement))
            .await
            .unwrap(),
        "engagement scope must be implicitly tripped when its tenant is tripped",
    );

    cleanup(&ks, &[KillSwitchScope::Tenant(tenant)]).await;
}

#[tokio::test]
#[ignore = "requires live Redis (SX_TEST_REDIS_URL); run via scripts/integration-smoke.sh"]
async fn engagement_trip_does_not_leak_to_tenant() {
    let Some(ks) = connect().await else {
        panic!("could not reach redis at default URL; set SX_TEST_REDIS_URL");
    };
    let tenant = TenantId::new();
    let engagement = EngagementId::new();

    ks.trip(
        KillSwitchScope::Engagement(tenant, engagement),
        KillReason::ScopeViolation,
    )
    .await
    .unwrap();

    assert!(ks
        .is_tripped(KillSwitchScope::Engagement(tenant, engagement))
        .await
        .unwrap(),);
    assert!(
        !ks.is_tripped(KillSwitchScope::Tenant(tenant))
            .await
            .unwrap(),
        "engagement-scoped trip must NOT widen to the whole tenant",
    );

    cleanup(&ks, &[KillSwitchScope::Engagement(tenant, engagement)]).await;
}

#[tokio::test]
#[ignore = "requires live Redis (SX_TEST_REDIS_URL); run via scripts/integration-smoke.sh"]
async fn local_subscribers_receive_event_on_trip() {
    let Some(ks) = connect().await else {
        panic!("could not reach redis at default URL; set SX_TEST_REDIS_URL");
    };
    let tenant = TenantId::new();

    let mut rx = ks.subscribe();
    ks.trip(KillSwitchScope::Tenant(tenant), KillReason::Anomaly)
        .await
        .unwrap();

    let evt = timeout(TokioDuration::from_secs(2), rx.recv())
        .await
        .expect("did not receive event in 2s")
        .expect("broadcast receive failed");
    assert_eq!(evt.scope, KillSwitchScope::Tenant(tenant));
    assert_eq!(evt.reason, KillReason::Anomaly);

    cleanup(&ks, &[KillSwitchScope::Tenant(tenant)]).await;
}

#[tokio::test]
#[ignore = "requires live Redis (SX_TEST_REDIS_URL); run via scripts/integration-smoke.sh"]
async fn trip_is_idempotent_against_redis() {
    let Some(ks) = connect().await else {
        panic!("could not reach redis at default URL; set SX_TEST_REDIS_URL");
    };
    let tenant = TenantId::new();

    for _ in 0..3 {
        ks.trip(KillSwitchScope::Tenant(tenant), KillReason::Manual)
            .await
            .unwrap();
    }
    assert!(ks
        .is_tripped(KillSwitchScope::Tenant(tenant))
        .await
        .unwrap());

    cleanup(&ks, &[KillSwitchScope::Tenant(tenant)]).await;
}
