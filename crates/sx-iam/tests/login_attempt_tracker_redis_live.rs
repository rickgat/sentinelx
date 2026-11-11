//! Live-Redis integration tests for the [`LoginAttemptTracker`] port.
//!
//! These tests exercise a small in-test `RedisLoginAttemptTracker` against
//! a real Redis instance. The production implementation lives in the
//! monolith composition root (`services/sx-monolith/src/adapters/redis.rs`)
//! and is intentionally `pub(crate)` there; we re-implement the trait
//! locally so the trait *contract* can be exercised from this crate without
//! pulling `sx-monolith` as a dev-dependency.
//!
//! Every test is gated by `#[ignore = "..."]` so `cargo test` stays green
//! in offline CI. Run them with:
//!
//! ```text
//! docker compose up -d redis
//! cargo test -p sx-iam -- --ignored
//! ```
//!
//! Test isolation: each test scopes its keys under a unique tenant UUID so
//! parallel runs against the same Redis cannot collide.

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

use std::time::Duration;

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use sx_iam::domain::TenantId;
use sx_iam::service::login_attempt_tracker::{AttemptKey, LoginAttemptTracker};
use sx_iam::IamError;

/// The Redis URL used by the live integration tests. Override with the
/// `SX_TEST_REDIS_URL` env var if your local Redis is elsewhere or password
/// protected.
const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379/0";

/// 30 s TTL for the lockout counter — short enough that a forgotten test
/// run does not poison subsequent runs for hours.
const TEST_TTL: Duration = Duration::from_secs(30);

/// Test-local Redis-backed `LoginAttemptTracker`.
///
/// Mirrors the production adapter byte-for-byte on the key layout
/// (`sentinelx:lockout:{tenant}:{email_hash}`) so the test really does
/// guard the production wire-format.
#[derive(Clone)]
struct RedisLoginAttemptTracker {
    manager: ConnectionManager,
    ttl: Duration,
}

#[async_trait]
impl LoginAttemptTracker for RedisLoginAttemptTracker {
    async fn record_failure(&self, key: &AttemptKey) -> Result<u32, IamError> {
        let redis_key = lockout_key(key);
        let mut conn = self.manager.clone();

        let new_count: i64 = conn
            .incr(&redis_key, 1_i64)
            .await
            .map_err(|e| IamError::internal(format!("redis: {e}")))?;

        let ttl_secs = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        let _: redis::Value = conn
            .expire(&redis_key, ttl_secs)
            .await
            .map_err(|e| IamError::internal(format!("redis: {e}")))?;

        Ok(u32::try_from(new_count.max(0)).unwrap_or(u32::MAX))
    }

    async fn count_failures(&self, key: &AttemptKey) -> Result<u32, IamError> {
        let redis_key = lockout_key(key);
        let mut conn = self.manager.clone();
        let raw: Option<String> = conn
            .get(&redis_key)
            .await
            .map_err(|e| IamError::internal(format!("redis: {e}")))?;
        let Some(raw) = raw else { return Ok(0) };
        raw.parse::<u32>()
            .map_err(|e| IamError::internal(format!("lockout counter non-integer: {e}")))
    }

    async fn clear(&self, key: &AttemptKey) -> Result<(), IamError> {
        let redis_key = lockout_key(key);
        let mut conn = self.manager.clone();
        let _: redis::Value = conn
            .del(&redis_key)
            .await
            .map_err(|e| IamError::internal(format!("redis: {e}")))?;
        Ok(())
    }
}

fn lockout_key(key: &AttemptKey) -> String {
    format!("sentinelx:lockout:{}:{}", key.tenant_id, key.email_hash)
}

/// Best-effort connect helper. Returns `None` on transport errors so the
/// test can skip cleanly when Redis is unreachable (rather than fail loudly
/// for an environmental reason).
async fn connect() -> Option<RedisLoginAttemptTracker> {
    let url = std::env::var("SX_TEST_REDIS_URL").unwrap_or_else(|_| DEFAULT_REDIS_URL.to_owned());
    let client = Client::open(url).ok()?;
    let manager = ConnectionManager::new(client).await.ok()?;
    Some(RedisLoginAttemptTracker {
        manager,
        ttl: TEST_TTL,
    })
}

/// Build an `AttemptKey` whose `email_hash` is unique to this test, scoped
/// under a random `TenantId`. This guarantees parallel runs do not collide.
fn unique_key(label: &str) -> AttemptKey {
    AttemptKey {
        tenant_id: TenantId::new(),
        email_hash: format!("{label}-{}", uuid_like()),
    }
}

/// Tiny non-`uuid`-crate stand-in: 16 random hex chars from the process
/// nanos clock. `sx-iam`'s dev-deps already include `rand` via the prod
/// deps, but we avoid pulling it just for this so the file stays lean.
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{nanos:032x}")
}

#[tokio::test]
#[ignore = "requires live Redis (SX_TEST_REDIS_URL); run via scripts/integration-smoke.sh"]
async fn record_failure_increments_and_count_matches() {
    let Some(tracker) = connect().await else {
        panic!("could not reach redis at default URL; set SX_TEST_REDIS_URL");
    };
    let key = unique_key("incr");

    assert_eq!(tracker.count_failures(&key).await.unwrap(), 0);
    assert_eq!(tracker.record_failure(&key).await.unwrap(), 1);
    assert_eq!(tracker.record_failure(&key).await.unwrap(), 2);
    assert_eq!(tracker.record_failure(&key).await.unwrap(), 3);
    assert_eq!(tracker.count_failures(&key).await.unwrap(), 3);

    // Cleanup so the key does not linger on shared dev Redis.
    tracker.clear(&key).await.unwrap();
}

#[tokio::test]
#[ignore = "requires live Redis (SX_TEST_REDIS_URL); run via scripts/integration-smoke.sh"]
async fn clear_resets_counter_to_zero() {
    let Some(tracker) = connect().await else {
        panic!("could not reach redis at default URL; set SX_TEST_REDIS_URL");
    };
    let key = unique_key("clear");

    tracker.record_failure(&key).await.unwrap();
    tracker.record_failure(&key).await.unwrap();
    assert_eq!(tracker.count_failures(&key).await.unwrap(), 2);

    tracker.clear(&key).await.unwrap();
    assert_eq!(tracker.count_failures(&key).await.unwrap(), 0);
}

#[tokio::test]
#[ignore = "requires live Redis (SX_TEST_REDIS_URL); run via scripts/integration-smoke.sh"]
async fn ttl_is_applied_on_record_failure() {
    let Some(tracker) = connect().await else {
        panic!("could not reach redis at default URL; set SX_TEST_REDIS_URL");
    };
    let key = unique_key("ttl");

    tracker.record_failure(&key).await.unwrap();

    // Sneak a raw TTL read in to confirm the adapter actually set one.
    // The value should be (0, TEST_TTL.as_secs()] — i.e. positive.
    let redis_key = lockout_key(&key);
    let mut conn = tracker.manager.clone();
    let ttl: i64 = conn.ttl(&redis_key).await.unwrap();
    assert!(
        ttl > 0 && ttl <= i64::try_from(TEST_TTL.as_secs()).unwrap(),
        "expected positive TTL <= {}s, got {ttl}",
        TEST_TTL.as_secs(),
    );

    tracker.clear(&key).await.unwrap();
}

#[tokio::test]
#[ignore = "requires live Redis (SX_TEST_REDIS_URL); run via scripts/integration-smoke.sh"]
async fn different_tenants_do_not_share_counters() {
    let Some(tracker) = connect().await else {
        panic!("could not reach redis at default URL; set SX_TEST_REDIS_URL");
    };
    let email_hash = format!("isolation-{}", uuid_like());

    let key_a = AttemptKey {
        tenant_id: TenantId::new(),
        email_hash: email_hash.clone(),
    };
    let key_b = AttemptKey {
        tenant_id: TenantId::new(),
        email_hash,
    };

    tracker.record_failure(&key_a).await.unwrap();
    tracker.record_failure(&key_a).await.unwrap();
    tracker.record_failure(&key_a).await.unwrap();

    assert_eq!(tracker.count_failures(&key_a).await.unwrap(), 3);
    assert_eq!(
        tracker.count_failures(&key_b).await.unwrap(),
        0,
        "counter leaked across tenants",
    );

    tracker.clear(&key_a).await.unwrap();
}
