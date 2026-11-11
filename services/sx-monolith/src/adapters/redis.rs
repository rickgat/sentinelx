//! Redis-backed cluster-shared adapters for kill-switch and login attempt
//! tracking.
//!
//! This module is part of the monolith binary's composition root. It provides
//! cluster-shared implementations of two ports declared by sibling crates:
//!
//! - [`sx_engagement::service::kill_switch::KillSwitch`] — backed by string
//!   keys plus a Redis pub/sub channel so a `trip` issued on one process is
//!   reflected on every other process within pub/sub latency.
//! - [`sx_iam::service::login_attempt_tracker::LoginAttemptTracker`] — backed
//!   by a per-`(tenant, email_hash)` integer counter with a configurable TTL.
//!
//! ## Key layout
//!
//! ```text
//! sentinelx:kill:global
//! sentinelx:kill:tenant:{tenant_uuid}
//! sentinelx:kill:engagement:{tenant_uuid}:{engagement_uuid}
//! sentinelx:killswitch                 (pub/sub channel)
//! sentinelx:lockout:{tenant_uuid}:{email_hash}
//! ```
//!
//! ## Wiring
//!
//! The parent `adapters` module invokes [`build`] during startup and forwards
//! the returned [`RedisBundle`] to whichever ports require cluster-shared
//! semantics (kill-switch, lockout tracker). The bundle exposes both the
//! trait-object handles (for ports) and the concrete `RedisKillSwitch`
//! handle (so a `TriggerKillSwitchUseCase` can be wired against the
//! shared instance).
//!
//! Items are tagged `#[allow(dead_code)]` until the parent `adapters::mod`
//! wires `build` into the composition root — at that point every item
//! becomes reachable through that single entry point.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use sx_config::secret::expose_str;
use sx_engagement::error::EngagementError;
use sx_engagement::service::kill_switch::{
    KillReason, KillSwitch, KillSwitchEvent, KillSwitchScope,
};
use sx_iam::service::login_attempt_tracker::{AttemptKey, LoginAttemptTracker};
use sx_iam::IamError;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Connection handle shared across every Redis-backed adapter.
///
/// `redis::aio::ConnectionManager` already multiplexes commands over a single
/// reconnecting TCP stream and is `Clone` — i.e. it behaves as a pool from
/// the caller's perspective. We alias it as `Pool` here so the composition
/// root and the [`ping`] health check can refer to it by intent rather than
/// the concrete library type.
pub type Pool = ConnectionManager;

/// Default broadcast channel capacity for kill-switch subscribers.
///
/// Mirrors `sx_engagement::service::kill_switch`'s in-memory default — large
/// enough for the modest fan-out we expect (HTTP request handlers + a
/// background reaper).
const DEFAULT_BROADCAST_CAPACITY: usize = 64;

/// Pub/sub channel name carrying serialised [`KillSwitchEvent`]s.
const PUBSUB_CHANNEL: &str = "sentinelx:killswitch";

/// Backoff applied before reconnecting a dropped pub/sub subscription.
const PUBSUB_RECONNECT_BACKOFF: Duration = Duration::from_secs(2);

/// 24-hour TTL applied to every `trip` write.
///
/// The kill-switch is operator-driven; surviving a 24-hour window across a
/// process restart is the intended behaviour, while still bounding the blast
/// radius of a forgotten manual trip.
const KILL_SWITCH_TTL_SECS: u64 = 86_400;

/// Bundle of Redis-backed adapter handles produced by [`build`].
///
/// Returned to the composition root so it can wire the ports and keep the
/// connection manager alive for the lifetime of the process.
pub(crate) struct RedisBundle {
    /// Kill-switch port as a trait object — for `sx-api` wiring.
    pub kill_switch_arc: Arc<dyn KillSwitch>,
    /// Kill-switch concrete type — for `TriggerKillSwitchUseCase` wiring.
    pub kill_switch_concrete: Arc<RedisKillSwitch>,
    /// Login attempt tracker port as a trait object.
    pub login_tracker: Arc<dyn LoginAttemptTracker>,
    /// The connection manager. Kept on the bundle so it lives for the
    /// process lifetime and so callers can clone it for further adapters.
    pub manager: ConnectionManager,
}

/// Construct every Redis-backed adapter.
///
/// 1. Parses `redis_cfg.url` (a [`secrecy::SecretString`]).
/// 2. Opens a [`Client`] and a [`ConnectionManager`].
/// 3. Issues a `PING` to fail-fast on misconfiguration.
/// 4. Spawns a background pub/sub listener subscribed to
///    [`PUBSUB_CHANNEL`] that forwards each message into the
///    kill-switch's broadcast channel.
///
/// `lockout_ttl` is the TTL applied by [`RedisLoginAttemptTracker`] to the
/// per-`(tenant, email_hash)` counter; it should match
/// `LockoutPolicy::lock_duration`.
///
/// # Errors
///
/// Returns an error if the URL is empty, the client fails to open, the
/// connection manager fails to connect, or the initial `PING` fails.
pub(crate) async fn build(
    redis_cfg: &sx_config::RedisConfig,
    lockout_ttl: Duration,
) -> anyhow::Result<RedisBundle> {
    let raw_url = expose_str(&redis_cfg.url);
    if raw_url.is_empty() {
        anyhow::bail!("redis.url is empty");
    }

    // Log a redacted host descriptor once at boot. Never log the password
    // segment of the URL: we extract only host[:port] via `url::Url`.
    let host_label = redact_host(raw_url);
    info!(
        target = "sx_monolith::adapters::redis",
        event = "connect_begin",
        host = %host_label,
        "connecting to redis",
    );

    let client =
        Client::open(raw_url).map_err(|e| anyhow::anyhow!("failed to open redis client: {e}"))?;

    let manager = ConnectionManager::new(client.clone())
        .await
        .map_err(|e| anyhow::anyhow!("failed to create redis connection manager: {e}"))?;

    // Fail-fast PING delegated to the public health-check helper so it has
    // a single, reusable implementation.
    ping(&manager).await?;

    let (tx, _) = broadcast::channel::<KillSwitchEvent>(DEFAULT_BROADCAST_CAPACITY);

    let kill_switch = Arc::new(RedisKillSwitch {
        manager: manager.clone(),
        tx: tx.clone(),
    });

    let login_tracker = Arc::new(RedisLoginAttemptTracker {
        manager: manager.clone(),
        ttl: lockout_ttl,
    });

    // Spawn pub/sub listener. The listener owns its own Client because
    // pub/sub requires a dedicated connection (it cannot share the
    // ConnectionManager multiplexed stream). The original `tx` is moved
    // into the listener; both the kill-switch and our local subscribers
    // already hold cloned `Sender` handles.
    tokio::spawn(async move {
        run_pubsub_listener(client, tx).await;
    });

    let kill_switch_arc: Arc<dyn KillSwitch> = Arc::clone(&kill_switch) as Arc<dyn KillSwitch>;
    let login_tracker_arc: Arc<dyn LoginAttemptTracker> =
        Arc::clone(&login_tracker) as Arc<dyn LoginAttemptTracker>;

    Ok(RedisBundle {
        kill_switch_arc,
        kill_switch_concrete: kill_switch,
        login_tracker: login_tracker_arc,
        manager,
    })
}

/// Public health-check: issue a `PING` against `pool` and verify the response.
///
/// Called by [`build`] at boot so a misconfigured `redis.url` (wrong host,
/// wrong password, unreachable port) is surfaced as an early-exit error
/// rather than as a flood of runtime failures from every adapter. Operators
/// may also call this from periodic liveness probes.
///
/// `pool` is taken by reference; the underlying `ConnectionManager` is
/// `Clone` and the clone is cheap (it shares the same multiplexed stream),
/// so this call does not perturb other in-flight commands.
///
/// # Errors
///
/// Returns the wrapped `redis::RedisError` (as `anyhow::Error`) if the
/// `PING` round-trip fails or the response is not the expected `PONG`.
pub async fn ping(pool: &Pool) -> Result<(), anyhow::Error> {
    let mut conn = pool.clone();
    let pong: String = redis::cmd("PING")
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            warn!(
                target = "sx_monolith::adapters::redis",
                event = "ping_failed",
                error = %e,
                "redis PING failed",
            );
            anyhow::anyhow!("redis PING failed: {e}")
        })?;
    if !pong.eq_ignore_ascii_case("PONG") {
        warn!(
            target = "sx_monolith::adapters::redis",
            event = "ping_unexpected_response",
            response = %pong,
            "redis PING returned an unexpected reply",
        );
        anyhow::bail!("redis PING returned unexpected reply: {pong}");
    }
    info!(
        target = "sx_monolith::adapters::redis",
        event = "ping_ok",
        response = %pong,
        "redis PING succeeded",
    );
    Ok(())
}

/// Extract a redacted `host[:port]` descriptor from a Redis URL for logging.
///
/// Never returns any portion of the URL containing credentials. If the URL
/// cannot be parsed (or has no host) the returned string is a constant
/// placeholder so the log site never accidentally emits the raw input.
fn redact_host(raw_url: &str) -> String {
    match url::Url::parse(raw_url) {
        Ok(parsed) => match (parsed.host_str(), parsed.port()) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => host.to_owned(),
            _ => "<unknown>".to_owned(),
        },
        Err(_) => "<unparseable>".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// RedisKillSwitch
// ---------------------------------------------------------------------------

/// Cluster-shared `KillSwitch` implementation backed by Redis string keys
/// and a pub/sub channel.
///
/// `trip` writes `SET sentinelx:kill:{scope} {reason} EX 86400` and publishes
/// the serialised [`KillSwitchEvent`] to `sentinelx:killswitch`. `is_tripped`
/// reads the per-scope key plus every wider scope that contains it.
/// `subscribe` returns a receiver into the local broadcast channel that the
/// background pub/sub task feeds.
#[derive(Clone)]
pub(crate) struct RedisKillSwitch {
    manager: ConnectionManager,
    tx: broadcast::Sender<KillSwitchEvent>,
}

impl std::fmt::Debug for RedisKillSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisKillSwitch")
            .field("manager", &"<redis::aio::ConnectionManager>")
            .field("subscribers", &self.tx.receiver_count())
            .finish()
    }
}

impl RedisKillSwitch {
    /// Borrow the broadcast sender — used internally by the pub/sub task
    /// and exposed for tests in the same crate.
    #[cfg(test)]
    pub(crate) const fn sender(&self) -> &broadcast::Sender<KillSwitchEvent> {
        &self.tx
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

        // SET key reason EX 86400 — idempotent and self-expiring.
        let _: redis::Value = conn
            .set_ex(&key, reason.to_string(), KILL_SWITCH_TTL_SECS)
            .await
            .map_err(redis_to_engagement)?;

        let event = KillSwitchEvent {
            scope,
            reason,
            at: time::OffsetDateTime::now_utc(),
        };

        // Publish to the cluster-wide channel so peers can update their
        // local broadcast streams.
        if let Ok(payload) = serde_json::to_string(&event) {
            let publish_result: Result<i64, redis::RedisError> =
                conn.publish(PUBSUB_CHANNEL, payload).await;
            if let Err(e) = publish_result {
                warn!(
                    target = "sx_monolith::adapters::redis",
                    event = "publish_failed",
                    error = %e,
                    scope = %scope,
                    "kill-switch publish failed; local subscribers still notified",
                );
            }
        } else {
            warn!(
                target = "sx_monolith::adapters::redis",
                event = "serialise_failed",
                scope = %scope,
                "failed to serialise KillSwitchEvent; publish skipped",
            );
        }

        // Also notify local subscribers immediately — pub/sub round-trip
        // back to ourselves is best-effort.
        let _ = self.tx.send(event);

        Ok(())
    }

    async fn is_tripped(&self, scope: KillSwitchScope) -> Result<bool, EngagementError> {
        let mut conn = self.manager.clone();
        for key in cascade_keys(scope) {
            let exists: bool = conn.exists(&key).await.map_err(redis_to_engagement)?;
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

/// Compute the Redis key for a single scope.
fn scope_key(scope: KillSwitchScope) -> String {
    match scope {
        KillSwitchScope::Global => "sentinelx:kill:global".to_owned(),
        KillSwitchScope::Tenant(t) => format!("sentinelx:kill:tenant:{t}"),
        KillSwitchScope::Engagement(t, e) => {
            format!("sentinelx:kill:engagement:{t}:{e}")
        }
    }
}

/// Compute every key whose presence would cause `scope` to be considered
/// tripped — i.e. the scope itself plus all wider scopes containing it.
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

/// Pub/sub listener. Connects with a fresh `PubSub` connection, subscribes
/// to [`PUBSUB_CHANNEL`], and forwards every parseable [`KillSwitchEvent`]
/// into the broadcast sender. On transport errors it logs and restarts
/// after a short backoff. The task only exits when the broadcast sender
/// has zero `Sender` clones left, which only happens at shutdown.
///
/// The cognitive complexity is dominated by `tracing` macro expansions
/// for the structured-log events; the actual control flow is a single
/// `loop` over `run_pubsub_session`.
#[allow(clippy::cognitive_complexity)]
async fn run_pubsub_listener(client: Client, tx: broadcast::Sender<KillSwitchEvent>) {
    info!(
        target = "sx_monolith::adapters::redis",
        event = "pubsub_task_start",
        channel = PUBSUB_CHANNEL,
        "kill-switch pub/sub listener starting",
    );

    loop {
        if tx.receiver_count() == 0 && tx.strong_count() <= 1 {
            // No interested local receivers and no other senders — safe
            // to stop. In practice this never fires because the
            // `RedisKillSwitch` holds a sender for the process lifetime.
            info!(
                target = "sx_monolith::adapters::redis",
                event = "pubsub_task_stop",
                "kill-switch pub/sub listener stopping (no senders)",
            );
            return;
        }

        run_pubsub_session(&client, &tx).await;

        warn!(
            target = "sx_monolith::adapters::redis",
            event = "pubsub_task_restart",
            "kill-switch pub/sub session ended; reconnecting",
        );
        tokio::time::sleep(PUBSUB_RECONNECT_BACKOFF).await;
    }
}

/// Single connect-subscribe-consume cycle of the pub/sub listener.
///
/// Returns when the session ends — either through a connect failure, a
/// subscribe failure, or the underlying stream closing. Transport errors
/// are logged as `warn` events; the outer loop handles backoff.
#[allow(clippy::cognitive_complexity)]
async fn run_pubsub_session(client: &Client, tx: &broadcast::Sender<KillSwitchEvent>) {
    let mut pubsub = match client.get_async_pubsub().await {
        Ok(p) => p,
        Err(e) => {
            warn!(
                target = "sx_monolith::adapters::redis",
                event = "pubsub_connect_failed",
                error = %e,
                "kill-switch pub/sub connect failed",
            );
            return;
        }
    };

    if let Err(e) = pubsub.subscribe(PUBSUB_CHANNEL).await {
        warn!(
            target = "sx_monolith::adapters::redis",
            event = "pubsub_subscribe_failed",
            error = %e,
            channel = PUBSUB_CHANNEL,
            "kill-switch pub/sub subscribe failed",
        );
        return;
    }

    info!(
        target = "sx_monolith::adapters::redis",
        event = "pubsub_subscribed",
        channel = PUBSUB_CHANNEL,
        "kill-switch pub/sub subscribed",
    );

    consume_messages(&mut pubsub, tx).await;
}

/// Consume messages from a live [`redis::aio::PubSub`] until the underlying
/// stream ends. Each parseable [`KillSwitchEvent`] is forwarded into the
/// broadcast sender. Decode and parse failures are logged but do not stop
/// the loop.
async fn consume_messages(
    pubsub: &mut redis::aio::PubSub,
    tx: &broadcast::Sender<KillSwitchEvent>,
) {
    use futures::StreamExt as _;

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let Some(event) = decode_event(&msg) else {
            continue;
        };
        info!(
            target = "sx_monolith::adapters::redis",
            event = "kill_switch_pubsub_received",
            scope = %event.scope,
            reason = %event.reason,
            "kill switch trip received via pub/sub",
        );
        let _ = tx.send(event);
    }
}

/// Decode a single [`redis::Msg`] into a [`KillSwitchEvent`]. Returns
/// `None` and logs a `warn` if either the payload extraction or JSON
/// parse fails.
fn decode_event(msg: &redis::Msg) -> Option<KillSwitchEvent> {
    let payload: String = match msg.get_payload() {
        Ok(p) => p,
        Err(e) => {
            warn!(
                target = "sx_monolith::adapters::redis",
                event = "pubsub_payload_decode_failed",
                error = %e,
                "kill-switch pub/sub payload decode failed",
            );
            return None;
        }
    };
    match serde_json::from_str::<KillSwitchEvent>(&payload) {
        Ok(event) => Some(event),
        Err(e) => {
            warn!(
                target = "sx_monolith::adapters::redis",
                event = "pubsub_parse_failed",
                error = %e,
                "kill-switch pub/sub event JSON parse failed",
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// RedisLoginAttemptTracker
// ---------------------------------------------------------------------------

/// Cluster-shared `LoginAttemptTracker` implementation backed by Redis
/// integer counters with a fixed TTL.
///
/// `record_failure` issues an `INCR` followed by `EXPIRE`; `count_failures`
/// reads the counter with `GET`; `clear` deletes the key.
#[derive(Clone)]
pub(crate) struct RedisLoginAttemptTracker {
    manager: ConnectionManager,
    ttl: Duration,
}

impl std::fmt::Debug for RedisLoginAttemptTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisLoginAttemptTracker")
            .field("manager", &"<redis::aio::ConnectionManager>")
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl RedisLoginAttemptTracker {
    /// TTL applied to every counter — exposed for tests.
    #[cfg(test)]
    pub(crate) const fn ttl(&self) -> Duration {
        self.ttl
    }
}

#[async_trait]
impl LoginAttemptTracker for RedisLoginAttemptTracker {
    async fn record_failure(&self, key: &AttemptKey) -> Result<u32, IamError> {
        let redis_key = lockout_key(key);
        let mut conn = self.manager.clone();

        let new_count: i64 = conn.incr(&redis_key, 1_i64).await.map_err(redis_to_iam)?;

        // Refresh the window every failure so the lockout window slides
        // until the user goes quiet for `ttl`.
        let ttl_secs = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        let _: redis::Value = conn
            .expire(&redis_key, ttl_secs)
            .await
            .map_err(redis_to_iam)?;

        Ok(u32::try_from(new_count.max(0)).unwrap_or(u32::MAX))
    }

    async fn count_failures(&self, key: &AttemptKey) -> Result<u32, IamError> {
        let redis_key = lockout_key(key);
        let mut conn = self.manager.clone();
        let raw: Option<String> = conn.get(&redis_key).await.map_err(redis_to_iam)?;
        let Some(raw) = raw else { return Ok(0) };
        raw.parse::<u32>().map_err(|e| {
            IamError::internal(format!("lockout counter contained non-integer value: {e}",))
        })
    }

    async fn clear(&self, key: &AttemptKey) -> Result<(), IamError> {
        let redis_key = lockout_key(key);
        let mut conn = self.manager.clone();
        let _: redis::Value = conn.del(&redis_key).await.map_err(redis_to_iam)?;
        Ok(())
    }
}

/// Render the Redis key for an [`AttemptKey`].
fn lockout_key(key: &AttemptKey) -> String {
    format!("sentinelx:lockout:{}:{}", key.tenant_id, key.email_hash)
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map a `redis::RedisError` to `EngagementError::Internal`, preserving the
/// `Display` form so operators can correlate logs.
///
/// Passes the error by value so it can be plugged directly into
/// `.map_err(redis_to_engagement)`.
#[allow(clippy::needless_pass_by_value)]
fn redis_to_engagement(e: redis::RedisError) -> EngagementError {
    EngagementError::Internal(format!("redis: {e}"))
}

/// Map a `redis::RedisError` to `IamError::Internal`.
///
/// Passes the error by value so it can be plugged directly into
/// `.map_err(redis_to_iam)`.
#[allow(clippy::needless_pass_by_value)]
fn redis_to_iam(e: redis::RedisError) -> IamError {
    IamError::internal(format!("redis: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sx_core::value_object::ids::{EngagementId, TenantId};

    #[test]
    fn scope_key_shapes() {
        let t = TenantId::new();
        let e = EngagementId::new();
        assert_eq!(scope_key(KillSwitchScope::Global), "sentinelx:kill:global");
        assert_eq!(
            scope_key(KillSwitchScope::Tenant(t)),
            format!("sentinelx:kill:tenant:{t}"),
        );
        assert_eq!(
            scope_key(KillSwitchScope::Engagement(t, e)),
            format!("sentinelx:kill:engagement:{t}:{e}"),
        );
    }

    #[test]
    fn cascade_keys_widen() {
        let t = TenantId::new();
        let e = EngagementId::new();
        let keys = cascade_keys(KillSwitchScope::Engagement(t, e));
        assert_eq!(keys.len(), 3);
        assert!(keys
            .first()
            .is_some_and(|k| k.starts_with("sentinelx:kill:engagement:")));
        assert!(keys
            .get(1)
            .is_some_and(|k| k.starts_with("sentinelx:kill:tenant:")));
        assert_eq!(
            keys.get(2).map(String::as_str),
            Some("sentinelx:kill:global")
        );
    }

    #[test]
    fn lockout_key_shape() {
        let tid = sx_iam::domain::TenantId::new();
        let key = AttemptKey {
            tenant_id: tid,
            email_hash: "deadbeef".to_owned(),
        };
        let rendered = lockout_key(&key);
        assert!(rendered.starts_with("sentinelx:lockout:"));
        assert!(rendered.ends_with(":deadbeef"));
    }

    #[test]
    fn redis_to_engagement_maps_to_internal() {
        let err = redis::RedisError::from((redis::ErrorKind::Io, "boom"));
        match redis_to_engagement(err) {
            EngagementError::Internal(msg) => assert!(msg.contains("redis:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn redis_to_iam_maps_to_internal() {
        let err = redis::RedisError::from((redis::ErrorKind::Io, "boom"));
        match redis_to_iam(err) {
            IamError::Internal(msg) => assert!(msg.contains("redis:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn redact_host_strips_credentials() {
        // Password segment must never appear.
        let raw = "redis://:s3cret@redis.internal:6380/0";
        let label = redact_host(raw);
        assert!(!label.contains("s3cret"), "password leaked: {label}");
        assert_eq!(label, "redis.internal:6380");
    }

    #[test]
    fn redact_host_handles_no_port() {
        let label = redact_host("redis://example.com/0");
        assert_eq!(label, "example.com");
    }

    #[test]
    fn redact_host_handles_garbage() {
        let label = redact_host("definitely not a url");
        assert_eq!(label, "<unparseable>");
    }
}

/// Redis-backed [`crate::adapters::iam::SessionRevoker`].
///
/// Each revoked access-token `jti` becomes a key `revoked_token:{jti}` with a
/// TTL equal to the access-token lifetime — after that the token is expired
/// anyway, so the key can safely lapse. Because Redis outlives the monolith
/// process, revocations survive a restart (unlike the in-memory fallback).
///
/// `is_revoked` fails **open** (returns `false`) on a Redis error, logging a
/// warning: a revocation cache being briefly unreachable must not reject
/// every request (availability), and the token's own short TTL bounds the
/// exposure. `revoke` surfaces the error so logout can report failure.
#[derive(Clone)]
pub(crate) struct RedisSessionRevoker {
    manager: ConnectionManager,
    ttl_secs: u64,
}

impl std::fmt::Debug for RedisSessionRevoker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisSessionRevoker")
            .field("ttl_secs", &self.ttl_secs)
            .finish_non_exhaustive()
    }
}

impl RedisSessionRevoker {
    pub(crate) fn new(manager: ConnectionManager, ttl_secs: u64) -> Self {
        // Guard against a zero/absurd TTL; Redis SETEX needs a positive value.
        let ttl_secs = ttl_secs.clamp(1, 7 * 24 * 60 * 60);
        Self { manager, ttl_secs }
    }

    fn key(jti: &str) -> String {
        format!("revoked_token:{jti}")
    }
}

#[async_trait]
impl crate::adapters::iam::SessionRevoker for RedisSessionRevoker {
    async fn revoke(&self, jti: &str) -> Result<(), sx_iam::IamError> {
        let mut conn = self.manager.clone();
        conn.set_ex::<_, _, ()>(Self::key(jti), "1", self.ttl_secs)
            .await
            .map_err(|e| sx_iam::IamError::internal(format!("redis revoke: {e}")))
    }

    async fn is_revoked(&self, jti: &str) -> bool {
        let mut conn = self.manager.clone();
        match conn.exists::<_, bool>(Self::key(jti)).await {
            Ok(present) => present,
            Err(e) => {
                warn!(target: "adapters.redis.revoker", error = %e, "revocation check failed; failing open");
                false
            }
        }
    }
}
