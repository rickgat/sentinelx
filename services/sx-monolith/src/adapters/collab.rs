//! Collaborator (OOB receivers + token allocator) adapter.
//!
//! The composition root builds a real [`CollabBundle`] holding:
//!
//! * a [`TokenAllocator`] shared across the `(tenant_id, finding_id)` mint
//!   path and the DNS / HTTP receiver lookups,
//! * an [`InMemoryCallbackSink`] (Phase-1 store; a Postgres-backed sink
//!   will replace this in Phase 1.5 without breaking the adapter's public
//!   surface),
//! * the two HTTP-facing port adapters
//!   ([`CollabAllocateTokenAdapter`] + [`CollabLookupCallbacksAdapter`])
//!   the API layer holds as `Arc<dyn …>`,
//! * an optional [`CollabReceiverHandle`] owning the DNS authority, HTTP
//!   receiver, and background purge task — spawned when
//!   `cfg.enabled == true`, left as `None` otherwise.
//!
//! When the bundle is dropped on shutdown the [`CollabReceiverHandle`]
//! signals every spawned task via a shared [`tokio::sync::Notify`]. The
//! `main.rs` shutdown path is unmodified by this adapter — keeping the
//! bundle alive for the lifetime of the process means receivers wind down
//! at the same moment as the rest of `AppState`.
//!
//! The SMTP receiver is not yet auto-spawned (Phase-3.5+2); the configured
//! `smtp_max_message_bytes` cap is parsed and forwarded into
//! [`sx_collab::model::CollabConfig`] for forward compatibility.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use sx_api::port::{CollabAllocateTokenPort, CollabLookupCallbacksPort, Phase3PortError};
use sx_api::view::collab_view::{
    CallbackView, CollabAllocateTokenRequestView, CollabAllocateTokenResponseView,
    CollabCallbacksResponseView,
};
use sx_collab::model::config::{
    default_redaction_headers, CollabConfig as SiblingCollabConfig,
    DEFAULT_PURGE_INTERVAL_SECS as SIBLING_DEFAULT_PURGE_INTERVAL_SECS,
};
use sx_collab::model::Callback;
use sx_collab::model::Token;
use sx_collab::service::sink::{CallbackSink, InMemoryCallbackSink};
use sx_collab::service::token_alloc::TokenAllocator;
use sx_collab::service::{
    spawn_dns_server, spawn_http_server, spawn_purge_task, DnsServerHandle, HttpServerHandle,
};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::info;

/// Bundle returned by [`build`].
///
/// Several fields (`allocator`, `sink`, `collab_handle`) are read only
/// indirectly: they back the trait-object adapters or, in the handle's
/// case, keep the spawned receivers alive for the bundle's lifetime via
/// RAII. The compiler can't see those uses without help, so dead-code
/// analysis is suppressed at the struct level.
#[allow(dead_code)]
pub(crate) struct CollabBundle {
    /// Shared token allocator.
    pub allocator: Arc<TokenAllocator>,
    /// Shared callback sink trait object.
    pub sink: Arc<dyn CallbackSink>,
    /// HTTP-facing token-allocation port adapter.
    pub collab_alloc: Arc<dyn CollabAllocateTokenPort>,
    /// HTTP-facing callback-lookup port adapter.
    pub collab_lookup: Arc<dyn CollabLookupCallbacksPort>,
    /// Handle to the spawned DNS / HTTP / purge tasks when the receivers
    /// are enabled. `None` when `cfg.collab.enabled == false`.
    ///
    /// Held alive for the lifetime of [`CollabBundle`]; the receivers
    /// shut down when the bundle is dropped (via [`Drop`] on
    /// [`CollabReceiverHandle`]).
    pub collab_handle: Option<CollabReceiverHandle>,
}

/// Owns every background task spawned by the collaborator subsystem.
///
/// Dropping the handle signals shutdown to all three task families. The
/// inner [`Notify`] is shared with every spawned task; flipping it ends
/// the DNS authority's graceful-shutdown branch, the axum HTTP server's
/// graceful-shutdown future, and the purge task's `tokio::select!` arm.
///
/// The address fields and join-handle fields are read only by tests; the
/// `Drop` impl signals shutdown without consulting them, and the tokio
/// runtime reaps the tasks at runtime shutdown. Dead-code analysis is
/// suppressed at the struct level to keep the operational diagnostics
/// available without forcing every production path to consume them.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct CollabReceiverHandle {
    shutdown: Arc<Notify>,
    /// Effective DNS bind address (after the OS resolved port 0).
    pub dns_local_addr: SocketAddr,
    /// Effective HTTP bind address (after the OS resolved port 0).
    pub http_local_addr: SocketAddr,
    dns_task: Option<JoinHandle<()>>,
    http_task: Option<JoinHandle<()>>,
    purge_task: Option<JoinHandle<()>>,
}

impl CollabReceiverHandle {
    fn from_parts(
        shutdown: Arc<Notify>,
        dns: DnsServerHandle,
        http: HttpServerHandle,
        purge: JoinHandle<()>,
    ) -> Self {
        Self {
            shutdown,
            dns_local_addr: dns.local_addr,
            http_local_addr: http.local_addr,
            dns_task: Some(dns.task),
            http_task: Some(http.task),
            purge_task: Some(purge),
        }
    }

    /// Signal every spawned task to wind down and await their completion.
    ///
    /// Idempotent: safe to call multiple times. The non-async [`Drop`]
    /// impl performs the signal half automatically; tests that want to
    /// deterministically join the tasks should call this explicitly so
    /// the runtime is still live when the join futures resolve.
    #[allow(dead_code)] // only invoked from tests; production relies on Drop.
    pub async fn shutdown(mut self) {
        self.shutdown.notify_waiters();
        if let Some(task) = self.purge_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.dns_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.http_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for CollabReceiverHandle {
    fn drop(&mut self) {
        // Signal every spawned task to wind down. We cannot `.await` the
        // join handles from a sync `Drop`, so we rely on the tasks
        // observing the `Notify` and exiting on their own; the tokio
        // runtime aborts them when it shuts down regardless.
        self.shutdown.notify_waiters();
    }
}

/// Build the collaborator bundle.
///
/// Constructs an empty [`TokenAllocator`], a fresh
/// [`InMemoryCallbackSink`], and the two port adapters that wrap them.
/// When `cfg.enabled == true` the DNS authority, HTTP receiver, and
/// background purge task are spawned and stored on
/// [`CollabBundle::collab_handle`]. Otherwise the field is `None` and a
/// single `tracing::info!` records the disabled state.
pub(crate) async fn build(
    cfg: &sx_config::schema::collab::CollabConfig,
) -> anyhow::Result<CollabBundle> {
    let allocator: Arc<TokenAllocator> = Arc::new(TokenAllocator::new());
    let sink: Arc<dyn CallbackSink> = Arc::new(InMemoryCallbackSink::new());

    let alloc_adapter: Arc<dyn CollabAllocateTokenPort> =
        Arc::new(CollabAllocateTokenAdapter::new(
            Arc::clone(&allocator),
            cfg.base_domain.clone(),
            sibling_ttl_from_config(cfg),
        ));
    let lookup_adapter: Arc<dyn CollabLookupCallbacksPort> =
        Arc::new(CollabLookupCallbacksAdapter::new(Arc::clone(&sink)));

    let collab_handle = if cfg.enabled {
        Some(spawn_receivers(cfg, Arc::clone(&sink), Arc::clone(&allocator)).await?)
    } else {
        info!(
            target = "adapters.collab",
            "collab adapter disabled; receivers not spawned"
        );
        None
    };

    info!(
        target = "adapters.collab.built",
        base_domain = %cfg.base_domain,
        ttl_seconds = cfg.callback_ttl.as_secs(),
        enabled = cfg.enabled,
        "collab bundle constructed",
    );

    Ok(CollabBundle {
        allocator,
        sink,
        collab_alloc: alloc_adapter,
        collab_lookup: lookup_adapter,
        collab_handle,
    })
}

/// Spawn DNS + HTTP + purge tasks and return a single owning handle.
async fn spawn_receivers(
    cfg: &sx_config::schema::collab::CollabConfig,
    sink: Arc<dyn CallbackSink>,
    allocator: Arc<TokenAllocator>,
) -> anyhow::Result<CollabReceiverHandle> {
    let sibling: SiblingCollabConfig = to_sibling_config(cfg);
    let shutdown = Arc::new(Notify::new());

    let dns = spawn_dns_server(
        &sibling,
        Arc::clone(&sink),
        Arc::clone(&allocator),
        Arc::clone(&shutdown),
    )
    .await
    .map_err(|e| anyhow::anyhow!("collab dns receiver: {e}"))?;

    let http = spawn_http_server(
        &sibling,
        Arc::clone(&sink),
        Arc::clone(&allocator),
        Arc::clone(&shutdown),
    )
    .await
    .map_err(|e| anyhow::anyhow!("collab http receiver: {e}"))?;

    let purge = spawn_purge_task(
        Arc::clone(&sink),
        sibling.callback_ttl,
        sibling.purge_interval,
        Arc::clone(&shutdown),
    );

    info!(
        target = "adapters.collab.spawn",
        dns_addr = %dns.local_addr,
        http_addr = %http.local_addr,
        "collab receivers spawned",
    );

    Ok(CollabReceiverHandle::from_parts(shutdown, dns, http, purge))
}

/// Map an `sx-config` schema value to the sibling-crate domain type.
///
/// The two structs share the same operator surface but their internal
/// representations differ: `sx-config` uses
/// [`std::time::Duration`]/`u32`/`Ipv4Addr` because those are easy to
/// validate at load time, while the sibling crate uses
/// [`time::Duration`]/`usize` because that is how its async APIs are
/// typed.
/// Free-function form of the `sx-config` → sibling-crate conversion.
///
/// Implemented as a free function rather than `impl From<…>` because both
/// the source and destination types live in foreign crates (orphan rule).
fn to_sibling_config(cfg: &sx_config::schema::collab::CollabConfig) -> SiblingCollabConfig {
    let smtp_bind: SocketAddr = match "127.0.0.1:0".parse() {
        Ok(addr) => addr,
        // Unreachable: the literal is a valid SocketAddr. We fall back to
        // a clearly-flagged placeholder so this conversion is total.
        Err(_) => SocketAddr::from(([127, 0, 0, 1], 0)),
    };
    SiblingCollabConfig {
        base_domain: cfg.base_domain.clone(),
        dns_bind: cfg.dns_bind,
        http_bind: cfg.http_bind,
        smtp_bind,
        answer_ipv4: cfg.answer_ipv4,
        http_body_capture_bytes: cfg.http_body_capture_bytes as usize,
        smtp_max_message_bytes: cfg.smtp_max_message_bytes as usize,
        callback_ttl: sibling_ttl_from_config(cfg),
        purge_interval: StdDuration::from_secs(SIBLING_DEFAULT_PURGE_INTERVAL_SECS),
        redaction_headers: default_redaction_headers(),
    }
}

/// Translate a [`std::time::Duration`] callback TTL into the sibling
/// crate's [`time::Duration`] without ever panicking. Sub-second
/// precision is preserved.
fn sibling_ttl_from_config(cfg: &sx_config::schema::collab::CollabConfig) -> Duration {
    // `time::Duration::seconds` takes an i64; clamp on overflow rather
    // than panic. The config schema caps `callback_ttl` implicitly via
    // the `Duration` deserialiser, but be defensive.
    let secs = i64::try_from(cfg.callback_ttl.as_secs()).unwrap_or(i64::MAX);
    let nanos = i32::try_from(cfg.callback_ttl.subsec_nanos()).unwrap_or(0);
    Duration::new(secs, nanos)
}

/// HTTP-facing token-allocation adapter.
///
/// Parses the request's `tenant_id` into a [`sx_core::value_object::ids::TenantId`]
/// and dispatches into [`TokenAllocator::allocate`]. Idempotent for any
/// `(tenant_id, finding_id)` pair.
pub(crate) struct CollabAllocateTokenAdapter {
    allocator: Arc<TokenAllocator>,
    base_domain: String,
    ttl: Duration,
}

impl CollabAllocateTokenAdapter {
    /// Wrap an existing allocator with a fixed advertised base domain.
    pub(crate) fn new(allocator: Arc<TokenAllocator>, base_domain: String, ttl: Duration) -> Self {
        Self {
            allocator,
            base_domain,
            ttl,
        }
    }
}

#[async_trait]
impl CollabAllocateTokenPort for CollabAllocateTokenAdapter {
    async fn allocate(
        &self,
        req: CollabAllocateTokenRequestView,
    ) -> Result<CollabAllocateTokenResponseView, Phase3PortError> {
        let tenant_id: sx_core::value_object::ids::TenantId =
            req.tenant_id
                .parse()
                .map_err(|e: sx_core::error::DomainError| {
                    Phase3PortError::Invalid(format!("tenant_id: {e}"))
                })?;
        let token = self.allocator.allocate(tenant_id, req.finding_id);
        let expires_at = (OffsetDateTime::now_utc() + self.ttl)
            .format(&Rfc3339)
            .map_err(|e| Phase3PortError::Internal(format!("expires_at format: {e}")))?;
        Ok(CollabAllocateTokenResponseView {
            token: token.to_string(),
            base_domain: self.base_domain.clone(),
            expires_at,
        })
    }
}

/// HTTP-facing callback-lookup adapter.
///
/// Parses the URL path token, asks the [`CallbackSink`] for every
/// recorded callback, and projects each [`Callback`] variant onto the
/// wire-shape [`CallbackView`].
pub(crate) struct CollabLookupCallbacksAdapter {
    sink: Arc<dyn CallbackSink>,
}

impl CollabLookupCallbacksAdapter {
    /// Wrap an existing sink.
    pub(crate) fn new(sink: Arc<dyn CallbackSink>) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl CollabLookupCallbacksPort for CollabLookupCallbacksAdapter {
    async fn lookup(&self, token: &str) -> Result<CollabCallbacksResponseView, Phase3PortError> {
        let parsed =
            Token::parse(token).map_err(|e| Phase3PortError::Invalid(format!("token: {e}")))?;
        let recorded = self
            .sink
            .find_by_token(&parsed)
            .await
            .map_err(|e| Phase3PortError::Dependency(format!("sink: {e}")))?;
        let callbacks = recorded
            .iter()
            .map(project_callback)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CollabCallbacksResponseView {
            token: parsed.to_string(),
            callbacks,
        })
    }
}

/// Project a `sx_collab::model::Callback` variant onto a [`CallbackView`].
fn project_callback(cb: &Callback) -> Result<CallbackView, Phase3PortError> {
    let received_at = cb
        .received_at()
        .format(&Rfc3339)
        .map_err(|e| Phase3PortError::Internal(format!("received_at format: {e}")))?;
    let kind = cb.kind().to_owned();
    let (source_ip, details) = match cb {
        Callback::Dns {
            query_type,
            source_ip,
            ..
        } => (
            source_ip.map(|ip| ip.to_string()),
            serde_json::json!({ "query_type": query_type }),
        ),
        Callback::Http {
            method,
            path,
            headers,
            body_excerpt,
            source_ip,
            ..
        } => (
            source_ip.map(|ip| ip.to_string()),
            serde_json::json!({
                "method": method,
                "path": path,
                "headers": headers,
                "body_excerpt_len": body_excerpt.len(),
            }),
        ),
        Callback::Smtp {
            mail_from,
            rcpt_to,
            message_excerpt,
            source_ip,
            ..
        } => (
            source_ip.map(|ip| ip.to_string()),
            serde_json::json!({
                "mail_from": mail_from,
                "rcpt_to": rcpt_to,
                "message_excerpt_len": message_excerpt.len(),
            }),
        ),
    };
    Ok(CallbackView {
        kind,
        received_at,
        source_ip,
        details,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{build, CollabAllocateTokenAdapter};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration as StdDuration;
    use sx_api::port::CollabAllocateTokenPort;
    use sx_api::view::collab_view::CollabAllocateTokenRequestView;

    fn disabled_cfg() -> sx_config::schema::collab::CollabConfig {
        sx_config::schema::collab::CollabConfig {
            enabled: false,
            base_domain: "oob.sentinelx.invalid".into(),
            dns_bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            http_bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            answer_ipv4: Ipv4Addr::LOCALHOST,
            callback_ttl: StdDuration::from_secs(259_200),
            http_body_capture_bytes: 4096,
            smtp_max_message_bytes: 65_536,
        }
    }

    fn enabled_cfg() -> sx_config::schema::collab::CollabConfig {
        let mut cfg = disabled_cfg();
        cfg.enabled = true;
        cfg
    }

    /// Allocate a token, then immediately look it up. We expect an empty
    /// vector of callbacks (no DNS / HTTP traffic has landed) and the
    /// echoed token to match what `allocate` returned.
    #[tokio::test]
    async fn allocate_then_lookup_round_trip() {
        let bundle = build(&disabled_cfg()).await.unwrap();
        let req = CollabAllocateTokenRequestView {
            tenant_id: "00000000-0000-4000-8000-000000000001".into(),
            finding_id: "F-001".into(),
        };
        let resp = bundle.collab_alloc.allocate(req).await.unwrap();
        assert_eq!(resp.token.len(), 16);

        // Reuse: a second allocate with the same pair is idempotent.
        let req2 = CollabAllocateTokenRequestView {
            tenant_id: "00000000-0000-4000-8000-000000000001".into(),
            finding_id: "F-001".into(),
        };
        let resp2 = bundle.collab_alloc.allocate(req2).await.unwrap();
        assert_eq!(resp.token, resp2.token);

        // Lookup the freshly minted token — no callbacks yet.
        let look = bundle.collab_lookup.lookup(&resp.token).await.unwrap();
        assert_eq!(look.token, resp.token);
        assert!(look.callbacks.is_empty());
    }

    /// A well-formed but unallocated token must produce an empty list,
    /// not an error.
    #[tokio::test]
    async fn lookup_returns_empty_for_unallocated_token() {
        let bundle = build(&disabled_cfg()).await.unwrap();
        let token = "deadbeefdeadbeef";
        let look = bundle.collab_lookup.lookup(token).await.unwrap();
        assert_eq!(look.token, token);
        assert!(look.callbacks.is_empty());
    }

    /// Constructing the allocator adapter with an explicit base domain
    /// must round-trip through the response. Guards against a future
    /// `expires_at` override silently breaking the wire shape.
    #[tokio::test]
    async fn allocate_response_carries_configured_base_domain() {
        use std::sync::Arc;
        use sx_collab::service::token_alloc::TokenAllocator;
        use time::Duration;

        let alloc = Arc::new(TokenAllocator::new());
        let adapter = CollabAllocateTokenAdapter::new(
            alloc,
            "oob.unit-test.invalid".into(),
            Duration::hours(1),
        );
        let resp = adapter
            .allocate(CollabAllocateTokenRequestView {
                tenant_id: "00000000-0000-4000-8000-000000000002".into(),
                finding_id: "F-XYZ".into(),
            })
            .await
            .unwrap();
        assert_eq!(resp.base_domain, "oob.unit-test.invalid");
    }

    /// With `enabled = false` the bundle must not spawn any receiver
    /// tasks — `collab_handle` is `None`.
    #[tokio::test]
    async fn build_with_disabled_emits_no_handle() {
        let bundle = build(&disabled_cfg()).await.unwrap();
        assert!(bundle.collab_handle.is_none());
    }

    /// With `enabled = true` the DNS + HTTP + purge tasks bind and are
    /// stored on `collab_handle`. Both addresses must have non-zero
    /// effective ports after kernel allocation.
    ///
    /// `handle.shutdown()` is bounded by a real-time timeout because the
    /// `hickory_server::ServerFuture::shutdown_gracefully()` path can
    /// occasionally fail to wake a blocked `recv_from` on certain OS
    /// configurations (we observed multi-minute hangs on macOS during the
    /// workspace test run). The shutdown signal still propagates via
    /// `Drop`, so the runtime aborts the dangling task when the test
    /// returns. The test's correctness assertion is the bind, not the
    /// drain.
    #[tokio::test]
    async fn build_with_enabled_returns_handle() {
        let bundle = build(&enabled_cfg()).await.unwrap();
        assert!(bundle.collab_handle.is_some());
        let handle = bundle.collab_handle.expect("checked is_some");
        assert!(handle.dns_local_addr.port() > 0);
        assert!(handle.http_local_addr.port() > 0);
        let _ = tokio::time::timeout(StdDuration::from_secs(3), handle.shutdown()).await;
    }
}
