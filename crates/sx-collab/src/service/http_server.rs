//! HTTP receiver.
//!
//! A single axum router with a fallback handler that records every
//! incoming request as a [`Callback::Http`].

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use sx_core::value_object::ids::TenantId;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::error::CollabError;
use crate::model::callback::Callback;
use crate::model::config::CollabConfig;
use crate::model::token::Token;
use crate::service::sink::CallbackSink;
use crate::service::token_alloc::TokenAllocator;
use crate::service::TRACING_TARGET;

/// Placeholder used for redacted header values.
pub const REDACTED: &str = "<REDACTED>";

#[derive(Clone)]
struct AppState {
    base_domain: String,
    body_cap: usize,
    redact: Arc<Vec<String>>,
    sink: Arc<dyn CallbackSink>,
    allocator: Arc<TokenAllocator>,
}

/// Handle owning the spawned HTTP listener task.
#[derive(Debug)]
pub struct HttpServerHandle {
    /// Effective bind address (after the OS resolved port 0, if used).
    pub local_addr: SocketAddr,
    /// `JoinHandle` of the background driver task.
    pub task: JoinHandle<()>,
}

/// Spawn the HTTP receiver.
pub async fn spawn_http_server(
    cfg: &CollabConfig,
    sink: Arc<dyn CallbackSink>,
    allocator: Arc<TokenAllocator>,
    shutdown: Arc<Notify>,
) -> Result<HttpServerHandle, CollabError> {
    let listener = TcpListener::bind(cfg.http_bind)
        .await
        .map_err(|e| CollabError::http_server(format!("bind {}: {e}", cfg.http_bind)))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| CollabError::http_server(format!("local_addr: {e}")))?;
    info!(
        target: TRACING_TARGET,
        addr = %local_addr,
        "http receiver bound",
    );

    let state = AppState {
        base_domain: cfg.base_domain.clone(),
        body_cap: cfg.http_body_capture_bytes,
        redact: Arc::new(
            cfg.redaction_headers
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        ),
        sink,
        allocator,
    };

    let router: Router = Router::new().fallback(record_any).with_state(state);

    let task = tokio::spawn(async move {
        let svc = router.into_make_service_with_connect_info::<SocketAddr>();
        let server = axum::serve(listener, svc);
        let server = server.with_graceful_shutdown(async move {
            shutdown.notified().await;
            debug!(target: TRACING_TARGET, "http receiver shutting down");
        });
        if let Err(e) = server.await {
            warn!(target: TRACING_TARGET, error = %e, "http server ended");
        }
    });
    Ok(HttpServerHandle { local_addr, task })
}

async fn record_any(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> impl IntoResponse {
    let method = request.method().as_str().to_ascii_uppercase();
    let path = request
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_string(), |p| p.as_str().to_string());

    let host_header = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let headers = sanitise_headers(request.headers(), &state.redact);

    // Cap body read at `body_cap`.
    let body = request.into_body();
    let body_bytes = match collect_capped(body, state.body_cap).await {
        Ok(b) => b,
        Err(e) => {
            warn!(target: TRACING_TARGET, error = %e, "http body collect failed");
            Vec::new()
        }
    };

    let token = match extract_http_token(&host_header, &state.base_domain) {
        Some(s) => match Token::parse(&s) {
            Ok(t) => t,
            Err(_) => {
                warn!(
                    target: TRACING_TARGET,
                    host = host_header,
                    "http request host token failed validation",
                );
                return (StatusCode::OK, "ok").into_response();
            }
        },
        None => {
            warn!(
                target: TRACING_TARGET,
                host = host_header,
                "http request outside base_domain ignored",
            );
            return (StatusCode::OK, "ok").into_response();
        }
    };

    // Track unknown-token case for verification audit.
    if state.allocator.lookup(&token).is_none() {
        warn!(
            target: TRACING_TARGET,
            token = token.as_str(),
            tenant = %TenantId::new(),
            "http callback for unknown token recorded as unknown tenant",
        );
    }

    let cb = Callback::Http {
        token,
        method,
        path,
        headers,
        body_excerpt: body_bytes,
        source_ip: Some(peer.ip()),
        received_at: OffsetDateTime::now_utc(),
    };
    if let Err(e) = state.sink.append(cb).await {
        warn!(target: TRACING_TARGET, error = %e, "http sink append failed");
    } else {
        info!(
            target: TRACING_TARGET,
            kind = "http",
            src = %peer,
            "callback recorded",
        );
    }
    (StatusCode::OK, "ok").into_response()
}

/// Drop sensitive headers and return a sorted `BTreeMap`.
pub fn sanitise_headers(map: &HeaderMap, redact: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in map {
        let name_lc = name.as_str().to_ascii_lowercase();
        let value = if redact.iter().any(|r| r == &name_lc) {
            REDACTED.to_string()
        } else {
            value.to_str().unwrap_or("<binary>").to_string()
        };
        out.insert(name_lc, value);
    }
    out
}

/// Extract the leftmost label of `host` when `host` ends with `oob.<base_domain>`.
#[must_use]
pub fn extract_http_token(host: &str, base_domain: &str) -> Option<String> {
    // Drop any `:port` suffix.
    let host_no_port = host.split(':').next().unwrap_or("");
    let lower = host_no_port.to_ascii_lowercase();
    let suffix = format!(".oob.{}", base_domain.to_ascii_lowercase());
    let stripped = lower.strip_suffix(&suffix)?;
    if stripped.is_empty() {
        return None;
    }
    stripped.rsplit('.').next().map(ToOwned::to_owned)
}

async fn collect_capped(body: Body, cap: usize) -> Result<Vec<u8>, CollabError> {
    let mut buf = Vec::with_capacity(cap.min(8 * 1024));
    let mut body = body.into_data_stream();
    use futures_util::StreamExt;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| CollabError::http_server(format!("body chunk: {e}")))?;
        let remaining = cap.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        // Indexing into `chunk` is bounded by `take`.
        buf.extend_from_slice(chunk.get(..take).unwrap_or(&[]));
        if buf.len() >= cap {
            break;
        }
    }
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{extract_http_token, sanitise_headers, REDACTED};
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    fn redact_list() -> Vec<String> {
        crate::model::config::default_redaction_headers()
    }

    #[test]
    fn redacted_headers_replaced_with_placeholder() {
        let mut m = HeaderMap::new();
        m.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer secret"),
        );
        m.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("sid=xyz"),
        );
        m.insert(
            HeaderName::from_static("set-cookie"),
            HeaderValue::from_static("sid=xyz"),
        );
        m.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("k123"),
        );
        m.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("curl/8"),
        );
        let sanitised = sanitise_headers(&m, &redact_list());
        assert_eq!(sanitised.get("authorization").unwrap(), REDACTED);
        assert_eq!(sanitised.get("cookie").unwrap(), REDACTED);
        assert_eq!(sanitised.get("set-cookie").unwrap(), REDACTED);
        assert_eq!(sanitised.get("x-api-key").unwrap(), REDACTED);
        assert_eq!(sanitised.get("user-agent").unwrap(), "curl/8");
    }

    #[test]
    fn extract_http_token_returns_label() {
        assert_eq!(
            extract_http_token("0123456789abcdef.oob.example.com", "example.com")
                .unwrap()
                .as_str(),
            "0123456789abcdef",
        );
        assert_eq!(
            extract_http_token("0123456789abcdef.oob.example.com:8443", "example.com",).unwrap(),
            "0123456789abcdef",
        );
    }

    #[test]
    fn extract_http_token_refuses_outside_scope() {
        assert!(extract_http_token("abc.oob.evil.example.org", "example.com").is_none());
        assert!(extract_http_token("oob.example.com", "example.com").is_none());
        assert!(extract_http_token("", "example.com").is_none());
    }

    #[tokio::test]
    async fn http_body_capture_caps_at_configured_size() {
        let body = axum::body::Body::from(vec![b'x'; 10_000]);
        let captured = super::collect_capped(body, 512).await.unwrap();
        assert_eq!(captured.len(), 512);
    }

    #[tokio::test]
    async fn http_handler_records_unknown_token_as_unknown_tenant() {
        use crate::model::callback::Callback;
        use crate::model::config::CollabConfig;
        use crate::model::token::Token;
        use crate::service::sink::{CallbackSink, InMemoryCallbackSink};
        use crate::service::token_alloc::TokenAllocator;
        use std::sync::Arc;
        use tokio::sync::Notify;

        let cfg = CollabConfig::loopback_for_tests("example.com");
        let sink = Arc::new(InMemoryCallbackSink::new());
        let allocator = Arc::new(TokenAllocator::new());
        let shutdown = Arc::new(Notify::new());

        let handle = super::spawn_http_server(
            &cfg,
            sink.clone() as Arc<dyn CallbackSink>,
            allocator.clone(),
            shutdown.clone(),
        )
        .await
        .unwrap();

        // Build a request whose Host matches our base domain but the token
        // is fresh (never registered with the allocator).
        let synthetic = Token::new();
        let url = format!("http://127.0.0.1:{}/probe", handle.local_addr.port());
        let host = format!("{}.oob.example.com", synthetic.as_str());
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .header("host", host)
            .header("authorization", "Bearer hunter2")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());

        // Wait briefly for the async append.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let recorded = sink.snapshot().await;
        assert_eq!(recorded.len(), 1);
        match &recorded[0] {
            Callback::Http { token, headers, .. } => {
                assert_eq!(token, &synthetic);
                assert_eq!(
                    headers.get("authorization").map(String::as_str),
                    Some(REDACTED)
                );
            }
            other => panic!("unexpected callback: {other:?}"),
        }
        // Unknown token: allocator has no binding.
        assert!(allocator.lookup(&synthetic).is_none());

        shutdown.notify_waiters();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle.task).await;
    }
}
