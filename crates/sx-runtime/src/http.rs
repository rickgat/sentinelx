//! Self-contained [`axum`] router exposing `POST /v1/runtime/falco/alerts`.
//!
//! This router is mountable directly from a binary (or composed under
//! `axum::Router::nest`). The handler:
//!
//! 1. extracts the three runtime headers ([`TENANT_HEADER`],
//!    [`TIMESTAMP_HEADER`], [`SIGNATURE_HEADER`]),
//! 2. reads the raw body bytes verbatim,
//! 3. delegates to [`FalcoIngestService::ingest`],
//! 4. translates [`RuntimeError`] into appropriate HTTP status codes.
//!
//! Error responses never echo the request body, headers, or HMAC bytes.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use axum::Router;
use serde::Serialize;
use time::OffsetDateTime;

use crate::auth::{SIGNATURE_HEADER, TENANT_HEADER, TIMESTAMP_HEADER};
use crate::error::RuntimeError;
use crate::service::{FalcoIngestService, IngestionReport};

/// Build the runtime router. The returned router is stateless from the
/// embedder's perspective; the shared [`FalcoIngestService`] is held
/// behind an `Arc` so cloning is cheap.
pub fn router(service: Arc<FalcoIngestService>) -> Router {
    Router::new()
        .route("/v1/runtime/falco/alerts", post(ingest_handler))
        .with_state(service)
}

/// Response envelope returned on `200 OK`.
#[derive(Debug, Serialize)]
pub struct IngestResponse {
    /// Total alerts in the batch (== `findings.len()` for non-partial).
    pub alert_count: usize,
    /// Number of accepted alerts.
    pub accepted: usize,
    /// Findings emitted, mirrored back to the caller.
    pub findings: Vec<crate::finding::RuntimeFinding>,
}

impl From<IngestionReport> for IngestResponse {
    fn from(r: IngestionReport) -> Self {
        Self {
            alert_count: r.alert_count,
            accepted: r.accepted,
            findings: r.findings,
        }
    }
}

/// Error envelope returned on non-2xx responses. The `code` is a stable,
/// public string the API contract commits to.
#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

async fn ingest_handler(
    State(service): State<Arc<FalcoIngestService>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let tenant_id = match headers.get(TENANT_HEADER).and_then(|v| v.to_str().ok()) {
        Some(v) if !v.is_empty() => v.to_owned(),
        _ => return error_response(StatusCode::UNAUTHORIZED, &RuntimeError::UnknownTenant),
    };
    let Some(timestamp) = headers
        .get(TIMESTAMP_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
    else {
        return error_response(StatusCode::UNAUTHORIZED, &RuntimeError::InvalidSignature);
    };
    let signature = headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    match service
        .ingest(&tenant_id, timestamp, signature.as_deref(), &body, now)
        .await
    {
        Ok(report) => (StatusCode::OK, Json(IngestResponse::from(report))).into_response(),
        Err(e) => error_response(status_for(&e), &e),
    }
}

const fn status_for(e: &RuntimeError) -> StatusCode {
    match e {
        RuntimeError::BadPayload => StatusCode::BAD_REQUEST,
        RuntimeError::InvalidSignature
        | RuntimeError::ReplayWindowExceeded
        | RuntimeError::UnknownTenant => StatusCode::UNAUTHORIZED,
        RuntimeError::Audit(_) | RuntimeError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn error_response(status: StatusCode, e: &RuntimeError) -> Response {
    let (code, message) = code_and_message(e);
    (status, Json(ErrorBody { code, message })).into_response()
}

const fn code_and_message(e: &RuntimeError) -> (&'static str, &'static str) {
    match e {
        RuntimeError::BadPayload => ("bad_payload", "malformed payload"),
        RuntimeError::InvalidSignature => ("invalid_signature", "invalid signature"),
        RuntimeError::ReplayWindowExceeded => ("replay_window", "timestamp outside replay window"),
        RuntimeError::UnknownTenant => ("unknown_tenant", "tenant unknown"),
        RuntimeError::Audit(_) => ("audit_failed", "audit sink rejected the batch"),
        RuntimeError::Internal(_) => ("internal", "internal error"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::audit::RecordingAuditSink;
    use crate::auth::sign_body_for_tests;
    use crate::tenant_key::TenantKeyStore;
    use axum::body::to_bytes;
    use axum::http::Request;
    use secrecy::SecretString;
    use sx_secrets::{InMemoryProvider, SecretsProvider};
    use tower::ServiceExt;

    async fn build_service(
        tenant: &str,
        key: &str,
    ) -> (Arc<FalcoIngestService>, RecordingAuditSink) {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let store = TenantKeyStore::new(provider);
        store
            .put_key(tenant, SecretString::from(key.to_owned()))
            .await
            .unwrap();
        let sink = RecordingAuditSink::new();
        let svc = Arc::new(FalcoIngestService::new(store, Arc::new(sink.clone())));
        (svc, sink)
    }

    fn signed_request(tenant: &str, key: &str, body: &[u8], ts: i64) -> Request<axum::body::Body> {
        let sig = sign_body_for_tests(&SecretString::from(key.to_owned()), ts, body);
        Request::builder()
            .method("POST")
            .uri("/v1/runtime/falco/alerts")
            .header(TENANT_HEADER, tenant)
            .header(TIMESTAMP_HEADER, ts.to_string())
            .header(SIGNATURE_HEADER, sig)
            .body(axum::body::Body::from(body.to_vec()))
            .unwrap()
    }

    #[tokio::test]
    async fn happy_path_returns_200() {
        let (svc, sink) = build_service("t1", "k").await;
        let app = router(svc);
        let body = serde_json::to_vec(&serde_json::json!({
            "rule": "Terminal shell in container",
            "priority": "Warning",
            "output": "shell spawned",
            "time": "2026-06-12T10:30:01Z",
            "source": "syscall"
        }))
        .unwrap();
        let ts = OffsetDateTime::now_utc().unix_timestamp();
        let resp = app
            .oneshot(signed_request("t1", "k", &body, ts))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["accepted"].as_u64().unwrap(), 1);
        assert_eq!(sink.snapshot().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn missing_tenant_returns_401() {
        let (svc, _sink) = build_service("t1", "k").await;
        let app = router(svc);
        let req = Request::builder()
            .method("POST")
            .uri("/v1/runtime/falco/alerts")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bad_signature_returns_401() {
        let (svc, _sink) = build_service("t1", "k").await;
        let app = router(svc);
        let body = b"{}".to_vec();
        let ts = OffsetDateTime::now_utc().unix_timestamp();
        let req = Request::builder()
            .method("POST")
            .uri("/v1/runtime/falco/alerts")
            .header(TENANT_HEADER, "t1")
            .header(TIMESTAMP_HEADER, ts.to_string())
            .header(SIGNATURE_HEADER, "v1=deadbeef")
            .body(axum::body::Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_body_returns_400() {
        let (svc, _sink) = build_service("t1", "k").await;
        let app = router(svc);
        let body = b"not-json".to_vec();
        let ts = OffsetDateTime::now_utc().unix_timestamp();
        let resp = app
            .oneshot(signed_request("t1", "k", &body, ts))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
