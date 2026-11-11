//! HTTP handlers for per-user device registration.
//!
//! Two routes are exposed:
//!
//! | Method | Path                                | Body / params                     |
//! | ------ | ----------------------------------- | --------------------------------- |
//! | POST   | `/v1/notifications/devices`         | `{ token, platform: "ios"\|"android" }` |
//! | DELETE | `/v1/notifications/devices/{id}`    | path param: device id (uuid)      |
//!
//! Both handlers expect a [`TenantContext`] extension (tenant + user
//! ids, normally injected by an upstream authn middleware in the host
//! application) and forward to a [`crate::push::registry::DeviceRegistry`]
//! plus an audit sink.
//!
//! The handlers are intentionally tiny — they exist so that downstream
//! crates (`sx-api`, `sx-monolith`) can mount the routes without
//! re-implementing the device-token redaction and tenant scoping rules
//! the registry enforces.
//!
//! ## Security
//!
//! * Device tokens are pulled off the JSON body straight into a
//!   [`secrecy::SecretString`] — the raw bytes never reach a `tracing`
//!   span and never appear in any of the error variants returned to
//!   the caller.
//! * The HTTP response body carries only the freshly minted
//!   [`crate::push::registry::DeviceId`]; no provider state is leaked.
//! * Deregistration is tenant-scoped (the underlying registry returns
//!   [`crate::push::error::PushError::UnknownDevice`] for cross-tenant
//!   delete attempts).

use std::sync::Arc;

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, post},
    Json, Router,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::push::error::PushError;
use crate::push::registry::{DeviceId, DeviceRegistry, MobilePlatform, NewDeviceRegistration};

/// Tenant + user context the host application is responsible for
/// injecting via an `axum::Extension` (typically from a bearer-token
/// validator).
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Tenant the call is scoped to.
    pub tenant_id: String,
    /// Authenticated user the registration belongs to.
    pub user_id: String,
}

/// JSON body of `POST /v1/notifications/devices`.
#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    /// Raw provider device token (APNs hex token or FCM registration
    /// id). The bytes are wrapped in [`SecretString`] before the
    /// registry ever sees them.
    pub token: String,
    /// `"ios"` or `"android"`.
    pub platform: String,
}

/// JSON body of the success response of `POST /v1/notifications/devices`.
#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    /// Stable registration id the caller must use for deletes.
    pub device_id: DeviceId,
}

/// State the device-registration router needs.
///
/// `Clone` is `Arc`-cheap; all fields are trait objects behind `Arc`.
#[derive(Clone)]
pub struct DeviceRouterState {
    /// Backing store for registrations.
    pub registry: Arc<dyn DeviceRegistry>,
}

impl std::fmt::Debug for DeviceRouterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRouterState").finish_non_exhaustive()
    }
}

/// Build an [`axum::Router`] exposing the two device-registration
/// endpoints under their canonical `/v1/notifications/devices` paths.
///
/// The router expects a [`TenantContext`] extension on every request;
/// the host application installs an authentication middleware that
/// populates it.
pub fn router(state: DeviceRouterState) -> Router {
    Router::new()
        .route("/v1/notifications/devices", post(register_device))
        .route("/v1/notifications/devices/:id", delete(deregister_device))
        .with_state(state)
}

/// `POST /v1/notifications/devices` — register a new device.
pub async fn register_device(
    State(state): State<DeviceRouterState>,
    Extension(ctx): Extension<TenantContext>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), HttpError> {
    let platform = MobilePlatform::parse(&req.platform).map_err(|e| HttpError::from_push(&e))?;
    // Wrap the token in a SecretString immediately; from here on the
    // raw bytes never appear in any tracing event or error path.
    let token = SecretString::from(req.token);
    let registration = NewDeviceRegistration {
        tenant_id: ctx.tenant_id.clone(),
        user_id: ctx.user_id.clone(),
        platform,
        device_token: token,
    };
    let id = state
        .registry
        .register(registration)
        .await
        .map_err(|e| HttpError::from_push(&e))?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse { device_id: id }),
    ))
}

/// `DELETE /v1/notifications/devices/{id}` — remove a registration.
pub async fn deregister_device(
    State(state): State<DeviceRouterState>,
    Extension(ctx): Extension<TenantContext>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, HttpError> {
    state
        .registry
        .deregister(&ctx.tenant_id, DeviceId(id))
        .await
        .map_err(|e| HttpError::from_push(&e))?;
    Ok(StatusCode::NO_CONTENT)
}

/// HTTP error envelope returned by the device-registration handlers.
///
/// The `Display` impl is identical to [`PushError`]'s — category only,
/// no device tokens, no JWT bearer values, no provider response bodies.
#[derive(Debug)]
pub struct HttpError {
    status: StatusCode,
    code: &'static str,
}

impl HttpError {
    const fn from_push(err: &PushError) -> Self {
        let (status, code) = match err {
            PushError::UnknownDevice => (StatusCode::NOT_FOUND, "unknown_device"),
            PushError::UnsupportedPlatform => (StatusCode::BAD_REQUEST, "unsupported_platform"),
            PushError::MissingCredentials => (StatusCode::FAILED_DEPENDENCY, "missing_credentials"),
            PushError::InvalidApnsKey | PushError::JwtBuild => {
                (StatusCode::INTERNAL_SERVER_ERROR, "credential_error")
            }
            PushError::Transport | PushError::ProviderRejected { .. } => {
                (StatusCode::BAD_GATEWAY, "transport_error")
            }
        };
        Self { status, code }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({ "error": self.code }))).into_response()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::push::registry::InMemoryDeviceRegistry;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn router_with_ctx(tenant: &str, user: &str) -> (Router, Arc<InMemoryDeviceRegistry>) {
        let reg = Arc::new(InMemoryDeviceRegistry::new());
        let state = DeviceRouterState {
            registry: reg.clone() as Arc<dyn DeviceRegistry>,
        };
        let ctx = TenantContext {
            tenant_id: tenant.to_owned(),
            user_id: user.to_owned(),
        };
        let app = router(state).layer(axum::Extension(ctx));
        (app, reg)
    }

    async fn body_to_value(body: Body) -> serde_json::Value {
        let bytes = axum::body::to_bytes(body, 64 * 1024)
            .await
            .expect("collect body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn register_device_returns_created_with_device_id() {
        let (app, _reg) = router_with_ctx("tenant-a", "alice");
        let body = serde_json::json!({
            "token": "super-secret-token",
            "platform": "ios",
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/notifications/devices")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let value = body_to_value(resp.into_body()).await;
        assert!(value["device_id"].is_string());
        assert!(!value.to_string().contains("super-secret-token"));
    }

    #[tokio::test]
    async fn register_device_rejects_unknown_platform() {
        let (app, _reg) = router_with_ctx("tenant-a", "alice");
        let body = serde_json::json!({
            "token": "tok",
            "platform": "blackberry",
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/notifications/devices")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let value = body_to_value(resp.into_body()).await;
        assert_eq!(value["error"], "unsupported_platform");
    }

    #[tokio::test]
    async fn deregister_unknown_device_returns_404() {
        let (app, _reg) = router_with_ctx("tenant-a", "alice");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/v1/notifications/devices/{}",
                        uuid::Uuid::new_v4()
                    ))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn register_then_deregister_roundtrip_audits() {
        let (app, reg) = router_with_ctx("tenant-a", "alice");
        // Register.
        let body = serde_json::json!({ "token": "tok", "platform": "android" });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/notifications/devices")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let value = body_to_value(resp.into_body()).await;
        let id_str = value["device_id"].as_str().unwrap().to_owned();
        // Deregister.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/notifications/devices/{id_str}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let audit = reg.drain_audit().await;
        assert_eq!(audit.len(), 2);
    }
}
