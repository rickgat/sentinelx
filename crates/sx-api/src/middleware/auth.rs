//! Bearer-token authentication middleware.
//!
//! Pulls `Authorization: Bearer <jwt>` off the request, delegates to a
//! [`ValidateTokenPort`] implementation, and on success stuffs the
//! [`AccessClaims`] into the request extensions as [`AuthenticatedUser`].
//! Missing / malformed / rejected tokens become [`ApiError::Unauthorized`].
//!
//! ## Allow-list
//!
//! Some routes legitimately serve unauthenticated requests (healthz,
//! readyz, login, refresh). The middleware accepts an explicit set of
//! exact-match path prefixes via [`AuthConfig`] and skips authentication
//! for those.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, Response};
use axum::middleware::Next;
use axum::response::IntoResponse;
use sx_iam::model::claims::AccessClaims;

use crate::error::ApiError;
use crate::port::ValidateTokenPort;

/// Wraps the validated claims, inserted into request extensions on success.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// Decoded bearer-token claims.
    pub claims: AccessClaims,
}

/// Layer configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Path prefixes that bypass authentication. Compared with
    /// `Request::uri().path()` exactly, or `<prefix>/...`.
    pub bypass_prefixes: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            bypass_prefixes: vec![
                "/healthz".to_owned(),
                "/readyz".to_owned(),
                "/metrics".to_owned(),
                "/openapi.json".to_owned(),
                "/v1/auth/login".to_owned(),
                "/v1/auth/refresh".to_owned(),
                "/v1/auth/oidc/exchange".to_owned(),
                // SAML 2.0 SP endpoints (P0-004) — public; the SAML
                // bindings are self-authenticating via the IdP
                // signature on the assertion.
                "/v1/auth/saml".to_owned(),
                // CRIT-004 — OIDC back-channel / front-channel logout
                // are self-authenticating via the IdP-signed
                // `logout_token` and the `sid` lookup respectively. The
                // RP-initiated `/v1/auth/oidc/logout` still goes
                // through the bearer middleware (the caller's session
                // identifies the local record we revoke).
                "/v1/auth/oidc/back-channel-logout".to_owned(),
                "/v1/auth/oidc/front-channel-logout".to_owned(),
                // OIDC discovery document — public; advertises SP
                // endpoints and supported features.
                "/.well-known/openid-configuration".to_owned(),
                "/v1/auth/signup".to_owned(),
                "/v1/auth/verify-email".to_owned(),
                "/v1/auth/forgot-password".to_owned(),
                "/v1/auth/reset-password".to_owned(),
                // SCIM 2.0 surface — uses its own per-tenant bearer-token
                // scheme (see `controller::scim::authenticate`), not the
                // JWT validator. Bypassing the JWT middleware here lets
                // SCIM clients (Okta, AAD, ...) hit the endpoints with
                // their SCIM token instead of a SentinelX session token.
                "/scim/v2".to_owned(),
                // P2-016 — Falco runtime webhook. Self-authenticated via
                // HMAC-SHA256 over `v1:{timestamp}:{body}` using the
                // per-tenant ingestion key resolved by
                // `sx_runtime::TenantKeyStore`. The bearer-token
                // middleware would otherwise 401 the inbound webhook.
                "/v1/runtime/falco/alerts".to_owned(),
                // HIGH-009 — Kubernetes admission webhook. The cluster
                // apiserver authenticates itself via mutual TLS pinned
                // by the `ValidatingWebhookConfiguration` caBundle
                // (cert-manager-injected). The bearer-token middleware
                // would otherwise 401 the inbound apiserver call.
                "/v1/runtime/k8s/admit".to_owned(),
            ],
        }
    }
}

/// Bundle passed via axum state to [`auth_middleware`].
#[derive(Clone)]
pub struct AuthState {
    /// Validator implementation.
    pub validator: Arc<dyn ValidateTokenPort>,
    /// Auth config (bypass list).
    pub cfg: Arc<AuthConfig>,
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthState")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

fn extract_bearer(req: &Request) -> Option<String> {
    let v = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let v = v.trim();
    let mut parts = v.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    if scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty() {
        Some(token.to_owned())
    } else {
        None
    }
}

fn is_bypassed(path: &str, cfg: &AuthConfig) -> bool {
    cfg.bypass_prefixes
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

/// `axum::middleware::from_fn_with_state` callback.
pub async fn auth_middleware(
    State(auth): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response<Body> {
    let path = req.uri().path().to_owned();
    if is_bypassed(&path, &auth.cfg) {
        return next.run(req).await;
    }
    let Some(token) = extract_bearer(&req) else {
        return ApiError::Unauthorized.into_response();
    };
    match auth.validator.validate(&token).await {
        Ok(claims) => {
            req.extensions_mut().insert(AuthenticatedUser { claims });
            next.run(req).await
        }
        Err(_) => ApiError::Unauthorized.into_response(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use std::sync::Mutex;
    use sx_iam::model::claims::{AccessClaims, TokenType};
    use sx_iam::IamError;
    use tower::ServiceExt;

    #[derive(Debug, Default)]
    struct MockValidator {
        accept: Mutex<bool>,
    }

    impl MockValidator {
        fn accepting() -> Arc<Self> {
            Arc::new(Self {
                accept: Mutex::new(true),
            })
        }
        fn rejecting() -> Arc<Self> {
            Arc::new(Self {
                accept: Mutex::new(false),
            })
        }
    }

    #[async_trait]
    impl ValidateTokenPort for MockValidator {
        async fn validate(&self, _token: &str) -> Result<AccessClaims, IamError> {
            let accept = *self.accept.lock().unwrap();
            if accept {
                Ok(AccessClaims {
                    sub: "u".into(),
                    tenant_id: "t".into(),
                    iss: "i".into(),
                    aud: "a".into(),
                    iat: 0,
                    nbf: 0,
                    exp: 0,
                    jti: "j".into(),
                    sid: "s".into(),
                    token_type: TokenType::Access,
                    roles: vec![],
                    permissions: vec![],

                    cred_id: None,
                })
            } else {
                Err(IamError::InvalidToken)
            }
        }
    }

    fn make_app<V: ValidateTokenPort + 'static>(v: Arc<V>) -> Router {
        let state = AuthState {
            validator: v,
            cfg: Arc::new(AuthConfig::default()),
        };
        Router::new()
            .route("/v1/things", get(|| async { "ok" }))
            .route("/healthz", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(state, auth_middleware))
    }

    #[tokio::test]
    async fn missing_bearer_is_unauthorized() {
        let app = make_app(MockValidator::accepting());
        let req = Request::builder()
            .uri("/v1/things")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_bearer_is_unauthorized() {
        let app = make_app(MockValidator::accepting());
        let req = Request::builder()
            .uri("/v1/things")
            .header(header::AUTHORIZATION, "Basic Zm9vOmJhcg==")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_token_is_unauthorized() {
        let app = make_app(MockValidator::rejecting());
        let req = Request::builder()
            .uri("/v1/things")
            .header(header::AUTHORIZATION, "Bearer xyz")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_token_passes_through() {
        let app = make_app(MockValidator::accepting());
        let req = Request::builder()
            .uri("/v1/things")
            .header(header::AUTHORIZATION, "Bearer xyz")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_bypasses_auth() {
        let app = make_app(MockValidator::rejecting());
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
