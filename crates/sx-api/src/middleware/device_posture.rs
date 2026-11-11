//! Device-posture middleware (P2-008).
//!
//! Pulls the `X-Sentinelx-Device-Posture` header off every authenticated
//! request, decodes it as a JWT signed with the same HMAC secret used by
//! the session JWT, and on success attaches the decoded
//! [`sx_device_trust::PostureClaims`] (and a freshly-computed
//! [`DevicePostureDecision`]) to the request extensions so downstream
//! handlers + policy layers can inspect them.
//!
//! ## Pass-through semantics
//!
//! Per the P2-008 design, this middleware is **never** a hard gate:
//!
//! * Missing header → pass through (the agent is not enrolled yet).
//! * Malformed JWT  → pass through with a `Stale` decision attached so
//!   policy layers can deny if they wish.
//! * Tampered JWT   → pass through with an `Untrusted` decision attached
//!   carrying the reason; the policy / dashboard layer decides what to
//!   do with that signal.
//!
//! ## JWT bounds
//!
//! * Algorithm pinned to HMAC-SHA256.
//! * `iat` age window bounded by
//!   [`sx_device_trust::posture::DEFAULT_MAX_AGE_SECONDS`] (one hour).
//! * `exp` validated by the underlying decoder.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, Response};
use axum::middleware::Next;

use sx_device_trust::posture::{decode_posture_jwt, PostureJwtError, DEFAULT_MAX_AGE_SECONDS};
use sx_device_trust::service::{DeviceTrustDecision, DeviceTrustStatus};
use sx_device_trust::PostureClaims;

use crate::middleware::auth::AuthenticatedUser;
use crate::port::DeviceTrustPort;

/// HTTP header carrying the posture JWT.
pub const POSTURE_HEADER: HeaderName = HeaderName::from_static("x-sentinelx-device-posture");

/// Bundle stashed into request extensions when a posture header was
/// successfully (or unsuccessfully) decoded.
///
/// Downstream code reads this via
/// `req.extensions().get::<DevicePostureDecision>()`. The bundle is
/// always either present (header was supplied) or absent (header was
/// missing) — the middleware never blocks the request.
#[derive(Debug, Clone)]
pub struct DevicePostureDecision {
    /// Decoded posture claims when available. `None` when the JWT was
    /// malformed / stale / tampered.
    pub claims: Option<PostureClaims>,
    /// Per-rule evaluation against the tenant's policy.
    pub decision: DeviceTrustDecision,
}

/// Bundle passed via axum state to [`device_posture_middleware`].
#[derive(Clone)]
pub struct DevicePostureState {
    /// Backing port — used for evaluate + snapshot record.
    pub port: Arc<dyn DeviceTrustPort>,
    /// Header JWT max age in seconds. Defaults to
    /// [`DEFAULT_MAX_AGE_SECONDS`] (one hour).
    pub max_age_seconds: u64,
}

impl DevicePostureState {
    /// Construct with the default 1-hour age window.
    #[must_use]
    pub fn new(port: Arc<dyn DeviceTrustPort>) -> Self {
        Self {
            port,
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
        }
    }
}

impl std::fmt::Debug for DevicePostureState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevicePostureState")
            .field("max_age_seconds", &self.max_age_seconds)
            .finish_non_exhaustive()
    }
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn extract_header_token(req: &Request) -> Option<String> {
    let v = req.headers().get(&POSTURE_HEADER)?.to_str().ok()?;
    let v = v.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_owned())
    }
}

/// Axum `from_fn_with_state` callback.
///
/// Decodes the posture header (when present) and attaches the
/// resulting [`PostureClaims`] + [`DevicePostureDecision`] to the
/// request extensions. **Never blocks** the request — the policy layer
/// is responsible for any enforcement.
pub async fn device_posture_middleware(
    State(state): State<DevicePostureState>,
    mut req: Request,
    next: Next,
) -> Response<Body> {
    let Some(token) = extract_header_token(&req) else {
        // No posture header → pass through without attaching anything.
        return next.run(req).await;
    };

    // Determine the tenant id from the bearer claims when present so
    // policy lookups happen against the right tenant. Anonymous /
    // bypassed routes (healthz, login) won't have an
    // `AuthenticatedUser` extension and that's fine — we still decode
    // the JWT so the resulting `claims` can be attached.
    let tenant_id: Option<String> = req
        .extensions()
        .get::<AuthenticatedUser>()
        .map(|u| u.claims.tenant_id.clone());

    let secret = state.port.jwt_secret();
    let now = now_unix();
    match decode_posture_jwt(&token, &secret, now, state.max_age_seconds) {
        Ok(claims) => {
            let decision = match &tenant_id {
                Some(t) => state.port.evaluate(t, &claims).await.unwrap_or_else(|err| {
                    tracing::warn!(
                        target: "middleware.device_posture",
                        error = %err,
                        "device-trust evaluate failed; falling back to permissive trusted",
                    );
                    DeviceTrustDecision::trusted()
                }),
                None => DeviceTrustDecision::trusted(),
            };
            tracing::debug!(
                target: "middleware.device_posture",
                status = decision.status.as_str(),
                tenant = ?tenant_id,
                "posture jwt decoded",
            );
            req.extensions_mut().insert(DevicePostureDecision {
                claims: Some(claims),
                decision,
            });
        }
        Err(err) => {
            // Map decode error → conservative decision attached to the
            // request. We surface the reason so policy layers can
            // distinguish "tampered" from "stale" without re-parsing
            // the header.
            let status = match err {
                PostureJwtError::Stale | PostureJwtError::Expired => DeviceTrustStatus::Stale,
                _ => DeviceTrustStatus::Untrusted,
            };
            tracing::warn!(
                target: "middleware.device_posture",
                error = %err,
                status = status.as_str(),
                "posture jwt rejected; attaching decision and passing through",
            );
            let decision = match status {
                DeviceTrustStatus::Stale => DeviceTrustDecision::stale(err.to_string()),
                _ => DeviceTrustDecision::untrusted(vec![err.to_string()]),
            };
            req.extensions_mut().insert(DevicePostureDecision {
                claims: None,
                decision,
            });
        }
    }

    next.run(req).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Extension, Router};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use sx_device_trust::policy::PosturePolicy;
    use sx_device_trust::service::{DeviceTrustError, PostureSnapshot};
    use tower::ServiceExt;

    const SECRET: &[u8] = b"shared-test-secret--shared-secret";

    #[derive(Debug, Default)]
    struct MockPort;

    #[async_trait]
    impl DeviceTrustPort for MockPort {
        async fn get_policy(&self, _t: &str) -> Result<PosturePolicy, DeviceTrustError> {
            Ok(PosturePolicy::permissive())
        }
        async fn put_policy(
            &self,
            _t: &str,
            p: PosturePolicy,
        ) -> Result<PosturePolicy, DeviceTrustError> {
            Ok(p)
        }
        async fn evaluate(
            &self,
            _t: &str,
            posture: &PostureClaims,
        ) -> Result<DeviceTrustDecision, DeviceTrustError> {
            // Default policy under permissive: only fail when disk
            // encryption explicitly false AND edr_present false to
            // surface a meaningful Untrusted case in tests.
            if !posture.disk_encrypted && !posture.edr_present {
                return Ok(DeviceTrustDecision::untrusted(vec![
                    "missing baseline signals".into(),
                ]));
            }
            Ok(DeviceTrustDecision::trusted())
        }
        async fn record_snapshot(
            &self,
            _t: &str,
            _s: PostureSnapshot,
        ) -> Result<(), DeviceTrustError> {
            Ok(())
        }
        async fn list_snapshots(
            &self,
            _t: &str,
            _l: usize,
        ) -> Result<Vec<PostureSnapshot>, DeviceTrustError> {
            Ok(vec![])
        }
        fn jwt_secret(&self) -> Vec<u8> {
            SECRET.to_vec()
        }
    }

    fn sign(claims: &PostureClaims, secret: &[u8]) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn make_app() -> Router {
        let state = DevicePostureState::new(Arc::new(MockPort));
        Router::new()
            .route(
                "/probe",
                get(
                    |Extension(maybe_decision): Extension<Option<DevicePostureDecision>>| async move {
                        match maybe_decision {
                            Some(d) => axum::Json(serde_json::json!({
                                "attached": true,
                                "status": d.decision.status.as_str(),
                                "claims_present": d.claims.is_some(),
                            })),
                            None => axum::Json(serde_json::json!({"attached": false})),
                        }
                    },
                ),
            )
            // Tiny shim layer: bridge `Option<DevicePostureDecision>`
            // from the request extensions into an axum `Extension` so
            // the handler can read it via the typed extractor. The
            // middleware below attaches the decision when present.
            .layer(axum::middleware::from_fn(
                |mut req: Request, next: Next| async move {
                    let dec = req
                        .extensions()
                        .get::<DevicePostureDecision>()
                        .cloned();
                    req.extensions_mut().insert::<Option<DevicePostureDecision>>(dec);
                    next.run(req).await
                },
            ))
            .layer(axum::middleware::from_fn_with_state(
                state,
                device_posture_middleware,
            ))
    }

    #[tokio::test]
    async fn missing_header_passes_through() {
        let app = make_app();
        let req = Request::builder()
            .uri("/probe")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1_024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["attached"], false);
    }

    #[tokio::test]
    async fn valid_jwt_attaches_claims() {
        let app = make_app();
        let now = now_unix();
        let claims = PostureClaims {
            iat: Some(now),
            exp: Some(now + 60),
            os_name: Some("macOS".into()),
            disk_encrypted: true,
            edr_present: true,
            ..PostureClaims::default()
        };
        let token = sign(&claims, SECRET);
        let req = Request::builder()
            .uri("/probe")
            .header(&POSTURE_HEADER, token)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1_024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["attached"], true);
        assert_eq!(v["status"], "trusted");
        assert_eq!(v["claims_present"], true);
    }

    #[tokio::test]
    async fn tampered_jwt_attaches_untrusted_and_passes_through() {
        let app = make_app();
        let now = now_unix();
        let claims = PostureClaims {
            iat: Some(now),
            exp: Some(now + 60),
            ..PostureClaims::default()
        };
        let mut token = sign(&claims, SECRET);
        // Mutate the signature segment.
        let last = token.pop().unwrap_or('a');
        token.push(if last == 'a' { 'b' } else { 'a' });
        let req = Request::builder()
            .uri("/probe")
            .header(&POSTURE_HEADER, token)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        // Request always succeeds — middleware never blocks.
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1_024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["attached"], true);
        assert_eq!(v["status"], "untrusted");
        assert_eq!(v["claims_present"], false);
    }

    #[tokio::test]
    async fn stale_jwt_attaches_stale_decision() {
        let app = make_app();
        let now = now_unix();
        let claims = PostureClaims {
            // iat far in the past
            iat: Some(now - 86_400),
            exp: Some(now + 86_400),
            ..PostureClaims::default()
        };
        let token = sign(&claims, SECRET);
        let req = Request::builder()
            .uri("/probe")
            .header(&POSTURE_HEADER, token)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1_024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "stale");
    }

    #[tokio::test]
    async fn empty_header_value_passes_through() {
        let app = make_app();
        let req = Request::builder()
            .uri("/probe")
            .header(&POSTURE_HEADER, "   ")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1_024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["attached"], false);
    }
}
