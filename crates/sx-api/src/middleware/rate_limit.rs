//! In-memory token-bucket rate limiter.
//!
//! Keyed by either:
//! * `(tenant_id, route)` — once an [`AuthenticatedUser`] is present, or
//! * `(ip, route)` — for unauthenticated routes (login, healthz).
//!
//! The bucket refills at `limit_per_minute / 60` tokens per second and is
//! capped at `burst`. When a request finds the bucket empty it is rejected
//! with [`ApiError::TooMany`]. A 429 response is rendered with the standard
//! envelope and a `Retry-After` header.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Response};
use axum::middleware::Next;
use axum::response::IntoResponse;

use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Sustained rate (requests per minute) per key.
    pub limit_per_minute: u32,
    /// Maximum burst above the sustained rate.
    pub burst: u32,
    /// Whether the limiter is engaged at all. When `false` every request
    /// passes — useful for local development.
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            limit_per_minute: 600,
            burst: 60,
            enabled: true,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// State shared across the limiter.
#[derive(Debug, Default)]
pub struct RateLimiterState {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiterState {
    /// Construct an empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to consume one token from `key`'s bucket.
    pub fn allow(&self, key: &str, cfg: &RateLimitConfig) -> bool {
        if !cfg.enabled {
            return true;
        }
        let now = Instant::now();
        let per_second = f64::from(cfg.limit_per_minute) / 60.0;
        let burst = f64::from(cfg.burst);

        // Lock poisoning means a previous handler panicked while holding
        // the lock — refuse the request rather than panicking again.
        let Ok(mut guard) = self.buckets.lock() else {
            return false;
        };
        let bucket = guard.entry(key.to_owned()).or_insert(Bucket {
            tokens: burst,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = elapsed.mul_add(per_second, bucket.tokens).min(burst);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Bundle passed via axum state to [`rate_limit_middleware`].
#[derive(Clone)]
pub struct RateLimitState {
    /// Config snapshot.
    pub cfg: Arc<RateLimitConfig>,
    /// Shared bucket state.
    pub state: Arc<RateLimiterState>,
}

impl std::fmt::Debug for RateLimitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitState")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

/// `axum::middleware::from_fn_with_state` callback.
pub async fn rate_limit_middleware(
    State(rls): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let path = req.uri().path().to_owned();
    let key = if let Some(claims) = req.extensions().get::<AuthenticatedUser>() {
        format!("tenant:{}:{}", claims.claims.tenant_id, path)
    } else {
        let ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown");
        format!("ip:{ip}:{path}")
    };

    if !rls.state.allow(&key, &rls.cfg) {
        let mut res = ApiError::TooMany.into_response();
        res.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return res;
    }
    next.run(req).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_then_throttles() {
        let state = RateLimiterState::new();
        let cfg = RateLimitConfig {
            limit_per_minute: 60,
            burst: 3,
            enabled: true,
        };
        assert!(state.allow("k1", &cfg));
        assert!(state.allow("k1", &cfg));
        assert!(state.allow("k1", &cfg));
        // 4th call within the same instant should be rejected.
        assert!(!state.allow("k1", &cfg));
    }

    #[test]
    fn disabled_config_allows_everything() {
        let state = RateLimiterState::new();
        let cfg = RateLimitConfig {
            limit_per_minute: 1,
            burst: 1,
            enabled: false,
        };
        for _ in 0..100 {
            assert!(state.allow("k", &cfg));
        }
    }

    #[test]
    fn different_keys_get_independent_buckets() {
        let state = RateLimiterState::new();
        let cfg = RateLimitConfig {
            limit_per_minute: 60,
            burst: 1,
            enabled: true,
        };
        assert!(state.allow("a", &cfg));
        assert!(state.allow("b", &cfg));
        assert!(!state.allow("a", &cfg));
        assert!(!state.allow("b", &cfg));
    }

    // Exercise the middleware through axum.
    #[tokio::test]
    async fn middleware_rejects_excess_requests() {
        use axum::http::StatusCode;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let state = RateLimitState {
            cfg: Arc::new(RateLimitConfig {
                limit_per_minute: 60,
                burst: 2,
                enabled: true,
            }),
            state: Arc::new(RateLimiterState::new()),
        };
        let app = Router::new()
            .route("/v1/things", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                rate_limit_middleware,
            ));
        let make = || {
            axum::extract::Request::builder()
                .uri("/v1/things")
                .header("x-forwarded-for", "1.2.3.4")
                .body(Body::empty())
                .unwrap()
        };
        let r1 = app.clone().oneshot(make()).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app.clone().oneshot(make()).await.unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
        let r3 = app.clone().oneshot(make()).await.unwrap();
        assert_eq!(r3.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(r3.headers().get("retry-after").is_some());
    }
}
