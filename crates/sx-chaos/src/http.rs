//! HTTP chaos middleware.
//!
//! Wraps an axum router with a `from_fn_with_state` callback that consults
//! the shared [`ChaosRegistry`](crate::ChaosRegistry) on every request:
//!
//! * [`ChaosOutcome::Pass`] → fall through to the next layer.
//! * [`ChaosOutcome::Latency`] → the registry already slept for us — fall
//!   through to the next layer with no body alteration.
//! * [`ChaosOutcome::Error`] → return `503 Service Unavailable` with a
//!   structured JSON body explaining chaos was injected.
//! * [`ChaosOutcome::Dependency`] → return `503` (unavailable) or `504`
//!   (timeout) depending on the manifestation.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::json;

use crate::model::{ChaosInjector, ChaosOutcome, DependencyOutcome};
use crate::registry::SharedChaosRegistry;

/// HTTP header set whenever chaos was injected. Useful for tests + ops
/// dashboards to differentiate organic 5xx from chaos-induced 5xx.
pub const CHAOS_HEADER: HeaderName = HeaderName::from_static("x-sentinelx-chaos");

/// State bundle for [`chaos_middleware`].
#[derive(Clone, Debug)]
pub struct ChaosHttpState {
    /// Shared registry (cheap to clone — `Arc` inside).
    pub registry: SharedChaosRegistry,
}

impl ChaosHttpState {
    /// Construct from a shared registry.
    #[must_use]
    pub const fn new(registry: SharedChaosRegistry) -> Self {
        Self { registry }
    }
}

/// Axum `from_fn_with_state` callback.
pub async fn chaos_middleware(
    State(state): State<ChaosHttpState>,
    req: Request,
    next: Next,
) -> Response {
    let outcome = state.registry.inject_http().await;
    match outcome {
        ChaosOutcome::Pass | ChaosOutcome::Latency { .. } => {
            let mut response = next.run(req).await;
            if let ChaosOutcome::Latency { slept_ms } = outcome {
                if let Ok(v) = HeaderValue::from_str(&format!("latency;ms={slept_ms}")) {
                    response.headers_mut().insert(CHAOS_HEADER, v);
                }
            }
            response
        }
        ChaosOutcome::Error => synth_error(StatusCode::SERVICE_UNAVAILABLE, "error_rate", None),
        ChaosOutcome::Dependency {
            kind,
            outcome: manifestation,
        } => {
            let status = match manifestation {
                DependencyOutcome::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                DependencyOutcome::Timeout => StatusCode::GATEWAY_TIMEOUT,
            };
            synth_error(
                status,
                "dependency",
                Some((kind.as_str(), manifestation.as_str())),
            )
        }
    }
}

/// Apply the chaos middleware to an existing axum router.
///
/// This is a tiny helper that wraps
/// `axum::middleware::from_fn_with_state(ChaosHttpState::new(reg),
/// chaos_middleware)` so callers do not have to mention the awkward
/// `FromFnLayer` generics. Returns the router with the layer applied —
/// must be `.with_state(())`'d (or merged) by the caller as usual.
pub fn apply<S>(router: axum::Router<S>, registry: SharedChaosRegistry) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(axum::middleware::from_fn_with_state(
        ChaosHttpState::new(registry),
        chaos_middleware,
    ))
}

fn synth_error(
    status: StatusCode,
    fault_kind: &'static str,
    dependency: Option<(&'static str, &'static str)>,
) -> Response {
    let body = match dependency {
        Some((target, manifestation)) => json!({
            "error": "chaos_injected",
            "kind": fault_kind,
            "dependency": target,
            "outcome": manifestation,
        }),
        None => json!({
            "error": "chaos_injected",
            "kind": fault_kind,
        }),
    };
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()));
    let header_val = match dependency {
        Some((_, manifestation)) => format!("{fault_kind};outcome={manifestation}"),
        None => fault_kind.to_owned(),
    };
    if let Ok(v) = HeaderValue::from_str(&header_val) {
        resp.headers_mut().insert(CHAOS_HEADER, v);
    }
    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::{ChaosConfig, DependencyConfig, DependencyKind, ErrorRateConfig};
    use crate::registry::ChaosRegistry;
    use crate::sampler::deterministic_sampler;
    use axum::routing::get;
    use axum::Router;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn registry_for(cfg: ChaosConfig, samples: Vec<f64>) -> SharedChaosRegistry {
        Arc::new(ChaosRegistry::with_sampler(
            cfg,
            deterministic_sampler(samples),
        ))
    }

    fn app(reg: SharedChaosRegistry) -> Router {
        apply(Router::new().route("/ok", get(|| async { "ok" })), reg)
    }

    #[tokio::test]
    async fn pass_through_when_disabled() {
        let reg = Arc::new(ChaosRegistry::disabled());
        let app = app(reg);
        let resp = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(&CHAOS_HEADER).is_none());
    }

    #[tokio::test]
    async fn error_arm_returns_503() {
        let cfg = ChaosConfig {
            enabled: true,
            error_rate: ErrorRateConfig { fraction: 1.0 },
            ..ChaosConfig::default()
        };
        let reg = registry_for(cfg, vec![0.99, 0.0]);
        let app = app(reg);
        let resp = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let header = resp.headers().get(&CHAOS_HEADER).cloned();
        assert!(header.is_some());
    }

    #[tokio::test]
    async fn dependency_arm_returns_503() {
        let cfg = ChaosConfig {
            enabled: true,
            dependency: DependencyConfig {
                fraction: 1.0,
                kind: DependencyKind::Db,
                outcome: DependencyOutcome::Unavailable,
            },
            ..ChaosConfig::default()
        };
        // inject_http samples latency arm first (skip via 0.99), then error
        // arm (skip via 0.99). Dependency arm is consulted via the repo
        // wrapper, but we surface it directly via custom router below.
        let reg = registry_for(cfg, vec![0.0]);
        // Route that asks for a dependency outcome explicitly.
        let app = Router::new().route(
            "/dep",
            get({
                let reg = Arc::clone(&reg);
                move || {
                    let reg = Arc::clone(&reg);
                    async move {
                        let outcome = reg.inject_dependency(DependencyKind::Db).await;
                        match outcome {
                            ChaosOutcome::Dependency { .. } => {
                                (StatusCode::SERVICE_UNAVAILABLE, "dep_down")
                            }
                            _ => (StatusCode::OK, "ok"),
                        }
                    }
                }
            }),
        );
        let resp = app
            .oneshot(Request::builder().uri("/dep").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test(start_paused = true)]
    async fn latency_arm_delays_request() {
        let cfg = ChaosConfig {
            enabled: true,
            latency: crate::model::LatencyConfig {
                fraction: 1.0,
                p50_ms: 25,
                p99_ms: 100,
            },
            ..ChaosConfig::default()
        };
        // First sample triggers latency arm (0.0 < 1.0); second sample
        // chooses tail (0.99 > 0.05 -> p50_ms path).
        let reg = registry_for(cfg, vec![0.0, 0.99]);
        let app = app(reg);
        let start = tokio::time::Instant::now();
        let resp = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(25),
            "expected ≥25ms latency, got {elapsed:?}",
        );
        let header = resp
            .headers()
            .get(&CHAOS_HEADER)
            .and_then(|h| h.to_str().ok())
            .map(ToOwned::to_owned)
            .unwrap_or_default();
        assert!(header.contains("latency"));
    }
}
