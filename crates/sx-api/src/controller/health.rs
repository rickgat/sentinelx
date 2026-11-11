//! Health-check controllers.
//!
//! - `GET /healthz` — process liveness; always 200 (provided the server is
//!   accepting connections).
//! - `GET /readyz` — process readiness; right now just returns 200 with the
//!   same envelope, but the intent is for a future enhancement to ping the
//!   downstream dependencies.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::port::ReadinessReport;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;

/// Body of the `healthz` envelope.
#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    /// Always `"ok"`.
    pub status: &'static str,
}

/// `GET /healthz` — liveness.
///
/// Always 200 while the process can serve a request; it deliberately checks
/// no dependencies (that is `readyz`'s job), so a transient dependency
/// outage never causes an orchestrator to kill a healthy process.
pub async fn healthz() -> Json<ApiResponse<HealthStatus>> {
    Json(ApiResponse::ok(HealthStatus { status: "ok" }))
}

/// `GET /readyz` — readiness.
///
/// Runs the configured [`ReadinessProbe`] over the process's critical
/// dependencies and returns `200` only when every check passes; otherwise
/// `503 Service Unavailable` with the per-dependency breakdown, so an
/// orchestrator holds traffic until the instance can serve.
pub async fn readyz(
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<ReadinessReport>>) {
    let report = state.readiness.check().await;
    let code = if report.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(ApiResponse::ok(report)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::port::{AlwaysReady, ReadinessCheck, ReadinessProbe, ReadinessReport};

    #[tokio::test]
    async fn healthz_returns_ok() {
        let Json(env) = healthz().await;
        assert_eq!(env.data.status, "ok");
    }

    #[tokio::test]
    async fn always_ready_probe_reports_ready() {
        let report = AlwaysReady.check().await;
        assert!(report.ready);
        assert!(report.checks.iter().any(|c| c.name == "process" && c.ok));
    }

    #[test]
    fn report_is_not_ready_when_any_check_fails() {
        // Readiness is the AND of every check — a single failing dependency
        // flips the aggregate to not-ready (→ the handler returns 503).
        let report = ReadinessReport::from_checks(vec![
            ReadinessCheck {
                name: "process".to_owned(),
                ok: true,
                detail: None,
            },
            ReadinessCheck {
                name: "database".to_owned(),
                ok: false,
                detail: Some("connection refused".to_owned()),
            },
        ]);
        assert!(!report.ready);
    }
}
