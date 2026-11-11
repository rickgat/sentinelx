//! Remediation-outcomes controllers — MTTR / regression read endpoints.
//!
//! Both endpoints are tenant-scoped reads. The HTTP surface is
//! intentionally narrow: the writer side (record-close, detect-
//! regression) is wired as an observer hook inside the finding state-
//! transition pipeline by the composition root.
//!
//! ## Endpoints
//!
//! - `GET /v1/remediation/outcomes/metrics?window_days=N` — per-severity
//!   MTTR aggregate + regression rate + top regressing `check_id`.
//!   `window_days` defaults to 30 when absent or zero. Capped at 365 so
//!   a deliberately huge value never blows out the underlying scan.
//! - `GET /v1/remediation/outcomes/regressions?limit=N` — newest-first
//!   regression events. `limit` defaults to 50 and is capped at 500.

use axum::extract::{Query, State};
use axum::Json;

use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::remediation_outcomes_view::{
    OutcomesMetricsQuery, OutcomesRegressionsQuery, RegressionListView, RemediationMetricsView,
};

/// Default window when the caller omits `window_days`.
const DEFAULT_WINDOW_DAYS: u32 = 30;
/// Hard cap so a malicious caller can't request an absurd window.
const MAX_WINDOW_DAYS: u32 = 365;
/// Default limit when the caller omits `limit`.
const DEFAULT_REGRESSION_LIMIT: u32 = 50;
/// Hard cap for `limit`.
const MAX_REGRESSION_LIMIT: u32 = 500;

/// `GET /v1/remediation/outcomes/metrics`
pub async fn metrics(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<OutcomesMetricsQuery>,
) -> Result<Json<ApiResponse<RemediationMetricsView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `remediation:read`.
    require_permission(&user, "remediation:read")?;
    let window = clamp_window(q.window_days);
    let view = state
        .remediation_outcomes
        .metrics(&user.claims.tenant_id, window)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// `GET /v1/remediation/outcomes/regressions`
pub async fn regressions(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<OutcomesRegressionsQuery>,
) -> Result<Json<ApiResponse<RegressionListView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `remediation:read`.
    require_permission(&user, "remediation:read")?;
    let limit = clamp_limit(q.limit);
    let view = state
        .remediation_outcomes
        .list_regressions(&user.claims.tenant_id, limit)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// Wildcard-aware permission gate (local copy — each controller owns its
/// own so the authorization decision stays beside the handler it guards).
/// A grant of `*` on either the resource or the action segment matches.
fn require_permission(user: &AuthenticatedUser, perm: &str) -> Result<(), ApiError> {
    let Ok(required) = Permission::parse(perm) else {
        return Err(ApiError::Internal("invalid permission constant".into()));
    };
    let allowed = user.claims.permissions.iter().any(|p| {
        let r = p.resource() == required.resource() || p.resource() == "*";
        let a = p.action() == required.action() || p.action() == "*";
        r && a
    });
    if allowed {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

fn clamp_window(input: Option<u32>) -> u32 {
    let raw = input.unwrap_or(DEFAULT_WINDOW_DAYS);
    if raw == 0 {
        DEFAULT_WINDOW_DAYS
    } else {
        raw.min(MAX_WINDOW_DAYS)
    }
}

fn clamp_limit(input: Option<u32>) -> u32 {
    let raw = input.unwrap_or(DEFAULT_REGRESSION_LIMIT);
    if raw == 0 {
        DEFAULT_REGRESSION_LIMIT
    } else {
        raw.min(MAX_REGRESSION_LIMIT)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn user(perms: Vec<&str>) -> AuthenticatedUser {
        use sx_iam::model::claims::{AccessClaims, TokenType};
        AuthenticatedUser {
            claims: AccessClaims {
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
                permissions: perms
                    .into_iter()
                    .map(|p| Permission::parse(p).unwrap())
                    .collect(),
                cred_id: None,
            },
        }
    }

    #[test]
    fn exact_permission_is_allowed() {
        assert!(require_permission(&user(vec!["remediation:read"]), "remediation:read").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["remediation:*"]), "remediation:read").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "remediation:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "remediation:read").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn window_clamp_handles_zero_and_overflow() {
        assert_eq!(clamp_window(None), DEFAULT_WINDOW_DAYS);
        assert_eq!(clamp_window(Some(0)), DEFAULT_WINDOW_DAYS);
        assert_eq!(clamp_window(Some(7)), 7);
        assert_eq!(clamp_window(Some(10_000)), MAX_WINDOW_DAYS);
    }

    #[test]
    fn limit_clamp_handles_zero_and_overflow() {
        assert_eq!(clamp_limit(None), DEFAULT_REGRESSION_LIMIT);
        assert_eq!(clamp_limit(Some(0)), DEFAULT_REGRESSION_LIMIT);
        assert_eq!(clamp_limit(Some(25)), 25);
        assert_eq!(clamp_limit(Some(10_000)), MAX_REGRESSION_LIMIT);
    }
}
