//! Autonomy controllers — `POST /v1/autonomy/pr`,
//! `POST /v1/autonomy/threat-network`, `POST/DELETE /v1/autonomy/validation/schedules`.
//!
//! All four routes are RBAC-gated by the `autonomy:run` permission. The
//! controller layer only enforces the gate and dispatches; every business
//! rule (protected-branch refusal, HTTPS endpoint check, schedule
//! cancellation semantics) lives in the adapter.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::{
    AutonomyEngineId, ProposePrChange, ProposePrInput, ScheduleValidationInput, SubmitThreatInput,
    SubmitThreatObservation,
};
use crate::state::AppState;
use crate::view::autonomy_view::{
    ProposePrRequestView, ProposePrResponseView, ScheduleValidationRequestView,
    ScheduleValidationResponseView, SubmitThreatRequestView, SubmitThreatResponseView,
};
use crate::view::envelope::ApiResponse;

/// `POST /v1/autonomy/pr` — propose an auto-remediation pull request.
pub async fn propose_pr(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<ProposePrRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "autonomy:run")?;
    let input = ProposePrInput {
        tenant_id: req.tenant_id,
        finding_id: req.finding_id,
        repo_owner: req.repo_owner,
        repo_name: req.repo_name,
        target_branch: req.target_branch,
        title: req.title,
        description: req.description,
        changes: req
            .changes
            .into_iter()
            .map(|c| ProposePrChange {
                path: c.path,
                new_content: c.new_content,
            })
            .collect(),
    };
    let outcome = state.propose_pr.propose(input).await.map_err(map_phase3)?;
    let view = ProposePrResponseView {
        pull_request_number: outcome.pull_request_number,
        url: outcome.url,
    };
    Ok(Json(ApiResponse::ok(view)))
}

/// `POST /v1/autonomy/threat-network` — submit anonymised threat
/// observations.
pub async fn submit_threat(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<SubmitThreatRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "autonomy:run")?;
    let input = SubmitThreatInput {
        tenant_id: req.tenant_id,
        consented_at: req.consented_at,
        scope: req.scope,
        observations: req
            .observations
            .into_iter()
            .map(|o| SubmitThreatObservation {
                cve_id: o.cve_id,
                asset_kind: o.asset_kind,
                count: o.count,
            })
            .collect(),
    };
    let outcome = state
        .submit_threat
        .submit(input)
        .await
        .map_err(map_phase3)?;
    let view = SubmitThreatResponseView {
        accepted: outcome.accepted,
        submitted_count: outcome.submitted_count,
    };
    Ok(Json(ApiResponse::ok(view)))
}

/// `POST /v1/autonomy/validation/schedules` — schedule a continuous
/// validation engine.
pub async fn schedule_validation(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<ScheduleValidationRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "autonomy:run")?;
    let input = ScheduleValidationInput {
        tenant_id: req.tenant_id,
        engagement_id: req.engagement_id,
        interval_secs: req.interval_secs,
        technique_ids: req.technique_ids,
    };
    let id = state
        .schedule_validation
        .schedule(input)
        .await
        .map_err(map_phase3)?;
    let view = ScheduleValidationResponseView { engine_id: id.0 };
    Ok(Json(ApiResponse::ok(view)))
}

/// `DELETE /v1/autonomy/validation/schedules/{engine_id}` — cancel a
/// previously scheduled engine. Returns `204 No Content` on success.
pub async fn cancel_validation(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(engine_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "autonomy:run")?;
    let id = AutonomyEngineId(engine_id);
    state
        .schedule_validation
        .cancel(&id)
        .await
        .map_err(map_phase3)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Enforce a single `resource:action` permission with wildcard support.
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::port::Phase3PortError;
    use sx_iam::model::claims::{AccessClaims, TokenType};

    fn user(perms: Vec<&str>) -> AuthenticatedUser {
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
    fn missing_permission_is_forbidden() {
        let u = user(vec!["finding:read"]);
        assert!(matches!(
            require_permission(&u, "autonomy:run"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_permission_allowed() {
        let u = user(vec!["autonomy:run"]);
        assert!(require_permission(&u, "autonomy:run").is_ok());
    }

    #[test]
    fn wildcard_action_allowed() {
        let u = user(vec!["autonomy:*"]);
        assert!(require_permission(&u, "autonomy:run").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = user(vec!["*:run"]);
        assert!(require_permission(&u, "autonomy:run").is_ok());
    }

    /// Phase3PortError variants round-trip into the appropriate ApiError
    /// (and therefore HTTP status). Mirrors the shared `map_phase3`
    /// table for the autonomy surface.
    #[test]
    fn phase3_errors_map_to_correct_statuses() {
        use axum::http::StatusCode;
        assert_eq!(
            map_phase3(Phase3PortError::Forbidden("nope".into())).status(),
            StatusCode::FORBIDDEN,
        );
        assert_eq!(
            map_phase3(Phase3PortError::NotFound).status(),
            StatusCode::NOT_FOUND,
        );
        assert_eq!(
            map_phase3(Phase3PortError::Internal("boom".into())).status(),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_eq!(
            map_phase3(Phase3PortError::Invalid("bad".into())).status(),
            StatusCode::UNPROCESSABLE_ENTITY,
        );
        assert_eq!(
            map_phase3(Phase3PortError::Dependency("db".into())).status(),
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
}
