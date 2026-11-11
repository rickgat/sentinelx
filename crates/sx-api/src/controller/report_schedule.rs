//! Scheduled-report distribution controllers (P2-001).
//!
//! * `GET    /v1/reports/schedules`      — list the tenant's schedules.
//! * `POST   /v1/reports/schedules`      — register a schedule.
//! * `DELETE /v1/reports/schedules/{id}` — disable a schedule.
//!
//! Reads require `report:read`; writes require `report:write`. Tenant is
//! always derived from the caller's JWT claims.

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::ReportSchedulePortError;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::report_schedule_view::{CreateReportScheduleRequest, ReportScheduleView};

fn map_err(err: ReportSchedulePortError) -> ApiError {
    match err {
        ReportSchedulePortError::Invalid(m) => ApiError::Unprocessable(m),
        ReportSchedulePortError::NotFound => ApiError::NotFound,
        ReportSchedulePortError::Internal(m) => ApiError::Internal(m),
    }
}

/// `GET /v1/reports/schedules`
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "report:read")?;
    let rows: Vec<ReportScheduleView> = state
        .report_schedules
        .list(&user.claims.tenant_id)
        .await
        .map_err(map_err)?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// `POST /v1/reports/schedules`
pub async fn create(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CreateReportScheduleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "report:write")?;
    let view = state
        .report_schedules
        .create(&user.claims.tenant_id, req)
        .await
        .map_err(map_err)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// `DELETE /v1/reports/schedules/{id}`
pub async fn delete(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "report:write")?;
    state
        .report_schedules
        .delete(&user.claims.tenant_id, &id)
        .await
        .map_err(map_err)?;
    Ok(Json(ApiResponse::ok(serde_json::json!({ "deleted": id }))))
}

/// Wildcard-aware permission gate (local copy, per project convention).
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
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
    fn read_and_write_gates() {
        assert!(require_permission(&user(vec!["report:read"]), "report:read").is_ok());
        assert!(require_permission(&user(vec!["report:write"]), "report:write").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "report:write").is_ok());
        assert!(matches!(
            require_permission(&user(vec!["report:read"]), "report:write"),
            Err(ApiError::Forbidden)
        ));
    }
}
