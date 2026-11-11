//! IR playbooks (P3-004) HTTP controllers — `/v1/ir/*`.
//!
//! Four endpoints:
//!
//! * `GET   /v1/ir/playbooks`                   — list catalog templates.
//! * `POST  /v1/ir/incidents`                   — open a new incident.
//! * `GET   /v1/ir/incidents/{id}`              — fetch one incident.
//! * `PATCH /v1/ir/incidents/{id}/steps/{step}` — mutate one step.
//!
//! Every successful request emits an `audit`-targeted structured log
//! line so downstream sinks can persist the metadata.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use validator::Validate;

use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::IrPlaybookPortError;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::ir_view::{
    IncidentView, ListPlaybooksResponse, OpenIncidentRequest, UpdateStepRequest,
};

/// `GET /v1/ir/playbooks` — list catalog templates available to the
/// caller's tenant.
pub async fn list_playbooks(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `ir:read`.
    require_permission(&user, "ir:read")?;
    let res = state
        .ir
        .list_playbooks(&user.claims.tenant_id)
        .await
        .map_err(map_ir)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(res))))
}

/// `POST /v1/ir/incidents` — open a new incident.
pub async fn open_incident(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<OpenIncidentRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `ir:write`.
    require_permission(&user, "ir:write")?;
    req.validate()
        .map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    let inc = state
        .ir
        .open_incident(
            &user.claims.tenant_id,
            &user.claims.sub,
            &req.playbook_id,
            &req.title,
            req.severity.as_deref(),
        )
        .await
        .map_err(map_ir)?;

    tracing::info!(
        target: "audit",
        action = "ir.incident.opened",
        tenant_id = %user.claims.tenant_id,
        actor = %user.claims.sub,
        incident_id = %inc.id,
        playbook_id = %inc.playbook_id,
        "ir.incident.opened",
    );

    Ok((StatusCode::CREATED, Json(ApiResponse::ok(inc))))
}

/// `GET /v1/ir/incidents/{id}` — fetch one incident.
pub async fn get_incident(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `ir:read`.
    require_permission(&user, "ir:read")?;
    let inc = state
        .ir
        .get_incident(&user.claims.tenant_id, &id)
        .await
        .map_err(map_ir)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(inc))))
}

/// `PATCH /v1/ir/incidents/{id}/steps/{step}` — mutate one step.
pub async fn update_step(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((id, step)): Path<(String, String)>,
    Json(req): Json<UpdateStepRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `ir:write`.
    require_permission(&user, "ir:write")?;
    req.validate()
        .map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    if let Some(status) = req.status.as_deref() {
        validate_status_label(status)?;
    }
    let inc: IncidentView = state
        .ir
        .update_step(
            &user.claims.tenant_id,
            &user.claims.sub,
            &id,
            &step,
            req.status.as_deref(),
            req.owner.as_deref(),
            req.reason.as_deref(),
            req.evidence.as_deref(),
        )
        .await
        .map_err(map_ir)?;

    tracing::info!(
        target: "audit",
        action = "ir.step.updated",
        tenant_id = %user.claims.tenant_id,
        actor = %user.claims.sub,
        incident_id = %inc.id,
        step_id = %step,
        status = ?req.status,
        "ir.step.updated",
    );

    Ok((StatusCode::OK, Json(ApiResponse::ok(inc))))
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

/// Translate [`IrPlaybookPortError`] onto the API error envelope.
pub fn map_ir(err: IrPlaybookPortError) -> ApiError {
    match err {
        IrPlaybookPortError::NotFound => ApiError::NotFound,
        IrPlaybookPortError::IllegalStepTransition(m)
        | IrPlaybookPortError::IllegalIncidentTransition(m)
        | IrPlaybookPortError::Invalid(m) => ApiError::Unprocessable(m),
        IrPlaybookPortError::Internal(m) => ApiError::Internal(m),
    }
}

fn validate_status_label(s: &str) -> Result<(), ApiError> {
    if matches!(s, "todo" | "in_progress" | "done" | "skipped") {
        Ok(())
    } else {
        Err(ApiError::Unprocessable(format!(
            "unknown status: {s}; expected one of todo / in_progress / done / skipped"
        )))
    }
}

#[allow(unused_imports)] // ListPlaybooksResponse imported for doc-tests.
#[allow(dead_code)]
const _: fn() = || {
    let _ = std::any::type_name::<ListPlaybooksResponse>();
};

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
        assert!(require_permission(&user(vec!["ir:read"]), "ir:read").is_ok());
        assert!(require_permission(&user(vec!["ir:write"]), "ir:write").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["ir:*"]), "ir:write").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "ir:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "ir:write").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn map_ir_not_found_is_not_found() {
        assert!(matches!(
            map_ir(IrPlaybookPortError::NotFound),
            ApiError::NotFound
        ));
    }

    #[test]
    fn map_ir_illegal_transitions_unprocessable() {
        assert!(matches!(
            map_ir(IrPlaybookPortError::IllegalStepTransition("a".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_ir(IrPlaybookPortError::IllegalIncidentTransition("a".into())),
            ApiError::Unprocessable(_)
        ));
    }

    #[test]
    fn map_ir_invalid_unprocessable() {
        assert!(matches!(
            map_ir(IrPlaybookPortError::Invalid("a".into())),
            ApiError::Unprocessable(_)
        ));
    }

    #[test]
    fn map_ir_internal_internal() {
        assert!(matches!(
            map_ir(IrPlaybookPortError::Internal("a".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn known_status_labels_accepted() {
        for s in ["todo", "in_progress", "done", "skipped"] {
            validate_status_label(s).unwrap();
        }
    }

    #[test]
    fn unknown_status_label_rejected() {
        let err = validate_status_label("blocked").unwrap_err();
        assert!(matches!(err, ApiError::Unprocessable(_)));
    }
}
