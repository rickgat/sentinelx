use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_compliance_evidence;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::compliance_evidence_view::CollectEvidenceRequestView;
use crate::view::envelope::ApiResponse;

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

/// `POST /v1/compliance/evidence/collect`
pub async fn collect(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CollectEvidenceRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `compliance:write`.
    require_permission(&user, "compliance:write")?;
    let resp = state
        .compliance_evidence
        .collect(
            &user.claims.tenant_id,
            req.period_start.as_deref(),
            req.period_end.as_deref(),
        )
        .await
        .map_err(map_compliance_evidence)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `GET /v1/compliance/evidence/bundles`
pub async fn list_bundles(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `compliance:read`.
    require_permission(&user, "compliance:read")?;
    let resp = state
        .compliance_evidence
        .list_bundles(&user.claims.tenant_id)
        .await
        .map_err(map_compliance_evidence)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `GET /v1/compliance/evidence/bundles/:id/download`
pub async fn download_bundle(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(run_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `compliance:read`.
    require_permission(&user, "compliance:read")?;
    let resp = state
        .compliance_evidence
        .download_bundle(&user.claims.tenant_id, &run_id)
        .await
        .map_err(map_compliance_evidence)?;
    Ok(Json(ApiResponse::ok(resp)))
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
        assert!(require_permission(&user(vec!["compliance:write"]), "compliance:write").is_ok());
        assert!(require_permission(&user(vec!["compliance:read"]), "compliance:read").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["compliance:*"]), "compliance:write").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "compliance:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "compliance:write").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }
}
