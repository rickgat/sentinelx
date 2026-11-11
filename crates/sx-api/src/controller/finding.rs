use axum::extract::{Path, Query, State};
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_engagement;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::finding_view::{FindingView, UpdateFindingStatusView};
use crate::view::pagination::{PageQuery, PageView};

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

/// `GET /v1/findings`
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<PageQuery>,
) -> Result<Json<ApiResponse<PageView<FindingView>>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `finding:read`.
    require_permission(&user, "finding:read")?;
    let items = state
        .findings
        .list(&user.claims.tenant_id, q.offset(), q.limit())
        .await
        .map_err(map_engagement)?;
    let page = PageView::new(items, q.offset(), q.limit());
    Ok(Json(ApiResponse::ok(page)))
}

/// `GET /v1/findings/{id}`
pub async fn get_one(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<FindingView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `finding:read`.
    require_permission(&user, "finding:read")?;
    let f = state
        .findings
        .get(&user.claims.tenant_id, &id)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(f)))
}

/// `PATCH /v1/findings/{id}/status`
pub async fn update_status(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    ValidatedJson(req): ValidatedJson<UpdateFindingStatusView>,
) -> Result<Json<ApiResponse<FindingView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `finding:write`.
    require_permission(&user, "finding:write")?;
    let f = state
        .findings
        .update_status(
            &user.claims.tenant_id,
            &id,
            &req.status,
            req.comment.as_deref(),
        )
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(f)))
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
        assert!(require_permission(&user(vec!["finding:read"]), "finding:read").is_ok());
        assert!(require_permission(&user(vec!["finding:write"]), "finding:write").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["finding:*"]), "finding:write").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "finding:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["asset:read"]), "finding:write").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }
}
