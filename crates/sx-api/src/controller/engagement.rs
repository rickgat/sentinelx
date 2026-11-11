//! Engagement controllers — CRUD over `/v1/engagements` plus the four
//! state-machine transitions (`pause` / `resume` / `abort` / `complete`).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_engagement;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::engagement_view::{
    CloneEngagementRequest, CreateEngagementView, EngagementAbortRequest, EngagementView,
    UpdateEngagementView,
};
use crate::view::envelope::ApiResponse;
use crate::view::pagination::{PageQuery, PageView};

/// `POST /v1/engagements`
pub async fn create(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CreateEngagementView>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `engagement:write`.
    require_permission(&user, "engagement:write")?;
    let e = state
        .engagements
        .create(&scope.tenant_id, req)
        .await
        .map_err(map_engagement)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(e))))
}

/// `GET /v1/engagements`
pub async fn list(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    Query(q): Query<PageQuery>,
) -> Result<Json<ApiResponse<PageView<EngagementView>>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `engagement:read`.
    require_permission(&user, "engagement:read")?;
    let items = state
        .engagements
        .list(&scope.tenant_id, q.offset(), q.limit())
        .await
        .map_err(map_engagement)?;
    let page = PageView::new(items, q.offset(), q.limit());
    Ok(Json(ApiResponse::ok(page)))
}

/// `GET /v1/engagements/{id}`
pub async fn get_one(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<EngagementView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `engagement:read`.
    require_permission(&user, "engagement:read")?;
    let e = state
        .engagements
        .get(&scope.tenant_id, &id)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(e)))
}

/// `PATCH /v1/engagements/{id}`
pub async fn update(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    ValidatedJson(req): ValidatedJson<UpdateEngagementView>,
) -> Result<Json<ApiResponse<EngagementView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `engagement:write`.
    require_permission(&user, "engagement:write")?;
    let e = state
        .engagements
        .update(&scope.tenant_id, &id, req)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(e)))
}

/// `POST /v1/engagements/{id}/pause` — transition `Active -> Paused`.
///
/// Requires the `engagements:transition` permission. Illegal transitions
/// surface as `403 Forbidden` (the underlying port returns
/// [`crate::port::EngagementPortError::Forbidden`]).
pub async fn pause(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<EngagementView>>, ApiError> {
    require_permission(&user, "engagements:transition")?;
    let e = state
        .engagement_transitions
        .pause(&scope.tenant_id, &id)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(e)))
}

/// `POST /v1/engagements/{id}/resume` — transition `Paused -> Active`.
pub async fn resume(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<EngagementView>>, ApiError> {
    require_permission(&user, "engagements:transition")?;
    let e = state
        .engagement_transitions
        .resume(&scope.tenant_id, &id)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(e)))
}

/// `POST /v1/engagements/{id}/activate` — transition `Draft -> Active`.
///
/// The operator-triggered "start the engagement" transition. Requires the
/// `engagements:transition` permission. Illegal source states (anything
/// other than `Draft` or `Paused`) surface as `403 Forbidden`.
pub async fn activate(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<EngagementView>>, ApiError> {
    require_permission(&user, "engagements:transition")?;
    let e = state
        .engagement_transitions
        .activate(&scope.tenant_id, &id)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(e)))
}

/// `POST /v1/engagements/{id}/abort` — transition to `Aborted`.
///
/// Valid from `Draft`, `Active`, or `Paused`. Body carries a bounded
/// `reason` (1..=2000 chars) for the audit trail.
pub async fn abort(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    ValidatedJson(req): ValidatedJson<EngagementAbortRequest>,
) -> Result<Json<ApiResponse<EngagementView>>, ApiError> {
    require_permission(&user, "engagements:transition")?;
    let e = state
        .engagement_transitions
        .abort(&scope.tenant_id, &id, &req.reason)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(e)))
}

/// `POST /v1/engagements/{id}/complete` — transition `Active -> Completed`.
pub async fn complete(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<EngagementView>>, ApiError> {
    require_permission(&user, "engagements:transition")?;
    let e = state
        .engagement_transitions
        .complete(&scope.tenant_id, &id)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(e)))
}

/// `POST /v1/engagements/{id}/clone` — create a fresh `Draft` engagement
/// that inherits its scope + window-duration from the source.
///
/// Requires the `engagements:write` permission. The body carries an
/// optional `new_name` override; when omitted the adapter mints the
/// default `"{source.name} (clone)"`.
///
/// A missing source surfaces as `404 Not Found` (the underlying port
/// returns [`crate::port::EngagementPortError::NotFound`]).
pub async fn clone_engagement(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    ValidatedJson(req): ValidatedJson<CloneEngagementRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "engagements:write")?;
    let e = state
        .engagement_clone
        .clone_engagement(&scope.tenant_id, &id, req)
        .await
        .map_err(map_engagement)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(e))))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper in [`crate::controller::autonomy`] verbatim — kept
/// per-controller so each route owns its own permission constant and there
/// is no cross-module coupling.
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
            require_permission(&u, "engagements:transition"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_transition_permission_allowed() {
        let u = user(vec!["engagements:transition"]);
        assert!(require_permission(&u, "engagements:transition").is_ok());
    }

    #[test]
    fn wildcard_action_allowed() {
        let u = user(vec!["engagements:*"]);
        assert!(require_permission(&u, "engagements:transition").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = user(vec!["*:transition"]);
        assert!(require_permission(&u, "engagements:transition").is_ok());
    }
}
