//! Asset write controllers — `POST`, `PATCH`, `DELETE` on `/v1/assets`.
//!
//! The read-only counterparts (`GET /v1/assets`, `GET /v1/assets/{id}`)
//! live in [`crate::controller::asset`] and remain untouched.
//!
//! Every handler:
//!
//! 1. Pulls the caller's [`AuthenticatedUser`] and [`TenantScope`] from the
//!    request extensions populated by the auth middleware.
//! 2. Enforces the `assets:write` RBAC permission via
//!    [`require_permission`] — wildcards (`assets:*`, `*:write`, `*:*`)
//!    are honoured.
//! 3. Delegates the mutation to the [`crate::port::AssetWritePort`]
//!    trait object held by [`AppState`].
//! 4. Translates port errors via [`crate::controller::map_engagement`].
//!
//! Wire shapes:
//!
//! - `POST   /v1/assets`            -> `201 Created` + `AssetView`
//! - `PATCH  /v1/assets/{id}`       -> `200 OK`       + `AssetView`
//! - `DELETE /v1/assets/{id}`       -> `204 No Content`

use axum::extract::{Path, State};
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
use crate::view::asset_view::{AssetView, CreateAssetRequest, UpdateAssetRequest};
use crate::view::envelope::ApiResponse;

/// `POST /v1/assets` — provision a new asset under the caller's tenant.
///
/// Returns `201 Created` carrying the persisted [`AssetView`] on success.
pub async fn create(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<CreateAssetRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "assets:write")?;
    let view = state
        .asset_write
        .create(&scope.tenant_id, req)
        .await
        .map_err(map_engagement)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(view))))
}

/// `PATCH /v1/assets/{id}` — apply a partial update to an asset.
///
/// Returns `200 OK` carrying the persisted [`AssetView`] on success.
pub async fn update(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Path(id): Path<String>,
    ValidatedJson(req): ValidatedJson<UpdateAssetRequest>,
) -> Result<Json<ApiResponse<AssetView>>, ApiError> {
    require_permission(&user, "assets:write")?;
    let view = state
        .asset_write
        .update(&scope.tenant_id, &id, req)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// `DELETE /v1/assets/{id}` — remove an asset.
///
/// Returns `204 No Content` on success and `404 Not Found` when the asset
/// is unknown to the caller's tenant.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_permission(&user, "assets:write")?;
    state
        .asset_write
        .delete(&scope.tenant_id, &id)
        .await
        .map_err(map_engagement)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper used by [`crate::controller::soc`] /
/// [`crate::controller::admin`] / [`crate::controller::copilot`]. The
/// helper is local rather than shared because the wildcard semantics are
/// stable per-controller and inlining keeps the dependency graph small.
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
    fn create_requires_assets_write_permission() {
        let u = user(vec!["assets:read"]);
        assert!(matches!(
            require_permission(&u, "assets:write"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_assets_write_permission_allowed() {
        let u = user(vec!["assets:write"]);
        assert!(require_permission(&u, "assets:write").is_ok());
    }

    #[test]
    fn wildcard_assets_action_allowed() {
        let u = user(vec!["assets:*"]);
        assert!(require_permission(&u, "assets:write").is_ok());
    }

    #[test]
    fn wildcard_resource_for_write_allowed() {
        let u = user(vec!["*:write"]);
        assert!(require_permission(&u, "assets:write").is_ok());
    }

    #[test]
    fn full_wildcard_grant_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "assets:write").is_ok());
    }

    #[test]
    fn no_permissions_denied() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "assets:write"),
            Err(ApiError::Forbidden)
        ));
    }
}
