//! Role-administration controllers — four endpoints under
//! `/v1/admin/roles*` and `/v1/admin/users/{user_id}/roles`.
//!
//! Every handler is intentionally thin: it gates on the
//! `admin:roles` permission, forwards to the [`crate::port::RolesPort`]
//! trait object on [`crate::state::AppState`], and serialises the
//! projection.
//!
//! ## Endpoints
//!
//! | Method | Path                                       | RBAC          |
//! | ------ | ------------------------------------------ | ------------- |
//! | GET    | `/v1/admin/roles`                          | `admin:roles` |
//! | POST   | `/v1/admin/roles`                          | `admin:roles` |
//! | DELETE | `/v1/admin/roles/{role_id}`                | `admin:roles` |
//! | POST   | `/v1/admin/users/{user_id}/roles`          | `admin:roles` |
//!
//! ## Conflict handling
//!
//! The adapter signals duplicate-name (idempotency) collisions by
//! returning [`Phase3PortError::Invalid`] carrying the sentinel
//! `"role already exists"`. [`map_roles_error`] translates that into
//! HTTP `409 Conflict`; every other `Invalid` lands on `422`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::Phase3PortError;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::roles_view::{
    AssignRolesRequestView, AssignRolesResponseView, CreateRoleRequestView, ListRolesResponseView,
};

/// Sentinel string the adapter returns inside
/// [`Phase3PortError::Invalid`] to signal an idempotency collision on
/// `(tenant_id, role_name)`. Mapped into HTTP `409 Conflict` by
/// [`map_roles_error`].
pub(crate) const DUPLICATE_ROLE_MARKER: &str = "role already exists";

/// `GET /v1/admin/roles` — list roles for the caller's tenant.
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
) -> Result<Json<ApiResponse<ListRolesResponseView>>, ApiError> {
    require_permission(&user, "admin:roles")?;
    let resp = state
        .roles
        .list(&scope.tenant_id)
        .await
        .map_err(map_roles_error)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `POST /v1/admin/roles` — create a role with the supplied
/// permissions. Returns `201 Created` on success, `409 Conflict` on a
/// duplicate name.
pub async fn create(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<CreateRoleRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:roles")?;
    let resp = state
        .roles
        .create(&scope.tenant_id, req)
        .await
        .map_err(map_roles_error)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(resp))))
}

/// `DELETE /v1/admin/roles/{role_id}` — delete a role by id. Returns
/// `204 No Content` on success.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Path(role_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:roles")?;
    state
        .roles
        .delete(&scope.tenant_id, &role_id)
        .await
        .map_err(map_roles_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/admin/users/{user_id}/roles` — replace the role list bound
/// to `user_id`.
pub async fn assign(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Path(user_id): Path<String>,
    ValidatedJson(req): ValidatedJson<AssignRolesRequestView>,
) -> Result<Json<ApiResponse<AssignRolesResponseView>>, ApiError> {
    require_permission(&user, "admin:roles")?;
    let resp = state
        .roles
        .assign(&scope.tenant_id, &user_id, req)
        .await
        .map_err(map_roles_error)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// Map a `Phase3PortError` into the appropriate `ApiError`, treating
/// the adapter's idempotency sentinel as `409 Conflict` instead of
/// `422`.
fn map_roles_error(err: Phase3PortError) -> ApiError {
    match err {
        Phase3PortError::Invalid(ref msg) if msg == DUPLICATE_ROLE_MARKER => {
            ApiError::Conflict(DUPLICATE_ROLE_MARKER.to_owned())
        }
        other => map_phase3(other),
    }
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper used by [`crate::controller::admin`] +
/// [`crate::controller::bas`] — kept private here so the role-admin
/// surface owns its own check rather than relying on a cross-module
/// import.
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

    /// Build a synthetic [`AuthenticatedUser`] carrying the supplied
    /// permission tokens.
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
    fn list_requires_admin_roles_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "admin:roles"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn create_requires_admin_roles_permission() {
        let u = user(vec!["admin:users"]);
        assert!(matches!(
            require_permission(&u, "admin:roles"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn delete_requires_admin_roles_permission() {
        let u = user(vec!["assets:read"]);
        assert!(matches!(
            require_permission(&u, "admin:roles"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn assign_requires_admin_roles_permission() {
        let u = user(vec!["engagements:read"]);
        assert!(matches!(
            require_permission(&u, "admin:roles"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_admin_roles_permission_allowed() {
        let u = user(vec!["admin:roles"]);
        assert!(require_permission(&u, "admin:roles").is_ok());
    }

    #[test]
    fn admin_wildcard_grants_roles_permission() {
        let u = user(vec!["admin:*"]);
        assert!(require_permission(&u, "admin:roles").is_ok());
    }

    #[test]
    fn full_wildcard_grants_roles_permission() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "admin:roles").is_ok());
    }

    #[test]
    fn duplicate_marker_maps_to_conflict() {
        let err = map_roles_error(Phase3PortError::Invalid(DUPLICATE_ROLE_MARKER.into()));
        assert!(
            matches!(err, ApiError::Conflict(ref m) if m == DUPLICATE_ROLE_MARKER),
            "expected Conflict, got {err:?}"
        );
    }

    #[test]
    fn other_invalid_maps_to_unprocessable() {
        let err = map_roles_error(Phase3PortError::Invalid("bad role name".into()));
        assert!(
            matches!(err, ApiError::Unprocessable(_)),
            "expected Unprocessable, got {err:?}"
        );
    }

    #[test]
    fn not_found_maps_to_not_found() {
        let err = map_roles_error(Phase3PortError::NotFound);
        assert!(
            matches!(err, ApiError::NotFound),
            "expected NotFound, got {err:?}"
        );
    }
}
