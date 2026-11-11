//! Asset bulk-import controller — `POST /v1/assets/bulk-import`.
//!
//! Accepts either a JSON array or a CSV body (with the canonical header
//! `engagement_id,kind,identifier,source`) and persists each row through
//! the [`crate::port::AssetBulkImportPort`] trait object held by
//! [`AppState`]. The handler:
//!
//! 1. Pulls the caller's [`AuthenticatedUser`] and [`TenantScope`] from
//!    the request extensions populated by the auth middleware.
//! 2. Enforces the `assets:write` RBAC permission via
//!    [`require_permission`] — wildcards (`assets:*`, `*:write`, `*:*`)
//!    are honoured.
//! 3. Delegates the parse + dispatch to the
//!    [`crate::port::AssetBulkImportPort`] trait object.
//! 4. Translates port errors via [`crate::controller::map_phase3`].
//!
//! Wire shape:
//!
//! - `POST /v1/assets/bulk-import` -> `200 OK` + `BulkImportResponse`.

use axum::extract::State;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::asset_view::{BulkImportRequest, BulkImportResponse};
use crate::view::envelope::ApiResponse;

/// `POST /v1/assets/bulk-import` — parse the payload and bulk-create
/// assets under the caller's tenant.
///
/// Returns `200 OK` carrying the per-row outcome breakdown on success.
pub async fn import(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<BulkImportRequest>,
) -> Result<Json<ApiResponse<BulkImportResponse>>, ApiError> {
    require_permission(&user, "assets:write")?;
    let resp = state
        .asset_bulk
        .import(&scope.tenant_id, req)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper used by [`crate::controller::assets`] —
/// kept local so the controller stays self-contained.
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
    fn import_requires_assets_write_permission() {
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
