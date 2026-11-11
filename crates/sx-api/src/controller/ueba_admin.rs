//! UEBA admin controllers — freeze-baseline mode (HIGH-010).
//!
//! Three endpoints, all gated on the `admin:users` permission via the
//! per-controller [`require_permission`] helper (there is no global
//! router-level policy on `/v1/admin/*`; each handler enforces its own
//! documented permission):
//!
//! * `POST /v1/admin/ueba/baseline/{user_id}/freeze`   — engage Frozen mode
//! * `POST /v1/admin/ueba/baseline/{user_id}/unfreeze` — run drift detector + Active
//! * `GET  /v1/admin/ueba/baseline/{user_id}/snapshot` — current state + snapshot
//!
//! Every endpoint derives `tenant_id` from the authenticated user's JWT
//! claims — the URL only carries `user_id`. The caller's `email` becomes
//! the audit `actor` so every freeze / unfreeze is attributable.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_ueba_admin;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::ueba_admin_view::{BaselineStateView, FreezeRequest};

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

/// `POST /v1/admin/ueba/baseline/{user_id}/freeze` — capture a snapshot
/// of the user's current baseline and gate subsequent writes.
pub async fn freeze(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
    Json(req): Json<FreezeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:users`.
    require_permission(&user, "admin:users")?;
    let view: BaselineStateView = state
        .ueba_admin
        .freeze(
            &user.claims.tenant_id,
            &user_id,
            Some(user.claims.sub.as_str()),
            req.reason.as_deref(),
        )
        .await
        .map_err(map_ueba_admin)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(view))))
}

/// `POST /v1/admin/ueba/baseline/{user_id}/unfreeze` — release the freeze.
///
/// Runs drift detection, returns to Active. Drift findings are routed to
/// SOC in-process; the HTTP response reports only the new state.
pub async fn unfreeze(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
    Json(req): Json<FreezeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:users`.
    require_permission(&user, "admin:users")?;
    let view: BaselineStateView = state
        .ueba_admin
        .unfreeze(
            &user.claims.tenant_id,
            &user_id,
            Some(user.claims.sub.as_str()),
            req.reason.as_deref(),
        )
        .await
        .map_err(map_ueba_admin)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(view))))
}

/// `GET /v1/admin/ueba/baseline/{user_id}/snapshot` — report the current
/// state + (if Frozen) the captured snapshot.
pub async fn snapshot(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:users`.
    require_permission(&user, "admin:users")?;
    let view: BaselineStateView = state
        .ueba_admin
        .snapshot(&user.claims.tenant_id, &user_id)
        .await
        .map_err(map_ueba_admin)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(view))))
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
        assert!(require_permission(&user(vec!["admin:users"]), "admin:users").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["admin:*"]), "admin:users").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "admin:users").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["ueba:read"]), "admin:users").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }
}
