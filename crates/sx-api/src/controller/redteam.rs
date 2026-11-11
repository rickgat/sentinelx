//! AI Red Team controller — `POST /v1/redteam/chain`.
//!
//! The HTTP surface validates the request body (non-empty engagement id,
//! `max_steps` in `1..=14`) and enforces the `redteam:compose` permission
//! before dispatching to the underlying [`crate::port::RedteamPort`]. All
//! business logic — engagement lookup, scope-to-`TargetSpec` derivation,
//! chain composition, projection — lives in the adapter.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::redteam_view::RedteamComposeRequest;

/// `POST /v1/redteam/chain` — compose an AI Red Team kill chain for the
/// supplied engagement.
///
/// Requires the `redteam:compose` permission. The caller's tenant id is
/// resolved from the bearer token and forwarded to the port; the adapter
/// MUST refuse cross-tenant lookups.
pub async fn compose(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<RedteamComposeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "redteam:compose")?;
    let view = state
        .redteam
        .compose(&user.claims.tenant_id, req)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(view)))
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
            require_permission(&u, "redteam:compose"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_permission_allowed() {
        let u = user(vec!["redteam:compose"]);
        assert!(require_permission(&u, "redteam:compose").is_ok());
    }

    #[test]
    fn wildcard_action_allowed() {
        let u = user(vec!["redteam:*"]);
        assert!(require_permission(&u, "redteam:compose").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = user(vec!["*:compose"]);
        assert!(require_permission(&u, "redteam:compose").is_ok());
    }

    #[test]
    fn full_wildcard_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "redteam:compose").is_ok());
    }
}
