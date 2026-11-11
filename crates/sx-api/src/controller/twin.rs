//! Cyber-digital-twin controller — `GET /v1/twin/engagement/{id}`.
//!
//! Thin façade over [`crate::port::TwinPort`]. The HTTP layer is the
//! perimeter that enforces:
//!
//! 1. RBAC — caller must hold `twin:read` (wildcards honoured).
//! 2. Tenant scope — the tenant uuid is resolved from the bearer token,
//!    never read off the URL or body.
//!
//! The handler returns the current twin snapshot (assets, edges, and
//! the set of currently-compromised asset ids) for the requested
//! engagement. An unseeded engagement returns an **empty**
//! [`crate::view::twin_view::TwinStateView`] — the endpoint is read-only
//! and is allowed to be called before any BAS / discovery run has
//! populated the twin.

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;

/// `GET /v1/twin/engagement/{engagement_id}`
pub async fn get_twin(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Path(engagement_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "twin:read")?;
    let view = state
        .twin
        .get(&scope.tenant_id, &engagement_id)
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
    fn get_twin_requires_twin_read_permission() {
        // Caller has an unrelated permission — must be rejected as
        // forbidden before any state is touched.
        let u = user(vec!["finding:read"]);
        assert!(matches!(
            require_permission(&u, "twin:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_twin_read_permission_allowed() {
        let u = user(vec!["twin:read"]);
        assert!(require_permission(&u, "twin:read").is_ok());
    }

    #[test]
    fn wildcard_action_allowed_for_twin_resource() {
        let u = user(vec!["twin:*"]);
        assert!(require_permission(&u, "twin:read").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = user(vec!["*:read"]);
        assert!(require_permission(&u, "twin:read").is_ok());
    }

    #[test]
    fn empty_permissions_are_forbidden() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "twin:read"),
            Err(ApiError::Forbidden)
        ));
    }
}
