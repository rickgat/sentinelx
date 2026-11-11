//! Chaos engineering admin controllers (P2-012).
//!
//! Two endpoints:
//!
//! * `GET  /v1/chaos/config` — snapshot the current chaos configuration.
//!   Requires the `admin:users` permission (operator-level only).
//! * `PUT  /v1/chaos/config` — replace the chaos configuration. Requires
//!   the same admin permission AND is hard-refused when `APP_ENV=production`
//!   by the underlying [`sx_chaos::admin::ChaosAdminService`]. Every PUT
//!   emits an audit record via the configured sink.
//!
//! The chaos registry itself is also consulted on every request by the
//! HTTP chaos middleware applied at the outer layer of
//! [`crate::router::build_router`].

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_chaos::{ChaosConfig, ChaosError};
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;

/// `GET /v1/chaos/config`
pub async fn get_config(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:users")?;
    let cfg = state.chaos_admin.get();
    Ok((StatusCode::OK, Json(ApiResponse::ok(cfg))))
}

/// `PUT /v1/chaos/config`
pub async fn put_config(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<ChaosConfig>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:users")?;
    let applied = state
        .chaos_admin
        .put(&user.claims.tenant_id, &user.claims.sub, body)
        .await
        .map_err(map_chaos)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(applied))))
}

/// Translate a [`ChaosError`] to an [`ApiError`].
fn map_chaos(err: ChaosError) -> ApiError {
    match err {
        // Production refusal is a 403 — the caller has the permission
        // but the deployment environment forbids the action.
        ChaosError::ProductionRefused { .. } => ApiError::Forbidden,
        // Out-of-range fractions are user input validation failures.
        ChaosError::InvalidFraction { .. } => ApiError::Unprocessable(err.to_string()),
    }
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper in [`crate::controller::rba`] — kept local so this
/// module has no compile dependency on a sibling controller.
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
    fn chaos_put_requires_admin_users_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "admin:users"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn admin_users_permission_allows_chaos_put() {
        let u = user(vec!["admin:users"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn admin_wildcard_allows_chaos_put() {
        let u = user(vec!["admin:*"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn map_chaos_production_refused_is_forbidden() {
        let err = ChaosError::ProductionRefused {
            env: "production".into(),
        };
        assert!(matches!(map_chaos(err), ApiError::Forbidden));
    }

    #[test]
    fn map_chaos_invalid_fraction_is_unprocessable() {
        let err = ChaosError::InvalidFraction {
            kind: "latency",
            fraction: 1.5,
        };
        assert!(matches!(map_chaos(err), ApiError::Unprocessable(_)));
    }
}
