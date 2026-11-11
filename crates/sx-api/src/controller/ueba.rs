//! UEBA controllers — read-side of the User & Entity Behavioural Analytics
//! engine.
//!
//! Two endpoints:
//!
//! * `GET /v1/ueba/baselines/{user_id}` — snapshot the per-user behavioural
//!   baseline for the caller's tenant. Returns `404 Not Found` when no
//!   events have been observed yet.
//! * `GET /v1/ueba/anomalies?limit=N` — list the most recent anomalies,
//!   newest-first, capped by the engine's per-tenant ring buffer.
//!
//! Both endpoints derive the active tenant from the caller's
//! [`AuthenticatedUser`] claims so an attacker cannot ask for another
//! tenant's data via URL manipulation.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_ueba;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::ueba_view::{UebaAnomaliesQuery, UebaAnomaliesResponse, UebaBaselineView};

/// Wildcard-aware permission gate (local copy — each controller owns its
/// own so the authorization decision stays beside the handler it guards).
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

/// Default cap applied when the caller does not supply `?limit=`.
const DEFAULT_LIMIT: u32 = 100;
/// Hard ceiling so the HTTP surface never returns more than 500 rows in
/// one shot.
const MAX_LIMIT: u32 = 500;
/// Fallback `limit` used when the `u32 → usize` conversion fails. Pinned
/// to `u16::MAX` so the worst-case response is still bounded on a 16-bit
/// host even though `usize` is at least 32 bits on every platform we
/// build for.
const LIMIT_FALLBACK: usize = u16::MAX as usize;

/// `GET /v1/ueba/baselines/{user_id}` — fetch the caller-tenant baseline
/// for `user_id`. Always tenant-scoped via the caller's JWT claims.
pub async fn get_baseline(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `ueba:read`; enforce it.
    require_permission(&user, "ueba:read")?;
    let base: UebaBaselineView = state
        .ueba
        .get_baseline(&user.claims.tenant_id, &user_id)
        .await
        .map_err(map_ueba)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(base))))
}

/// `GET /v1/ueba/anomalies?limit=N` — list anomalies for the caller's
/// tenant. `limit` is clamped to `[1, MAX_LIMIT]`.
pub async fn list_anomalies(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<UebaAnomaliesQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `ueba:read`; enforce it.
    require_permission(&user, "ueba:read")?;
    let raw = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    // `raw <= MAX_LIMIT <= u16::MAX`, so the conversion is always lossless;
    // the unreachable fallback is bounded by `LIMIT_FALLBACK`.
    let limit = usize::try_from(raw).unwrap_or(LIMIT_FALLBACK);
    let rows = state
        .ueba
        .list_anomalies(&user.claims.tenant_id, limit)
        .await
        .map_err(map_ueba)?;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(UebaAnomaliesResponse { anomalies: rows })),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn limit_constants_are_sane() {
        const _: () = assert!(DEFAULT_LIMIT > 0);
        const _: () = assert!(MAX_LIMIT >= DEFAULT_LIMIT);
        const _: () = assert!(MAX_LIMIT <= 1000);
    }

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
        assert!(require_permission(&user(vec!["ueba:read"]), "ueba:read").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["ueba:*"]), "ueba:read").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "ueba:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["findings:read"]), "ueba:read").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }
}
