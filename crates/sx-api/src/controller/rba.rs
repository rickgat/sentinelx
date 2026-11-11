//! Risk-Based Authentication controllers.
//!
//! Three endpoints:
//!
//! * `GET  /v1/rba/decisions?limit=N` — list the most recent decisions
//!   for the caller's tenant. Returns rows newest-first, capped by the
//!   engine's per-tenant ring capacity.
//! * `GET  /v1/rba/config` — fetch the effective configuration for the
//!   caller's tenant (defaults applied if no custom config exists).
//! * `PUT  /v1/rba/config` — replace the configuration. Gated on the
//!   `admin:users` permission so a regular operator cannot relax the
//!   thresholds.
//!
//! All three endpoints derive the active tenant from the caller's
//! [`AuthenticatedUser`] claims so an attacker cannot ask for another
//! tenant's audit trail by URL manipulation.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_rba;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::rba_view::{RbaConfigView, RbaDecisionsQuery, RbaDecisionsResponse};

/// Default limit applied when the caller does not supply one.
const DEFAULT_LIMIT: u32 = 100;
/// Hard upper bound on the per-request limit. Mirrors
/// `sx_rba::service::MAX_DECISIONS_PER_REQUEST` so the API surface
/// cannot exceed what the engine ring buffer can serve.
const MAX_LIMIT: u32 = 500;

/// `GET /v1/rba/decisions?limit=N`
///
/// LOW-007: when the caller holds `admin:users` the response rows
/// include the per-signal sub-score / weight / weighted contribution
/// breakdown (`signals` field). Regular operators get the legacy 8-key
/// shape — `signals` is omitted entirely via
/// `#[serde(skip_serializing_if = "Option::is_none")]`, preserving
/// back-compat with pre-LOW-007 dashboard consumers.
pub async fn list_decisions(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<RbaDecisionsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let include_signals = has_permission(&user, "admin:users");
    let rows = state
        .rba
        .list_decisions(&user.claims.tenant_id, limit, include_signals)
        .await
        .map_err(map_rba)?;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(RbaDecisionsResponse { decisions: rows })),
    ))
}

/// `GET /v1/rba/config`
pub async fn get_config(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `rba:read`.
    require_permission(&user, "rba:read")?;
    let cfg = state
        .rba
        .get_config(&user.claims.tenant_id)
        .await
        .map_err(map_rba)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(cfg))))
}

/// `PUT /v1/rba/config` — gated on `admin:users`.
pub async fn put_config(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<RbaConfigView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:users")?;
    let cfg = state
        .rba
        .put_config(&user.claims.tenant_id, req)
        .await
        .map_err(map_rba)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(cfg))))
}

/// `GET /v1/rba/users/{user_id}/devices` — list known device fingerprints for a user.
///
/// Within the caller's tenant. Gated on `admin:users` since enumerating
/// a user's device inventory is an admin-only operation.
pub async fn list_known_devices(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:users")?;
    let resp = state
        .rba
        .list_known_devices(&user.claims.tenant_id, &user_id)
        .await
        .map_err(map_rba)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `DELETE /v1/rba/users/{user_id}/devices/{fp_hash}` — revoke a
/// single device fingerprint. Gated on `admin:users`. Idempotent —
/// revoking a previously-revoked fingerprint returns 204.
pub async fn revoke_known_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, fp_hash)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:users")?;
    state
        .rba
        .revoke_known_device(&user.claims.tenant_id, &user_id, &fp_hash)
        .await
        .map_err(map_rba)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Same shape as the admin/roles controllers — duplicated here so the
/// permission check stays explicit at the call site and so this module
/// has no compile dependency on `admin.rs`.
fn require_permission(user: &AuthenticatedUser, perm: &str) -> Result<(), ApiError> {
    if has_permission(user, perm) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Predicate form of [`require_permission`]. Returns `true` iff `user`
/// carries `perm` (with the same wildcard semantics).
///
/// Used by LOW-007 to *gate the response shape* rather than reject the
/// request — `list_decisions` is always accessible, but the
/// signal-by-signal breakdown is only attached for admins.
fn has_permission(user: &AuthenticatedUser, perm: &str) -> bool {
    let Ok(required) = Permission::parse(perm) else {
        return false;
    };
    user.claims.permissions.iter().any(|p| {
        let r = p.resource() == required.resource() || p.resource() == "*";
        let a = p.action() == required.action() || p.action() == "*";
        r && a
    })
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
    fn put_config_requires_admin_users_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "admin:users"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn admin_users_permission_allows_put_config() {
        let u = user(vec!["admin:users"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn admin_wildcard_allows_put_config() {
        let u = user(vec!["admin:*"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn full_wildcard_allows_put_config() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn has_permission_returns_false_without_admin_users() {
        // LOW-007 capability gate: a non-admin caller asking for
        // /v1/rba/decisions still gets the list, but the signal
        // breakdown is suppressed by the controller passing
        // include_signals=false to the port. The predicate is the
        // single source of truth for that decision — pin it.
        let u = user(vec!["findings:read"]);
        assert!(!has_permission(&u, "admin:users"));
    }

    #[test]
    fn has_permission_returns_true_with_admin_users() {
        let u = user(vec!["admin:users"]);
        assert!(has_permission(&u, "admin:users"));
    }

    #[test]
    fn has_permission_honours_admin_wildcard() {
        let u = user(vec!["admin:*"]);
        assert!(has_permission(&u, "admin:users"));
    }

    #[test]
    fn has_permission_honours_full_wildcard() {
        let u = user(vec!["*:*"]);
        assert!(has_permission(&u, "admin:users"));
    }

    #[test]
    fn default_limit_constants_are_sane() {
        // Compile-time checked relationships — these assertions are
        // intentionally `const` so the resulting test acts purely as a
        // doc + tripwire if someone changes the constants out of band.
        const _: () = assert!(DEFAULT_LIMIT > 0);
        const _: () = assert!(MAX_LIMIT >= DEFAULT_LIMIT);
        const _: () = assert!(MAX_LIMIT <= 1000);
    }
}
