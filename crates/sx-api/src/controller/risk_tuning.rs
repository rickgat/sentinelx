//! Per-tenant risk-model tuning controller (P1-014).
//!
//! Three endpoints, all tenant-scoped via the bearer:
//!
//! - `GET  /v1/risk/config`            — fetch the sparse override (or
//!   the platform defaults projected through [`TenantRiskConfigView`]
//!   when no row exists).
//! - `PUT  /v1/risk/config`            — replace the sparse override.
//!   Admin RBAC (`risk:tune`) enforced; audit + idempotent recompute
//!   are emitted by the service layer.
//! - `GET  /v1/risk/config/effective`  — fetch the merged effective
//!   config (defaults ⊕ override) the scorer is using right now.
//!
//! ## RBAC
//!
//! The PUT endpoint requires the `risk:tune` permission (wildcard on
//! resource or action also accepted). Reads stay open to any
//! authenticated user in the tenant — there is no sensitive secret
//! material on the wire, just numeric vectors.
//!
//! ## Bearer hygiene
//!
//! The controller never forwards the raw `Authorization` header into
//! the audit pipeline. The bearer-less sub-claim (`AccessClaims::sub`)
//! is propagated to the service as the `actor` so the audit row carries
//! "who" without ever touching the JWT itself. The audit sink also
//! debug-asserts no `Bearer ` substring leaks into the diff.

use axum::extract::State;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_risk_tuning;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::risk_tuning_view::{EffectiveRiskConfigView, TenantRiskConfigView};

/// `GET /v1/risk/config` — return the sparse per-tenant override row.
///
/// When no override has been written for the tenant, the response is
/// the empty view (`{}` on the wire — every field omitted). The client
/// is expected to call `/v1/risk/config/effective` when it needs the
/// merged result.
pub async fn get_config(
    State(state): State<AppState>,
    scope: TenantScope,
) -> Result<Json<ApiResponse<TenantRiskConfigView>>, ApiError> {
    let v = state
        .risk_tuning
        .get_override(&scope.tenant_id)
        .await
        .map_err(map_risk_tuning)?;
    Ok(Json(ApiResponse::ok(v)))
}

/// `PUT /v1/risk/config` — replace the sparse per-tenant override row.
///
/// Admin RBAC: `risk:tune` (wildcard accepted on either half). The
/// service layer records the audit diff and enqueues an idempotent
/// finding-recompute on success.
pub async fn put_config(
    State(state): State<AppState>,
    scope: TenantScope,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<TenantRiskConfigView>,
) -> Result<Json<ApiResponse<EffectiveRiskConfigView>>, ApiError> {
    require_risk_tune(&user)?;
    // Pass the bearer-less sub-claim as the audit actor — never the
    // raw JWT. The audit sink double-checks the diff for any `Bearer`
    // substring at debug-assert time.
    let actor = Some(user.claims.sub.clone());
    let v = state
        .risk_tuning
        .put_override(&scope.tenant_id, actor, req)
        .await
        .map_err(map_risk_tuning)?;
    Ok(Json(ApiResponse::ok(v)))
}

/// `GET /v1/risk/config/effective` — return the merged config (defaults
/// ⊕ stored override) the scorer would consume for the caller's tenant.
pub async fn get_effective(
    State(state): State<AppState>,
    scope: TenantScope,
) -> Result<Json<ApiResponse<EffectiveRiskConfigView>>, ApiError> {
    let v = state
        .risk_tuning
        .get_effective(&scope.tenant_id)
        .await
        .map_err(map_risk_tuning)?;
    Ok(Json(ApiResponse::ok(v)))
}

/// Admin gate for the PUT endpoint. Matches the
/// `require_admin`-pattern used by every other admin-only controller
/// (e.g. `killswitch`) so the audit + permissions story stays uniform.
fn require_risk_tune(user: &AuthenticatedUser) -> Result<(), ApiError> {
    let Ok(required) = Permission::parse("risk:tune") else {
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

    fn claims(perms: Vec<&str>) -> AuthenticatedUser {
        AuthenticatedUser {
            claims: AccessClaims {
                sub: "alice".into(),
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
    fn no_perm_is_forbidden() {
        let u = claims(vec!["engagement:read"]);
        assert!(matches!(require_risk_tune(&u), Err(ApiError::Forbidden)));
    }

    #[test]
    fn exact_perm_allowed() {
        let u = claims(vec!["risk:tune"]);
        assert!(require_risk_tune(&u).is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = claims(vec!["*:tune"]);
        assert!(require_risk_tune(&u).is_ok());
    }

    #[test]
    fn wildcard_action_allowed() {
        let u = claims(vec!["risk:*"]);
        assert!(require_risk_tune(&u).is_ok());
    }

    #[test]
    fn double_wildcard_allowed() {
        let u = claims(vec!["*:*"]);
        assert!(require_risk_tune(&u).is_ok());
    }

    #[test]
    fn empty_perms_forbidden() {
        let u = claims(vec![]);
        assert!(matches!(require_risk_tune(&u), Err(ApiError::Forbidden)));
    }
}
