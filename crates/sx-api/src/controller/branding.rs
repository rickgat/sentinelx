//! Per-tenant report branding controllers (P2-002 MSSP white-label).
//!
//! * `GET  /v1/reports/branding` — read the caller tenant's branding.
//! * `PUT  /v1/reports/branding` — set it (logo, colour, cover/footer).
//!
//! Both derive the tenant from the caller's JWT claims; there is no path
//! parameter, so one tenant can never read or overwrite another's brand.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_branding;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::branding_view::{BrandingView, SetBrandingRequest};
use crate::view::envelope::ApiResponse;

/// `GET /v1/reports/branding` — current branding for the caller's tenant.
///
/// Requires the `report:read` permission.
pub async fn get(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "report:read")?;
    let view: BrandingView = state
        .branding
        .get(&user.claims.tenant_id)
        .await
        .map_err(map_branding)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// `PUT /v1/reports/branding` — replace the caller tenant's branding.
///
/// Requires the `report:write` permission.
pub async fn put(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<SetBrandingRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "report:write")?;
    let view: BrandingView = state
        .branding
        .set(&user.claims.tenant_id, &user.claims.sub, req)
        .await
        .map_err(map_branding)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// Wildcard-aware permission gate (local copy — the project keeps each
/// controller's authorization decision beside the handler it guards).
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
    fn read_requires_report_read() {
        assert!(require_permission(&user(vec!["report:read"]), "report:read").is_ok());
        assert!(require_permission(&user(vec!["report:*"]), "report:read").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "report:read").is_ok());
        assert!(matches!(
            require_permission(&user(vec!["finding:read"]), "report:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn write_requires_report_write() {
        assert!(require_permission(&user(vec!["report:write"]), "report:write").is_ok());
        assert!(matches!(
            require_permission(&user(vec!["report:read"]), "report:write"),
            Err(ApiError::Forbidden)
        ));
    }
}
