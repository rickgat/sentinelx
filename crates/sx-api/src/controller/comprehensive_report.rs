//! Comprehensive cross-module report controller (#3).
//!
//! `GET /v1/reports/comprehensive` — generate a single executive report
//! aggregated across the platform's modules, server-side. Requires
//! `report:read`. Tenant is derived from the caller's JWT claims.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::ComprehensiveReportPortError;
use crate::state::AppState;
use crate::view::comprehensive_report_view::ComprehensiveReportView;
use crate::view::envelope::ApiResponse;

fn map_err(err: ComprehensiveReportPortError) -> ApiError {
    match err {
        ComprehensiveReportPortError::Invalid(m) => ApiError::Unprocessable(m),
        ComprehensiveReportPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// `GET /v1/reports/comprehensive`
pub async fn get(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "report:read")?;
    let view: ComprehensiveReportView = state
        .comprehensive_report
        .generate(&user.claims.tenant_id)
        .await
        .map_err(map_err)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// Wildcard-aware permission gate (local copy, per project convention).
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
    fn requires_report_read() {
        assert!(require_permission(&user(vec!["report:read"]), "report:read").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "report:read").is_ok());
        assert!(matches!(
            require_permission(&user(vec!["finding:read"]), "report:read"),
            Err(ApiError::Forbidden)
        ));
    }
}
