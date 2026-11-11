use axum::extract::{Path, State};
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_risk;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::risk_view::{
    CalculateEngagementRiskRequest, CalculateRiskRequest, CalculateRiskView,
    EngagementRiskBreakdownView,
};

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

/// `POST /v1/risk/calculate`
pub async fn calculate(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CalculateRiskRequest>,
) -> Result<Json<ApiResponse<CalculateRiskView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `risk:read`.
    require_permission(&user, "risk:read")?;
    let v = state.risk.calculate(req).await.map_err(map_risk)?;
    Ok(Json(ApiResponse::ok(v)))
}

/// `POST /v1/risk/engagement/{engagement_id}`
///
/// Aggregate composite risk across every CVE-linked finding in the
/// authenticated tenant's scope. The aggregate is bounded to the
/// engagement carried in the URL path.
pub async fn calculate_for_engagement(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(engagement_id): Path<String>,
    ValidatedJson(req): ValidatedJson<CalculateEngagementRiskRequest>,
) -> Result<Json<ApiResponse<EngagementRiskBreakdownView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `risk:read`.
    require_permission(&user, "risk:read")?;
    let v = state
        .risk
        .calculate_engagement(&user.claims.tenant_id, &engagement_id, req)
        .await
        .map_err(map_risk)?;
    Ok(Json(ApiResponse::ok(v)))
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
        assert!(require_permission(&user(vec!["risk:read"]), "risk:read").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["risk:*"]), "risk:read").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "risk:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "risk:read").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }
}
