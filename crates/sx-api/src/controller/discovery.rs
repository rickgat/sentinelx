use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use sx_iam::domain::Permission;
use validator::Validate;

use crate::controller::map_discovery;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;

/// Discovery-run request body.
#[derive(Debug, Deserialize, Validate)]
pub struct RunDiscoveryRequest {
    /// Engagement uuid.
    #[validate(length(min = 1))]
    pub engagement_id: String,
}

/// Discovery-run response body.
#[derive(Debug, Clone, Serialize)]
pub struct RunDiscoveryView {
    /// Run uuid.
    pub run_id: String,
    /// Engagement uuid.
    pub engagement_id: String,
}

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

/// `POST /v1/discovery/runs`
pub async fn run(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<RunDiscoveryRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `discovery:write`.
    require_permission(&user, "discovery:write")?;
    let run_id = state
        .discovery
        .run(&user.claims.tenant_id, &req.engagement_id)
        .await
        .map_err(map_discovery)?;
    let view = RunDiscoveryView {
        run_id,
        engagement_id: req.engagement_id,
    };
    Ok((StatusCode::ACCEPTED, Json(ApiResponse::ok(view))))
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
        assert!(require_permission(&user(vec!["discovery:write"]), "discovery:write").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["discovery:*"]), "discovery:write").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "discovery:write").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "discovery:write").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }
}
