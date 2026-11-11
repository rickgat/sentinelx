//! Predictive finding-risk controller — `POST /v1/ml/predict/finding`.
//!
//! Thin façade over [`crate::port::PredictivePort`]. The HTTP layer is the
//! perimeter that enforces:
//!
//! 1. RBAC — caller must hold `ml:predict` (wildcards honoured).
//! 2. Schema — `finding_id` is validated as non-empty via
//!    `validator::Validate` on [`PredictRequest`].
//!
//! The adapter inside `sx-monolith` is responsible for the stronger
//! tenant-boundary check (the request is implicitly scoped to the bearer
//! token's `tenant_id` claim) and for projecting the resolved finding +
//! asset into the model's `FindingFeatures` shape.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::predictive_view::PredictRequest;

/// `POST /v1/ml/predict/finding`
pub async fn predict(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<PredictRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "ml:predict")?;
    let resp = state
        .predictive
        .predict(&scope.tenant_id, &req.finding_id)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
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
    fn predict_requires_ml_predict_permission() {
        let u = user(vec!["finding:read"]);
        assert!(matches!(
            require_permission(&u, "ml:predict"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_ml_predict_permission_allowed() {
        let u = user(vec!["ml:predict"]);
        assert!(require_permission(&u, "ml:predict").is_ok());
    }

    #[test]
    fn wildcard_action_allowed_for_ml_resource() {
        let u = user(vec!["ml:*"]);
        assert!(require_permission(&u, "ml:predict").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = user(vec!["*:predict"]);
        assert!(require_permission(&u, "ml:predict").is_ok());
    }

    #[test]
    fn full_wildcard_grant_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "ml:predict").is_ok());
    }
}
