//! Kill-switch controller — admin-only.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use sx_iam::domain::Permission;
use validator::Validate;

use crate::controller::map_engagement;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::KillSwitchTrigger;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;

/// Kill-switch trigger request body.
#[derive(Debug, Deserialize, Validate)]
pub struct KillSwitchView {
    /// Operator-supplied reason. Required, max 1k characters.
    #[validate(length(min = 1, max = 1_000))]
    pub reason: String,
}

/// Kill-switch state response.
#[derive(Debug, Clone, Serialize)]
pub struct KillSwitchStateView {
    /// `true` when the switch is currently engaged.
    pub tripped: bool,
}

/// `POST /v1/safety/kill-switch`
pub async fn trip(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<KillSwitchView>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&user)?;
    let trigger = KillSwitchTrigger {
        actor: user.claims.sub.clone(),
        reason: req.reason,
    };
    state
        .kill_switch
        .trip(trigger)
        .await
        .map_err(map_engagement)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(ApiResponse::ok(KillSwitchStateView { tripped: true })),
    ))
}

fn require_admin(user: &AuthenticatedUser) -> Result<(), ApiError> {
    let Ok(required) = Permission::parse("safety:trip") else {
        return Err(ApiError::Internal("invalid permission constant".into()));
    };
    let allowed = user.claims.permissions.iter().any(|p| {
        // Exact match or wildcard on either half.
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

    fn claims(perms: Vec<&str>) -> AuthenticatedUser {
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
    fn admin_required_for_kill_switch() {
        let no_perm = claims(vec!["engagement:read"]);
        assert!(matches!(require_admin(&no_perm), Err(ApiError::Forbidden)));
    }

    #[test]
    fn admin_with_exact_permission_allowed() {
        let ok = claims(vec!["safety:trip"]);
        assert!(require_admin(&ok).is_ok());
    }

    #[test]
    fn admin_with_wildcard_action_allowed() {
        let ok = claims(vec!["safety:*"]);
        assert!(require_admin(&ok).is_ok());
    }

    #[test]
    fn admin_with_wildcard_resource_allowed() {
        let ok = claims(vec!["*:trip"]);
        assert!(require_admin(&ok).is_ok());
    }
}
