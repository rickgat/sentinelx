//! AI Copilot controller — `POST /v1/copilot/chat`.
//!
//! Thin wrapper over the [`crate::port::CopilotPort`]. The wire-layer
//! validator has already rejected empty / oversized prompts by the time
//! the handler runs; the only work left at the HTTP boundary is the
//! permission gate and translating the port error.
//!
//! ## Permission model
//!
//! Callers MUST hold the `copilot:use` permission (or a wildcard that
//! covers it). The permission constant is brand-new — operators who want
//! analyst seats to talk to the Copilot grant it explicitly.
//!
//! ## Logging posture
//!
//! Neither the prompt nor the reply is logged. The handler emits a single
//! structured event carrying the prompt length and (on success) the reply
//! length plus the model id. Bodies stay off the wire-log.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;
use tracing::debug;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::copilot_view::CopilotChatRequest;
use crate::view::envelope::ApiResponse;

/// `POST /v1/copilot/chat` — forward a single-turn prompt to the AI Copilot.
///
/// Requires the `copilot:use` permission.
pub async fn chat(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CopilotChatRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "copilot:use")?;

    let prompt_len = req.prompt.len();
    debug!(
        target: "sx_api::copilot",
        prompt_len,
        "copilot chat request received",
    );

    let resp = state
        .copilot
        .chat(&user.claims.tenant_id, &user.claims.sub, &req.prompt)
        .await
        .map_err(map_phase3)?;

    debug!(
        target: "sx_api::copilot",
        reply_len = resp.reply.len(),
        model = %resp.model,
        "copilot chat response produced",
    );

    Ok(Json(ApiResponse::ok(resp)))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Duplicated across controllers (rather than centralised in a helper
/// module) because the project convention is to keep each controller's
/// permission decisions self-contained — see e.g.
/// [`crate::controller::redteam::require_permission`].
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
    fn missing_permission_is_forbidden() {
        let u = user(vec!["finding:read"]);
        assert!(matches!(
            require_permission(&u, "copilot:use"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_permission_allowed() {
        let u = user(vec!["copilot:use"]);
        assert!(require_permission(&u, "copilot:use").is_ok());
    }

    #[test]
    fn wildcard_action_allowed() {
        let u = user(vec!["copilot:*"]);
        assert!(require_permission(&u, "copilot:use").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = user(vec!["*:use"]);
        assert!(require_permission(&u, "copilot:use").is_ok());
    }

    #[test]
    fn full_wildcard_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "copilot:use").is_ok());
    }
}
