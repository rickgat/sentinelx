//! Per-tenant webhook signing-key rotation admin controller (MED-003).
//!
//! One route, gated by the `admin:webhooks` permission:
//!
//! - `POST /v1/admin/webhooks/keys/rotate`
//!   * Body: [`crate::view::webhooks_admin_view::RotateWebhookKeyRequest`].
//!   * Force-rotates the per-tenant webhook HMAC signing key right
//!     now. Delegates to
//!     [`crate::port::WebhookKeyRotationAdminPort::force_rotate`]. The
//!     adapter handles persistence + audit; the controller's only job
//!     is to enforce the permission gate and pass the bearer subject
//!     claim through to the audit log.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_webhook_key_rotation;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::webhooks_admin_view::{RotateWebhookKeyRequest, RotateWebhookKeyResponse};

/// `POST /v1/admin/webhooks/keys/rotate` — force-rotate the signing key.
pub async fn rotate_webhook_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<RotateWebhookKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:webhooks")?;
    if body.tenant_id.trim().is_empty() {
        return Err(ApiError::Unprocessable("tenant_id is required".into()));
    }

    let actor = if user.claims.sub.is_empty() {
        None
    } else {
        Some(user.claims.sub.clone())
    };
    let view: RotateWebhookKeyResponse = state
        .webhook_key_rotation_admin
        .force_rotate(&body.tenant_id, actor)
        .await
        .map_err(map_webhook_key_rotation)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// Permission gate — identical helper shape to the other admin
/// controllers; kept private so each controller stays self-contained.
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
                sub: "operator@example.com".into(),
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
    fn requires_admin_webhooks_permission() {
        let u = user(vec!["audit:read"]);
        assert!(matches!(
            require_permission(&u, "admin:webhooks"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_admin_webhooks_allowed() {
        let u = user(vec!["admin:webhooks"]);
        assert!(require_permission(&u, "admin:webhooks").is_ok());
    }

    #[test]
    fn admin_wildcard_action_allowed() {
        let u = user(vec!["admin:*"]);
        assert!(require_permission(&u, "admin:webhooks").is_ok());
    }

    #[test]
    fn full_wildcard_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "admin:webhooks").is_ok());
    }

    #[test]
    fn no_permissions_denied() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "admin:webhooks"),
            Err(ApiError::Forbidden)
        ));
    }
}
