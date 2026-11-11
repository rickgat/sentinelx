//! Out-of-band collaborator controllers.
//!
//! `POST /v1/collab/tokens` allocates a fresh token bound to a
//! `(tenant_id, finding_id)` pair; `GET /v1/collab/tokens/{token}/callbacks`
//! returns every callback recorded against the token across the DNS / HTTP /
//! SMTP receivers.
//!
//! Token format is enforced at the HTTP boundary: lookups must address a
//! 16-character lowercase-hex token. Malformed tokens return 400 without
//! reaching the adapter.

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::collab_view::CollabAllocateTokenRequestView;
use crate::view::envelope::ApiResponse;

/// Canonical token length (16 lowercase-hex characters).
const TOKEN_HEX_LEN: usize = 16;

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

/// `POST /v1/collab/tokens`
///
/// Allocates a fresh out-of-band token bound to the supplied
/// `(tenant_id, finding_id)` pair and returns the canonical wire form.
pub async fn allocate(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CollabAllocateTokenRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    // Newly specified (SEC-AUTHZ-001): minting an out-of-band collaboration
    // token is a sensitive mutation, so it is gated on `collab:write`
    // (documented in OpenAPI alongside this change).
    require_permission(&user, "collab:write")?;
    let resp = state.collab_alloc.allocate(req).await.map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `GET /v1/collab/tokens/{token}/callbacks`
///
/// Returns every recorded callback for `token`. The token must be a
/// 16-character lowercase-hex string; anything else is rejected as
/// `400 Bad Request` before the adapter is touched.
pub async fn lookup(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    validate_token_format(&token)?;
    let resp = state
        .collab_lookup
        .lookup(&token)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// Validate that `token` matches the canonical 16-hex-character form.
///
/// We re-implement the predicate inline rather than depend on
/// `sx_collab::model::Token::parse` so the API crate need not import the
/// concrete token type.
fn validate_token_format(token: &str) -> Result<(), ApiError> {
    if token.len() != TOKEN_HEX_LEN {
        return Err(ApiError::BadRequest(format!(
            "token must be {TOKEN_HEX_LEN} hex chars",
        )));
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    {
        return Err(ApiError::BadRequest(
            "token must be lowercase hex".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        require_permission, validate_token_format, AuthenticatedUser, Permission, TOKEN_HEX_LEN,
    };
    use crate::error::ApiError;

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
        assert!(require_permission(&user(vec!["collab:write"]), "collab:write").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["collab:*"]), "collab:write").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "collab:write").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "collab:write").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn lookup_returns_400_on_malformed_token() {
        // Too short.
        assert!(matches!(
            validate_token_format("abc"),
            Err(ApiError::BadRequest(_))
        ));
        // Too long.
        let too_long = "0".repeat(TOKEN_HEX_LEN + 1);
        assert!(matches!(
            validate_token_format(&too_long),
            Err(ApiError::BadRequest(_))
        ));
        // Non-hex characters.
        assert!(matches!(
            validate_token_format("zzzz567890abcdef"),
            Err(ApiError::BadRequest(_))
        ));
        // Uppercase hex is rejected — the canonical form is lowercase.
        assert!(matches!(
            validate_token_format("0123456789ABCDEF"),
            Err(ApiError::BadRequest(_))
        ));
        // The well-formed token passes.
        assert!(validate_token_format("0123456789abcdef").is_ok());
    }
}
