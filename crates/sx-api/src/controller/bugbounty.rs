//! Bug-bounty bridge controllers — `/v1/integrations/bugbounty/*` (P3-010).
//!
//! Four endpoints back the dashboard + the platform-driven webhook:
//!
//! | Method | Path                                                | Auth          |
//! | ------ | --------------------------------------------------- | ------------- |
//! | POST   | `/v1/integrations/bugbounty/configs`                | `admin:users` |
//! | GET    | `/v1/integrations/bugbounty/configs`                | (authn)       |
//! | POST   | `/v1/integrations/bugbounty/push`                   | (authn)       |
//! | POST   | `/v1/integrations/bugbounty/inbound/{platform}`     | HMAC          |
//!
//! Inbound is intentionally *unauthenticated* via JWT — the platform
//! authenticates itself by signing the request body with the
//! per-tenant per-platform HMAC secret. The controller reads the raw
//! body bytes, hands them + the platform-supplied signature header to
//! the port, and the port runs the constant-time compare. A missing
//! tenant query parameter is a 400 because the platform's webhook
//! configuration always carries the `tenant_id` query string —
//! a delivery without it is structurally malformed.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::BugBountyPortError;
use crate::state::AppState;
use crate::view::bugbounty_view::{
    BugBountyConfigUpsertRequest, BugBountyConfigView, BugBountyInboundOutcomeView,
    BugBountyPushOutcomeView, BugBountyPushRequest,
};
use crate::view::envelope::ApiResponse;

/// Translate the port-level error into the HTTP envelope.
///
/// Rate limits collapse onto 503 because by the time the dispatcher
/// gives up the retry budget is already exhausted — the client never
/// sees the raw `429` from the vendor.
pub fn map_bugbounty(err: BugBountyPortError) -> ApiError {
    match err {
        BugBountyPortError::NotFound => ApiError::NotFound,
        BugBountyPortError::Invalid(m) => ApiError::Unprocessable(m),
        BugBountyPortError::Unauthorized => ApiError::Unauthorized,
        BugBountyPortError::RateLimited | BugBountyPortError::Dependency(_) => {
            ApiError::Dependency("bug-bounty upstream unavailable".to_owned())
        }
        BugBountyPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Query parameters for the inbound webhook endpoint. The platform's
/// webhook URL embeds `tenant_id`; the controller refuses to dispatch
/// without one.
#[derive(Debug, Deserialize)]
pub struct InboundQuery {
    /// Tenant uuid the platform delivery is scoped to.
    pub tenant_id: String,
}

/// `POST /v1/integrations/bugbounty/configs` — upsert the per-tenant
/// per-platform connection.
///
/// Requires `admin:users`. The API token + webhook HMAC secret travel
/// inline on the request body; the adapter rewrites them to the
/// configured [`sx_secrets::SecretsProvider`] and only the *paths*
/// survive on the persisted row.
pub async fn upsert_config(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<BugBountyConfigUpsertRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:users")?;
    let view = state
        .bugbounty
        .upsert_config(&scope.tenant_id, req)
        .await
        .map_err(map_bugbounty)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(view))))
}

/// `GET /v1/integrations/bugbounty/configs` — list the tenant's
/// configured connections.
pub async fn list_configs(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
) -> Result<Json<ApiResponse<Vec<BugBountyConfigView>>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `integrations:read`.
    require_permission(&user, "integrations:read")?;
    let items = state
        .bugbounty
        .list_configs(&scope.tenant_id)
        .await
        .map_err(map_bugbounty)?;
    Ok(Json(ApiResponse::ok(items)))
}

/// `POST /v1/integrations/bugbounty/push` — dispatch a triaged finding
/// as an internal draft note. The adapter enforces the severity ≥ HIGH
/// floor and translates the connector outcome into the view shape.
pub async fn push(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<BugBountyPushRequest>,
) -> Result<Json<ApiResponse<BugBountyPushOutcomeView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `integrations:write`.
    require_permission(&user, "integrations:write")?;
    let view = state
        .bugbounty
        .push(&scope.tenant_id, req)
        .await
        .map_err(map_bugbounty)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// `POST /v1/integrations/bugbounty/inbound/{platform}` — webhook
/// delivery from the platform.
///
/// Intentionally *not* JWT-authenticated. The platform proves it by
/// signing the raw request body with the per-tenant per-platform HMAC
/// secret persisted under the connection row. The controller reads the
/// raw bytes before any JSON deserialisation so the bytes hashed
/// match the bytes the platform signed.
pub async fn inbound(
    State(state): State<AppState>,
    Path(platform): Path<String>,
    Query(query): Query<InboundQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApiResponse<BugBountyInboundOutcomeView>>, ApiError> {
    if query.tenant_id.trim().is_empty() {
        return Err(ApiError::BadRequest("tenant_id is required".to_owned()));
    }

    // Both vendor signature headers are lower-cased on the way in by
    // axum's `HeaderMap` — try the canonical names per-platform.
    let signature_header = headers
        .get("x-h1-signature")
        .or_else(|| headers.get("x-bugcrowd-signature"))
        .and_then(|h| h.to_str().ok());

    let view = state
        .bugbounty
        .inbound(&query.tenant_id, &platform, signature_header, body)
        .await
        .map_err(map_bugbounty)?;

    Ok(Json(ApiResponse::ok(view)))
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
                    .filter_map(|p| Permission::parse(p).ok())
                    .collect(),
                cred_id: None,
            },
        }
    }

    #[test]
    fn map_bugbounty_translates_known_variants() {
        assert!(matches!(
            map_bugbounty(BugBountyPortError::NotFound),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_bugbounty(BugBountyPortError::Invalid("x".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_bugbounty(BugBountyPortError::Unauthorized),
            ApiError::Unauthorized
        ));
        assert!(matches!(
            map_bugbounty(BugBountyPortError::RateLimited),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_bugbounty(BugBountyPortError::Dependency("d".into())),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_bugbounty(BugBountyPortError::Internal("i".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn require_admin_users_rejects_without_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "admin:users"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn require_admin_users_accepts_with_explicit_permission() {
        let u = user(vec!["admin:users"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn require_admin_users_accepts_wildcard() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }
}
