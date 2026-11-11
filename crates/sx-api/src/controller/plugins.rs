//! Plugin marketplace + SDK controllers (P3-007).
//!
//! Endpoints (all tenant-scoped via the caller's JWT claims):
//!
//! * `GET    /v1/plugins`                      — list installed plugins.
//! * `POST   /v1/plugins/install`              — install (register) a plugin.
//! * `DELETE /v1/plugins/{id}`                 — uninstall a plugin.
//! * `GET    /v1/plugins/{id}/dispatches`      — recent dispatch history.
//!
//! Every install + uninstall emits a structured `tracing::info!` event
//! against `target = "audit"`. The tap-sink picks those up and threads
//! them onto the same audit chain the rest of the platform writes to.
//!
//! ## Permissions
//!
//! - `plugins:read`   — list + dispatch-history endpoints.
//! - `plugins:write`  — install + uninstall endpoints.
//!
//! Wildcard `*:*` permissions are honoured so operator / superadmin
//! tokens continue to work.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use secrecy::SecretString;
use serde::Deserialize;
use sx_iam::domain::Permission;
use sx_plugins::{DispatchRecord, PluginId, PluginManifest, RegisteredPlugin};

use crate::controller::map_plugins;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::plugins_view::{
    InstallPluginRequest, ListPluginDispatchesResponse, ListPluginsResponse, PluginDispatchView,
    PluginView,
};

/// Default `limit` when the dispatch-history caller does not supply one.
const DEFAULT_DISPATCH_LIMIT: u32 = 50;
/// Hard ceiling on the dispatch-history page size.
const MAX_DISPATCH_LIMIT: u32 = 500;
/// Fallback for the `u32 → usize` conversion — bounded so the worst case
/// is still safe even on a 16-bit host.
const LIMIT_FALLBACK: usize = u16::MAX as usize;

/// `GET /v1/plugins` — list every plugin registered for the caller's
/// tenant, newest-first.
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "plugins:read")?;
    let rows: Vec<RegisteredPlugin> = state
        .plugins
        .list(&user.claims.tenant_id)
        .await
        .map_err(map_plugins)?;
    let plugins: Vec<PluginView> = rows.into_iter().map(PluginView::from).collect();
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(ListPluginsResponse { plugins })),
    ))
}

/// `POST /v1/plugins/install` — register a plugin under the caller's
/// tenant.
///
/// The request body is fully validated by [`ValidatedJson`] before the
/// controller sees it; the controller additionally enforces
/// `plugins:write` and projects the request onto a [`PluginManifest`]
/// before handing it off to the port.
pub async fn install(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<InstallPluginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "plugins:write")?;

    let manifest = PluginManifest {
        name: req.name.clone(),
        vendor: req.vendor.clone(),
        version: req.version.clone(),
        webhook_url: req.webhook_url.clone(),
        supported_events: req.supported_events.clone(),
        required_scopes: req.required_scopes.clone(),
    };
    let secret = SecretString::new(req.secret.into());

    let registered = state
        .plugins
        .install(&user.claims.tenant_id, manifest, secret)
        .await
        .map_err(map_plugins)?;

    // Audit: structured event picked up by the tap-sink and threaded
    // onto the existing audit chain. The secret never appears here.
    tracing::info!(
        target: "audit",
        action = "plugins.install",
        plugin_id = %registered.id,
        plugin_name = %registered.name,
        plugin_vendor = %registered.vendor,
        plugin_version = %registered.version,
        actor = %user.claims.sub,
        tenant_id = %user.claims.tenant_id,
        "plugin installed"
    );

    let view: PluginView = registered.into();
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(view))))
}

/// `DELETE /v1/plugins/{id}` — uninstall a plugin. The adapter wipes
/// both the registration and the dispatch history.
pub async fn uninstall(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "plugins:write")?;
    let plugin_id = PluginId::parse(&id)
        .map_err(|e| ApiError::BadRequest(format!("invalid plugin id: {e}")))?;
    state
        .plugins
        .uninstall(&user.claims.tenant_id, plugin_id)
        .await
        .map_err(map_plugins)?;

    tracing::info!(
        target: "audit",
        action = "plugins.uninstall",
        plugin_id = %plugin_id,
        actor = %user.claims.sub,
        tenant_id = %user.claims.tenant_id,
        "plugin uninstalled"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Query string for `GET /v1/plugins/{id}/dispatches`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ListDispatchesQuery {
    /// Caller-supplied page size cap. The controller clamps to
    /// `[1, MAX_DISPATCH_LIMIT]`.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `GET /v1/plugins/{id}/dispatches?limit=N` — recent dispatch history,
/// newest-first.
pub async fn list_dispatches(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    Query(q): Query<ListDispatchesQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "plugins:read")?;
    let plugin_id = PluginId::parse(&id)
        .map_err(|e| ApiError::BadRequest(format!("invalid plugin id: {e}")))?;

    let raw = q
        .limit
        .unwrap_or(DEFAULT_DISPATCH_LIMIT)
        .clamp(1, MAX_DISPATCH_LIMIT);
    // `raw <= MAX_DISPATCH_LIMIT <= u16::MAX`, so the conversion is
    // always lossless; the fallback is bounded by `LIMIT_FALLBACK`.
    let limit = usize::try_from(raw).unwrap_or(LIMIT_FALLBACK);

    let rows: Vec<DispatchRecord> = state
        .plugins
        .list_dispatches(&user.claims.tenant_id, plugin_id, limit)
        .await
        .map_err(map_plugins)?;

    let dispatches: Vec<PluginDispatchView> = rows
        .into_iter()
        .map(|r| PluginDispatchView {
            id: r.id.to_string(),
            event_kind: r.event_kind,
            status: r.status.as_str().to_owned(),
            latency_ms: r.latency_ms,
            response_excerpt: r.response_excerpt,
            ts: r.ts,
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(ListPluginDispatchesResponse { dispatches })),
    ))
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
    fn list_requires_plugins_read_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "plugins:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn install_requires_plugins_write_permission() {
        let u = user(vec!["plugins:read"]);
        assert!(matches!(
            require_permission(&u, "plugins:write"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn superadmin_wildcard_grants_both() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "plugins:read").is_ok());
        assert!(require_permission(&u, "plugins:write").is_ok());
    }

    #[test]
    fn limit_constants_are_sane() {
        const _: () = assert!(DEFAULT_DISPATCH_LIMIT > 0);
        const _: () = assert!(MAX_DISPATCH_LIMIT >= DEFAULT_DISPATCH_LIMIT);
        const _: () = assert!(MAX_DISPATCH_LIMIT <= 1_000);
    }
}
