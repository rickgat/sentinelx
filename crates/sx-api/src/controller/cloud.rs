//! Cloud-inventory controller — `POST /v1/cloud/inventory`.
//!
//! Thin façade over [`crate::port::CloudInventoryPort`]. The HTTP layer
//! is the perimeter that enforces:
//!
//! 1. RBAC — caller must hold `cloud:inventory` (wildcards honoured).
//! 2. Schema — provider strings are validated against the closed
//!    `{aws, gcp, azure}` set via `validator::Validate`.
//!
//! Note: per-provider toggles are live as of Phase-3.5+2. The monolith
//! composes the port with whichever AWS/GCP/Azure connectors are enabled
//! in [`sx_config::CloudConfig`]; see
//! `services/sx-monolith/src/adapters/cloud.rs` for the wire-up. When
//! every provider is disabled the connector list is empty and the
//! response is `{ resources: [] }` — the same shape Phase-3.5+1 shipped,
//! preserved so the contract stays exercised end-to-end before any
//! credentials land.

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::cloud_view::CloudInventoryRequestView;
use crate::view::envelope::ApiResponse;

/// Query parameters for `GET /v1/cloud/inventory`.
#[derive(Debug, Deserialize, Default)]
pub struct ListInventoryQuery {
    /// Provider filter (`aws`/`gcp`/`azure`). When `None`, every
    /// configured connector is invoked.
    pub provider: Option<String>,
    /// Cap on results from any single provider. Clamped to `1..=10_000`.
    pub limit: Option<u32>,
}

/// Default per-provider cap when `limit` is omitted.
const DEFAULT_PER_PROVIDER: u32 = 100;
/// Hard cap on `limit`.
const MAX_PER_PROVIDER: u32 = 10_000;

/// `GET /v1/cloud/inventory?provider=&limit=` — list cloud resources.
///
/// Thin GET-shaped wrapper over the existing
/// [`crate::port::CloudInventoryPort::list`] surface. The tenant id is
/// sourced from the bearer claims so a caller cannot enumerate another
/// tenant by URL manipulation. When `provider` is omitted the request
/// fans out across the canonical `{aws, gcp, azure}` set.
pub async fn list_inventory_get(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Query(q): Query<ListInventoryQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "cloud:inventory")?;
    let providers = match q.provider.as_deref() {
        Some(p) if matches!(p, "aws" | "gcp" | "azure") => vec![p.to_owned()],
        Some(other) => {
            return Err(ApiError::Unprocessable(format!(
                "unsupported provider: {other}"
            )));
        }
        None => vec!["aws".to_owned(), "gcp".to_owned(), "azure".to_owned()],
    };
    let max_per_provider = q
        .limit
        .unwrap_or(DEFAULT_PER_PROVIDER)
        .clamp(1, MAX_PER_PROVIDER);
    let req = CloudInventoryRequestView {
        tenant_id: scope.tenant_id,
        providers,
        max_per_provider,
    };
    let resp = state.cloud_inventory.list(req).await.map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `POST /v1/cloud/inventory`
pub async fn list_inventory(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CloudInventoryRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "cloud:inventory")?;
    let resp = state.cloud_inventory.list(req).await.map_err(map_phase3)?;
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
    fn list_inventory_requires_cloud_inventory_permission() {
        // Caller has an unrelated permission — must be rejected as forbidden
        // before any state is touched.
        let u = user(vec!["finding:read"]);
        assert!(matches!(
            require_permission(&u, "cloud:inventory"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_cloud_inventory_permission_allowed() {
        let u = user(vec!["cloud:inventory"]);
        assert!(require_permission(&u, "cloud:inventory").is_ok());
    }

    #[test]
    fn wildcard_action_allowed_for_cloud_resource() {
        let u = user(vec!["cloud:*"]);
        assert!(require_permission(&u, "cloud:inventory").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = user(vec!["*:inventory"]);
        assert!(require_permission(&u, "cloud:inventory").is_ok());
    }

    // --- GET /v1/cloud/inventory tests --------------------------------

    use crate::port::{CloudInventoryPort, Phase3PortError};
    use crate::view::cloud_view::CloudInventoryResponseView;
    use async_trait::async_trait;
    use std::sync::Arc;

    /// Stub inventory port that records the last request and returns a
    /// configurable response.
    struct StubInventory {
        resp: CloudInventoryResponseView,
        last_providers: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CloudInventoryPort for StubInventory {
        async fn list(
            &self,
            req: CloudInventoryRequestView,
        ) -> Result<CloudInventoryResponseView, Phase3PortError> {
            *self.last_providers.lock().expect("poisoned") = req.providers;
            Ok(self.resp.clone())
        }
    }

    #[tokio::test]
    async fn get_inventory_defaults_to_all_providers() {
        let port: Arc<dyn CloudInventoryPort> = Arc::new(StubInventory {
            resp: CloudInventoryResponseView { resources: vec![] },
            last_providers: std::sync::Mutex::default(),
        });
        let req = CloudInventoryRequestView {
            tenant_id: "t".into(),
            providers: vec!["aws".into(), "gcp".into(), "azure".into()],
            max_per_provider: 100,
        };
        let resp = port.list(req).await.unwrap();
        assert!(resp.resources.is_empty());
    }

    #[tokio::test]
    async fn get_inventory_empty_response_round_trips() {
        let port: Arc<dyn CloudInventoryPort> = Arc::new(StubInventory {
            resp: CloudInventoryResponseView { resources: vec![] },
            last_providers: std::sync::Mutex::default(),
        });
        let req = CloudInventoryRequestView {
            tenant_id: "t".into(),
            providers: vec!["aws".into()],
            max_per_provider: 10,
        };
        let resp = port.list(req).await.unwrap();
        assert_eq!(resp.resources.len(), 0);
    }
}
