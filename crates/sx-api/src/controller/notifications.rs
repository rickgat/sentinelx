//! Notifications controller — `GET /v1/notifications/devices`.
//!
//! Read-only surface over the per-user push device registry (P3-008).
//! The handler is intentionally thin: it gates on the
//! `notifications:read` permission, resolves the target `user_id` from
//! the (optional) `?user_id=` query parameter or the authenticated
//! caller's `sub`, and forwards to
//! [`crate::port::DeviceRegistryPort::list_devices`].
//!
//! Tenant scoping is sourced from the bearer claims — the adapter MUST
//! refuse to leak devices that belong to a different tenant regardless
//! of the supplied id pair.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::admin_view::DeviceSummaryView;
use crate::view::envelope::ApiResponse;

/// Query parameters for `GET /v1/notifications/devices`.
#[derive(Debug, Deserialize, Default)]
pub struct ListDevicesQuery {
    /// User uuid whose registrations to list. When omitted, defaults to
    /// the authenticated caller's `sub`.
    pub user_id: Option<String>,
}

/// `GET /v1/notifications/devices` — list registered push devices for
/// the authenticated tenant + caller.
///
/// Gates on the `notifications:read` permission. The raw `device_token`
/// is intentionally NEVER projected onto the wire — only the stable
/// id, platform, and registration timestamp are returned.
pub async fn list_devices(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Query(q): Query<ListDevicesQuery>,
) -> Result<Json<ApiResponse<Vec<DeviceSummaryView>>>, ApiError> {
    require_permission(&user, "notifications:read")?;
    let user_id = q.user_id.unwrap_or_else(|| user.claims.sub.clone());
    let rows = state
        .device_registry
        .list_devices(&scope.tenant_id, &user_id)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper used by sibling controllers (`audit`, `cloud`,
/// `intel`) so the notification surface owns its own check rather than
/// relying on a cross-module import.
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
    use std::sync::Arc;

    use async_trait::async_trait;
    use sx_iam::model::claims::{AccessClaims, TokenType};

    use super::*;
    use crate::port::{DeviceRegistryPort, Phase3PortError};

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

    /// Stub device registry returning a configurable set of devices.
    struct StubRegistry {
        rows: Vec<DeviceSummaryView>,
    }

    #[async_trait]
    impl DeviceRegistryPort for StubRegistry {
        async fn list_devices(
            &self,
            tenant_id: &str,
            user_id: &str,
        ) -> Result<Vec<DeviceSummaryView>, Phase3PortError> {
            Ok(self
                .rows
                .iter()
                .filter(|r| r.tenant_id == tenant_id && r.user_id == user_id)
                .cloned()
                .collect())
        }
    }

    fn device_row(id: &str, tenant: &str, user_id: &str, platform: &str) -> DeviceSummaryView {
        DeviceSummaryView {
            id: id.to_owned(),
            tenant_id: tenant.to_owned(),
            user_id: user_id.to_owned(),
            platform: platform.to_owned(),
            registered_at: "2026-06-13T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn list_devices_requires_notifications_read_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "notifications:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_notifications_read_permission_allowed() {
        let u = user(vec!["notifications:read"]);
        assert!(require_permission(&u, "notifications:read").is_ok());
    }

    #[test]
    fn wildcard_grants_notifications_read() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "notifications:read").is_ok());
    }

    #[tokio::test]
    async fn list_devices_returns_rows_for_user() {
        let port: Arc<dyn DeviceRegistryPort> = Arc::new(StubRegistry {
            rows: vec![
                device_row("d1", "t-a", "u-1", "ios"),
                device_row("d2", "t-a", "u-1", "android"),
                device_row("d3", "t-a", "u-2", "ios"),
            ],
        });
        let rows = port.list_devices("t-a", "u-1").await.unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn list_devices_empty_when_no_registrations() {
        let port: Arc<dyn DeviceRegistryPort> = Arc::new(StubRegistry { rows: vec![] });
        let rows = port.list_devices("t-a", "u-1").await.unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn list_devices_refuses_cross_tenant() {
        let port: Arc<dyn DeviceRegistryPort> = Arc::new(StubRegistry {
            rows: vec![device_row("d1", "t-a", "u-1", "ios")],
        });
        let rows = port.list_devices("t-b", "u-1").await.unwrap();
        assert!(rows.is_empty(), "cross-tenant rows must not leak");
    }
}
