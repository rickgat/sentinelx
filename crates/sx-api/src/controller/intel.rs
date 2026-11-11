//! Threat-intel indicator-check controller — `POST /v1/intel/check`.
//!
//! Thin wrapper over the [`crate::port::IntelCheckPort`]. The validator
//! has already rejected unknown `kind` strings by the time the handler
//! runs; the only work left at the HTTP boundary is the permission gate
//! and translating the port error.
//!
//! ## Permission model
//!
//! Callers MUST hold the `intel:read` permission (or a wildcard that
//! covers it). The permission constant is the same string the SOC
//! tooling already uses for intel-feed reads, so analyst roles do not
//! need a fresh grant.

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
use crate::view::intel_view::{FeedStatusView, IntelCheckRequest};

/// `GET /v1/intel/feeds` — list configured intel feeds + their last-poll
/// status for the caller's tenant. Gated on the `intel:read` permission.
pub async fn list_feeds(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
) -> Result<Json<ApiResponse<Vec<FeedStatusView>>>, ApiError> {
    require_permission(&user, "intel:read")?;
    let rows = state
        .intel_feed_status
        .list_feeds(&scope.tenant_id)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// `POST /v1/intel/check`
///
/// Requires the `intel:read` permission.
pub async fn check_indicator(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<IntelCheckRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "intel:read")?;
    let resp = state.intel_check.check(req).await.map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Duplicated across controllers (rather than centralised in a helper
/// module) because the project convention is to keep each controller's
/// permission decisions self-contained — see e.g.
/// [`crate::controller::bas::require_permission`].
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
    use crate::port::{IntelCheckPort, Phase3PortError};
    use crate::view::intel_view::IntelCheckResponse;

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

    /// Stub port that always reports the same canned answer.
    #[derive(Debug, Default)]
    struct StubIntelPort {
        known: bool,
    }

    #[async_trait]
    impl IntelCheckPort for StubIntelPort {
        async fn check(
            &self,
            _req: IntelCheckRequest,
        ) -> Result<IntelCheckResponse, Phase3PortError> {
            Ok(IntelCheckResponse {
                known: self.known,
                source: self.known.then(|| "stub".to_owned()),
                last_seen: None,
            })
        }
    }

    #[test]
    fn missing_permission_is_forbidden() {
        let u = user(vec!["finding:read"]);
        assert!(matches!(
            require_permission(&u, "intel:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_permission_allowed() {
        let u = user(vec!["intel:read"]);
        assert!(require_permission(&u, "intel:read").is_ok());
    }

    #[test]
    fn wildcard_action_allowed() {
        let u = user(vec!["intel:*"]);
        assert!(require_permission(&u, "intel:read").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = user(vec!["*:read"]);
        assert!(require_permission(&u, "intel:read").is_ok());
    }

    #[tokio::test]
    async fn port_round_trips_known_indicator() {
        let port: Arc<dyn IntelCheckPort> = Arc::new(StubIntelPort { known: true });
        let resp = port
            .check(IntelCheckRequest {
                kind: "domain".into(),
                value: "evil.example".into(),
            })
            .await
            .unwrap();
        assert!(resp.known);
        assert_eq!(resp.source.as_deref(), Some("stub"));
    }

    // --- GET /v1/intel/feeds tests ------------------------------------

    use crate::port::IntelFeedStatusPort;

    /// Stub feed-status port returning a configurable row list.
    struct StubFeedStatus {
        rows: Vec<FeedStatusView>,
    }

    #[async_trait]
    impl IntelFeedStatusPort for StubFeedStatus {
        async fn list_feeds(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<FeedStatusView>, Phase3PortError> {
            Ok(self.rows.clone())
        }
    }

    fn feed_row(name: &str, kind: &str) -> FeedStatusView {
        FeedStatusView {
            name: name.to_owned(),
            kind: kind.to_owned(),
            last_poll_at: Some("2026-06-13T00:00:00Z".to_owned()),
            last_success_at: Some("2026-06-13T00:00:00Z".to_owned()),
            error_count_24h: 0,
        }
    }

    #[tokio::test]
    async fn list_feeds_returns_rows() {
        let port: Arc<dyn IntelFeedStatusPort> = Arc::new(StubFeedStatus {
            rows: vec![feed_row("kev", "kev"), feed_row("nvd", "nvd")],
        });
        let rows = port.list_feeds("t").await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "kev");
    }

    #[tokio::test]
    async fn list_feeds_empty_when_none_configured() {
        let port: Arc<dyn IntelFeedStatusPort> = Arc::new(StubFeedStatus { rows: vec![] });
        let rows = port.list_feeds("t").await.unwrap();
        assert!(rows.is_empty());
    }
}
