//! SOAR low-code workflow builder controllers (P3-005).
//!
//! Four endpoints:
//!
//! * `POST /v1/soar/workflows`          — create a workflow.
//! * `GET  /v1/soar/workflows/{id}`     — fetch a previously created workflow.
//! * `POST /v1/soar/workflows/{id}/run` — execute a workflow once against a
//!   caller-supplied trigger event.
//! * `GET  /v1/soar/runs/{id}`          — fetch a previously executed run
//!   log row.
//!
//! All three derive the active tenant from the caller's
//! [`AuthenticatedUser`] claims so an attacker cannot operate on another
//! tenant's workflows via URL manipulation.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sx_iam::domain::Permission;

use crate::controller::map_soar;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::soar_view::{CreateWorkflowRequest, RunWorkflowRequest, WorkflowSummaryView};

/// Query parameters for `GET /v1/soar/workflows`.
#[derive(Debug, Deserialize, Default)]
pub struct ListWorkflowsQuery {
    /// Page size, clamped to `1..=500`. Defaults to `100`.
    pub limit: Option<u32>,
}

/// Default page size when `limit` is omitted on the list endpoint.
const DEFAULT_LIST_LIMIT: u32 = 100;
/// Hard cap on the page size for the list endpoint.
const MAX_LIST_LIMIT: u32 = 500;

/// `GET /v1/soar/workflows` — list workflows for the caller's tenant.
///
/// Returns the narrow [`WorkflowSummaryView`] projection rather than the
/// full graph definition so the list response stays small at scale. The
/// tenant id is sourced from the bearer claims; cross-tenant enumeration
/// is impossible by construction.
pub async fn list_workflows(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListWorkflowsQuery>,
) -> Result<Json<ApiResponse<Vec<WorkflowSummaryView>>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `soar:read`.
    require_permission(&user, "soar:read")?;
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let rows = state
        .soar
        .list_workflows(&user.claims.tenant_id, limit)
        .await
        .map_err(map_soar)?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// `POST /v1/soar/workflows` — create a workflow.
pub async fn create_workflow(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CreateWorkflowRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `soar:write`.
    require_permission(&user, "soar:write")?;
    let view = state
        .soar
        .create_workflow(&user.claims.tenant_id, req)
        .await
        .map_err(map_soar)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(view))))
}

/// `GET /v1/soar/workflows/{id}` — fetch a previously created workflow.
pub async fn get_workflow(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(workflow_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `soar:read`.
    require_permission(&user, "soar:read")?;
    let view = state
        .soar
        .get_workflow(&user.claims.tenant_id, &workflow_id)
        .await
        .map_err(map_soar)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(view))))
}

/// `POST /v1/soar/workflows/{id}/run` — execute a workflow once.
pub async fn run_workflow(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(workflow_id): Path<String>,
    Json(req): Json<RunWorkflowRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `soar:run`.
    require_permission(&user, "soar:run")?;
    let view = state
        .soar
        .run_workflow(&user.claims.tenant_id, &workflow_id, req.event)
        .await
        .map_err(map_soar)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(view))))
}

/// `GET /v1/soar/runs/{id}` — fetch a previously executed run.
pub async fn get_run(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(run_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `soar:read`.
    require_permission(&user, "soar:read")?;
    let view = state
        .soar
        .get_run(&user.claims.tenant_id, &run_id)
        .await
        .map_err(map_soar)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(view))))
}

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use sx_soar::TriggerEvent;

    use super::*;
    use crate::port::{SoarPort, SoarPortError};
    use crate::view::soar_view::{WorkflowRunView, WorkflowView};

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
        assert!(require_permission(&user(vec!["soar:read"]), "soar:read").is_ok());
        assert!(require_permission(&user(vec!["soar:write"]), "soar:write").is_ok());
        assert!(require_permission(&user(vec!["soar:run"]), "soar:run").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["soar:*"]), "soar:run").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "soar:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "soar:write").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    /// Stub `SoarPort` returning a configurable workflow-summary list.
    struct StubSoar {
        rows: Vec<WorkflowSummaryView>,
    }

    #[async_trait]
    impl SoarPort for StubSoar {
        async fn create_workflow(
            &self,
            _tenant_id: &str,
            _req: CreateWorkflowRequest,
        ) -> Result<WorkflowView, SoarPortError> {
            Err(SoarPortError::Internal("stub".into()))
        }
        async fn get_workflow(
            &self,
            _tenant_id: &str,
            _workflow_id: &str,
        ) -> Result<WorkflowView, SoarPortError> {
            Err(SoarPortError::NotFound)
        }
        async fn list_workflows(
            &self,
            _tenant_id: &str,
            limit: u32,
        ) -> Result<Vec<WorkflowSummaryView>, SoarPortError> {
            Ok(self.rows.iter().take(limit as usize).cloned().collect())
        }
        async fn run_workflow(
            &self,
            _tenant_id: &str,
            _workflow_id: &str,
            _event: TriggerEvent,
        ) -> Result<WorkflowRunView, SoarPortError> {
            Err(SoarPortError::NotFound)
        }
        async fn get_run(
            &self,
            _tenant_id: &str,
            _run_id: &str,
        ) -> Result<WorkflowRunView, SoarPortError> {
            Err(SoarPortError::NotFound)
        }
    }

    fn summary(id: &str, name: &str) -> WorkflowSummaryView {
        WorkflowSummaryView {
            id: id.to_owned(),
            name: name.to_owned(),
            version: 1,
            created_at: "2026-06-13T00:00:00Z".to_owned(),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn list_workflows_returns_rows() {
        let port: Arc<dyn SoarPort> = Arc::new(StubSoar {
            rows: vec![summary("w-1", "first"), summary("w-2", "second")],
        });
        let rows = port.list_workflows("t", 100).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "first");
    }

    #[tokio::test]
    async fn list_workflows_empty_when_none() {
        let port: Arc<dyn SoarPort> = Arc::new(StubSoar { rows: vec![] });
        let rows = port.list_workflows("t", 100).await.unwrap();
        assert!(rows.is_empty());
    }
}
