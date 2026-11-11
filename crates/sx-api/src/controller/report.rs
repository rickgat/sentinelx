//! Report-render controller — `POST /v1/reports/render` + `POST /v1/reports/diff`
//! + `GET /v1/reports` (list).

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::report_view::{ReportDiffRequestView, ReportRenderRequestView, ReportSummaryView};

/// Query parameters for `GET /v1/reports`.
#[derive(Debug, Deserialize, Default)]
pub struct ListReportsQuery {
    /// Page size, clamped to `1..=500`. Defaults to `100`.
    pub limit: Option<u32>,
}

/// Default page size for [`list`].
const DEFAULT_LIST_LIMIT: u32 = 100;
/// Hard cap on the page size for [`list`].
const MAX_LIST_LIMIT: u32 = 500;

/// `GET /v1/reports` — list previously rendered reports for the caller's
/// tenant. Returns the narrow [`ReportSummaryView`] projection.
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListReportsQuery>,
) -> Result<Json<ApiResponse<Vec<ReportSummaryView>>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `report:read`.
    require_permission(&user, "report:read")?;
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let rows = state
        .report
        .list_rendered(&user.claims.tenant_id, limit)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// `POST /v1/reports/render`
pub async fn render(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(mut req): ValidatedJson<ReportRenderRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `report:write`.
    require_permission(&user, "report:write")?;
    // Force the scoped tenant id so a client cannot render reports for
    // another tenant by mutating the body.
    req.tenant_id = user.claims.tenant_id;
    let resp = state.report.render(req).await.map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `POST /v1/reports/diff` — week-over-week differential report.
///
/// (Or any `[since, until]` window.) Returns `added` / `resolved` /
/// `reopened` finding buckets plus per-severity drift and top-line
/// metrics. When `render_pdf=true`, also materialises a `diff_pdf`
/// artifact (with its metadata returned in the `pdf` field).
pub async fn diff(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(mut req): ValidatedJson<ReportDiffRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `report:read`.
    require_permission(&user, "report:read")?;
    // Force the scoped tenant id; defence-in-depth against mutating the
    // body to query another tenant.
    req.tenant_id = user.claims.tenant_id;
    let resp = state.report_diff.compute(req).await.map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
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

    use super::*;
    use crate::port::{Phase3PortError, ReportRenderPort};

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
        assert!(require_permission(&user(vec!["report:read"]), "report:read").is_ok());
        assert!(require_permission(&user(vec!["report:write"]), "report:write").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["report:*"]), "report:write").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "report:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "report:write").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }
    use crate::view::report_view::ReportRenderResponseView;

    /// Stub render port returning a configurable summary list.
    struct StubReport {
        rows: Vec<ReportSummaryView>,
    }

    #[async_trait]
    impl ReportRenderPort for StubReport {
        async fn render(
            &self,
            _req: ReportRenderRequestView,
        ) -> Result<ReportRenderResponseView, Phase3PortError> {
            Err(Phase3PortError::Internal("stub".into()))
        }
        async fn list_rendered(
            &self,
            _tenant_id: &str,
            limit: u32,
        ) -> Result<Vec<ReportSummaryView>, Phase3PortError> {
            Ok(self.rows.iter().take(limit as usize).cloned().collect())
        }
    }

    fn summary(id: &str, kind: &str) -> ReportSummaryView {
        ReportSummaryView {
            id: id.to_owned(),
            kind: kind.to_owned(),
            generated_at: "2026-06-13T00:00:00Z".to_owned(),
            format: kind.to_owned(),
            size_bytes: 1024,
        }
    }

    #[tokio::test]
    async fn list_returns_rows() {
        let port: Arc<dyn ReportRenderPort> = Arc::new(StubReport {
            rows: vec![summary("r1", "executive_pdf"), summary("r2", "sarif")],
        });
        let rows = port.list_rendered("t", 100).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "r1");
    }

    #[tokio::test]
    async fn list_empty_when_no_rendered_reports() {
        let port: Arc<dyn ReportRenderPort> = Arc::new(StubReport { rows: vec![] });
        let rows = port.list_rendered("t", 100).await.unwrap();
        assert!(rows.is_empty());
    }
}
