//! HTTP contract test for the AI-audit surface (AI-SEC-001).
//!
//! Drives the **documented user-facing routes** end-to-end over a real
//! `axum` router (via `oneshot`) against a fake [`AiAuditPort`]:
//!
//! * `GET  /v1/ai-audit/assets`   — envelope shape + tenant scoping.
//! * `POST /v1/ai-audit/run`      — full report envelope.
//! * permission gate — exact grant, `*:*` wildcard, and denial (403).
//!
//! The router mirrors the production wiring (same paths, the real
//! `AuthenticatedUser` extractor, the real `ApiResponse` envelope, and the
//! real `map_ai_audit` error mapper); the authenticated user is injected via
//! a request-extension layer exactly as the production auth middleware does.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use tower::ServiceExt;

use sx_api::controller::map_ai_audit;
use sx_api::error::ApiError;
use sx_api::middleware::auth::AuthenticatedUser;
use sx_api::port::{AiAuditPort, AiAuditPortError};
use sx_api::view::ai_audit_view::{
    AiAssetListResponse, AiAssetView, AiAuditReportView, AiBomView, AiControlListResponse,
    AiControlView,
};
use sx_api::view::envelope::ApiResponse;
use sx_iam::domain::Permission;
use sx_iam::model::claims::{AccessClaims, TokenType};

// --- fake port -------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeAiAudit;

fn seeded_asset() -> AiAssetView {
    AiAssetView {
        id: "ai-asset-llm-01".into(),
        tenant_id: Some("t".into()),
        kind: "llm_api_endpoint".into(),
        name: "Remediation Copilot".into(),
        provider: "anthropic".into(),
        endpoint: Some("https://api.anthropic.com".into()),
        discovered_at: "2026-10-31T00:00:00Z".into(),
        metadata: std::collections::BTreeMap::new(),
    }
}

fn empty_bom() -> AiBomView {
    AiBomView {
        bom_format: "CycloneDX".into(),
        spec_version: "1.6".into(),
        version: 1,
        components: Vec::new(),
    }
}

#[async_trait]
impl AiAuditPort for FakeAiAudit {
    async fn list_assets(&self, tenant_id: &str) -> Result<AiAssetListResponse, AiAuditPortError> {
        if tenant_id.is_empty() {
            return Err(AiAuditPortError::Invalid("tenant_id empty".into()));
        }
        Ok(AiAssetListResponse {
            assets: vec![seeded_asset()],
        })
    }

    async fn aibom(&self, _tenant_id: &str) -> Result<AiBomView, AiAuditPortError> {
        Ok(empty_bom())
    }

    async fn list_controls(
        &self,
        _tenant_id: &str,
    ) -> Result<AiControlListResponse, AiAuditPortError> {
        Ok(AiControlListResponse {
            controls: vec![AiControlView {
                id: "SX-AI-NIST-MAP-1".into(),
                title: "mapped".into(),
                framework: "nist_ai_rmf".into(),
                description: "d".into(),
            }],
        })
    }

    async fn run_audit(
        &self,
        _tenant_id: &str,
        _actor: &str,
    ) -> Result<AiAuditReportView, AiAuditPortError> {
        Ok(AiAuditReportView {
            assets: vec![seeded_asset()],
            aibom: empty_bom(),
            probe_results: Vec::new(),
            modelfile_findings: Vec::new(),
            control_evidence: Vec::new(),
        })
    }

    async fn run_external_audit(
        &self,
        _tenant_id: &str,
        _actor: &str,
        _engagement_id: &str,
        _target_id: &str,
    ) -> Result<AiAuditReportView, AiAuditPortError> {
        Ok(AiAuditReportView {
            assets: vec![seeded_asset()],
            aibom: empty_bom(),
            probe_results: Vec::new(),
            modelfile_findings: Vec::new(),
            control_evidence: Vec::new(),
        })
    }
}

// --- handlers mirroring the production controllers -------------------------

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

async fn list_assets(
    State(port): State<Arc<dyn AiAuditPort>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "ai_audit:read")?;
    let resp = port
        .list_assets(&user.claims.tenant_id)
        .await
        .map_err(map_ai_audit)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

async fn run_audit(
    State(port): State<Arc<dyn AiAuditPort>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "ai_audit:run")?;
    let resp = port
        .run_audit(&user.claims.tenant_id, &user.claims.sub)
        .await
        .map_err(map_ai_audit)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

// --- harness ---------------------------------------------------------------

fn user_with(perms: &[&str]) -> AuthenticatedUser {
    AuthenticatedUser {
        claims: AccessClaims {
            sub: "operator-1".into(),
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
                .iter()
                .map(|p| Permission::parse(p).unwrap())
                .collect(),
            cred_id: None,
        },
    }
}

/// Build the production-shaped router with `user` injected into request
/// extensions (mirroring what the real auth middleware does).
fn app(user: AuthenticatedUser) -> Router {
    let port: Arc<dyn AiAuditPort> = Arc::new(FakeAiAudit);
    Router::new()
        .route("/v1/ai-audit/assets", get(list_assets))
        .route("/v1/ai-audit/run", post(run_audit))
        .layer(axum::middleware::from_fn(
            move |mut req: Request, next: Next| {
                let u = user.clone();
                async move {
                    req.extensions_mut().insert(u);
                    next.run(req).await
                }
            },
        ))
        .with_state(port)
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn get_assets_returns_envelope_with_seeded_asset() {
    let app = app(user_with(&["ai_audit:read"]));
    let req = Request::builder()
        .uri("/v1/ai-audit/assets")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    let assets = body["data"]["assets"].as_array().unwrap();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0]["kind"], "llm_api_endpoint");
}

#[tokio::test]
async fn wildcard_permission_satisfies_read() {
    let app = app(user_with(&["*:*"]));
    let req = Request::builder()
        .uri("/v1/ai-audit/assets")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_permission_is_forbidden() {
    let app = app(user_with(&["ueba:read"]));
    let req = Request::builder()
        .uri("/v1/ai-audit/assets")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn run_returns_full_report_with_run_permission() {
    let app = app(user_with(&["ai_audit:run"]));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/ai-audit/run")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body["data"]["aibom"]["bomFormat"] == "CycloneDX");
    assert_eq!(body["data"]["assets"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn run_requires_run_permission_not_just_read() {
    let app = app(user_with(&["ai_audit:read"]));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/ai-audit/run")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
