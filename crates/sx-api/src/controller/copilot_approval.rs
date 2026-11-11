//! Copilot human-in-loop approval controller (P1-012).
//!
//! Routes:
//! - `GET  /v1/copilot/approvals`                  — list pending approvals.
//! - `POST /v1/copilot/approvals/{token}/decide`   — approve / reject.
//!
//! Both handlers require the `copilot:review` permission. RBAC is
//! enforced inline (same idiom as [`crate::controller::copilot::chat`]).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_collab::copilot_approval::ApprovalToken;
use sx_iam::domain::Permission;
use tracing::{debug, info};

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::copilot_approval_view::{
    DecideApprovalRequest, DecisionOutcomeView, PendingApprovalListView, PendingApprovalView,
};
use crate::view::envelope::ApiResponse;

/// `GET /v1/copilot/approvals` — list pending approvals for the caller's tenant.
///
/// Requires the `copilot:review` permission.
pub async fn list_pending(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "copilot:review")?;

    debug!(
        target: "controller.copilot_approval.list_pending",
        tenant_id = %user.claims.tenant_id,
        "listing pending copilot approvals",
    );

    let items = state
        .copilot_approval
        .list_pending(&user.claims.tenant_id)
        .await
        .map_err(map_phase3)?;

    let view = PendingApprovalListView {
        items: items
            .into_iter()
            .map(PendingApprovalView::from_domain)
            .collect(),
    };
    Ok((StatusCode::OK, Json(ApiResponse::ok(view))))
}

/// `POST /v1/copilot/approvals/{token}/decide` — approve or reject a pending
/// approval.
///
/// Requires the `copilot:review` permission. A `reject` decision MUST
/// carry a non-empty `reason`; the service refuses an empty reason.
pub async fn decide(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(token_str): Path<String>,
    ValidatedJson(req): ValidatedJson<DecideApprovalRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "copilot:review")?;

    let Some(token) = ApprovalToken::parse(&token_str) else {
        return Err(ApiError::Unprocessable("malformed approval token".into()));
    };
    let Some(decision) = req.parse_decision() else {
        return Err(ApiError::Unprocessable(
            "decision must be \"approve\" or \"reject\"".into(),
        ));
    };

    info!(
        target: "controller.copilot_approval.decide",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        decision = %req.decision,
        "copilot approval decision requested",
    );

    let outcome = state
        .copilot_approval
        .decide(
            &user.claims.tenant_id,
            token,
            decision,
            &user.claims.sub,
            req.reason,
        )
        .await
        .map_err(map_phase3)?;

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(DecisionOutcomeView::from_domain(outcome))),
    ))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors [`crate::controller::copilot::require_permission`]; controllers
/// keep permission decisions self-contained by project convention.
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
                    .map(|p| Permission::parse(p).unwrap())
                    .collect(),

                cred_id: None,
            },
        }
    }

    #[test]
    fn missing_permission_is_forbidden() {
        let u = user(vec!["copilot:use"]);
        assert!(matches!(
            require_permission(&u, "copilot:review"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_permission_allowed() {
        let u = user(vec!["copilot:review"]);
        assert!(require_permission(&u, "copilot:review").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed() {
        let u = user(vec!["*:review"]);
        assert!(require_permission(&u, "copilot:review").is_ok());
    }

    #[test]
    fn full_wildcard_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "copilot:review").is_ok());
    }

    /// Round-trip integration coverage: propose → list → approve, using
    /// the same in-memory copilot approval service that backs the
    /// production adapter, behind the [`CopilotApprovalPort`] trait
    /// the controller depends on. This proves the trait method
    /// signatures + the projection helpers fit together correctly.
    #[tokio::test]
    async fn list_and_decide_round_trip_via_port() {
        use crate::port::CopilotApprovalPort;
        use async_trait::async_trait;
        use std::sync::Arc;
        use sx_collab::copilot_approval::{
            ApprovalSnapshot, ApprovalToken, CopilotApprovalService, CopilotProposer, Decision,
            DecisionOutcome, InMemoryCopilotApprovalService, PendingApproval, ProposedAction,
            TenantScope, UserId,
        };

        struct PortAdapter(Arc<InMemoryCopilotApprovalService>);

        #[async_trait]
        impl CopilotApprovalPort for PortAdapter {
            async fn propose(
                &self,
                tenant_id: &str,
                proposer: CopilotProposer,
                action: ProposedAction,
            ) -> Result<ApprovalToken, crate::port::Phase3PortError> {
                self.0
                    .propose(TenantScope(tenant_id.into()), proposer, action)
                    .await
                    .map_err(|e| crate::port::Phase3PortError::Internal(e.to_string()))
            }
            async fn decide(
                &self,
                tenant_id: &str,
                token: ApprovalToken,
                decision: Decision,
                reviewer: &str,
                reason: Option<String>,
            ) -> Result<DecisionOutcome, crate::port::Phase3PortError> {
                self.0
                    .decide(
                        token,
                        TenantScope(tenant_id.into()),
                        decision,
                        UserId(reviewer.into()),
                        reason,
                    )
                    .await
                    .map_err(|e| crate::port::Phase3PortError::Internal(e.to_string()))
            }
            async fn list_pending(
                &self,
                tenant_id: &str,
            ) -> Result<Vec<PendingApproval>, crate::port::Phase3PortError> {
                self.0
                    .list_pending(TenantScope(tenant_id.into()))
                    .await
                    .map_err(|e| crate::port::Phase3PortError::Internal(e.to_string()))
            }
            async fn inspect(
                &self,
                tenant_id: &str,
                token: ApprovalToken,
            ) -> Result<ApprovalSnapshot, crate::port::Phase3PortError> {
                self.0
                    .inspect(token, TenantScope(tenant_id.into()))
                    .await
                    .map_err(|e| crate::port::Phase3PortError::Internal(e.to_string()))
            }
        }

        let svc = Arc::new(InMemoryCopilotApprovalService::new());
        let port: Arc<dyn CopilotApprovalPort> = Arc::new(PortAdapter(svc));

        // POST equivalent — propose.
        let token = port
            .propose(
                "t-1",
                CopilotProposer::Copilot { model: "m".into() },
                ProposedAction::ChangeSafetyPolicy {
                    policy_diff: serde_json::json!({}),
                },
            )
            .await
            .unwrap();

        // GET equivalent — list pending.
        let pending = port.list_pending("t-1").await.unwrap();
        assert_eq!(pending.len(), 1);
        let view = PendingApprovalView::from_domain(pending.into_iter().next().unwrap());
        assert_eq!(view.action_kind, "change_safety_policy");
        assert_eq!(view.status, "pending");

        // POST equivalent — decide (approve).
        let outcome = port
            .decide("t-1", token, Decision::Approve, "u-1", None)
            .await
            .unwrap();
        let outcome_view = DecisionOutcomeView::from_domain(outcome);
        assert_eq!(outcome_view.status, "approved");
        assert_eq!(outcome_view.reviewer, "u-1");

        // After-state: list is empty.
        let pending_after = port.list_pending("t-1").await.unwrap();
        assert!(pending_after.is_empty());
    }
}
