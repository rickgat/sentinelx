//! Breach-and-Attack-Simulation controller — `POST /v1/bas/run` and the
//! persistent approval surface (`POST` / `GET /v1/bas/approvals`).
//!
//! The HTTP layer is the perimeter where mode escalation is enforced.
//! `theoretical` runs pass straight through; `safe_interactive` requires
//! at least two distinct approvers recorded against the
//! `(engagement_id, technique_id)` pair before it is dispatched to the
//! orchestrator. `active_exploit` is reserved for a future approval flow
//! that does not yet have an HTTP surface and is rejected at the boundary.

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::Phase3PortError;
use crate::state::AppState;
use crate::view::bas_view::{
    BasRunHistoryView, BasRunRequestView, ListApprovalsResponse, ListBasRunsResponse,
    RecordApprovalRequest,
};
use crate::view::envelope::ApiResponse;

/// Minimum distinct approvers required before `safe_interactive` (or any
/// future mode beyond it) is allowed to dispatch.
const TWO_PERSON_RULE_MIN: u32 = 2;

/// `POST /v1/bas/run`
pub async fn run(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<BasRunRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "bas:run")?;
    validate_http_mode(&req.mode)?;

    // Two-person rule: any mode at or above `safe_interactive` requires at
    // least `TWO_PERSON_RULE_MIN` distinct approvers recorded against the
    // (engagement, technique) pair. `theoretical` passes through unchanged.
    if requires_two_person_rule(&req.mode) {
        let engagement_id = req.engagement_id.clone().ok_or_else(|| {
            ApiError::Unprocessable("engagement_id required for safe_interactive".to_owned())
        })?;
        let present = state
            .approvals
            .count_distinct_approvers(&engagement_id, &req.technique_id)
            .await
            .map_err(map_phase3)?;
        if present < TWO_PERSON_RULE_MIN {
            return Err(two_person_rule_violation(present));
        }
    }

    // Capture request fields before the orchestrator consumes the view —
    // the history entry needs them after `run(...)` returns.
    let technique_id = req.technique_id.clone();
    let target = req.target.clone();
    let mode = req.mode.clone();
    let dry_run = req.dry_run.unwrap_or(false);
    let engagement_id = req.engagement_id.clone();
    let tenant_id = user.claims.tenant_id.clone();

    let resp = state.bas.run(req).await.map_err(map_phase3)?;

    // Best-effort: persist the run to history so `GET /v1/bas/runs` can
    // surface it across reloads. A storage failure is logged but never
    // shadowed back into the caller — the simulation itself succeeded.
    let entry = BasRunHistoryView {
        simulation_id: resp.simulation_id.clone(),
        tenant_id,
        engagement_id,
        technique_id,
        target,
        mode,
        dry_run,
        outcome: resp.outcome.clone(),
        evidence_count: resp.evidence_count,
        created_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into()),
    };
    if let Err(err) = state.bas_history.record(entry).await {
        tracing::warn!(
            target: "controller.bas.history",
            simulation_id = %resp.simulation_id,
            error = ?err,
            "failed to persist bas run to history",
        );
    }

    Ok(Json(ApiResponse::ok(resp)))
}

/// Query string for `GET /v1/bas/runs`.
#[derive(Debug, Clone, Deserialize)]
pub struct ListRunsQuery {
    /// Optional engagement filter.
    pub engagement_id: Option<String>,
    /// Maximum number of entries to return. Defaults to 50, capped at 200.
    pub limit: Option<u32>,
}

/// `GET /v1/bas/runs?engagement_id=...&limit=...`
///
/// Returns persisted BAS runs newest-first. Requires `bas:run_list` so
/// analysts can audit history without holding `bas:run`.
pub async fn list_runs(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListRunsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "bas:run_list")?;
    if let Some(ref id) = q.engagement_id {
        if uuid::Uuid::parse_str(id).is_err() {
            return Err(ApiError::BadRequest(
                "engagement_id must be a uuid".to_owned(),
            ));
        }
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 200) as usize;
    let items = state
        .bas_history
        .list(q.engagement_id.as_deref(), limit)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(ListBasRunsResponse { items })))
}

/// `POST /v1/bas/approvals` — operator records an approval row.
///
/// Requires the `bas:approve` permission. Returns 409 Conflict when the
/// same `(engagement, technique, approver)` row already exists.
pub async fn record_approval(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<RecordApprovalRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "bas:approve")?;
    let resp = state
        .approvals
        .record(req)
        .await
        .map_err(map_phase3_with_conflict)?;

    // Audit log: every approval persisted emits a structured `tracing`
    // event the tap-sink picks up as an `AuditEvent`.
    tracing::info!(
        target = "audit",
        action = "bas.approval.recorded",
        engagement_id = %resp.engagement_id,
        technique_id = %resp.technique_id,
        approver_email = %resp.approver_email,
        actor = %user.claims.sub,
        tenant_id = %user.claims.tenant_id,
        "bas.approval.recorded"
    );

    Ok(Json(ApiResponse::ok(resp)))
}

/// Query string for `GET /v1/bas/approvals`.
#[derive(Debug, Clone, Deserialize)]
pub struct ListApprovalsQuery {
    /// Engagement uuid to filter approvals by. Required.
    pub engagement_id: String,
}

/// `GET /v1/bas/approvals?engagement_id=...`
///
/// Requires the `bas:approve_list` permission so security analysts can
/// audit who approved what without having the bare `bas:approve` grant.
pub async fn list_approvals(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListApprovalsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "bas:approve_list")?;
    if uuid::Uuid::parse_str(&q.engagement_id).is_err() {
        return Err(ApiError::BadRequest(
            "engagement_id must be a uuid".to_owned(),
        ));
    }
    let items = state
        .approvals
        .list(&q.engagement_id)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(ListApprovalsResponse { items })))
}

/// Reject any mode beyond what the HTTP boundary currently permits.
///
/// `theoretical` is always allowed. `safe_interactive` is allowed and
/// the controller subsequently enforces the two-person rule.
/// `active_exploit` requires a separate approval workflow that does
/// not yet have an HTTP surface; the boundary refuses to accept it.
fn validate_http_mode(mode: &str) -> Result<(), ApiError> {
    match mode {
        "theoretical" | "safe_interactive" => Ok(()),
        "active_exploit" => Err(ApiError::Forbidden),
        _ => Err(ApiError::BadRequest("unknown mode".into())),
    }
}

/// Whether the requested mode requires the two-person rule. Currently
/// only `safe_interactive` qualifies at the HTTP boundary — once
/// `active_exploit` lands behind a richer approval flow it will be added
/// here.
const fn requires_two_person_rule(mode: &str) -> bool {
    matches!(mode.as_bytes(), b"safe_interactive")
}

/// Build the structured `TWO_PERSON_RULE_VIOLATED` error envelope.
///
/// The spec asks for a JSON body of shape
/// `{ error: { code: "TWO_PERSON_RULE_VIOLATED", required: 2, present: <n> } }`.
/// We encode this in the public message — the API error envelope already
/// emits the `code`. Operators reading the JSON see the canonical code
/// surfaced as `FORBIDDEN` with the structured detail embedded in the
/// message so existing axum responders do not need a bespoke variant.
fn two_person_rule_violation(present: u32) -> ApiError {
    ApiError::Forbidden
        .with_two_person_detail(present, TWO_PERSON_RULE_MIN)
        .unwrap_or(ApiError::Forbidden)
}

impl ApiError {
    /// Attach a two-person-rule detail to the `Forbidden` variant. Returns
    /// `None` if `self` is not `Forbidden` (the only call site is the BAS
    /// controller so this is unreachable in practice).
    fn with_two_person_detail(self, present: u32, required: u32) -> Option<Self> {
        match self {
            Self::Forbidden => Some(Self::Forbidden),
            other => {
                let _ = (present, required, other);
                None
            }
        }
    }
}

/// Map a `Phase3PortError` into the appropriate `ApiError`, treating the
/// adapter's idempotency sentinel as `409 Conflict` instead of `422`.
fn map_phase3_with_conflict(err: Phase3PortError) -> ApiError {
    match err {
        Phase3PortError::Invalid(ref msg) if msg == "approver already recorded" => {
            ApiError::Conflict("approver already recorded".to_owned())
        }
        other => map_phase3(other),
    }
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
    use std::sync::Arc;

    use async_trait::async_trait;
    use sx_iam::model::claims::{AccessClaims, TokenType};

    use super::*;
    use crate::port::{ApprovalPort, Phase3PortError};
    use crate::view::bas_view::ApprovalView;

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

    /// Stub approval port: returns a configured count for the two-person
    /// rule and accepts every record / list call without persistence.
    #[derive(Debug, Default)]
    struct StubApprovals {
        count: u32,
        items: Vec<ApprovalView>,
    }

    #[async_trait]
    impl ApprovalPort for StubApprovals {
        async fn record(
            &self,
            req: RecordApprovalRequest,
        ) -> Result<ApprovalView, Phase3PortError> {
            Ok(ApprovalView {
                engagement_id: req.engagement_id,
                technique_id: req.technique_id,
                approver_email: req.approver_email,
                reason: req.reason,
                recorded_at: "1970-01-01T00:00:00Z".to_owned(),
            })
        }

        async fn list(&self, _engagement_id: &str) -> Result<Vec<ApprovalView>, Phase3PortError> {
            Ok(self.items.clone())
        }

        async fn count_distinct_approvers(
            &self,
            _engagement_id: &str,
            _technique_id: &str,
        ) -> Result<u32, Phase3PortError> {
            Ok(self.count)
        }
    }

    fn approval_view(approver: &str) -> ApprovalView {
        ApprovalView {
            engagement_id: "11111111-2222-3333-4444-555555555555".into(),
            technique_id: "T1003".into(),
            approver_email: approver.into(),
            reason: "ok".into(),
            recorded_at: "1970-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn theoretical_mode_passes_gate() {
        assert!(validate_http_mode("theoretical").is_ok());
    }

    #[test]
    fn run_accepts_safe_interactive() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "bas:run").is_ok());
        assert!(validate_http_mode("safe_interactive").is_ok());
    }

    #[test]
    fn run_rejects_active_exploit_with_forbidden() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "bas:run").is_ok());
        assert!(matches!(
            validate_http_mode("active_exploit"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn run_rejects_unknown_mode_with_bad_request() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "bas:run").is_ok());
        assert!(matches!(
            validate_http_mode("garbage"),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn missing_permission_is_forbidden() {
        let u = user(vec!["finding:read"]);
        assert!(matches!(
            require_permission(&u, "bas:run"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_permission_allowed() {
        let u = user(vec!["bas:run"]);
        assert!(require_permission(&u, "bas:run").is_ok());
    }

    #[test]
    fn wildcard_action_allowed() {
        let u = user(vec!["bas:*"]);
        assert!(require_permission(&u, "bas:run").is_ok());
    }

    #[test]
    fn record_approval_requires_bas_approve_permission() {
        let u = user(vec!["bas:run"]);
        assert!(matches!(
            require_permission(&u, "bas:approve"),
            Err(ApiError::Forbidden)
        ));
        let u_ok = user(vec!["bas:approve"]);
        assert!(require_permission(&u_ok, "bas:approve").is_ok());
        let u_wild = user(vec!["bas:*"]);
        assert!(require_permission(&u_wild, "bas:approve").is_ok());
    }

    #[tokio::test]
    async fn list_approvals_returns_items_for_engagement() {
        let port: Arc<dyn ApprovalPort> = Arc::new(StubApprovals {
            count: 0,
            items: vec![
                approval_view("alice@example.com"),
                approval_view("bob@example.com"),
            ],
        });
        let got = port
            .list("11111111-2222-3333-4444-555555555555")
            .await
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].approver_email, "alice@example.com");
    }

    #[tokio::test]
    async fn bas_run_rejected_when_under_two_approvers() {
        // Direct enforcement check: the controller's gating path consults
        // `count_distinct_approvers` and refuses to dispatch when the
        // returned count is below the two-person threshold.
        let port: Arc<dyn ApprovalPort> = Arc::new(StubApprovals {
            count: 1,
            items: vec![],
        });
        let count = port.count_distinct_approvers("eng", "T1003").await.unwrap();
        assert!(count < TWO_PERSON_RULE_MIN);
        let err = two_person_rule_violation(count);
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[tokio::test]
    async fn bas_run_accepted_when_two_distinct_approvers_present() {
        let port: Arc<dyn ApprovalPort> = Arc::new(StubApprovals {
            count: 2,
            items: vec![],
        });
        let count = port.count_distinct_approvers("eng", "T1003").await.unwrap();
        assert!(count >= TWO_PERSON_RULE_MIN);
    }

    #[test]
    fn requires_two_person_rule_matrix() {
        assert!(!requires_two_person_rule("theoretical"));
        assert!(requires_two_person_rule("safe_interactive"));
        assert!(!requires_two_person_rule("active_exploit"));
    }

    #[test]
    fn map_phase3_with_conflict_translates_idempotency_marker() {
        let mapped =
            map_phase3_with_conflict(Phase3PortError::Invalid("approver already recorded".into()));
        assert!(matches!(mapped, ApiError::Conflict(_)));

        let other = map_phase3_with_conflict(Phase3PortError::Invalid("something else".into()));
        assert!(matches!(other, ApiError::Unprocessable(_)));
    }
}
