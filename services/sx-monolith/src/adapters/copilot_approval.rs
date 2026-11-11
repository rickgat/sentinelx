//! P1-012 Copilot human-in-loop approval adapter.
//!
//! Wraps [`sx_collab::copilot_approval::InMemoryCopilotApprovalService`]
//! behind the [`sx_api::port::CopilotApprovalPort`] trait so the API
//! crate stays free of the service-crate types. Every state transition
//! (`Pending → Approved | Rejected | Expired`) is additionally appended
//! to the `sx-audit` chain via an injected
//! [`sx_audit::prelude::RecordAuditEventUseCase`], keeping the public
//! audit trail consistent with the in-crate per-token history vector.
//!
//! ## Audit posture
//!
//! - **Propose** — emits a `Custom { code: "copilot_approval_proposed" }`
//!   action with the proposer code stamped on the actor `id` field. The
//!   `after` payload carries the `ProposedAction` JSON so the audit
//!   search endpoints can render what was requested.
//! - **Decide** — emits either `Custom { code:
//!   "copilot_approval_approved" }` or `Custom { code:
//!   "copilot_approval_rejected" }` keyed on the reviewer's user id. The
//!   `after` payload echoes the reason when supplied (required on
//!   reject).
//! - **Expire (lazy)** — the adapter does not re-emit on the lazy
//!   transition because expiry is detected only at the next read; the
//!   in-crate per-token history vector still records it. A follow-up
//!   sweep task can mint a delayed `expired` audit entry.
//!
//! Audit-chain failures do not block the API call — they are logged at
//! `warn` level and the underlying decision still surfaces to the
//! caller. The audit chain is best-effort against ephemeral storage
//! failures; durability lives in the sink implementation, not here.
//!
//! ## Safety contract
//!
//! - `#![forbid(unsafe_code)]` is inherited from the workspace.
//! - No `unwrap`/`expect`/`panic!` on production paths.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{CopilotApprovalPort, Phase3PortError};
use sx_audit::prelude::{
    Actor, AuditAction, AuditEntry, AuditSink, NewAuditEvent, RecordAuditEventUseCase,
};
use sx_collab::copilot_approval::{
    ApprovalSnapshot, ApprovalToken, CopilotApprovalError, CopilotApprovalService, CopilotProposer,
    Decision, DecisionOutcome, InMemoryCopilotApprovalService, PendingApproval, ProposedAction,
    TenantScope, UserId,
};
use sx_core::value_object::ids::TenantId;
use tracing::warn;

/// Stable action code emitted on every state transition. The audit search
/// surfaces filter on these strings, so they are kept short and snake-case.
const ACTION_PROPOSED: &str = "copilot_approval_proposed";
const ACTION_APPROVED: &str = "copilot_approval_approved";
const ACTION_REJECTED: &str = "copilot_approval_rejected";

/// Resource kind stamped on every audit entry. Matches the on-wire
/// resource name used by the dashboard.
const RESOURCE_KIND: &str = "copilot_approval";

/// Bundle returned by [`build`]. Single field today; kept as a struct so a
/// future Postgres-backed flavour can attach its handle here without
/// breaking the composition-root call site.
pub(crate) struct CopilotApprovalBundle {
    /// Trait object the API state slot binds to.
    pub copilot_approval: Arc<dyn CopilotApprovalPort>,
}

/// Build an in-memory copilot-approval adapter wired to the supplied audit
/// recorder. Pass `audit_recorder = None` to skip audit-chain integration
/// (the in-crate per-token history still records every transition).
#[allow(dead_code)] // composition root wires this in
pub(crate) fn build(audit_recorder: Option<Arc<RecordAuditEventUseCase>>) -> CopilotApprovalBundle {
    let svc: Arc<dyn CopilotApprovalService> = Arc::new(InMemoryCopilotApprovalService::new());
    CopilotApprovalBundle {
        copilot_approval: Arc::new(CopilotApprovalAdapter {
            svc,
            audit: audit_recorder,
        }),
    }
}

/// `CopilotApprovalPort` implementation backed by a polymorphic
/// [`CopilotApprovalService`] + an optional audit recorder.
pub(crate) struct CopilotApprovalAdapter {
    svc: Arc<dyn CopilotApprovalService>,
    audit: Option<Arc<RecordAuditEventUseCase>>,
}

impl std::fmt::Debug for CopilotApprovalAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopilotApprovalAdapter")
            .field("audit", &self.audit.is_some())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CopilotApprovalPort for CopilotApprovalAdapter {
    async fn propose(
        &self,
        tenant_id: &str,
        proposer: CopilotProposer,
        action: ProposedAction,
    ) -> Result<ApprovalToken, Phase3PortError> {
        let scope = TenantScope(tenant_id.to_owned());
        let action_kind = action.kind_code();
        let action_payload = serde_json::to_value(&action).ok();
        let proposer_id = proposer_code(&proposer);

        let token = self
            .svc
            .propose(scope, proposer.clone(), action)
            .await
            .map_err(map_collab_error)?;

        self.record_audit(
            tenant_id,
            Actor {
                kind: sx_audit::prelude::ActorKind::Service,
                id: proposer_id,
                ip: None,
                user_agent: None,
            },
            AuditAction::Custom {
                code: ACTION_PROPOSED.to_owned(),
            },
            token,
            serde_json::json!({
                "kind": action_kind,
                "action": action_payload,
            }),
        )
        .await;

        Ok(token)
    }

    async fn decide(
        &self,
        tenant_id: &str,
        token: ApprovalToken,
        decision: Decision,
        reviewer: &str,
        reason: Option<String>,
    ) -> Result<DecisionOutcome, Phase3PortError> {
        let scope = TenantScope(tenant_id.to_owned());
        let reviewer_id = UserId(reviewer.to_owned());

        let outcome = self
            .svc
            .decide(token, scope, decision, reviewer_id, reason.clone())
            .await
            .map_err(map_collab_error)?;

        let action_code = match decision {
            Decision::Approve => ACTION_APPROVED,
            Decision::Reject => ACTION_REJECTED,
        };

        self.record_audit(
            tenant_id,
            Actor {
                kind: sx_audit::prelude::ActorKind::User,
                id: reviewer.to_owned(),
                ip: None,
                user_agent: None,
            },
            AuditAction::Custom {
                code: action_code.to_owned(),
            },
            token,
            serde_json::json!({
                "decision": decision.as_str(),
                "reason": reason,
                "status": outcome.status.as_str(),
            }),
        )
        .await;

        Ok(outcome)
    }

    async fn list_pending(&self, tenant_id: &str) -> Result<Vec<PendingApproval>, Phase3PortError> {
        let scope = TenantScope(tenant_id.to_owned());
        self.svc.list_pending(scope).await.map_err(map_collab_error)
    }

    async fn inspect(
        &self,
        tenant_id: &str,
        token: ApprovalToken,
    ) -> Result<ApprovalSnapshot, Phase3PortError> {
        let scope = TenantScope(tenant_id.to_owned());
        self.svc
            .inspect(token, scope)
            .await
            .map_err(map_collab_error)
    }
}

impl CopilotApprovalAdapter {
    /// Best-effort audit append. Failures are logged but never block the
    /// API surface — durability is the sink implementation's problem,
    /// not the wrapper's.
    async fn record_audit(
        &self,
        tenant_id: &str,
        actor: Actor,
        action: AuditAction,
        token: ApprovalToken,
        payload: serde_json::Value,
    ) {
        let Some(audit) = &self.audit else {
            return;
        };
        let Ok(parsed_tenant) = TenantId::from_str(tenant_id) else {
            warn!(
                target: "adapters.copilot_approval.audit",
                tenant_id = %tenant_id,
                "skipping audit append: malformed tenant id (not a UUID)",
            );
            return;
        };
        let action_code = action.code().to_owned();
        let evt = NewAuditEvent {
            tenant_id: parsed_tenant,
            actor,
            action,
            resource_kind: RESOURCE_KIND.to_owned(),
            resource_id: token.as_string(),
            before: None,
            after: Some(payload),
            request_id: String::new(),
            ts: None,
        };
        if let Err(err) = audit.record(evt).await {
            warn!(
                target: "adapters.copilot_approval.audit",
                action = %action_code,
                token = %token,
                error = %err,
                "audit append failed; in-crate history retains the transition",
            );
        }
    }
}

/// Translate a [`CopilotApprovalError`] into the API-shared
/// [`Phase3PortError`].
fn map_collab_error(err: CopilotApprovalError) -> Phase3PortError {
    match err {
        CopilotApprovalError::NotFound => Phase3PortError::NotFound,
        CopilotApprovalError::TenantMismatch => {
            Phase3PortError::Forbidden("tenant mismatch".into())
        }
        CopilotApprovalError::AlreadyDecided => {
            Phase3PortError::Invalid("approval already decided".into())
        }
        CopilotApprovalError::Expired => Phase3PortError::Invalid("approval expired".into()),
        CopilotApprovalError::ReasonRequired => {
            Phase3PortError::Invalid("reason is required when rejecting an approval".into())
        }
        CopilotApprovalError::Internal(m) => Phase3PortError::Internal(m),
    }
}

/// Stable wire form for an [`Actor::id`] derived from a proposer.
fn proposer_code(p: &CopilotProposer) -> String {
    match p {
        CopilotProposer::Copilot { model } => format!("copilot:{model}"),
        CopilotProposer::Autonomy => "autonomy".to_owned(),
        CopilotProposer::Custom { code } => code.clone(),
        _ => "unknown".to_owned(),
    }
}

/// Test-only constructor used by the in-monolith integration test in
/// `services/sx-monolith/tests/copilot_approval_routes.rs` so it can
/// inject a deterministic audit sink without re-implementing the build
/// helper.
#[allow(dead_code)] // referenced from integration tests
pub(crate) fn build_with_sink<S: AuditSink + 'static>(
    sink: Arc<S>,
) -> (
    Arc<dyn CopilotApprovalPort>,
    Arc<RecordAuditEventUseCase>,
    Arc<S>,
) {
    let recorder_sink: Arc<dyn AuditSink> = Arc::clone(&sink) as Arc<dyn AuditSink>;
    let recorder = Arc::new(RecordAuditEventUseCase::new(recorder_sink));
    let svc: Arc<dyn CopilotApprovalService> = Arc::new(InMemoryCopilotApprovalService::new());
    let adapter: Arc<dyn CopilotApprovalPort> = Arc::new(CopilotApprovalAdapter {
        svc,
        audit: Some(Arc::clone(&recorder)),
    });
    (adapter, recorder, sink)
}

/// Trivial entry walker the integration test uses to assert the audit
/// chain advanced — kept out of `pub(crate)` so the API surface stays
/// stable across follow-up flavours.
#[allow(dead_code)]
pub(crate) fn entry_action_code(entry: &AuditEntry) -> &str {
    entry.action.code()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn tenant_uuid() -> &'static str {
        "00000000-0000-0000-0000-000000000001"
    }

    #[tokio::test]
    async fn propose_then_list_then_approve_round_trip() {
        let bundle = build(None);
        let token = bundle
            .copilot_approval
            .propose(
                tenant_uuid(),
                CopilotProposer::Copilot {
                    model: "claude-3-5-sonnet-latest".into(),
                },
                ProposedAction::ApplyRemediation {
                    finding_id: "f-1".into(),
                    vendor: "redhat".into(),
                    change_payload: serde_json::json!({ "rhsa": "RHSA-2024-0001" }),
                },
            )
            .await
            .unwrap();

        let pending = bundle
            .copilot_approval
            .list_pending(tenant_uuid())
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].token, token);

        let outcome = bundle
            .copilot_approval
            .decide(
                tenant_uuid(),
                token,
                Decision::Approve,
                "u-1",
                Some("LGTM".into()),
            )
            .await
            .unwrap();
        assert_eq!(
            outcome.status,
            sx_collab::copilot_approval::ApprovalStatus::Approved
        );
    }

    #[tokio::test]
    async fn reject_without_reason_is_unprocessable() {
        let bundle = build(None);
        let token = bundle
            .copilot_approval
            .propose(
                tenant_uuid(),
                CopilotProposer::Autonomy,
                ProposedAction::ChangeSafetyPolicy {
                    policy_diff: serde_json::Value::Null,
                },
            )
            .await
            .unwrap();
        let err = bundle
            .copilot_approval
            .decide(tenant_uuid(), token, Decision::Reject, "u-1", None)
            .await
            .unwrap_err();
        match err {
            Phase3PortError::Invalid(m) => assert!(m.contains("reason")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tenant_mismatch_is_forbidden() {
        let bundle = build(None);
        let token = bundle
            .copilot_approval
            .propose(
                tenant_uuid(),
                CopilotProposer::Autonomy,
                ProposedAction::ChangeSafetyPolicy {
                    policy_diff: serde_json::Value::Null,
                },
            )
            .await
            .unwrap();
        let err = bundle
            .copilot_approval
            .decide(
                "00000000-0000-0000-0000-000000000099",
                token,
                Decision::Approve,
                "u-1",
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::Forbidden(_)));
    }

    #[tokio::test]
    async fn not_found_is_surfaced() {
        let bundle = build(None);
        let bogus = ApprovalToken::new_random();
        let err = bundle
            .copilot_approval
            .decide(tenant_uuid(), bogus, Decision::Approve, "u-1", None)
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    /// Audit chain integration: propose → approve must produce TWO
    /// in-chain entries with the documented action codes.
    #[tokio::test]
    async fn audit_chain_records_propose_and_decide() {
        use crate::adapters::audit_query::InMemoryAuditBufferSink;

        let sink = Arc::new(InMemoryAuditBufferSink::new());
        let (adapter, _recorder, sink) = build_with_sink(sink);

        let token = adapter
            .propose(
                tenant_uuid(),
                CopilotProposer::Copilot {
                    model: "claude".into(),
                },
                ProposedAction::ApplyRemediation {
                    finding_id: "f-1".into(),
                    vendor: "v".into(),
                    change_payload: serde_json::Value::Null,
                },
            )
            .await
            .unwrap();
        adapter
            .decide(
                tenant_uuid(),
                token,
                Decision::Approve,
                "u-1",
                Some("ok".into()),
            )
            .await
            .unwrap();

        let entries = sink.snapshot().await;
        let codes: Vec<&str> = entries.iter().map(|e| e.action.code()).collect();
        assert_eq!(codes, vec![ACTION_PROPOSED, ACTION_APPROVED]);
        for e in &entries {
            assert_eq!(e.resource_kind, RESOURCE_KIND);
            assert_eq!(e.resource_id, token.as_string());
        }
    }

    /// Reject path: audit chain records the reject and the reason.
    #[tokio::test]
    async fn audit_chain_records_reject_with_reason() {
        use crate::adapters::audit_query::InMemoryAuditBufferSink;

        let sink = Arc::new(InMemoryAuditBufferSink::new());
        let (adapter, _recorder, sink) = build_with_sink(sink);

        let token = adapter
            .propose(
                tenant_uuid(),
                CopilotProposer::Autonomy,
                ProposedAction::ChangeSafetyPolicy {
                    policy_diff: serde_json::Value::Null,
                },
            )
            .await
            .unwrap();
        adapter
            .decide(
                tenant_uuid(),
                token,
                Decision::Reject,
                "u-2",
                Some("not safe".into()),
            )
            .await
            .unwrap();

        let entries = sink.snapshot().await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].action.code(), ACTION_REJECTED);
        let after = entries[1].after.as_ref().unwrap();
        assert_eq!(
            after.get("reason").and_then(|v| v.as_str()),
            Some("not safe")
        );
        assert_eq!(
            after.get("decision").and_then(|v| v.as_str()),
            Some("reject")
        );
    }

    #[test]
    fn error_map_buckets_variants() {
        assert!(matches!(
            map_collab_error(CopilotApprovalError::NotFound),
            Phase3PortError::NotFound
        ));
        assert!(matches!(
            map_collab_error(CopilotApprovalError::TenantMismatch),
            Phase3PortError::Forbidden(_)
        ));
        assert!(matches!(
            map_collab_error(CopilotApprovalError::AlreadyDecided),
            Phase3PortError::Invalid(_)
        ));
        assert!(matches!(
            map_collab_error(CopilotApprovalError::Expired),
            Phase3PortError::Invalid(_)
        ));
        assert!(matches!(
            map_collab_error(CopilotApprovalError::ReasonRequired),
            Phase3PortError::Invalid(_)
        ));
        assert!(matches!(
            map_collab_error(CopilotApprovalError::Internal("x".into())),
            Phase3PortError::Internal(_)
        ));
    }

    #[test]
    fn proposer_code_renders_each_variant() {
        assert_eq!(
            proposer_code(&CopilotProposer::Copilot {
                model: "claude".into()
            }),
            "copilot:claude"
        );
        assert_eq!(proposer_code(&CopilotProposer::Autonomy), "autonomy");
        assert_eq!(
            proposer_code(&CopilotProposer::Custom {
                code: "agent.x".into()
            }),
            "agent.x"
        );
    }
}
