//! Durable copilot-decision audit sink (ADR-0004 §Decision item 7).
//!
//! ADR-0004 requires every copilot call to write a prompt hash, response
//! hash, model id and user id to `sx-audit`. The AI-SEC-001 crate ships an
//! in-memory [`CopilotAuditSink`]; this adapter tees that in-memory store
//! together with the durable `sx-audit` hash chain so copilot decisions are
//! both readable in-process AND tamper-evident alongside the rest of the
//! platform's audit trail.
//!
//! The sx-audit append is best-effort: a malformed (non-UUID) tenant id or a
//! sink error is logged and swallowed so the copilot request itself never
//! fails because of an audit hiccup — the in-memory trail is always written
//! first and is never lost.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use sx_ai_audit::copilot_audit::{
    CopilotAuditSink, CopilotDecisionAudit, InMemoryCopilotAuditSink,
};
use sx_ai_audit::AiAuditError;
use sx_audit::prelude::{Actor, ActorKind, AuditAction, NewAuditEvent, RecordAuditEventUseCase};
use sx_core::value_object::ids::TenantId;
use tracing::warn;

/// `resource_kind` stamped on every copilot-decision audit entry.
const RESOURCE_KIND: &str = "copilot";
/// `AuditAction::Custom` code for a copilot decision.
const DECISION_CODE: &str = "copilot.decision";

/// Tees copilot-decision records to an in-memory store (read-back) and the
/// durable sx-audit hash chain.
pub(crate) struct AuditChainCopilotSink {
    inner: Arc<InMemoryCopilotAuditSink>,
    recorder: Arc<RecordAuditEventUseCase>,
}

impl std::fmt::Debug for AuditChainCopilotSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChainCopilotSink")
            .finish_non_exhaustive()
    }
}

impl AuditChainCopilotSink {
    pub(crate) fn new(
        inner: Arc<InMemoryCopilotAuditSink>,
        recorder: Arc<RecordAuditEventUseCase>,
    ) -> Self {
        Self { inner, recorder }
    }
}

#[async_trait]
impl CopilotAuditSink for AuditChainCopilotSink {
    async fn record(&self, entry: CopilotDecisionAudit) -> Result<(), AiAuditError> {
        // 1. In-memory read-back first — always written, never lost.
        self.inner.record(entry.clone()).await?;

        // 2. Durable sx-audit chain. Best-effort from here on.
        let Ok(tenant) = TenantId::from_str(&entry.tenant_id) else {
            warn!(
                target: "adapters.copilot_audit.chain",
                tenant_id = %entry.tenant_id,
                "skipping sx-audit append: tenant id is not a UUID",
            );
            return Ok(());
        };
        let evt = NewAuditEvent {
            tenant_id: tenant,
            // The copilot `sub` is not guaranteed to be a UUID, so build the
            // User actor from the raw claim string directly (matching the
            // copilot-approval adapter) rather than via `UserId` (a UUID).
            actor: Actor {
                kind: ActorKind::User,
                id: entry.user_id.clone(),
                ip: None,
                user_agent: None,
            },
            action: AuditAction::Custom {
                code: DECISION_CODE.to_owned(),
            },
            resource_kind: RESOURCE_KIND.to_owned(),
            resource_id: entry.action.clone(),
            before: None,
            // Only hashes + metadata — never raw prompt/response text.
            after: Some(json!({
                "prompt_hash": entry.prompt_hash,
                "response_hash": entry.response_hash,
                "model_id": entry.model_id,
                "action": entry.action,
                "decided_at": entry.decided_at,
            })),
            request_id: String::new(),
            ts: None,
        };
        if let Err(err) = self.recorder.record(evt).await {
            warn!(
                target: "adapters.copilot_audit.chain",
                error = %err,
                "sx-audit append failed; in-memory copilot trail retained",
            );
        }
        Ok(())
    }

    async fn all(&self, tenant_id: &str) -> Result<Vec<CopilotDecisionAudit>, AiAuditError> {
        self.inner.all(tenant_id).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::adapters::audit_query;

    fn recorder() -> Arc<RecordAuditEventUseCase> {
        let sink = audit_query::build(None).sink;
        Arc::new(RecordAuditEventUseCase::new(
            sink as Arc<dyn sx_audit::prelude::AuditSink>,
        ))
    }

    const TENANT: &str = "00000000-0000-0000-0000-000000000001";

    #[tokio::test]
    async fn tees_to_memory_and_chain() {
        let mem = Arc::new(InMemoryCopilotAuditSink::new());
        let sink = AuditChainCopilotSink::new(mem.clone(), recorder());
        let entry = CopilotDecisionAudit::new(TENANT, "analyst-1", "m", "chat", "p", "r");
        sink.record(entry).await.unwrap();
        // In-memory read-back works via the tee.
        let back = sink.all(TENANT).await.unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].user_id, "analyst-1");
    }

    #[tokio::test]
    async fn malformed_tenant_still_records_in_memory() {
        let mem = Arc::new(InMemoryCopilotAuditSink::new());
        let sink = AuditChainCopilotSink::new(mem.clone(), recorder());
        // Non-UUID tenant: sx-audit append is skipped, in-memory still kept.
        let entry = CopilotDecisionAudit::new("not-a-uuid", "u", "m", "chat", "p", "r");
        sink.record(entry).await.unwrap();
        assert_eq!(sink.all("not-a-uuid").await.unwrap().len(), 1);
    }
}
