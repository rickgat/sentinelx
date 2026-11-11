//! Bridge from the in-crate [`crate::service::AuditHook`] surface to the
//! tamper-evident `sx-audit` hash chain.
//!
//! # Why a bridge?
//!
//! The [`HuntService`] layer needs a small, async-friendly sink trait it
//! can hand a [`HuntAuditEntry`] to. The production audit trail is the
//! per-tenant SHA-256 hash chain owned by `sx-audit`, accessed through
//! [`RecordAuditEventUseCase`]. The two surfaces are deliberately
//! decoupled — the bridge converts a [`HuntAuditEntry`] into a
//! [`NewAuditEvent`] of action [`AuditAction::Custom { code: "hunt.query.executed" }`]
//! (or one of the failure codes below) so the wider audit chain can
//! continue to verify even if the hunt schema evolves.
//!
//! # Action codes emitted by the bridge
//!
//! | `outcome`         | `AuditAction::Custom.code`     |
//! |-------------------|--------------------------------|
//! | `ok`              | `hunt.query.executed`          |
//! | `parse_error`     | `hunt.query.parse_failed`      |
//! | `compile_error`   | `hunt.query.compile_failed`    |
//! | `exec_error`      | `hunt.query.exec_failed`       |
//! | (other)           | `hunt.query.unknown_outcome`   |
//!
//! # Tenant ID handling
//!
//! `HuntAuditEntry::tenant_id` is a `String` because the hunt surface
//! accepts free-form caller-supplied identifiers (the HTTP layer enforces
//! the value-object form upstream). The bridge attempts to parse it as a
//! [`TenantId`]; if parsing fails the entry is dropped (a warning is
//! emitted via `tracing`) so the rest of the chain remains well-formed.
//!
//! # User ID handling
//!
//! Same story — `user_id` parses to [`UserId`] when possible; otherwise we
//! fall back to [`Actor::service`] with the literal string as the opaque
//! tag, so the chain still records *some* principal.
//!
//! # Failure mode
//!
//! Audit-chain append failures are **silently swallowed** with a
//! `tracing::error!` log. This matches the rest of the codebase: the
//! hunt query has already executed, so refusing to surface the failure
//! to the analyst is the right trade-off. Operators monitor the audit
//! sink itself for the underlying failure.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, error, warn};

use sx_audit::model::action::AuditAction;
use sx_audit::model::actor::Actor;
use sx_audit::prelude::{NewAuditEvent, RecordAuditEventUseCase};
use sx_core::value_object::ids::{TenantId, UserId};

use crate::service::{AuditHook, HuntAuditEntry};

/// Resource kind under which hunt-query events are recorded.
pub const HUNT_RESOURCE_KIND: &str = "hunt_query";

/// `AuditAction::Custom.code` for the `ok` outcome.
pub const ACTION_CODE_EXECUTED: &str = "hunt.query.executed";
/// `AuditAction::Custom.code` for the `parse_error` outcome.
pub const ACTION_CODE_PARSE_FAILED: &str = "hunt.query.parse_failed";
/// `AuditAction::Custom.code` for the `compile_error` outcome.
pub const ACTION_CODE_COMPILE_FAILED: &str = "hunt.query.compile_failed";
/// `AuditAction::Custom.code` for the `exec_error` outcome.
pub const ACTION_CODE_EXEC_FAILED: &str = "hunt.query.exec_failed";
/// `AuditAction::Custom.code` fallback for unrecognised outcomes.
pub const ACTION_CODE_UNKNOWN: &str = "hunt.query.unknown_outcome";

/// [`AuditHook`] implementation that writes each [`HuntAuditEntry`] to the
/// `sx-audit` tamper-evident chain.
#[derive(Clone)]
pub struct SxAuditHook {
    record: Arc<RecordAuditEventUseCase>,
}

impl std::fmt::Debug for SxAuditHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SxAuditHook").finish_non_exhaustive()
    }
}

impl SxAuditHook {
    /// Wrap a shared [`RecordAuditEventUseCase`].
    #[must_use]
    pub fn new(record: Arc<RecordAuditEventUseCase>) -> Self {
        Self { record }
    }

    /// Map a [`HuntAuditEntry::outcome`] label to its `AuditAction::Custom`
    /// code. The mapping is exhaustive over the labels emitted by
    /// [`crate::service::NullHuntService`] and falls back to
    /// [`ACTION_CODE_UNKNOWN`] for forward-compatibility.
    #[must_use]
    pub fn action_code_for(outcome: &str) -> &'static str {
        match outcome {
            "ok" => ACTION_CODE_EXECUTED,
            "parse_error" => ACTION_CODE_PARSE_FAILED,
            "compile_error" => ACTION_CODE_COMPILE_FAILED,
            "exec_error" => ACTION_CODE_EXEC_FAILED,
            _ => ACTION_CODE_UNKNOWN,
        }
    }
}

#[async_trait]
impl AuditHook for SxAuditHook {
    async fn record(&self, entry: HuntAuditEntry) {
        let Ok(tenant_id) = TenantId::from_str(&entry.tenant_id) else {
            warn!(
                tenant = %entry.tenant_id,
                "hunt audit dropped: tenant_id is not a valid UUID",
            );
            return;
        };
        let actor = if let Ok(user) = UserId::from_str(&entry.user_id) {
            Actor::user(user)
        } else {
            Actor::service(entry.user_id.clone())
        };
        let action = AuditAction::Custom {
            code: Self::action_code_for(entry.outcome).to_string(),
        };
        // After-image: keep the compiled SQL + row count + duration so the
        // audit log is self-contained (the analyst's raw query and the
        // wall-clock budget are captured alongside).
        let after = serde_json::json!({
            "compiled_sql": entry.compiled_sql,
            "table": entry.table,
            "raw_query": entry.raw_query,
            "row_count": entry.row_count,
            "duration_ms": entry.duration_ms,
            "started_at": entry.started_at,
            "outcome": entry.outcome,
        });

        let payload = NewAuditEvent {
            tenant_id,
            actor,
            action,
            resource_kind: HUNT_RESOURCE_KIND.to_string(),
            resource_id: entry.table.clone(),
            before: None,
            after: Some(after),
            request_id: String::new(),
            ts: None,
        };

        match self.record.record(payload).await {
            Ok(written) => {
                debug!(
                    seq = written.seq,
                    "hunt query audit appended to sx-audit chain",
                );
            }
            Err(e) => {
                error!(error = %e, "hunt query audit append failed");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use sx_audit::model::entry::AuditEntry;
    use sx_audit::prelude::AuditSink;

    #[derive(Default, Debug)]
    struct InMemSink {
        entries: Mutex<Vec<AuditEntry>>,
    }

    #[async_trait]
    impl AuditSink for InMemSink {
        async fn append(&self, entry: &AuditEntry) -> Result<(), sx_audit::error::AuditError> {
            self.entries.lock().await.push(entry.clone());
            Ok(())
        }

        async fn last_entry_for_tenant(
            &self,
            tenant_id: TenantId,
        ) -> Result<Option<AuditEntry>, sx_audit::error::AuditError> {
            Ok(self
                .entries
                .lock()
                .await
                .iter()
                .rfind(|e| e.tenant_id == tenant_id)
                .cloned())
        }

        async fn read_range(
            &self,
            tenant_id: TenantId,
            from_seq: u64,
            to_seq: u64,
        ) -> Result<Vec<AuditEntry>, sx_audit::error::AuditError> {
            Ok(self
                .entries
                .lock()
                .await
                .iter()
                .filter(|e| e.tenant_id == tenant_id && e.seq >= from_seq && e.seq <= to_seq)
                .cloned()
                .collect())
        }
    }

    #[test]
    fn action_code_mapping() {
        assert_eq!(SxAuditHook::action_code_for("ok"), ACTION_CODE_EXECUTED);
        assert_eq!(
            SxAuditHook::action_code_for("parse_error"),
            ACTION_CODE_PARSE_FAILED
        );
        assert_eq!(
            SxAuditHook::action_code_for("compile_error"),
            ACTION_CODE_COMPILE_FAILED
        );
        assert_eq!(
            SxAuditHook::action_code_for("exec_error"),
            ACTION_CODE_EXEC_FAILED
        );
        assert_eq!(
            SxAuditHook::action_code_for("anything_else"),
            ACTION_CODE_UNKNOWN
        );
    }

    #[tokio::test]
    async fn bridge_records_ok_outcome_with_after_payload() {
        let sink = Arc::new(InMemSink::default());
        let uc = Arc::new(RecordAuditEventUseCase::new(sink.clone()));
        let hook = SxAuditHook::new(uc);

        let tenant = TenantId::new();
        let user = UserId::new();
        let entry = HuntAuditEntry {
            tenant_id: tenant.to_string(),
            user_id: user.to_string(),
            raw_query: "events_raw | top 5 by severity_id desc".into(),
            compiled_sql: "SELECT * FROM events_raw WHERE tenant_id = {tenant:String} ORDER BY severity_id DESC LIMIT 5 FORMAT JSONEachRow".into(),
            table: "events_raw".into(),
            row_count: Some(7),
            outcome: "ok",
            started_at: "2026-06-15T10:00:00Z".into(),
            duration_ms: 42,
        };
        hook.record(entry).await;

        let entries = sink.entries.lock().await;
        assert_eq!(entries.len(), 1);
        let written = &entries[0];
        match &written.action {
            AuditAction::Custom { code } => assert_eq!(code, ACTION_CODE_EXECUTED),
            other => panic!("expected Custom, got {other:?}"),
        }
        assert_eq!(written.tenant_id, tenant);
        assert_eq!(written.resource_kind, HUNT_RESOURCE_KIND);
        assert_eq!(written.resource_id, "events_raw");
        let after = written.after.as_ref().unwrap();
        assert_eq!(after["row_count"], serde_json::json!(7));
        assert_eq!(after["duration_ms"], serde_json::json!(42));
        assert_eq!(after["outcome"], serde_json::json!("ok"));
    }

    #[tokio::test]
    async fn bridge_drops_entry_with_bad_tenant() {
        let sink = Arc::new(InMemSink::default());
        let uc = Arc::new(RecordAuditEventUseCase::new(sink.clone()));
        let hook = SxAuditHook::new(uc);

        let entry = HuntAuditEntry {
            tenant_id: "not-a-uuid".into(),
            user_id: UserId::new().to_string(),
            raw_query: String::new(),
            compiled_sql: String::new(),
            table: String::new(),
            row_count: None,
            outcome: "parse_error",
            started_at: "2026-06-15T10:00:00Z".into(),
            duration_ms: 0,
        };
        hook.record(entry).await;

        let entries = sink.entries.lock().await;
        assert!(entries.is_empty());
    }
}
