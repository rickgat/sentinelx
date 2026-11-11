//! Audit-sink port for HIGH-006 override mutations + suppression events.
//!
//! Two event kinds are recorded:
//!
//! - [`OverrideAuditKind::Mutation`] — admin upsert / delete via the
//!   `/v1/admin/runtime/falco/overrides` HTTP surface.
//! - [`OverrideAuditKind::Suppressed`] — runtime-time alert suppressed
//!   by a `Deny` action; surfaces the rule + subkey + the reason
//!   string from the matching override row.
//! - [`OverrideAuditKind::Escalated`] / [`OverrideAuditKind::Downgraded`]
//!   — runtime-time severity adjustments; the row captures the
//!   `(from, to)` severity transition for post-incident analysis.
//!
//! Like [`crate::audit::IngestionAuditSink`], this port is intentionally
//! local to `sx-runtime`. An adapter at the monolith composition root
//! forwards into the hash-chained `sx_audit::AuditSink`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

use crate::error::RuntimeError;
use crate::finding::RuntimeSeverity;
use crate::overrides::OverrideAction;

/// Discriminator on [`OverrideAuditEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideAuditKind {
    /// Admin upserted a row.
    Mutation,
    /// Admin deleted a row.
    Deletion,
    /// Alert suppressed at ingest time by a matching `Deny` row.
    Suppressed,
    /// Alert severity bumped at ingest time by a matching `Escalate` row.
    Escalated,
    /// Alert severity dropped at ingest time by a matching `Downgrade` row.
    Downgraded,
}

impl OverrideAuditKind {
    /// Canonical lowercase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mutation => "mutation",
            Self::Deletion => "deletion",
            Self::Suppressed => "suppressed",
            Self::Escalated => "escalated",
            Self::Downgraded => "downgraded",
        }
    }
}

/// One audit row covering both admin mutations and ingest-time
/// override applications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideAuditEvent {
    /// Owning tenant.
    pub tenant_id: String,
    /// Wall-clock time the row was emitted.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// Event discriminator.
    pub kind: OverrideAuditKind,
    /// Matched / mutated rule name.
    pub rule_name: String,
    /// Matched / mutated subkey (or `"*"` for rule-wide).
    pub subkey: String,
    /// Action recorded on the row. `None` on `Deletion` because the
    /// caller only knows the key.
    pub action: Option<OverrideAction>,
    /// Operator who triggered the event. For ingest-time events this is
    /// the synthetic actor `runtime-ingest` because the alert source is
    /// not a user.
    pub actor: String,
    /// Operator-supplied or system-derived rationale string.
    pub reason: String,
    /// Pre-override severity. Only populated on
    /// `Suppressed`/`Escalated`/`Downgraded` rows.
    pub severity_before: Option<RuntimeSeverity>,
    /// Post-override severity. Only populated on
    /// `Escalated`/`Downgraded` rows (`None` after `Suppressed`).
    pub severity_after: Option<RuntimeSeverity>,
}

impl OverrideAuditEvent {
    /// Construct a mutation row (admin upsert).
    #[must_use]
    pub fn mutation(
        tenant_id: &str,
        rule_name: &str,
        subkey: &str,
        action: OverrideAction,
        reason: &str,
        actor: &str,
    ) -> Self {
        Self {
            tenant_id: tenant_id.to_owned(),
            at: OffsetDateTime::now_utc(),
            kind: OverrideAuditKind::Mutation,
            rule_name: rule_name.to_owned(),
            subkey: subkey.to_owned(),
            action: Some(action),
            actor: actor.to_owned(),
            reason: reason.to_owned(),
            severity_before: None,
            severity_after: None,
        }
    }

    /// Construct a deletion row (admin delete).
    #[must_use]
    pub fn deletion(tenant_id: &str, rule_name: &str, subkey: &str, actor: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_owned(),
            at: OffsetDateTime::now_utc(),
            kind: OverrideAuditKind::Deletion,
            rule_name: rule_name.to_owned(),
            subkey: subkey.to_owned(),
            action: None,
            actor: actor.to_owned(),
            reason: String::new(),
            severity_before: None,
            severity_after: None,
        }
    }

    /// Construct an ingest-time application row.
    #[must_use]
    pub fn application(
        tenant_id: &str,
        rule_name: &str,
        subkey: &str,
        action: OverrideAction,
        reason: &str,
        severity_before: RuntimeSeverity,
        severity_after: Option<RuntimeSeverity>,
    ) -> Self {
        let kind = match action {
            OverrideAction::Deny => OverrideAuditKind::Suppressed,
            OverrideAction::Escalate => OverrideAuditKind::Escalated,
            OverrideAction::Downgrade => OverrideAuditKind::Downgraded,
            OverrideAction::Allow => OverrideAuditKind::Mutation, // unreachable in practice
        };
        Self {
            tenant_id: tenant_id.to_owned(),
            at: OffsetDateTime::now_utc(),
            kind,
            rule_name: rule_name.to_owned(),
            subkey: subkey.to_owned(),
            action: Some(action),
            actor: "runtime-ingest".to_owned(),
            reason: reason.to_owned(),
            severity_before: Some(severity_before),
            severity_after,
        }
    }
}

/// Persistence port for override audit rows.
#[async_trait]
pub trait OverrideAuditSink: Send + Sync + std::fmt::Debug {
    /// Persist the audit event. Implementations must be idempotent under
    /// retries.
    async fn record(&self, event: OverrideAuditEvent) -> Result<(), RuntimeError>;
}

/// No-op sink used when no audit backend is wired in.
#[derive(Debug, Default, Clone)]
pub struct NullOverrideAuditSink;

#[async_trait]
impl OverrideAuditSink for NullOverrideAuditSink {
    async fn record(&self, event: OverrideAuditEvent) -> Result<(), RuntimeError> {
        tracing::debug!(
            target: "sx_runtime",
            tenant_id = event.tenant_id,
            kind = event.kind.as_str(),
            rule = event.rule_name,
            subkey = event.subkey,
            "override audit (null sink)",
        );
        Ok(())
    }
}

/// In-memory recording sink — used in tests + admin-controller assertions.
#[derive(Debug, Default)]
pub struct RecordingOverrideAuditSink {
    inner: Arc<Mutex<Vec<OverrideAuditEvent>>>,
}

impl Clone for RecordingOverrideAuditSink {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl RecordingOverrideAuditSink {
    /// Construct an empty recording sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded events.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Internal`] only if the internal mutex
    /// was poisoned by a panicking writer.
    pub fn snapshot(&self) -> Result<Vec<OverrideAuditEvent>, RuntimeError> {
        self.inner
            .lock()
            .map(|g| g.clone())
            .map_err(|_| RuntimeError::Internal("override audit mutex poisoned".to_owned()))
    }
}

#[async_trait]
impl OverrideAuditSink for RecordingOverrideAuditSink {
    async fn record(&self, event: OverrideAuditEvent) -> Result<(), RuntimeError> {
        self.inner
            .lock()
            .map(|mut g| g.push(event))
            .map_err(|_| RuntimeError::Internal("override audit mutex poisoned".to_owned()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn null_sink_accepts_everything() {
        let s = NullOverrideAuditSink;
        s.record(OverrideAuditEvent::mutation(
            "t",
            "r",
            "*",
            OverrideAction::Deny,
            "x",
            "u",
        ))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn recording_sink_collects_events() {
        let s = RecordingOverrideAuditSink::new();
        s.record(OverrideAuditEvent::mutation(
            "t",
            "r",
            "*",
            OverrideAction::Deny,
            "x",
            "u",
        ))
        .await
        .unwrap();
        s.record(OverrideAuditEvent::deletion("t", "r", "*", "u"))
            .await
            .unwrap();
        let snap = s.snapshot().unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].kind, OverrideAuditKind::Mutation);
        assert_eq!(snap[1].kind, OverrideAuditKind::Deletion);
    }

    #[test]
    fn application_event_picks_kind_from_action() {
        let e = OverrideAuditEvent::application(
            "t",
            "r",
            "execve",
            OverrideAction::Escalate,
            "approved",
            RuntimeSeverity::Medium,
            Some(RuntimeSeverity::High),
        );
        assert_eq!(e.kind, OverrideAuditKind::Escalated);
        assert_eq!(e.severity_before, Some(RuntimeSeverity::Medium));
        assert_eq!(e.severity_after, Some(RuntimeSeverity::High));

        let d = OverrideAuditEvent::application(
            "t",
            "r",
            "openat",
            OverrideAction::Deny,
            "noisy",
            RuntimeSeverity::High,
            None,
        );
        assert_eq!(d.kind, OverrideAuditKind::Suppressed);
        assert_eq!(d.severity_after, None);
    }

    #[test]
    fn audit_event_round_trips_through_serde() {
        let e = OverrideAuditEvent::mutation(
            "t1",
            "rule-a",
            "execve",
            OverrideAction::Escalate,
            "MITRE T1611",
            "00000000-0000-0000-0000-000000000001",
        );
        let s = serde_json::to_string(&e).unwrap();
        let back: OverrideAuditEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.tenant_id, e.tenant_id);
        assert_eq!(back.kind, e.kind);
        assert_eq!(back.action, e.action);
    }
}
