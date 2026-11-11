//! Audit sink for K8s admission decisions.
//!
//! HIGH-009 emits one audit row PER admission request — allow OR deny —
//! so an investigator can reconstruct exactly which workloads passed
//! through the webhook and which were rejected, including the
//! sanitised request payload that produced each decision.
//!
//! This module defines a narrow port ([`K8sAdmissionAuditSink`]) so
//! `sx-discovery` does not pull a hard dependency on `sx-audit`. The
//! composition root in `sx-monolith` bridges these events into the
//! tenant-wide hash-chained audit sink. Tests use
//! [`RecordingK8sAdmissionAuditSink`] (in-memory) or
//! [`NullK8sAdmissionAuditSink`] (drops).
//!
//! ## Retention
//!
//! Per the HIGH-009 spec, admission audit rows have a 90-day retention
//! target. The constant [`AUDIT_RETENTION_DAYS`] is published so the
//! downstream sink can apply the policy at write or vacuum time. The
//! audit event itself carries the constant in its `retention_days`
//! field so downstream consumers do not need to special-case the
//! source.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::types::AdmissionRequest;

/// HIGH-009 admission-audit retention target.
pub const AUDIT_RETENTION_DAYS: u32 = 90;

/// Decision recorded on each admission audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum K8sAdmissionDecision {
    /// Webhook returned `allowed=true`. No rule denied.
    Allow,
    /// Webhook returned `allowed=false`. One or more rules denied.
    Deny,
    /// Dry-run mode: the webhook returned `allowed=true` but at least
    /// one rule WOULD have denied the request. The audit row captures
    /// the would-deny reason in `reason` so an operator can preview
    /// enforcement impact.
    DryRunWouldDeny,
}

impl K8sAdmissionDecision {
    /// Canonical lowercase label, used in metrics and audit rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::DryRunWouldDeny => "dry_run_would_deny",
        }
    }
}

/// One audit row per admission decision.
///
/// The full sanitised [`AdmissionRequest`] is retained so an
/// investigator can reconstruct exactly what was `POSTed`. The audit
/// sink is responsible for any further redaction (e.g. dropping
/// `runtime/Secret` payloads) when the downstream sink has a stricter
/// content policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sAdmissionAuditEvent {
    /// Owning tenant (string form to keep the discovery crate free of a
    /// `Uuid` dependency on its public surface).
    pub tenant_id: String,
    /// Wall-clock time the decision was made.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// `AdmissionRequest.uid` — echoed for correlation with apiserver
    /// audit logs.
    pub request_uid: String,
    /// Resolved Kubernetes Kind (`Pod`, `Deployment`, ...) when present.
    pub kind: Option<String>,
    /// Target namespace (`None` for cluster-scoped resources).
    pub namespace: Option<String>,
    /// Verb (`CREATE`, `UPDATE`, `DELETE`, `CONNECT`) when present.
    pub operation: Option<String>,
    /// Effective decision.
    pub decision: K8sAdmissionDecision,
    /// Rule id (`pss-restricted`, `no-privileged`, ...) that produced
    /// the decision. `None` on allow when no rule was consulted (e.g.
    /// namespace opt-out).
    pub rule_id: Option<String>,
    /// Human-readable deny reason — populated for `Deny` and
    /// `DryRunWouldDeny`. Never carries secret material.
    pub reason: Option<String>,
    /// Sanitised request envelope; the engine forwards the parsed
    /// request as-is — downstream sinks may redact further before
    /// writing.
    pub request: AdmissionRequest,
    /// Retention target for this event in days. Always
    /// [`AUDIT_RETENTION_DAYS`].
    pub retention_days: u32,
}

impl K8sAdmissionAuditEvent {
    /// Convenience constructor stamped at wall clock with retention set
    /// to [`AUDIT_RETENTION_DAYS`].
    #[must_use]
    pub fn new(
        tenant_id: &str,
        request: &AdmissionRequest,
        decision: K8sAdmissionDecision,
        rule_id: Option<String>,
        reason: Option<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.to_owned(),
            at: OffsetDateTime::now_utc(),
            request_uid: request.uid.clone(),
            kind: request.kind.as_ref().map(|k| k.kind.clone()),
            namespace: request.namespace.clone(),
            operation: request.operation.clone(),
            decision,
            rule_id,
            reason,
            request: request.clone(),
            retention_days: AUDIT_RETENTION_DAYS,
        }
    }
}

/// Persistence port for admission audit events. Implementations MUST
/// be idempotent under retries.
#[async_trait]
pub trait K8sAdmissionAuditSink: Send + Sync + std::fmt::Debug {
    /// Persist `event`. Errors are swallowed by the engine after a
    /// `tracing::warn!` so a transient audit-sink failure cannot
    /// translate into an apiserver-side admission failure (the engine
    /// fails OPEN on audit-sink errors — failing closed would brick the
    /// cluster the moment Postgres has a hiccup).
    async fn record(&self, event: K8sAdmissionAuditEvent) -> Result<(), AuditSinkError>;
}

/// Error returned by [`K8sAdmissionAuditSink::record`].
#[derive(Debug, thiserror::Error)]
pub enum AuditSinkError {
    /// Transient persistence error (DB down, retry-eligible).
    #[error("transient: {0}")]
    Transient(String),
    /// Permanent error (schema mismatch, etc.).
    #[error("permanent: {0}")]
    Permanent(String),
}

/// No-op sink used in tests and during incremental rollout.
#[derive(Debug, Default, Clone)]
pub struct NullK8sAdmissionAuditSink;

#[async_trait]
impl K8sAdmissionAuditSink for NullK8sAdmissionAuditSink {
    async fn record(&self, event: K8sAdmissionAuditEvent) -> Result<(), AuditSinkError> {
        tracing::debug!(
            target: "sx_discovery::k8s_admission",
            tenant_id = %event.tenant_id,
            uid = %event.request_uid,
            decision = event.decision.as_str(),
            rule = ?event.rule_id,
            "admission audit (null sink)",
        );
        Ok(())
    }
}

/// In-memory sink used by tests to assert on recorded events.
#[derive(Debug, Default)]
pub struct RecordingK8sAdmissionAuditSink {
    inner: Arc<Mutex<Vec<K8sAdmissionAuditEvent>>>,
}

impl Clone for RecordingK8sAdmissionAuditSink {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl RecordingK8sAdmissionAuditSink {
    /// Construct an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of all events recorded so far.
    #[allow(clippy::missing_panics_doc, clippy::expect_used)] // Mutex poisoning is a bug.
    #[must_use]
    pub fn events(&self) -> Vec<K8sAdmissionAuditEvent> {
        self.inner.lock().expect("recording lock poisoned").clone()
    }

    /// Count of events recorded.
    #[allow(clippy::missing_panics_doc, clippy::expect_used)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("recording lock poisoned").len()
    }

    /// True when no events recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl K8sAdmissionAuditSink for RecordingK8sAdmissionAuditSink {
    #[allow(clippy::expect_used)] // Mutex poisoning is a bug; bubbling it as an Err would obscure the actual fault.
    async fn record(&self, event: K8sAdmissionAuditEvent) -> Result<(), AuditSinkError> {
        self.inner
            .lock()
            .expect("recording lock poisoned")
            .push(event);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::k8s_admission::types::{AdmissionRequest, GroupVersionKind};

    fn sample_request(uid: &str) -> AdmissionRequest {
        AdmissionRequest {
            uid: uid.into(),
            kind: Some(GroupVersionKind {
                group: String::new(),
                version: "v1".into(),
                kind: "Pod".into(),
            }),
            name: Some("nginx".into()),
            namespace: Some("default".into()),
            operation: Some("CREATE".into()),
            object: None,
            old_object: None,
            user_info: None,
            dry_run: Some(false),
        }
    }

    #[test]
    fn audit_event_default_retention_is_90_days() {
        let req = sample_request("u-1");
        let ev = K8sAdmissionAuditEvent::new("t-a", &req, K8sAdmissionDecision::Allow, None, None);
        assert_eq!(ev.retention_days, AUDIT_RETENTION_DAYS);
        assert_eq!(ev.retention_days, 90);
        assert_eq!(ev.tenant_id, "t-a");
        assert_eq!(ev.request_uid, "u-1");
        assert_eq!(ev.kind.as_deref(), Some("Pod"));
        assert_eq!(ev.namespace.as_deref(), Some("default"));
    }

    #[test]
    fn decision_labels_are_stable() {
        assert_eq!(K8sAdmissionDecision::Allow.as_str(), "allow");
        assert_eq!(K8sAdmissionDecision::Deny.as_str(), "deny");
        assert_eq!(
            K8sAdmissionDecision::DryRunWouldDeny.as_str(),
            "dry_run_would_deny",
        );
    }

    #[tokio::test]
    async fn null_sink_swallows_everything() {
        let req = sample_request("u-1");
        let ev = K8sAdmissionAuditEvent::new("t-a", &req, K8sAdmissionDecision::Allow, None, None);
        let sink = NullK8sAdmissionAuditSink;
        assert!(sink.record(ev).await.is_ok());
    }

    #[tokio::test]
    async fn recording_sink_round_trips_events_in_order() {
        let sink = RecordingK8sAdmissionAuditSink::new();
        assert!(sink.is_empty());
        for uid in ["a", "b", "c"] {
            let req = sample_request(uid);
            let ev =
                K8sAdmissionAuditEvent::new("t-a", &req, K8sAdmissionDecision::Allow, None, None);
            sink.record(ev).await.unwrap();
        }
        assert_eq!(sink.len(), 3);
        let events = sink.events();
        assert_eq!(events[0].request_uid, "a");
        assert_eq!(events[2].request_uid, "c");
    }

    #[tokio::test]
    async fn recording_sink_is_shared_across_clones() {
        let sink = RecordingK8sAdmissionAuditSink::new();
        let clone = sink.clone();
        let req = sample_request("u");
        let ev = K8sAdmissionAuditEvent::new(
            "t",
            &req,
            K8sAdmissionDecision::Deny,
            Some("no-privileged".into()),
            Some("denied".into()),
        );
        clone.record(ev).await.unwrap();
        assert_eq!(sink.len(), 1, "writes via clone visible on original");
    }
}
