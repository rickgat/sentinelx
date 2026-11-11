//! Audit logging for the Prowler import pipeline.
//!
//! The acceptance criteria require an audit-log entry per import. The trait
//! is intentionally minimal so the API crate (or `sx-audit`) can plug in a
//! real persistent log without dragging extra dependencies into
//! `sx-discovery`.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::contracts::TenantId;

/// One row in the import audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProwlerImportAuditEvent {
    /// UUID v7 row id.
    pub id: Uuid,
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Free-form actor identifier (`user:alice@example.com`, `svc:ci-bot`, …).
    pub actor: String,
    /// Hex-encoded SHA-256 of the uploaded bytes (or another stable digest).
    pub upload_digest: String,
    /// Original upload size in bytes.
    pub upload_bytes: u64,
    /// Total parsed findings (post-filter, pre-dedupe).
    pub parsed_findings: u32,
    /// Number written to the multicloud table.
    pub written_findings: u32,
    /// Number of cross-tenant rejected findings.
    pub rejected_cross_tenant: u32,
    /// Number of findings dropped by in-batch dedupe.
    pub deduplicated: u32,
    /// `true` iff at least one KEV uplift fired.
    pub kev_uplifts_applied: u32,
    /// Wall-clock time the audit row was written.
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
}

/// Sink for audit events. Implementations must be cheap to clone and
/// thread-safe.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Record `event`.
    fn record(&self, event: ProwlerImportAuditEvent);
}

/// No-op sink. Drops every event silently.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&self, _event: ProwlerImportAuditEvent) {}
}

/// In-memory recording sink — useful for tests.
#[derive(Debug, Default)]
pub struct RecordingAuditSink {
    events: Mutex<Vec<ProwlerImportAuditEvent>>,
}

impl RecordingAuditSink {
    /// New empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded events.
    #[must_use]
    pub fn events(&self) -> Vec<ProwlerImportAuditEvent> {
        match self.events.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Number of events recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.events.lock() {
            Ok(g) => g.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// `true` iff no events recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditSink for RecordingAuditSink {
    fn record(&self, event: ProwlerImportAuditEvent) {
        match self.events.lock() {
            Ok(mut g) => g.push(event),
            Err(poisoned) => poisoned.into_inner().push(event),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample(tenant: TenantId) -> ProwlerImportAuditEvent {
        ProwlerImportAuditEvent {
            id: Uuid::now_v7(),
            tenant_id: tenant,
            actor: "user:test".into(),
            upload_digest: "abc".into(),
            upload_bytes: 42,
            parsed_findings: 3,
            written_findings: 2,
            rejected_cross_tenant: 0,
            deduplicated: 1,
            kev_uplifts_applied: 0,
            recorded_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn recording_sink_captures_events() {
        let sink = RecordingAuditSink::new();
        assert!(sink.is_empty());
        let t = TenantId::new();
        sink.record(sample(t));
        sink.record(sample(t));
        assert_eq!(sink.len(), 2);
        assert_eq!(sink.events().len(), 2);
    }

    #[test]
    fn null_sink_silently_drops() {
        let sink = NullAuditSink;
        sink.record(sample(TenantId::new()));
    }
}
