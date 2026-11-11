//! Audit-sink port for signing-key rotation events (MED-003).
//!
//! Every rotation event — admin force-rotate, background auto-rotate,
//! retirement of an aged-out key — must be auditable. This crate
//! declares the narrow trait + an [`InMemoryRotationAuditSink`] for
//! tests; the composition root in `sx-monolith` adapts it to the
//! workspace-wide `sx_audit::AuditSink` chain.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::key::Kid;

/// One audit event recorded per rotation transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationAuditEvent {
    /// Tenant the rotation belongs to.
    pub tenant_id: String,
    /// Discrete transition kind.
    pub kind: RotationAuditKind,
    /// Affected kid (the *new* kid on `Minted`, the *retired* kid on
    /// `Retired`).
    pub kid: Kid,
    /// Optional companion kid (the *old* kid on `Minted`, when there
    /// was one).
    pub companion_kid: Option<Kid>,
    /// Operator subject claim when the call originated from the admin
    /// surface; `None` for background-loop rotations.
    pub actor: Option<String>,
    /// Wall-clock stamp.
    pub at: DateTime<Utc>,
    /// One-of-the-following stable reason code.
    pub reason: &'static str,
}

/// Discrete rotation-transition kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationAuditKind {
    /// A new key was minted (the previous active key, if any, is in
    /// `companion_kid`).
    Minted,
    /// An aged-out key was retired.
    Retired,
}

impl RotationAuditKind {
    /// Stable lower-snake string used in `sx-audit` action codes.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Minted => "webhook_key_minted",
            Self::Retired => "webhook_key_retired",
        }
    }
}

/// Persistence port for rotation audit events.
#[async_trait]
pub trait RotationAuditSink: Send + Sync + std::fmt::Debug {
    /// Persist a rotation event. Implementations MUST never log the
    /// secret bytes (none are passed in anyway).
    async fn record(&self, event: RotationAuditEvent);
}

#[async_trait]
impl<T: RotationAuditSink + ?Sized> RotationAuditSink for Arc<T> {
    async fn record(&self, event: RotationAuditEvent) {
        (**self).record(event).await;
    }
}

/// In-memory sink. Useful in tests for asserting the rotator emitted
/// the expected events.
#[derive(Debug, Default, Clone)]
pub struct InMemoryRotationAuditSink {
    inner: Arc<Mutex<Vec<RotationAuditEvent>>>,
}

impl InMemoryRotationAuditSink {
    /// Construct an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every recorded event so far.
    #[must_use]
    pub fn events(&self) -> Vec<RotationAuditEvent> {
        self.inner.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl RotationAuditSink for InMemoryRotationAuditSink {
    async fn record(&self, event: RotationAuditEvent) {
        if let Ok(mut g) = self.inner.lock() {
            g.push(event);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names
)]
mod tests {
    use super::*;

    #[test]
    fn audit_kind_codes_are_stable() {
        assert_eq!(RotationAuditKind::Minted.code(), "webhook_key_minted");
        assert_eq!(RotationAuditKind::Retired.code(), "webhook_key_retired");
    }

    #[tokio::test]
    async fn in_memory_sink_records_events() {
        let s = InMemoryRotationAuditSink::new();
        s.record(RotationAuditEvent {
            tenant_id: "t".into(),
            kind: RotationAuditKind::Minted,
            kid: Kid::new("kid_aa"),
            companion_kid: None,
            actor: Some("admin@example.com".into()),
            at: Utc::now(),
            reason: "admin_force",
        })
        .await;
        let evs = s.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, RotationAuditKind::Minted);
        assert_eq!(evs[0].actor.as_deref(), Some("admin@example.com"));
    }
}
