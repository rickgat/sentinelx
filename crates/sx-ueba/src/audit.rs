//! Audit port for UEBA state transitions.
//!
//! The crate defines its own narrow port — [`UebaAuditSink`] — rather than
//! taking a hard dependency on the heavy `sx_audit::prelude::AuditSink`
//! trait, because:
//!
//! 1. The real `AuditSink::append` requires a fully-formed `AuditEntry`
//!    (chain-linked seq, hash, signature) which can only be assembled at the
//!    composition root. The UEBA service does not own that context — the
//!    monolith does.
//! 2. Wiring the lighter port means the unit test harness can assert on
//!    audit emissions without spinning up a hash chain.
//!
//! The default [`TracingUebaAuditSink`] forwards every event to the
//! `tracing` `info!` target `ueba.audit`; the monolith composition root may
//! swap in an adapter that bridges to `sx_audit::AuditAction::Custom`.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::info;

use crate::state::BaselineState;

/// One UEBA audit event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UebaAuditEvent {
    /// Tenant id the transition belongs to. Stringly typed at this layer
    /// to avoid pulling `sx_core::value_object::ids::TenantId` into a
    /// downstream-light crate; the adapter at the monolith parses it.
    pub tenant_id: String,
    /// Subject (user) id the transition belongs to.
    pub user_id: String,
    /// State the baseline was in before the transition.
    pub from_state: BaselineState,
    /// State the baseline ended up in after the transition.
    pub to_state: BaselineState,
    /// Operator identity that requested the transition. `None` means
    /// "auto-promotion" (the warm-up complete path).
    pub actor: Option<String>,
    /// Wall-clock time the transition was recorded.
    pub at: OffsetDateTime,
    /// Optional free-text reason supplied by the operator.
    pub reason: Option<String>,
}

impl UebaAuditEvent {
    /// Stable machine code for this audit event, suitable for inclusion as
    /// the `AuditAction::Custom { code }` discriminator on the persistent
    /// chain.
    #[must_use]
    pub fn action_code(&self) -> String {
        format!(
            "ueba.baseline.transition.{from}_to_{to}",
            from = self.from_state.code(),
            to = self.to_state.code(),
        )
    }
}

/// Audit sink port — append-only emission of UEBA state-transition events.
#[async_trait]
pub trait UebaAuditSink: Send + Sync + std::fmt::Debug {
    /// Record `event`. Implementations MUST NOT block on slow I/O on the
    /// hot path; if the underlying store is unavailable they should buffer
    /// or drop with a metric (the UEBA service treats the call as fire-
    /// and-forget — failing audit emission MUST NOT block the freeze /
    /// unfreeze itself, because the operator's incident-response window is
    /// the priority).
    async fn record(&self, event: UebaAuditEvent);
}

/// Default sink — forwards every event to `tracing::info!` so it lands in
/// the same place every other UEBA log line does.
#[derive(Debug, Default)]
pub struct TracingUebaAuditSink;

#[async_trait]
impl UebaAuditSink for TracingUebaAuditSink {
    async fn record(&self, event: UebaAuditEvent) {
        info!(
            target: "ueba.audit",
            tenant_id = event.tenant_id.as_str(),
            user_id = event.user_id.as_str(),
            from = event.from_state.code(),
            to = event.to_state.code(),
            actor = event.actor.as_deref().unwrap_or("system"),
            reason = event.reason.as_deref().unwrap_or(""),
            code = event.action_code().as_str(),
            "UEBA baseline state transition",
        );
    }
}

/// In-memory capturing sink used by tests.
#[derive(Debug, Default, Clone)]
pub struct CapturingUebaAuditSink {
    events: Arc<Mutex<Vec<UebaAuditEvent>>>,
}

impl CapturingUebaAuditSink {
    /// Construct an empty capturing sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain captured events (FIFO).
    ///
    /// Returns an empty `Vec` if the internal lock is poisoned (treated
    /// as "no events" rather than panicking — this sink is test-only,
    /// and a poisoned lock there is a test bug worth surfacing via the
    /// resulting assertion failure, not via a panic on the unwind path).
    #[must_use]
    pub fn drain(&self) -> Vec<UebaAuditEvent> {
        self.events
            .lock()
            .map(|mut g| g.drain(..).collect())
            .unwrap_or_default()
    }

    /// Number of events captured without draining. Returns `0` if the
    /// internal lock is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` when no events have been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl UebaAuditSink for CapturingUebaAuditSink {
    async fn record(&self, event: UebaAuditEvent) {
        if let Ok(mut g) = self.events.lock() {
            g.push(event);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn evt(from: BaselineState, to: BaselineState) -> UebaAuditEvent {
        UebaAuditEvent {
            tenant_id: "t-1".into(),
            user_id: "alice".into(),
            from_state: from,
            to_state: to,
            actor: Some("op@sx".into()),
            at: datetime!(2027-02-01 0:00:00 UTC),
            reason: Some("incident".into()),
        }
    }

    #[tokio::test]
    async fn tracing_sink_does_not_panic() {
        let sink = TracingUebaAuditSink;
        sink.record(evt(BaselineState::Active, BaselineState::Frozen))
            .await;
    }

    #[tokio::test]
    async fn capturing_sink_records_and_drains() {
        let sink = CapturingUebaAuditSink::new();
        assert!(sink.is_empty());
        sink.record(evt(BaselineState::Active, BaselineState::Frozen))
            .await;
        sink.record(evt(BaselineState::Frozen, BaselineState::Active))
            .await;
        assert_eq!(sink.len(), 2);
        let drained = sink.drain();
        assert_eq!(drained.len(), 2);
        assert!(sink.is_empty());
    }

    #[test]
    fn action_code_is_stable() {
        let e = evt(BaselineState::Active, BaselineState::Frozen);
        assert_eq!(e.action_code(), "ueba.baseline.transition.active_to_frozen");
    }
}
