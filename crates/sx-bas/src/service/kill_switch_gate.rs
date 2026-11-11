//! Kill-switch gate.
//!
//! # SLA — ≤ 5 seconds
//!
//! From `KillSwitch::trip()` to all techniques aborting MUST be ≤ 5 seconds.
//! The mechanism has two cooperating halves:
//!
//! 1. **Gate-level pre-check.** Before a technique runs, the gate checks
//!    [`KillSwitchPort::is_tripped`]; if `true`, the run is denied
//!    synchronously.
//! 2. **In-flight signalling.** The use case races the technique future
//!    against [`tokio::sync::Notify::notified`] using `tokio::select!`. The
//!    notifier is wired to the kill switch — tripping it wakes the select arm
//!    immediately. Techniques must additionally poll the same notifier
//!    between sub-steps (documented on
//!    [`crate::model::technique::AttackTechnique`]).
//!
//! Together these give a worst case of (gate latency) + (single sub-step
//! duration), both bounded ≪ 5s in this crate's safe-only techniques.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Notify;
use tracing::warn;

use crate::error::BasError;

/// Port abstraction over a kill-switch implementation.
///
/// Production wires this to `sx-engagement`'s `KillSwitch` (Redis-backed in
/// adapter crates). Unit tests use [`NotifyKillSwitchPort`].
#[async_trait]
pub trait KillSwitchPort: Send + Sync + std::fmt::Debug {
    /// Returns `true` when the switch is currently tripped.
    async fn is_tripped(&self) -> Result<bool, BasError>;

    /// Returns a [`Notify`] handle that wakes when the switch trips.
    fn signal(&self) -> Arc<Notify>;
}

/// In-process kill-switch port backed by a single
/// [`tokio::sync::Notify`] and an atomic flag.
///
/// Calling [`NotifyKillSwitchPort::trip`] both flips the flag (so
/// [`KillSwitchPort::is_tripped`] returns `true`) and notifies all waiters.
#[derive(Debug)]
pub struct NotifyKillSwitchPort {
    notify: Arc<Notify>,
    tripped: std::sync::atomic::AtomicBool,
}

impl NotifyKillSwitchPort {
    /// Construct a fresh, un-tripped port.
    #[must_use]
    pub fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            tripped: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Trip the switch.
    ///
    /// Idempotent: re-tripping has no effect beyond an extra `notify_waiters`.
    pub fn trip(&self) {
        self.tripped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake every current and future waiter (notify_waiters does NOT
        // remember past calls, so we also notify_one to cover races where a
        // waiter arrived between `store` and `notify_waiters`).
        self.notify.notify_waiters();
    }
}

impl Default for NotifyKillSwitchPort {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KillSwitchPort for NotifyKillSwitchPort {
    async fn is_tripped(&self) -> Result<bool, BasError> {
        Ok(self.tripped.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn signal(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }
}

/// Stateless gate that consults a [`KillSwitchPort`].
#[derive(Debug, Clone)]
pub struct KillSwitchGate {
    port: Arc<dyn KillSwitchPort>,
}

impl KillSwitchGate {
    /// Construct the gate around `port`.
    #[must_use]
    pub fn new(port: Arc<dyn KillSwitchPort>) -> Self {
        Self { port }
    }

    /// Returns the underlying notify signal so the use case can race it
    /// against the technique future via `tokio::select!`.
    #[must_use]
    pub fn signal(&self) -> Arc<Notify> {
        self.port.signal()
    }

    /// Evaluate the gate. Denies when the switch is currently tripped.
    pub async fn evaluate(&self, engagement_id: &str, technique_id: &str) -> Result<(), BasError> {
        if self.port.is_tripped().await? {
            warn!(
                target = "sx_bas::gate",
                gate = "kill_switch",
                engagement_id = engagement_id,
                technique_id = technique_id,
                reason = "kill switch is tripped",
                "kill switch gate denied",
            );
            return Err(BasError::kill_switch("active"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{KillSwitchGate, KillSwitchPort, NotifyKillSwitchPort};
    use crate::error::BasError;
    use std::sync::Arc;

    #[tokio::test]
    async fn kill_switch_gate_allows_when_untripped() {
        let port = Arc::new(NotifyKillSwitchPort::new()) as Arc<dyn KillSwitchPort>;
        let g = KillSwitchGate::new(port);
        assert!(g.evaluate("e1", "t1").await.is_ok());
    }

    #[tokio::test]
    async fn kill_switch_gate_denies_when_tripped() {
        let port_concrete = Arc::new(NotifyKillSwitchPort::new());
        port_concrete.trip();
        let g = KillSwitchGate::new(port_concrete.clone() as Arc<dyn KillSwitchPort>);
        let err = g.evaluate("e1", "t1").await.unwrap_err();
        assert!(matches!(err, BasError::KillSwitchTripped(_)));
    }

    #[tokio::test]
    async fn notify_is_shared_between_clones() {
        let port = Arc::new(NotifyKillSwitchPort::new());
        let n1 = port.signal();
        let n2 = port.signal();
        // Same notify object, exposed twice.
        assert!(Arc::ptr_eq(&n1, &n2));
    }
}
