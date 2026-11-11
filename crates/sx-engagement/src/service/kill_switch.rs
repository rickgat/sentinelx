//! `KillSwitch` trait + in-memory implementation.
//!
//! # Propagation guarantee
//!
//! `is_tripped` reflects the latest tripped state immediately after `trip`
//! returns. Subscribers are notified asynchronously via the broadcast channel
//! and receive their event within their own channel latency (bounded by the
//! configured channel capacity).
//!
//! The Redis-backed implementation lives in a downstream adapter crate and
//! is wired by the composition root.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::{EngagementId, TenantId};
use tokio::sync::{broadcast, RwLock};
use tracing::warn;

use crate::error::EngagementError;

/// Scope at which the kill-switch fires.
///
/// `Global` halts every engagement across every tenant; `Tenant` halts every
/// engagement for one tenant; `Engagement` halts a single engagement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KillSwitchScope {
    /// Halt every engagement, every tenant.
    Global,
    /// Halt every engagement for one tenant.
    Tenant(TenantId),
    /// Halt a single engagement.
    Engagement(TenantId, EngagementId),
}

impl std::fmt::Display for KillSwitchScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global => f.write_str("global"),
            Self::Tenant(t) => write!(f, "tenant={t}"),
            Self::Engagement(t, e) => write!(f, "engagement(tenant={t},id={e})"),
        }
    }
}

/// Why the kill switch was tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillReason {
    /// Manual operator action.
    Manual,
    /// Auto-tripped by anomaly detection.
    Anomaly,
    /// Tripped because a scope violation was detected mid-flight.
    ScopeViolation,
    /// Generic emergency stop (e.g. SRE breaking glass).
    EmergencyStop,
}

impl std::fmt::Display for KillReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Manual => "manual",
            Self::Anomaly => "anomaly",
            Self::ScopeViolation => "scope_violation",
            Self::EmergencyStop => "emergency_stop",
        };
        f.write_str(s)
    }
}

/// Event broadcast to subscribers when the switch is tripped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchEvent {
    /// The scope that was tripped.
    pub scope: KillSwitchScope,
    /// Why it was tripped.
    pub reason: KillReason,
    /// When it was tripped (server-wall-clock).
    pub at: time::OffsetDateTime,
}

/// Kill-switch port. Production wires this to a Redis-pub/sub adapter.
#[async_trait]
pub trait KillSwitch: Send + Sync + std::fmt::Debug {
    /// Trip the switch for `scope`. Idempotent.
    async fn trip(&self, scope: KillSwitchScope, reason: KillReason)
        -> Result<(), EngagementError>;

    /// Returns `true` when `scope` (or any wider scope that contains it) is
    /// tripped.
    async fn is_tripped(&self, scope: KillSwitchScope) -> Result<bool, EngagementError>;

    /// Subscribe to live trip events. Each call returns a fresh receiver.
    fn subscribe(&self) -> broadcast::Receiver<KillSwitchEvent>;
}

/// Default channel capacity for [`InMemoryKillSwitch`] subscribers.
const DEFAULT_CHANNEL_CAPACITY: usize = 64;

/// In-memory implementation, suitable for tests and single-process workloads.
///
/// Backed by an `RwLock<HashSet<KillSwitchScope>>` for state and a
/// `tokio::sync::broadcast` for subscribers.
#[derive(Debug, Clone)]
pub struct InMemoryKillSwitch {
    inner: Arc<InMemoryInner>,
}

#[derive(Debug)]
struct InMemoryInner {
    tripped: RwLock<HashSet<KillSwitchScope>>,
    tx: broadcast::Sender<KillSwitchEvent>,
}

impl InMemoryKillSwitch {
    /// Construct with the default channel capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY)
    }

    /// Construct with a specific broadcast channel capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self {
            inner: Arc::new(InMemoryInner {
                tripped: RwLock::new(HashSet::new()),
                tx,
            }),
        }
    }
}

impl Default for InMemoryKillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KillSwitch for InMemoryKillSwitch {
    async fn trip(
        &self,
        scope: KillSwitchScope,
        reason: KillReason,
    ) -> Result<(), EngagementError> {
        {
            let mut guard = self.inner.tripped.write().await;
            guard.insert(scope);
        }
        let event = KillSwitchEvent {
            scope,
            reason,
            at: time::OffsetDateTime::now_utc(),
        };
        // Broadcast send fails only when there are zero receivers; that is
        // not an error — just nothing is listening yet.
        let _ = self.inner.tx.send(event);
        warn!(
            target = "sx_engagement::kill_switch",
            event = "tripped",
            scope = %scope,
            reason = %reason,
            "kill switch tripped",
        );
        Ok(())
    }

    async fn is_tripped(&self, scope: KillSwitchScope) -> Result<bool, EngagementError> {
        let guard = self.inner.tripped.read().await;
        Ok(scope_or_wider_tripped(&guard, scope))
    }

    fn subscribe(&self) -> broadcast::Receiver<KillSwitchEvent> {
        self.inner.tx.subscribe()
    }
}

/// Returns `true` if `query` (or any wider scope containing it) is in `set`.
fn scope_or_wider_tripped(set: &HashSet<KillSwitchScope>, query: KillSwitchScope) -> bool {
    if set.contains(&KillSwitchScope::Global) {
        return true;
    }
    match query {
        KillSwitchScope::Global => set.contains(&KillSwitchScope::Global),
        KillSwitchScope::Tenant(t) => set.contains(&KillSwitchScope::Tenant(t)),
        KillSwitchScope::Engagement(t, _) => {
            set.contains(&query) || set.contains(&KillSwitchScope::Tenant(t))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_core::value_object::ids::{EngagementId, TenantId};
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn global_blocks_all() {
        let ks = InMemoryKillSwitch::new();
        ks.trip(KillSwitchScope::Global, KillReason::EmergencyStop)
            .await
            .unwrap();
        let tenant = TenantId::new();
        let eng = EngagementId::new();
        assert!(ks
            .is_tripped(KillSwitchScope::Tenant(tenant))
            .await
            .unwrap());
        assert!(ks
            .is_tripped(KillSwitchScope::Engagement(tenant, eng))
            .await
            .unwrap());
        assert!(ks.is_tripped(KillSwitchScope::Global).await.unwrap());
    }

    #[tokio::test]
    async fn tenant_isolated_from_others() {
        let ks = InMemoryKillSwitch::new();
        let t1 = TenantId::new();
        let t2 = TenantId::new();
        ks.trip(KillSwitchScope::Tenant(t1), KillReason::Manual)
            .await
            .unwrap();
        assert!(ks.is_tripped(KillSwitchScope::Tenant(t1)).await.unwrap());
        assert!(!ks.is_tripped(KillSwitchScope::Tenant(t2)).await.unwrap());
        // engagement under t1 is implicitly tripped
        let e1 = EngagementId::new();
        assert!(ks
            .is_tripped(KillSwitchScope::Engagement(t1, e1))
            .await
            .unwrap());
        // engagement under t2 is not
        assert!(!ks
            .is_tripped(KillSwitchScope::Engagement(t2, e1))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn engagement_scope_does_not_leak_to_tenant() {
        let ks = InMemoryKillSwitch::new();
        let t = TenantId::new();
        let e = EngagementId::new();
        ks.trip(KillSwitchScope::Engagement(t, e), KillReason::Anomaly)
            .await
            .unwrap();
        assert!(ks
            .is_tripped(KillSwitchScope::Engagement(t, e))
            .await
            .unwrap());
        assert!(!ks.is_tripped(KillSwitchScope::Tenant(t)).await.unwrap());
    }

    #[tokio::test]
    async fn subscriber_receives_event() {
        let ks = InMemoryKillSwitch::new();
        let mut rx = ks.subscribe();
        ks.trip(KillSwitchScope::Global, KillReason::Manual)
            .await
            .unwrap();
        let evt = timeout(Duration::from_secs(1), rx.recv()).await.unwrap();
        let evt = evt.unwrap();
        assert_eq!(evt.scope, KillSwitchScope::Global);
        assert_eq!(evt.reason, KillReason::Manual);
    }

    #[tokio::test]
    async fn multiple_subscribers_each_receive_event() {
        let ks = InMemoryKillSwitch::new();
        let mut r1 = ks.subscribe();
        let mut r2 = ks.subscribe();
        ks.trip(KillSwitchScope::Global, KillReason::Manual)
            .await
            .unwrap();
        let e1 = timeout(Duration::from_secs(1), r1.recv())
            .await
            .unwrap()
            .unwrap();
        let e2 = timeout(Duration::from_secs(1), r2.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e1, e2);
    }

    #[tokio::test]
    async fn trip_is_idempotent() {
        let ks = InMemoryKillSwitch::new();
        ks.trip(KillSwitchScope::Global, KillReason::Manual)
            .await
            .unwrap();
        ks.trip(KillSwitchScope::Global, KillReason::Manual)
            .await
            .unwrap();
        assert!(ks.is_tripped(KillSwitchScope::Global).await.unwrap());
    }
}
