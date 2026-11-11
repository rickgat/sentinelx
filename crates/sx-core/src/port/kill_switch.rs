//! Canonical kill-switch port.
//!
//! A kill switch is a propagating "stop" signal that engagement and discovery
//! services consult before doing anything destructive. The
//! [`KillSwitchPort`] trait is intentionally minimal so the same contract can
//! be implemented by an in-process mock, a Redis adapter, or a distributed
//! consensus store.
//!
//! Scope hierarchy (wider scopes contain narrower ones):
//! ```text
//! Global ⊃ Tenant(t) ⊃ Engagement(t, e)
//! ```
//! [`KillSwitchPort::is_tripped`] returns `true` for a query when either the
//! exact scope OR any wider scope has been tripped.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::DomainError;
use crate::value_object::ids::{EngagementId, TenantId};

/// The scope at which a kill-switch is tripped.
///
/// Wider scopes implicitly contain narrower ones (see module-level docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum KillSwitchScope {
    /// Trip every probe across every tenant.
    Global,
    /// Trip every probe for a single tenant.
    Tenant(TenantId),
    /// Trip a single engagement, identified by `(tenant_id, engagement_id)`.
    Engagement(TenantId, EngagementId),
}

impl fmt::Display for KillSwitchScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => f.write_str("global"),
            Self::Tenant(t) => write!(f, "tenant={t}"),
            Self::Engagement(t, e) => write!(f, "engagement(tenant={t},id={e})"),
        }
    }
}

impl KillSwitchScope {
    /// `true` when `self` contains `other` (i.e. tripping `self` implies
    /// `other` is also tripped).
    #[must_use]
    pub fn contains(self, other: Self) -> bool {
        match (self, other) {
            (Self::Global, _) => true,
            (Self::Tenant(t1), Self::Tenant(t2) | Self::Engagement(t2, _)) => t1 == t2,
            (Self::Engagement(t1, e1), Self::Engagement(t2, e2)) => t1 == t2 && e1 == e2,
            _ => false,
        }
    }
}

/// Canonical kill-switch port — generic across in-memory, Redis, or
/// consensus-backed adapters.
///
/// Implementations MUST be idempotent: tripping the same scope twice is a
/// no-op. `is_tripped(scope)` MUST return `true` when `scope` OR any scope
/// containing it (via [`KillSwitchScope::contains`]) is currently tripped.
#[async_trait]
pub trait KillSwitchPort: Send + Sync {
    /// `true` when `scope` (or any wider scope containing it) is tripped.
    ///
    /// # Errors
    /// Adapter errors surface as [`DomainError::Repository`].
    async fn is_tripped(&self, scope: KillSwitchScope) -> Result<bool, DomainError>;

    /// Trip the switch for `scope`. Idempotent.
    ///
    /// `reason` is a short operator-friendly free-form string used for
    /// audit-log routing. Adapters MUST persist (or broadcast) the trip
    /// before returning.
    ///
    /// # Errors
    /// Adapter errors surface as [`DomainError::Repository`].
    async fn trip(&self, scope: KillSwitchScope, reason: &str) -> Result<(), DomainError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn kill_switch_scope_round_trip_serde() {
        let global = KillSwitchScope::Global;
        let tenant = KillSwitchScope::Tenant(TenantId::new());
        let eng = KillSwitchScope::Engagement(TenantId::new(), EngagementId::new());

        for scope in [global, tenant, eng] {
            let json = serde_json::to_string(&scope).unwrap();
            let back: KillSwitchScope = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, back, "serde round-trip failed for {scope}");
        }
    }

    #[test]
    fn contains_hierarchy() {
        let t = TenantId::new();
        let other_tenant = TenantId::new();
        let e = EngagementId::new();
        let global = KillSwitchScope::Global;
        let tenant = KillSwitchScope::Tenant(t);
        let other = KillSwitchScope::Tenant(other_tenant);
        let eng = KillSwitchScope::Engagement(t, e);
        let other_eng = KillSwitchScope::Engagement(other_tenant, e);

        assert!(global.contains(global));
        assert!(global.contains(tenant));
        assert!(global.contains(eng));

        assert!(tenant.contains(tenant));
        assert!(tenant.contains(eng));
        assert!(!tenant.contains(global));
        assert!(!tenant.contains(other));
        assert!(!tenant.contains(other_eng));

        assert!(eng.contains(eng));
        assert!(!eng.contains(tenant));
        assert!(!eng.contains(global));
    }

    #[test]
    fn display_is_stable() {
        assert_eq!(KillSwitchScope::Global.to_string(), "global");
        let t = TenantId::new();
        assert!(KillSwitchScope::Tenant(t)
            .to_string()
            .starts_with("tenant="));
        let e = EngagementId::new();
        assert!(KillSwitchScope::Engagement(t, e)
            .to_string()
            .starts_with("engagement"));
    }
}
