//! Pre-flight safety gate.
//!
//! The [`SafetyGate`] fuses two independent allow / deny mechanisms into a
//! single call:
//!
//! 1. The engagement's [`crate::contracts::KillSwitch`] — if tripped at any
//!    scope the request belongs to, the gate denies immediately.
//! 2. The engagement's [`crate::contracts::ScopeValidator`] — every target
//!    must be in scope and not on the denylist.
//!
//! Both checks happen **before any packet leaves the process**. The order is
//! kill-switch first (cheapest, broadest), then scope check per target.

use std::sync::Arc;

use crate::contracts::{Engagement, KillSwitch, KillSwitchScope, ScanRequest, ScopeValidator};
use crate::error::DiscoveryError;

/// The pre-flight safety gate.
#[derive(Debug, Clone)]
pub struct SafetyGate {
    validator: Arc<dyn ScopeValidator>,
    kill: Arc<dyn KillSwitch>,
}

impl SafetyGate {
    /// Build a new gate from a validator and a kill switch.
    #[must_use]
    pub fn new(validator: Arc<dyn ScopeValidator>, kill: Arc<dyn KillSwitch>) -> Self {
        Self { validator, kill }
    }

    /// Borrow the kill switch — useful for subscribing to trips elsewhere
    /// in the orchestration loop.
    #[must_use]
    pub fn kill_switch(&self) -> Arc<dyn KillSwitch> {
        Arc::clone(&self.kill)
    }

    /// Run the gate. Returns `Ok(())` if every target is in scope and the
    /// kill switch is not tripped.
    pub async fn check(
        &self,
        engagement: &Engagement,
        req: &ScanRequest,
    ) -> Result<(), DiscoveryError> {
        // Cross-check tenant / engagement.
        if engagement.id != req.engagement_id {
            return Err(DiscoveryError::safety_gate(format!(
                "request engagement {} does not match loaded engagement {}",
                req.engagement_id, engagement.id,
            )));
        }
        if engagement.tenant_id != req.tenant_id {
            return Err(DiscoveryError::safety_gate(format!(
                "request tenant {} does not match engagement tenant {}",
                req.tenant_id, engagement.tenant_id,
            )));
        }
        // Intensity cap.
        let req_rank = intensity_rank(req.intensity);
        let max_rank = intensity_rank(engagement.max_intensity);
        if req_rank > max_rank {
            return Err(DiscoveryError::safety_gate(format!(
                "requested intensity {:?} exceeds engagement max {:?}",
                req.intensity, engagement.max_intensity,
            )));
        }
        // Kill switch — broadest first.
        let scopes = Self::scopes_for(engagement);
        if self.kill.is_tripped(&scopes).await {
            return Err(DiscoveryError::KillSwitchTripped);
        }
        // Scope per target.
        if req.targets.is_empty() {
            return Err(DiscoveryError::safety_gate("no targets in request"));
        }
        for t in &req.targets {
            self.validator.validate(engagement, t).await?;
        }
        Ok(())
    }

    /// Helper to construct the kill-switch scope set the engagement
    /// subscribes to. Does not depend on validator state and is therefore
    /// associated.
    #[must_use]
    pub fn scopes_for(engagement: &Engagement) -> Vec<KillSwitchScope> {
        vec![
            KillSwitchScope::Global,
            KillSwitchScope::Tenant(engagement.tenant_id),
            KillSwitchScope::Engagement(engagement.id),
        ]
    }
}

const fn intensity_rank(i: crate::contracts::ScanIntensity) -> u8 {
    match i {
        crate::contracts::ScanIntensity::Passive => 0,
        crate::contracts::ScanIntensity::Light => 1,
        crate::contracts::ScanIntensity::Standard => 2,
        crate::contracts::ScanIntensity::Aggressive => 3,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::contracts::{
        EngagementId, Fqdn, InMemoryKillSwitch, InMemoryScopeValidator, ScanIntensity, ScopeTarget,
        TenantId,
    };

    fn engagement() -> Engagement {
        Engagement {
            id: EngagementId::new(),
            tenant_id: TenantId::new(),
            allowed_scope: vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())],
            denylist: vec![],
            max_intensity: ScanIntensity::Light,
        }
    }

    #[tokio::test]
    async fn denies_on_scope_violation() {
        let eng = engagement();
        let req = ScanRequest {
            tenant_id: eng.tenant_id,
            engagement_id: eng.id,
            targets: vec![ScopeTarget::Domain(Fqdn::new("evil.com").unwrap())],
            intensity: ScanIntensity::Light,
        };
        let gate = SafetyGate::new(
            Arc::new(InMemoryScopeValidator),
            Arc::new(InMemoryKillSwitch::new()),
        );
        let r = gate.check(&eng, &req).await;
        assert!(matches!(r, Err(DiscoveryError::SafetyGate(_))));
    }

    #[tokio::test]
    async fn denies_when_killswitch_tripped() {
        let eng = engagement();
        let req = ScanRequest {
            tenant_id: eng.tenant_id,
            engagement_id: eng.id,
            targets: vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())],
            intensity: ScanIntensity::Light,
        };
        let switch = InMemoryKillSwitch::new();
        switch.trip(&KillSwitchScope::Global);
        let gate = SafetyGate::new(Arc::new(InMemoryScopeValidator), Arc::new(switch));
        let r = gate.check(&eng, &req).await;
        assert!(matches!(r, Err(DiscoveryError::KillSwitchTripped)));
    }

    #[tokio::test]
    async fn intensity_cap_enforced() {
        let mut eng = engagement();
        eng.max_intensity = ScanIntensity::Passive;
        let req = ScanRequest {
            tenant_id: eng.tenant_id,
            engagement_id: eng.id,
            targets: vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())],
            intensity: ScanIntensity::Light,
        };
        let gate = SafetyGate::new(
            Arc::new(InMemoryScopeValidator),
            Arc::new(InMemoryKillSwitch::new()),
        );
        let r = gate.check(&eng, &req).await;
        assert!(matches!(r, Err(DiscoveryError::SafetyGate(_))));
    }
}
