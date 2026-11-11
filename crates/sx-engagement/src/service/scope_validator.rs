//! Scope validator — pure decision logic.
//!
//! # Defense in depth
//!
//! This validator is intended to run at **three** boundaries:
//! 1. **API boundary** — when an operator submits a `ScanRequest`.
//! 2. **Worker boundary** — when a worker picks a job off the queue.
//! 3. **Probe boundary** — immediately before any network I/O.
//!
//! The same `evaluate` function is invoked at all three sites; this prevents
//! a single missed guard from translating into an unauthorized probe.
//!
//! # Algorithm
//!
//! `evaluate` runs the following checks **in order**, returning a structured
//! `ScopeDecision` for every outcome:
//!
//! 1. Denylist hit  → deny (`denylisted: <pattern>`).
//! 2. Engagement not `Active` → deny.
//! 3. Approvals insufficient → deny.
//! 4. Outside time window → deny.
//! 5. Intensity above ceiling → deny.
//! 6. Target outside scope → deny.
//! 7. Otherwise → allow.
//!
//! Every denial emits a structured `tracing::warn!` for audit. No secret
//! material is ever logged.

use std::sync::Arc;

use sx_config::schema::engagement::EngagementConfig;
use tracing::warn;

use crate::model::decision::ScopeDecision;
use crate::model::engagement::{Engagement, EngagementStatus};
use crate::model::scope_request::ScanRequest;
use crate::model::scope_target::ScopeTarget;
use crate::service::clock::Clock;
use crate::service::denylist::DenylistChecker;

/// Pure-logic validator that bundles the denylist, clock, and approval policy.
#[derive(Debug, Clone)]
pub struct ScopeValidator {
    denylist: DenylistChecker,
    clock: Arc<dyn Clock>,
}

impl ScopeValidator {
    /// Construct a validator from its dependencies.
    #[must_use]
    pub fn new(denylist: DenylistChecker, clock: Arc<dyn Clock>) -> Self {
        Self { denylist, clock }
    }

    /// Convenience constructor that builds the denylist from `cfg`.
    #[must_use]
    pub fn from_config(cfg: &EngagementConfig, clock: Arc<dyn Clock>) -> Self {
        Self::new(DenylistChecker::from_config(cfg), clock)
    }

    /// Borrow the internal denylist.
    #[must_use]
    pub const fn denylist(&self) -> &DenylistChecker {
        &self.denylist
    }

    /// Run all checks against an engagement and a request.
    ///
    /// Always returns a `ScopeDecision`. Callers map `allowed = false` into
    /// `EngagementError` at the use-case boundary if a typed error is desired.
    #[must_use]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)] // ordered safety gates; each step is a single early-return
    pub fn evaluate(&self, engagement: &Engagement, req: &ScanRequest) -> ScopeDecision {
        // 1. Denylist always wins.
        if let Some(hit) = self.denylist.contains(&req.target) {
            warn!(
                target = "sx_engagement::scope",
                event = "denied",
                cause = "denylist",
                target_kind = req.target.kind_label(),
                pattern = %hit.pattern,
                reason = %hit.reason,
                tenant_id = %req.tenant_id,
                engagement_id = %req.engagement_id,
                "scan request denied by denylist",
            );
            return ScopeDecision::deny(
                format!("denylisted: {}", hit.pattern),
                engagement.window,
                engagement.max_intensity,
            );
        }

        // 2. Engagement must be Active.
        if engagement.status != EngagementStatus::Active {
            warn!(
                target = "sx_engagement::scope",
                event = "denied",
                cause = "not_active",
                status = %engagement.status,
                tenant_id = %req.tenant_id,
                engagement_id = %req.engagement_id,
                "scan request denied: engagement not active",
            );
            return ScopeDecision::deny(
                format!("engagement not active: {}", engagement.status),
                engagement.window,
                engagement.max_intensity,
            );
        }

        // 3. Approvals must satisfy the policy for the engagement's ceiling.
        //    Approval thresholds are derived externally via ApprovalPolicy;
        //    here we sanity-check that `RedTeam` engagements have at least
        //    one approval; the full policy gate runs at activate-time.
        if engagement.max_intensity.requires_dual_approval()
            && engagement.unique_approver_count() < 1
        {
            warn!(
                target = "sx_engagement::scope",
                event = "denied",
                cause = "no_approvals",
                tenant_id = %req.tenant_id,
                engagement_id = %req.engagement_id,
                "scan request denied: dual-approval gate has zero approvals",
            );
            return ScopeDecision::deny(
                "no approvals on file",
                engagement.window,
                engagement.max_intensity,
            );
        }

        // 4. Time window.
        let now = self.clock.now();
        if !engagement.window.contains(now) {
            warn!(
                target = "sx_engagement::scope",
                event = "denied",
                cause = "outside_window",
                tenant_id = %req.tenant_id,
                engagement_id = %req.engagement_id,
                "scan request denied: outside time window",
            );
            return ScopeDecision::deny(
                "outside time window",
                engagement.window,
                engagement.max_intensity,
            );
        }

        // 5. Intensity ceiling.
        if req.intensity > engagement.max_intensity {
            warn!(
                target = "sx_engagement::scope",
                event = "denied",
                cause = "intensity",
                requested = %req.intensity,
                ceiling = %engagement.max_intensity,
                tenant_id = %req.tenant_id,
                engagement_id = %req.engagement_id,
                "scan request denied: intensity above ceiling",
            );
            return ScopeDecision::deny(
                format!(
                    "intensity above ceiling: requested {}, ceiling {}",
                    req.intensity, engagement.max_intensity
                ),
                engagement.window,
                engagement.max_intensity,
            );
        }

        // 6. Scope match.
        if !target_in_scope(&engagement.scope, &req.target) {
            warn!(
                target = "sx_engagement::scope",
                event = "denied",
                cause = "out_of_scope",
                target_kind = req.target.kind_label(),
                tenant_id = %req.tenant_id,
                engagement_id = %req.engagement_id,
                "scan request denied: target not in engagement scope",
            );
            return ScopeDecision::deny(
                "target not in engagement scope",
                engagement.window,
                engagement.max_intensity,
            );
        }

        // 7. All clear.
        ScopeDecision::allow(engagement.window, engagement.max_intensity)
    }
}

/// Returns true when `target` is covered by at least one `ScopeTarget`
/// in `scope`.
fn target_in_scope(scope: &[ScopeTarget], target: &ScopeTarget) -> bool {
    scope.iter().any(|s| s.matches(target))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::engagement::{Engagement, EngagementApproval, EngagementStatus};
    use crate::model::intensity::ScanIntensity;
    use crate::model::scope_request::ScanRequest;
    use crate::model::scope_target::ScopeTarget;
    use crate::model::window::TimeWindow;
    use crate::service::clock::FakeClock;
    use crate::service::denylist::DenylistChecker;
    use ipnet::IpNet;
    use std::str::FromStr;
    use sx_config::schema::engagement::{DenylistEntry, DenylistKind};
    use sx_core::value_object::ids::{EngagementId, TenantId, UserId};
    use time::{Duration, OffsetDateTime};

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn make_validator(now: OffsetDateTime, denylist: &[DenylistEntry]) -> ScopeValidator {
        let clock = Arc::new(FakeClock::new(now));
        let checker = DenylistChecker::from_entries(denylist);
        ScopeValidator::new(checker, clock)
    }

    fn make_engagement(scope: Vec<ScopeTarget>, max: ScanIntensity) -> Engagement {
        let window = TimeWindow::new(epoch(), epoch() + Duration::hours(2)).unwrap();
        let mut e = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "t",
            scope,
            window,
            max,
            epoch(),
        )
        .unwrap();
        e.status = EngagementStatus::Active;
        // satisfy the validator's own "RedTeam needs >=1 approval" check
        if max.requires_dual_approval() {
            e.add_approval(EngagementApproval::new(UserId::new(), epoch()))
                .unwrap();
        }
        e
    }

    fn make_request(target: ScopeTarget, intensity: ScanIntensity) -> ScanRequest {
        ScanRequest::new(
            TenantId::new(),
            EngagementId::new(),
            target,
            intensity,
            UserId::new(),
        )
    }

    // --- positive matches ---

    #[test]
    fn scope_match_cidr_ipv4_positive() {
        let v = make_validator(epoch() + Duration::minutes(30), &[]);
        let scope = vec![ScopeTarget::Cidr(IpNet::from_str("10.0.0.0/8").unwrap())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::IpV4("10.1.2.3".parse().unwrap()),
            ScanIntensity::SafeInteractive,
        );
        let d = v.evaluate(&e, &req);
        assert!(d.allowed, "{}", d.reason);
    }

    #[test]
    fn scope_match_cidr_ipv4_negative() {
        let v = make_validator(epoch() + Duration::minutes(30), &[]);
        let scope = vec![ScopeTarget::Cidr(IpNet::from_str("10.0.0.0/8").unwrap())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::IpV4("11.0.0.1".parse().unwrap()),
            ScanIntensity::SafeInteractive,
        );
        let d = v.evaluate(&e, &req);
        assert!(!d.allowed);
    }

    #[test]
    fn scope_match_cidr_ipv6_positive() {
        let v = make_validator(epoch() + Duration::minutes(30), &[]);
        let scope = vec![ScopeTarget::Cidr(IpNet::from_str("2001:db8::/32").unwrap())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::IpV6("2001:db8::1".parse().unwrap()),
            ScanIntensity::SafeInteractive,
        );
        assert!(v.evaluate(&e, &req).allowed);
    }

    #[test]
    fn scope_match_cidr_ipv6_negative() {
        let v = make_validator(epoch() + Duration::minutes(30), &[]);
        let scope = vec![ScopeTarget::Cidr(IpNet::from_str("2001:db8::/32").unwrap())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::IpV6("2001:db9::1".parse().unwrap()),
            ScanIntensity::SafeInteractive,
        );
        assert!(!v.evaluate(&e, &req).allowed);
    }

    #[test]
    fn scope_match_domain_exact_positive() {
        let v = make_validator(epoch() + Duration::minutes(30), &[]);
        let scope = vec![ScopeTarget::Domain("example.com".into())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::Domain("example.com".into()),
            ScanIntensity::SafeInteractive,
        );
        assert!(v.evaluate(&e, &req).allowed);
    }

    #[test]
    fn scope_match_domain_wildcard_positive() {
        let v = make_validator(epoch() + Duration::minutes(30), &[]);
        let scope = vec![ScopeTarget::Domain("*.example.com".into())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::Domain("api.example.com".into()),
            ScanIntensity::SafeInteractive,
        );
        assert!(v.evaluate(&e, &req).allowed);
    }

    #[test]
    fn scope_subdomain_outside_scope_negative() {
        let v = make_validator(epoch() + Duration::minutes(30), &[]);
        let scope = vec![ScopeTarget::Domain("example.com".into())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::Domain("api.example.com".into()),
            ScanIntensity::SafeInteractive,
        );
        let d = v.evaluate(&e, &req);
        assert!(!d.allowed);
    }

    // --- denylist beats everything ---

    #[test]
    fn denylist_blocks_even_when_scope_includes() {
        let v = make_validator(
            epoch() + Duration::minutes(30),
            &[DenylistEntry {
                kind: DenylistKind::Domain,
                value: "*.gov".into(),
                reason: "government".into(),
            }],
        );
        // scope intentionally tries to include the target
        let scope = vec![ScopeTarget::Domain("*.gov".into())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::Domain("example.gov".into()),
            ScanIntensity::SafeInteractive,
        );
        let d = v.evaluate(&e, &req);
        assert!(!d.allowed);
        assert!(d.reason.starts_with("denylisted"));
    }

    // --- window enforcement ---

    #[test]
    fn outside_window_denied() {
        let v = make_validator(epoch() + Duration::hours(48), &[]);
        let scope = vec![ScopeTarget::Domain("example.com".into())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::Domain("example.com".into()),
            ScanIntensity::SafeInteractive,
        );
        let d = v.evaluate(&e, &req);
        assert!(!d.allowed);
        assert!(d.reason.contains("outside time window"));
    }

    // --- intensity ceiling ---

    #[test]
    fn intensity_above_ceiling_denied() {
        let v = make_validator(epoch() + Duration::minutes(30), &[]);
        let scope = vec![ScopeTarget::Domain("example.com".into())];
        let e = make_engagement(scope, ScanIntensity::SafeInteractive);
        let req = make_request(
            ScopeTarget::Domain("example.com".into()),
            ScanIntensity::ActiveExploit,
        );
        let d = v.evaluate(&e, &req);
        assert!(!d.allowed);
        assert!(d.reason.contains("intensity above ceiling"));
    }

    // --- inactive engagement ---

    #[test]
    fn inactive_engagement_denied() {
        let v = make_validator(epoch() + Duration::minutes(30), &[]);
        let scope = vec![ScopeTarget::Domain("example.com".into())];
        let mut e = make_engagement(scope, ScanIntensity::SafeInteractive);
        e.status = EngagementStatus::Paused;
        let req = make_request(
            ScopeTarget::Domain("example.com".into()),
            ScanIntensity::SafeInteractive,
        );
        let d = v.evaluate(&e, &req);
        assert!(!d.allowed);
    }
}
