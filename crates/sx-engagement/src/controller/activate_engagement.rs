//! `ActivateEngagement` use case — transitions Draft → Active.
//!
//! Pre-conditions:
//! 1. The engagement exists and is currently `Draft`.
//! 2. The approval ledger satisfies `ApprovalPolicy` for the engagement's
//!    intensity ceiling.

use std::sync::Arc;

use sx_config::schema::engagement::EngagementConfig;
use sx_core::value_object::ids::{EngagementId, TenantId};
use tracing::warn;

use crate::error::EngagementError;
use crate::model::engagement::EngagementStatus;
use crate::port::EngagementRepository;
use crate::service::clock::Clock;
use crate::service::dual_approval::ApprovalPolicy;

/// Use case that activates a Draft engagement.
#[derive(Debug, Clone)]
pub struct ActivateEngagementUseCase {
    repo: Arc<dyn EngagementRepository>,
    clock: Arc<dyn Clock>,
    cfg: Arc<EngagementConfig>,
}

impl ActivateEngagementUseCase {
    /// Build the use case.
    #[must_use]
    pub fn new(
        repo: Arc<dyn EngagementRepository>,
        clock: Arc<dyn Clock>,
        cfg: Arc<EngagementConfig>,
    ) -> Self {
        Self { repo, clock, cfg }
    }

    /// Execute. Returns the new status (always `Active`) on success.
    pub async fn execute(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
    ) -> Result<EngagementStatus, EngagementError> {
        let mut engagement = self
            .repo
            .find_by_id(tenant_id, engagement_id)
            .await?
            .ok_or_else(|| {
                EngagementError::Repository(format!("engagement {engagement_id} not found"))
            })?;

        // Approval gate.
        let policy = ApprovalPolicy::from_intensity(engagement.max_intensity, &self.cfg);
        if !policy.met(&engagement.approvals) {
            warn!(
                target = "sx_engagement::activate",
                event = "denied",
                cause = "approvals_insufficient",
                have = engagement.unique_approver_count(),
                need = policy.required_count,
                tenant_id = %tenant_id,
                engagement_id = %engagement_id,
                "activation denied: approvals insufficient",
            );
            return Err(EngagementError::ApprovalsInsufficient {
                have: engagement.unique_approver_count(),
                need: policy.required_count,
            });
        }

        engagement.transition_to(EngagementStatus::Active, self.clock.now())?;
        self.repo.update(&engagement).await?;
        Ok(engagement.status)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::engagement::{Engagement, EngagementApproval};
    use crate::model::intensity::ScanIntensity;
    use crate::model::scope_target::ScopeTarget;
    use crate::model::window::TimeWindow;
    use crate::service::clock::FakeClock;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use sx_config::schema::engagement::{DenylistEntry, Intensity};
    use sx_core::value_object::ids::UserId;
    use time::{Duration, OffsetDateTime};

    #[derive(Debug, Default)]
    struct InMemoryRepo {
        saved: Mutex<Vec<Engagement>>,
    }

    #[async_trait]
    impl EngagementRepository for InMemoryRepo {
        async fn create(&self, engagement: &Engagement) -> Result<(), EngagementError> {
            self.saved.lock().unwrap().push(engagement.clone());
            Ok(())
        }
        async fn find_by_id(
            &self,
            _tenant_id: TenantId,
            id: EngagementId,
        ) -> Result<Option<Engagement>, EngagementError> {
            Ok(self
                .saved
                .lock()
                .unwrap()
                .iter()
                .find(|e| e.id == id)
                .cloned())
        }
        async fn update(&self, engagement: &Engagement) -> Result<(), EngagementError> {
            let mut g = self.saved.lock().unwrap();
            g.iter_mut().find(|e| e.id == engagement.id).map_or_else(
                || Err(EngagementError::Repository("missing".into())),
                |slot| {
                    *slot = engagement.clone();
                    Ok(())
                },
            )
        }
    }

    fn cfg() -> EngagementConfig {
        EngagementConfig {
            max_concurrent: 4,
            default_intensity: Intensity::Passive,
            kill_switch_channel: "ks".into(),
            killswitch_watchdog_interval: std::time::Duration::from_secs(5),
            global_denylist: Vec::<DenylistEntry>::new(),
        }
    }

    fn make_engagement(max: ScanIntensity, approvals: u32) -> Engagement {
        let t = OffsetDateTime::UNIX_EPOCH;
        let window = TimeWindow::new(t, t + Duration::hours(24)).unwrap();
        let mut e = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "t",
            vec![ScopeTarget::Domain("example.com".into())],
            window,
            max,
            t,
        )
        .unwrap();
        for _ in 0..approvals {
            e.add_approval(EngagementApproval::new(UserId::new(), t))
                .unwrap();
        }
        e
    }

    #[tokio::test]
    async fn activate_succeeds_when_approvals_sufficient() {
        let repo = Arc::new(InMemoryRepo::default());
        // RedTeam needs 3 approvals per ApprovalThresholds default mapping.
        let e = make_engagement(ScanIntensity::RedTeam, 3);
        let (tenant, id) = (e.tenant_id, e.id);
        repo.create(&e).await.unwrap();
        let uc = ActivateEngagementUseCase::new(
            repo.clone(),
            Arc::new(FakeClock::new(OffsetDateTime::UNIX_EPOCH)),
            Arc::new(cfg()),
        );
        let status = uc.execute(tenant, id).await.unwrap();
        assert_eq!(status, EngagementStatus::Active);
    }

    #[tokio::test]
    async fn activate_engagement_requires_approvals() {
        let repo = Arc::new(InMemoryRepo::default());
        let e = make_engagement(ScanIntensity::RedTeam, 1);
        let (tenant, id) = (e.tenant_id, e.id);
        repo.create(&e).await.unwrap();
        let uc = ActivateEngagementUseCase::new(
            repo,
            Arc::new(FakeClock::new(OffsetDateTime::UNIX_EPOCH)),
            Arc::new(cfg()),
        );
        let r = uc.execute(tenant, id).await;
        assert!(matches!(
            r,
            Err(EngagementError::ApprovalsInsufficient { .. })
        ));
    }
}
