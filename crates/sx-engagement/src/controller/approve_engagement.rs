//! `ApproveEngagement` use case — records a human approval against an
//! engagement still in `Draft`.

use std::sync::Arc;

use sx_core::value_object::ids::{EngagementId, TenantId, UserId};

use crate::error::EngagementError;
use crate::model::engagement::{EngagementApproval, EngagementStatus};
use crate::port::EngagementRepository;
use crate::service::clock::Clock;

/// Use case that adds an approval entry to a Draft engagement.
#[derive(Debug, Clone)]
pub struct ApproveEngagementUseCase {
    repo: Arc<dyn EngagementRepository>,
    clock: Arc<dyn Clock>,
}

impl ApproveEngagementUseCase {
    /// Build the use case.
    #[must_use]
    pub fn new(repo: Arc<dyn EngagementRepository>, clock: Arc<dyn Clock>) -> Self {
        Self { repo, clock }
    }

    /// Execute. Returns the new unique-approver count on success.
    pub async fn execute(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        approver: UserId,
    ) -> Result<u32, EngagementError> {
        let mut engagement = self
            .repo
            .find_by_id(tenant_id, engagement_id)
            .await?
            .ok_or_else(|| {
                EngagementError::Repository(format!("engagement {engagement_id} not found"))
            })?;

        if engagement.status != EngagementStatus::Draft {
            return Err(EngagementError::NotActive {
                status: engagement.status.to_string(),
            });
        }

        engagement.add_approval(EngagementApproval::new(approver, self.clock.now()))?;
        self.repo.update(&engagement).await?;
        Ok(engagement.unique_approver_count())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::engagement::Engagement;
    use crate::model::intensity::ScanIntensity;
    use crate::model::scope_target::ScopeTarget;
    use crate::model::window::TimeWindow;
    use crate::service::clock::FakeClock;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use time::{Duration, OffsetDateTime};

    #[derive(Debug, Default)]
    struct Repo {
        saved: Mutex<Vec<Engagement>>,
    }

    #[async_trait]
    impl EngagementRepository for Repo {
        async fn create(&self, e: &Engagement) -> Result<(), EngagementError> {
            self.saved.lock().unwrap().push(e.clone());
            Ok(())
        }
        async fn find_by_id(
            &self,
            _t: TenantId,
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
        async fn update(&self, e: &Engagement) -> Result<(), EngagementError> {
            let mut g = self.saved.lock().unwrap();
            g.iter_mut().find(|x| x.id == e.id).map_or_else(
                || Err(EngagementError::Repository("missing".into())),
                |slot| {
                    *slot = e.clone();
                    Ok(())
                },
            )
        }
    }

    fn make_draft() -> Engagement {
        let t = OffsetDateTime::UNIX_EPOCH;
        let window = TimeWindow::new(t, t + Duration::hours(1)).unwrap();
        Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "t",
            vec![ScopeTarget::Domain("example.com".into())],
            window,
            ScanIntensity::ActiveExploit,
            t,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn approval_increments_count() {
        let repo = Arc::new(Repo::default());
        let e = make_draft();
        let (t, id) = (e.tenant_id, e.id);
        repo.create(&e).await.unwrap();
        let uc = ApproveEngagementUseCase::new(
            repo,
            Arc::new(FakeClock::new(OffsetDateTime::UNIX_EPOCH)),
        );
        let n = uc.execute(t, id, UserId::new()).await.unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn duplicate_approval_rejected() {
        let repo = Arc::new(Repo::default());
        let e = make_draft();
        let (t, id) = (e.tenant_id, e.id);
        repo.create(&e).await.unwrap();
        let uc = ApproveEngagementUseCase::new(
            repo,
            Arc::new(FakeClock::new(OffsetDateTime::UNIX_EPOCH)),
        );
        let user = UserId::new();
        uc.execute(t, id, user).await.unwrap();
        let r = uc.execute(t, id, user).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn cannot_approve_non_draft() {
        let repo = Arc::new(Repo::default());
        let mut e = make_draft();
        e.status = EngagementStatus::Aborted;
        let (t, id) = (e.tenant_id, e.id);
        repo.create(&e).await.unwrap();
        let uc = ApproveEngagementUseCase::new(
            repo,
            Arc::new(FakeClock::new(OffsetDateTime::UNIX_EPOCH)),
        );
        let r = uc.execute(t, id, UserId::new()).await;
        assert!(matches!(r, Err(EngagementError::NotActive { .. })));
    }
}
