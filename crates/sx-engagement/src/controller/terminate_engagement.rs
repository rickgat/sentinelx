//! `TerminateEngagement` use case — moves an engagement to a terminal state.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::{EngagementId, TenantId};

use crate::error::EngagementError;
use crate::model::engagement::EngagementStatus;
use crate::port::EngagementRepository;
use crate::service::clock::Clock;

/// Terminal disposition for an engagement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationOutcome {
    /// Finished cleanly.
    Completed,
    /// Aborted (manual / kill switch).
    Aborted,
}

impl From<TerminationOutcome> for EngagementStatus {
    fn from(t: TerminationOutcome) -> Self {
        match t {
            TerminationOutcome::Completed => Self::Completed,
            TerminationOutcome::Aborted => Self::Aborted,
        }
    }
}

/// Use case that terminates an engagement.
#[derive(Debug, Clone)]
pub struct TerminateEngagementUseCase {
    repo: Arc<dyn EngagementRepository>,
    clock: Arc<dyn Clock>,
}

impl TerminateEngagementUseCase {
    /// Build the use case.
    #[must_use]
    pub fn new(repo: Arc<dyn EngagementRepository>, clock: Arc<dyn Clock>) -> Self {
        Self { repo, clock }
    }

    /// Execute. Returns the new status on success.
    pub async fn execute(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        outcome: TerminationOutcome,
    ) -> Result<EngagementStatus, EngagementError> {
        let mut engagement = self
            .repo
            .find_by_id(tenant_id, engagement_id)
            .await?
            .ok_or_else(|| {
                EngagementError::Repository(format!("engagement {engagement_id} not found"))
            })?;
        engagement.transition_to(outcome.into(), self.clock.now())?;
        self.repo.update(&engagement).await?;
        Ok(engagement.status)
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

    fn make_active_engagement() -> Engagement {
        let t = OffsetDateTime::UNIX_EPOCH;
        let window = TimeWindow::new(t, t + Duration::hours(1)).unwrap();
        let mut e = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "t",
            vec![ScopeTarget::Domain("example.com".into())],
            window,
            ScanIntensity::SafeInteractive,
            t,
        )
        .unwrap();
        e.transition_to(EngagementStatus::Active, t).unwrap();
        e
    }

    #[tokio::test]
    async fn terminate_active_to_completed() {
        let repo = Arc::new(Repo::default());
        let e = make_active_engagement();
        let (t, id) = (e.tenant_id, e.id);
        repo.create(&e).await.unwrap();
        let uc = TerminateEngagementUseCase::new(
            repo,
            Arc::new(FakeClock::new(OffsetDateTime::UNIX_EPOCH)),
        );
        let s = uc
            .execute(t, id, TerminationOutcome::Completed)
            .await
            .unwrap();
        assert_eq!(s, EngagementStatus::Completed);
    }

    #[tokio::test]
    async fn terminate_active_to_aborted() {
        let repo = Arc::new(Repo::default());
        let e = make_active_engagement();
        let (t, id) = (e.tenant_id, e.id);
        repo.create(&e).await.unwrap();
        let uc = TerminateEngagementUseCase::new(
            repo,
            Arc::new(FakeClock::new(OffsetDateTime::UNIX_EPOCH)),
        );
        let s = uc
            .execute(t, id, TerminationOutcome::Aborted)
            .await
            .unwrap();
        assert_eq!(s, EngagementStatus::Aborted);
    }
}
