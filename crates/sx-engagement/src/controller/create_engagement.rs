//! `CreateEngagement` use case — creates a new `Draft` engagement.

use std::sync::Arc;

use sx_core::value_object::ids::EngagementId;

use crate::error::EngagementError;
use crate::model::engagement::Engagement;
use crate::model::window::TimeWindow;
use crate::port::EngagementRepository;
use crate::service::clock::Clock;
use crate::view::{CreateEngagementRequest, CreateEngagementResponse};

/// Use case that creates a `Draft` engagement and persists it.
#[derive(Debug, Clone)]
pub struct CreateEngagementUseCase {
    repo: Arc<dyn EngagementRepository>,
    clock: Arc<dyn Clock>,
}

impl CreateEngagementUseCase {
    /// Build the use case.
    #[must_use]
    pub fn new(repo: Arc<dyn EngagementRepository>, clock: Arc<dyn Clock>) -> Self {
        Self { repo, clock }
    }

    /// Execute the use case.
    pub async fn execute(
        &self,
        req: CreateEngagementRequest,
    ) -> Result<CreateEngagementResponse, EngagementError> {
        let CreateEngagementRequest {
            tenant_id,
            name,
            scope,
            window_start,
            window_end,
            max_intensity,
        } = req;

        let window = TimeWindow::new(window_start, window_end)?;
        let now = self.clock.now();
        let engagement = Engagement::new_draft(
            EngagementId::new(),
            tenant_id,
            name,
            scope,
            window,
            max_intensity,
            now,
        )?;

        self.repo.create(&engagement).await?;

        Ok(CreateEngagementResponse {
            engagement_id: engagement.id,
            tenant_id: engagement.tenant_id,
            status: engagement.status,
            created_at: engagement.created_at,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::engagement::EngagementStatus;
    use crate::model::intensity::ScanIntensity;
    use crate::model::scope_target::ScopeTarget;
    use crate::service::clock::FakeClock;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use sx_core::value_object::ids::TenantId;
    use time::{Duration, OffsetDateTime};

    #[derive(Debug, Default)]
    struct InMemoryRepo {
        saved: Mutex<Vec<Engagement>>,
    }

    #[async_trait]
    impl EngagementRepository for InMemoryRepo {
        async fn create(&self, engagement: &Engagement) -> Result<(), EngagementError> {
            self.saved
                .lock()
                .map_err(|_| EngagementError::internal("mutex poisoned"))?
                .push(engagement.clone());
            Ok(())
        }
        async fn find_by_id(
            &self,
            _tenant_id: TenantId,
            id: sx_core::value_object::ids::EngagementId,
        ) -> Result<Option<Engagement>, EngagementError> {
            Ok(self
                .saved
                .lock()
                .map_err(|_| EngagementError::internal("mutex poisoned"))?
                .iter()
                .find(|e| e.id == id)
                .cloned())
        }
        async fn update(&self, engagement: &Engagement) -> Result<(), EngagementError> {
            let mut g = self
                .saved
                .lock()
                .map_err(|_| EngagementError::internal("mutex poisoned"))?;
            g.iter_mut().find(|e| e.id == engagement.id).map_or_else(
                || Err(EngagementError::Repository("not found".into())),
                |slot| {
                    *slot = engagement.clone();
                    Ok(())
                },
            )
        }
    }

    #[tokio::test]
    async fn create_engagement_persists_and_returns_draft() {
        let repo = Arc::new(InMemoryRepo::default());
        let clock = Arc::new(FakeClock::new(OffsetDateTime::UNIX_EPOCH));
        let uc = CreateEngagementUseCase::new(repo.clone(), clock);
        let req = CreateEngagementRequest {
            tenant_id: TenantId::new(),
            name: "Q4 pentest".into(),
            scope: vec![ScopeTarget::Domain("example.com".into())],
            window_start: OffsetDateTime::UNIX_EPOCH,
            window_end: OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
            max_intensity: ScanIntensity::SafeInteractive,
        };
        let resp = uc.execute(req).await.unwrap();
        assert_eq!(resp.status, EngagementStatus::Draft);
        let saved_id = {
            let saved = repo.saved.lock().unwrap();
            assert_eq!(saved.len(), 1);
            saved.first().map(|e| e.id)
        };
        assert_eq!(saved_id, Some(resp.engagement_id));
    }

    #[tokio::test]
    async fn create_engagement_validates_input() {
        let repo = Arc::new(InMemoryRepo::default());
        let clock = Arc::new(FakeClock::new(OffsetDateTime::UNIX_EPOCH));
        let uc = CreateEngagementUseCase::new(repo, clock);
        let req = CreateEngagementRequest {
            tenant_id: TenantId::new(),
            name: String::new(),
            scope: vec![],
            window_start: OffsetDateTime::UNIX_EPOCH,
            window_end: OffsetDateTime::UNIX_EPOCH,
            max_intensity: ScanIntensity::SafeInteractive,
        };
        let r = uc.execute(req).await;
        assert!(r.is_err());
    }
}
