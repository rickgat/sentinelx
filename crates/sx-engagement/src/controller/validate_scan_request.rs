//! `ValidateScanRequest` use case — the single source of truth for
//! "may this scan proceed?".
//!
//! This use case is intended to be invoked at three different boundaries
//! (API, worker, probe). It composes the kill switch + the scope validator.

use std::sync::Arc;

use tracing::warn;

use crate::error::EngagementError;
use crate::model::decision::ScopeDecision;
use crate::model::scope_request::ScanRequest;
use crate::port::EngagementRepository;
use crate::service::kill_switch::{KillSwitch, KillSwitchScope};
use crate::service::scope_validator::ScopeValidator;
use crate::view::ScopeDecisionView;

/// Use case wrapping the scope validator + kill-switch + repository fetch.
#[derive(Debug, Clone)]
pub struct ValidateScanRequestUseCase {
    repo: Arc<dyn EngagementRepository>,
    validator: Arc<ScopeValidator>,
    kill_switch: Arc<dyn KillSwitch>,
}

impl ValidateScanRequestUseCase {
    /// Build the use case.
    #[must_use]
    pub fn new(
        repo: Arc<dyn EngagementRepository>,
        validator: Arc<ScopeValidator>,
        kill_switch: Arc<dyn KillSwitch>,
    ) -> Self {
        Self {
            repo,
            validator,
            kill_switch,
        }
    }

    /// Execute the validation, returning a structured `ScopeDecision`.
    ///
    /// On a denied decision a structured `tracing::warn!` is already emitted
    /// by the underlying components — this use case never logs request bodies.
    pub async fn execute(&self, req: ScanRequest) -> Result<ScopeDecision, EngagementError> {
        // 0. Kill switch first — if tripped, nothing else matters.
        let ks_scope = KillSwitchScope::Engagement(req.tenant_id, req.engagement_id);
        if self.kill_switch.is_tripped(ks_scope).await? {
            warn!(
                target = "sx_engagement::validate",
                event = "denied",
                cause = "kill_switch",
                tenant_id = %req.tenant_id,
                engagement_id = %req.engagement_id,
                "scan request denied: kill switch tripped",
            );
            return Err(EngagementError::KillSwitchTripped {
                scope: ks_scope.to_string(),
            });
        }

        // 1. Load engagement.
        let engagement = self
            .repo
            .find_by_id(req.tenant_id, req.engagement_id)
            .await?
            .ok_or_else(|| {
                EngagementError::Repository(format!("engagement {} not found", req.engagement_id))
            })?;

        // 2. Run the full scope decision.
        Ok(self.validator.evaluate(&engagement, &req))
    }

    /// Convenience wrapper returning a wire-shaped view.
    pub async fn execute_view(
        &self,
        req: ScanRequest,
    ) -> Result<ScopeDecisionView, EngagementError> {
        self.execute(req).await.map(Into::into)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::engagement::{Engagement, EngagementApproval, EngagementStatus};
    use crate::model::intensity::ScanIntensity;
    use crate::model::scope_target::ScopeTarget;
    use crate::model::window::TimeWindow;
    use crate::service::clock::FakeClock;
    use crate::service::denylist::DenylistChecker;
    use crate::service::kill_switch::{InMemoryKillSwitch, KillReason};
    use async_trait::async_trait;
    use std::sync::Mutex;
    use sx_core::value_object::ids::{EngagementId, TenantId, UserId};
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

    async fn build() -> (
        Arc<InMemoryRepo>,
        Arc<ScopeValidator>,
        Arc<InMemoryKillSwitch>,
        Engagement,
    ) {
        let repo = Arc::new(InMemoryRepo::default());
        let validator = Arc::new(ScopeValidator::new(
            DenylistChecker::from_entries(&[]),
            Arc::new(FakeClock::new(
                OffsetDateTime::UNIX_EPOCH + Duration::minutes(10),
            )),
        ));
        let ks = Arc::new(InMemoryKillSwitch::new());
        let window = TimeWindow::new(
            OffsetDateTime::UNIX_EPOCH,
            OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
        )
        .unwrap();
        let mut e = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "t",
            vec![ScopeTarget::Domain("example.com".into())],
            window,
            ScanIntensity::SafeInteractive,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        e.add_approval(EngagementApproval::new(
            UserId::new(),
            OffsetDateTime::UNIX_EPOCH,
        ))
        .unwrap();
        e.status = EngagementStatus::Active;
        repo.create(&e).await.unwrap();
        (repo, validator, ks, e)
    }

    #[tokio::test]
    async fn kill_switch_global_blocks_all() {
        let (repo, validator, ks, e) = build().await;
        ks.trip(KillSwitchScope::Global, KillReason::EmergencyStop)
            .await
            .unwrap();
        let uc = ValidateScanRequestUseCase::new(repo, validator, ks);
        let req = ScanRequest::new(
            e.tenant_id,
            e.id,
            ScopeTarget::Domain("example.com".into()),
            ScanIntensity::SafeInteractive,
            UserId::new(),
        );
        let r = uc.execute(req).await;
        assert!(matches!(r, Err(EngagementError::KillSwitchTripped { .. })));
    }

    #[tokio::test]
    async fn kill_switch_other_tenant_does_not_block() {
        let (repo, validator, ks, e) = build().await;
        ks.trip(KillSwitchScope::Tenant(TenantId::new()), KillReason::Manual)
            .await
            .unwrap();
        let uc = ValidateScanRequestUseCase::new(repo, validator, ks);
        let req = ScanRequest::new(
            e.tenant_id,
            e.id,
            ScopeTarget::Domain("example.com".into()),
            ScanIntensity::SafeInteractive,
            UserId::new(),
        );
        let d = uc.execute(req).await.unwrap();
        assert!(d.allowed);
    }

    #[tokio::test]
    async fn validate_returns_allow_for_in_scope_request() {
        let (repo, validator, ks, e) = build().await;
        let uc = ValidateScanRequestUseCase::new(repo, validator, ks);
        let req = ScanRequest::new(
            e.tenant_id,
            e.id,
            ScopeTarget::Domain("example.com".into()),
            ScanIntensity::SafeInteractive,
            UserId::new(),
        );
        let d = uc.execute(req).await.unwrap();
        assert!(d.allowed);
    }

    #[tokio::test]
    async fn validate_returns_deny_for_out_of_scope_request() {
        let (repo, validator, ks, e) = build().await;
        let uc = ValidateScanRequestUseCase::new(repo, validator, ks);
        let req = ScanRequest::new(
            e.tenant_id,
            e.id,
            ScopeTarget::Domain("other.com".into()),
            ScanIntensity::SafeInteractive,
            UserId::new(),
        );
        let d = uc.execute(req).await.unwrap();
        assert!(!d.allowed);
    }
}
