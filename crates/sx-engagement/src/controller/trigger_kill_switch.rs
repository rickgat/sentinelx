//! `TriggerKillSwitch` use case — explicitly trips the kill switch.

use std::sync::Arc;

use crate::error::EngagementError;
use crate::service::kill_switch::{KillReason, KillSwitch, KillSwitchScope};

/// Use case that flips the kill switch for a given scope.
#[derive(Debug, Clone)]
pub struct TriggerKillSwitchUseCase {
    kill_switch: Arc<dyn KillSwitch>,
}

impl TriggerKillSwitchUseCase {
    /// Build the use case.
    #[must_use]
    pub fn new(kill_switch: Arc<dyn KillSwitch>) -> Self {
        Self { kill_switch }
    }

    /// Execute. Idempotent on the underlying switch.
    pub async fn execute(
        &self,
        scope: KillSwitchScope,
        reason: KillReason,
    ) -> Result<(), EngagementError> {
        self.kill_switch.trip(scope, reason).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::service::kill_switch::InMemoryKillSwitch;

    #[tokio::test]
    async fn trigger_sets_is_tripped() {
        let ks = Arc::new(InMemoryKillSwitch::new());
        let uc = TriggerKillSwitchUseCase::new(ks.clone());
        uc.execute(KillSwitchScope::Global, KillReason::Manual)
            .await
            .unwrap();
        assert!(ks.is_tripped(KillSwitchScope::Global).await.unwrap());
    }
}
