//! Use case: start the continuous validation engine.
//!
//! Thin wrapper around
//! [`crate::service::validation_engine::ContinuousValidationEngine::execute`].

use sx_core::value_object::ids::{EngagementId, TenantId};

use crate::error::AutonomyError;
use crate::service::validation_engine::{ContinuousValidationEngine, EngineHandle};

/// Application-layer entry point that starts a continuous validation
/// engine for a given `(tenant_id, engagement_id)` pair.
#[derive(Debug)]
pub struct StartContinuousValidationUseCase {
    engine: ContinuousValidationEngine,
}

impl StartContinuousValidationUseCase {
    /// Build a new use case around the supplied engine.
    #[must_use]
    pub const fn new(engine: ContinuousValidationEngine) -> Self {
        Self { engine }
    }

    /// Start the engine and return its handle.
    ///
    /// The use case consumes itself because the underlying engine is
    /// also consumed by [`ContinuousValidationEngine::execute`].
    ///
    /// # Errors
    /// Surfaces any error returned by
    /// [`ContinuousValidationEngine::execute`].
    pub async fn execute(
        self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
    ) -> Result<EngineHandle, AutonomyError> {
        self.engine.execute(tenant_id, engagement_id).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::schedule::Schedule;
    use crate::model::validation_report::ValidationReport;
    use crate::service::validation_engine::{
        SimulationOutcomeKind, SimulationPort, SimulationPortOutcome, ValidationReportSink,
    };
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Debug)]
    struct NoopSim;

    #[async_trait]
    impl SimulationPort for NoopSim {
        async fn execute(
            &self,
            _tenant_id: TenantId,
            _engagement_id: EngagementId,
            _technique_id: String,
        ) -> Result<SimulationPortOutcome, AutonomyError> {
            Ok(SimulationPortOutcome::new(
                SimulationOutcomeKind::Pass,
                "ok",
            ))
        }
    }

    #[derive(Debug, Default)]
    struct NoopSink;

    #[async_trait]
    impl ValidationReportSink for NoopSink {
        async fn append(&self, _report: ValidationReport) -> Result<(), AutonomyError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn start_validation_use_case_returns_engine_handle() {
        let engine = ContinuousValidationEngine::new(
            Schedule::from_interval(Duration::from_secs(60)).unwrap(),
            vec!["t1".into()],
            Arc::new(NoopSim),
            Arc::new(NoopSink),
        )
        .unwrap();
        let use_case = StartContinuousValidationUseCase::new(engine);
        let handle = use_case
            .execute(TenantId::new(), EngagementId::new())
            .await
            .unwrap();
        // The handle's shutdown signal should be live.
        let sig = handle.shutdown_signal();
        // Shutdown immediately so the spawned task finishes before the
        // test exits.
        handle.shutdown().await.unwrap();
        // Re-using the signal is permitted after shutdown.
        sig.notify_waiters();
    }
}
