//! `SafeCredValidator` — MITRE T1078 (Valid Accounts).
//!
//! Takes a caller-supplied `test_username` + `test_password_hash` (NOT a
//! plain password — the orchestrator pre-hashes any input) and a single
//! `endpoint` URL. In production this would attempt an authentication
//! against that one endpoint with the supplied credentials.
//!
//! Real HTTP validation requires the `dangerous_execution` feature flag,
//! which is **never enabled** in this crate. For now the technique always
//! returns [`StepResult::Simulated`].
//!
//! `max_mode = SafeInteractive`.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::simulation::{EvidenceRecord, SimulationStepContext, StepResult};
use crate::model::technique::{AttackTechnique, Capabilities, IntensityHint, MitreTag};

/// Safe-only credential validator stub.
#[derive(Debug, Clone)]
pub struct SafeCredValidator {
    test_username: String,
    test_password_hash: String,
    endpoint: String,
}

impl SafeCredValidator {
    /// Construct a validator. `test_password_hash` MUST be a hash (e.g.
    /// SHA-256 hex) produced by the caller; the platform never accepts
    /// cleartext passwords across this boundary.
    #[must_use]
    pub const fn new(test_username: String, test_password_hash: String, endpoint: String) -> Self {
        Self {
            test_username,
            test_password_hash,
            endpoint,
        }
    }

    fn validate_inputs(&self) -> Result<(), BasError> {
        if self.test_username.is_empty() {
            return Err(BasError::invalid_input("test_username empty"));
        }
        if self.test_password_hash.is_empty() {
            return Err(BasError::invalid_input("test_password_hash empty"));
        }
        // Same minimal URL check as SafeSsrfProbe; keeps this crate
        // dependency-free.
        if !(self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://")) {
            return Err(BasError::invalid_input(
                "endpoint must start with http:// or https://",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl AttackTechnique for SafeCredValidator {
    fn id(&self) -> &'static str {
        "safe_cred_validator_v1"
    }

    fn mitre(&self) -> MitreTag {
        MitreTag::new("TA0001", "T1078", None)
    }

    fn max_mode(&self) -> AttackMode {
        AttackMode::SafeInteractive
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            intensity: IntensityHint::Medium,
            network_egress: true,
            destructive: false,
        }
    }

    async fn step(&self, ctx: SimulationStepContext) -> Result<StepResult, BasError> {
        self.validate_inputs()?;

        // dangerous_execution is OFF for this crate; the technique cannot
        // actually validate the credentials. Document that and return
        // Simulated.
        if cfg!(feature = "dangerous_execution") {
            return Err(BasError::execution_blocked(
                "dangerous_execution feature is disabled in sx-bas; \
                 real credential validation lives in adapter crates",
            ));
        }

        let mut details = HashMap::new();
        details.insert("endpoint".to_owned(), self.endpoint.clone());
        details.insert("username".to_owned(), self.test_username.clone());
        // NEVER log the hash itself — only its length, as a diagnostic.
        details.insert(
            "password_hash_len".to_owned(),
            self.test_password_hash.len().to_string(),
        );
        details.insert("phase".to_owned(), "phase-1-simulated".to_owned());

        let record = EvidenceRecord {
            technique_id: self.id().to_owned(),
            mode: ctx.mode,
            tenant_id: ctx.tenant_id,
            engagement_id: ctx.engagement_id,
            summary: format!(
                "safe_cred_validator would-test endpoint={} (dangerous_execution off)",
                self.endpoint
            ),
            details: details.clone(),
            recorded_at: time::OffsetDateTime::now_utc(),
        };
        ctx.evidence_sink.record(record).await?;

        Ok(StepResult::Simulated {
            summary: format!(
                "safe_cred_validator simulated against {} (dangerous_execution off)",
                self.endpoint
            ),
            details,
        })
    }
}

#[cfg(test)]
// Tests use `panic!` for unexpected-variant assertions.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::SafeCredValidator;
    use crate::model::mode::AttackMode;
    use crate::model::simulation::{InMemoryEvidenceSink, SimulationStepContext, StepResult};
    use crate::model::technique::AttackTechnique;
    use std::sync::Arc;
    use sx_core::value_object::ids::{EngagementId, TenantId};
    use time::{Duration, OffsetDateTime};
    use tokio::sync::Notify;

    fn ctx(sink: Arc<InMemoryEvidenceSink>) -> SimulationStepContext {
        SimulationStepContext {
            tenant_id: TenantId::new(),
            engagement_id: EngagementId::new(),
            mode: AttackMode::SafeInteractive,
            kill_switch_signal: Arc::new(Notify::new()),
            deadline: OffsetDateTime::now_utc() + Duration::seconds(30),
            evidence_sink: sink,
        }
    }

    #[tokio::test]
    async fn safe_cred_validator_returns_simulated_without_dangerous_flag() {
        let t = SafeCredValidator::new(
            "alice".into(),
            "deadbeef".into(),
            "https://login.example".into(),
        );
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let out = t.step(ctx(sink.clone())).await.unwrap();
        match out {
            StepResult::Simulated { details, .. } => {
                assert_eq!(details.get("username").unwrap(), "alice");
                assert_eq!(details.get("password_hash_len").unwrap(), "8");
                assert_eq!(details.get("endpoint").unwrap(), "https://login.example");
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
        assert_eq!(sink.len().await, 1);
    }

    #[tokio::test]
    async fn safe_cred_validator_rejects_empty_username() {
        let t = SafeCredValidator::new(
            String::new(),
            "deadbeef".into(),
            "https://login.example".into(),
        );
        let sink = Arc::new(InMemoryEvidenceSink::new());
        assert!(t.step(ctx(sink)).await.is_err());
    }

    #[tokio::test]
    async fn safe_cred_validator_rejects_bad_endpoint() {
        let t = SafeCredValidator::new("alice".into(), "deadbeef".into(), "tcp://x".into());
        let sink = Arc::new(InMemoryEvidenceSink::new());
        assert!(t.step(ctx(sink)).await.is_err());
    }
}
