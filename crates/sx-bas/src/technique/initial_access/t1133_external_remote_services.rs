//! `T1133ExternalRemoteServices` — MITRE ATT&CK T1133 (Initial Access).
//!
//! Safe-only passive probe over a declared inventory of externally-reachable
//! remote services (VPN concentrators, jump hosts, exposed RDP/SSH). Counts
//! how many lack multi-factor authentication. **No network I/O.**
//!
//! `max_mode = PassiveValidation`.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::simulation::{EvidenceRecord, SimulationStepContext, StepResult};
use crate::model::technique::{AttackTechnique, Capabilities, IntensityHint, MitreTag};

/// One declared external remote-access service.
#[derive(Debug, Clone)]
pub struct RemoteService {
    /// Logical name.
    pub name: String,
    /// `true` when MFA is enforced.
    pub mfa_enforced: bool,
}

/// Safe-only passive technique for T1133.
#[derive(Debug, Clone, Default)]
pub struct T1133ExternalRemoteServices {
    services: Vec<RemoteService>,
}

impl T1133ExternalRemoteServices {
    /// Construct.
    #[must_use]
    pub const fn new(services: Vec<RemoteService>) -> Self {
        Self { services }
    }
}

#[async_trait]
impl AttackTechnique for T1133ExternalRemoteServices {
    fn id(&self) -> &'static str {
        "t1133_external_remote_services_v1"
    }

    fn mitre(&self) -> MitreTag {
        MitreTag::new("TA0001", "T1133", None)
    }

    fn max_mode(&self) -> AttackMode {
        AttackMode::PassiveValidation
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            intensity: IntensityHint::Low,
            network_egress: false,
            destructive: false,
        }
    }

    async fn step(&self, ctx: SimulationStepContext) -> Result<StepResult, BasError> {
        let total: u32 = self.services.len().try_into().unwrap_or(u32::MAX);
        let no_mfa: u32 = self
            .services
            .iter()
            .filter(|s| !s.mfa_enforced)
            .count()
            .try_into()
            .unwrap_or(u32::MAX);

        let mut details = HashMap::new();
        details.insert("services".to_owned(), total.to_string());
        details.insert("no_mfa".to_owned(), no_mfa.to_string());
        details.insert("phase".to_owned(), "phase-1-passive".to_owned());
        details.insert(
            "explanation".to_owned(),
            "T1133: enumerates external remote services lacking MFA enforcement".to_owned(),
        );

        let record = EvidenceRecord {
            technique_id: self.id().to_owned(),
            mode: ctx.mode,
            tenant_id: ctx.tenant_id,
            engagement_id: ctx.engagement_id,
            summary: format!("T1133 passive: {no_mfa}/{total} services without MFA"),
            details: details.clone(),
            recorded_at: time::OffsetDateTime::now_utc(),
        };
        ctx.evidence_sink.record(record).await?;

        Ok(StepResult::Simulated {
            summary: format!("T1133 passive: {no_mfa}/{total} no-MFA remote services"),
            details,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{RemoteService, T1133ExternalRemoteServices};
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
            mode: AttackMode::PassiveValidation,
            kill_switch_signal: Arc::new(Notify::new()),
            deadline: OffsetDateTime::now_utc() + Duration::seconds(30),
            evidence_sink: sink,
        }
    }

    #[tokio::test]
    async fn t1133_safe_mode_and_simulation_output() {
        let t = T1133ExternalRemoteServices::new(vec![
            RemoteService {
                name: "vpn".into(),
                mfa_enforced: true,
            },
            RemoteService {
                name: "rdp".into(),
                mfa_enforced: false,
            },
        ]);
        assert!(t.max_mode() <= AttackMode::SafeInteractive);
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let out = t.step(ctx(sink.clone())).await.unwrap();
        match out {
            StepResult::Simulated { details, .. } => {
                assert_eq!(details.get("services").unwrap(), "2");
                assert_eq!(details.get("no_mfa").unwrap(), "1");
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
        assert_eq!(sink.len().await, 1);
        assert_eq!(t.mitre().technique_id, "T1133");
    }
}
