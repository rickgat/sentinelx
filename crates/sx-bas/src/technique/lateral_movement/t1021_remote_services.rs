//! `T1021RemoteServices` — MITRE ATT&CK T1021 (Lateral Movement).
//!
//! Safe-only passive technique. Counts items in a caller-supplied
//! inventory according to the heuristic explained below. **No I/O.**
//!
//! `max_mode = PassiveValidation`.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::simulation::{EvidenceRecord, SimulationStepContext, StepResult};
use crate::model::technique::{AttackTechnique, Capabilities, IntensityHint, MitreTag};

/// Inventory entry consumed by [`T1021RemoteServices`].
#[derive(Debug, Clone)]
pub struct T1021RemoteServicesEntry {
    /// Logical identifier (e.g. host name, account, service).
    pub name: String,
    /// `true` when the entry trips the technique's heuristic.
    pub flagged: bool,
}

/// Safe-only passive technique for T1021.
#[derive(Debug, Clone, Default)]
pub struct T1021RemoteServices {
    items: Vec<T1021RemoteServicesEntry>,
}

impl T1021RemoteServices {
    /// Construct with the caller-supplied inventory.
    #[must_use]
    pub const fn new(items: Vec<T1021RemoteServicesEntry>) -> Self {
        Self { items }
    }
}

#[async_trait]
impl AttackTechnique for T1021RemoteServices {
    fn id(&self) -> &'static str {
        "t1021_remote_services_v1"
    }

    fn mitre(&self) -> MitreTag {
        MitreTag::new("TA0008", "T1021", None)
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
        let total: u32 = self.items.len().try_into().unwrap_or(u32::MAX);
        let flagged: u32 = self
            .items
            .iter()
            .filter(|s| s.flagged)
            .count()
            .try_into()
            .unwrap_or(u32::MAX);

        let mut details = HashMap::new();
        details.insert("endpoints".to_owned(), total.to_string());
        details.insert("flagged".to_owned(), flagged.to_string());
        details.insert("phase".to_owned(), "phase-1-passive".to_owned());
        details.insert(
            "explanation".to_owned(),
            "T1021: counts open SSH/RDP/SMB endpoints discovered in connectivity check".to_owned(),
        );

        let record = EvidenceRecord {
            technique_id: self.id().to_owned(),
            mode: ctx.mode,
            tenant_id: ctx.tenant_id,
            engagement_id: ctx.engagement_id,
            summary: format!("T1021 passive: {flagged}/{total} flagged"),
            details: details.clone(),
            recorded_at: time::OffsetDateTime::now_utc(),
        };
        ctx.evidence_sink.record(record).await?;

        Ok(StepResult::Simulated {
            summary: format!("T1021 passive: {flagged}/{total} flagged"),
            details,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{T1021RemoteServices, T1021RemoteServicesEntry};
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
    async fn t1021_remote_services_safe_mode_and_simulation_output() {
        let t = T1021RemoteServices::new(vec![
            T1021RemoteServicesEntry {
                name: "a".into(),
                flagged: true,
            },
            T1021RemoteServicesEntry {
                name: "b".into(),
                flagged: false,
            },
        ]);
        // All P1-008 techniques must be capped at SafeInteractive or lower.
        assert!(t.max_mode() <= AttackMode::SafeInteractive);
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let out = t.step(ctx(sink.clone())).await.unwrap();
        match out {
            StepResult::Simulated { details, .. } => {
                assert_eq!(details.get("endpoints").unwrap(), "2");
                assert_eq!(details.get("flagged").unwrap(), "1");
                assert!(details.contains_key("explanation"));
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
        assert_eq!(sink.len().await, 1);
        assert_eq!(t.mitre().technique_id, "T1021");
        assert_eq!(t.mitre().tactic_id, "TA0008");
    }
}
