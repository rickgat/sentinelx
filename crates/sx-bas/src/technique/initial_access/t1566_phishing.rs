//! `T1566Phishing` — MITRE ATT&CK T1566 (Initial Access).
//!
//! Safe-only theoretical technique. Counts items in a caller-supplied
//! inventory according to the heuristic explained below. **No I/O.**
//!
//! `max_mode = Theoretical`.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::simulation::{EvidenceRecord, SimulationStepContext, StepResult};
use crate::model::technique::{AttackTechnique, Capabilities, IntensityHint, MitreTag};

/// Inventory entry consumed by [`T1566Phishing`].
#[derive(Debug, Clone)]
pub struct T1566PhishingEntry {
    /// Logical identifier (e.g. host name, account, service).
    pub name: String,
    /// `true` when the entry trips the technique's heuristic.
    pub flagged: bool,
}

/// Safe-only theoretical technique for T1566.
#[derive(Debug, Clone, Default)]
pub struct T1566Phishing {
    items: Vec<T1566PhishingEntry>,
}

impl T1566Phishing {
    /// Construct with the caller-supplied inventory.
    #[must_use]
    pub const fn new(items: Vec<T1566PhishingEntry>) -> Self {
        Self { items }
    }
}

#[async_trait]
impl AttackTechnique for T1566Phishing {
    fn id(&self) -> &'static str {
        "t1566_phishing_v1"
    }

    fn mitre(&self) -> MitreTag {
        MitreTag::new("TA0001", "T1566", None)
    }

    fn max_mode(&self) -> AttackMode {
        AttackMode::Theoretical
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            intensity: IntensityHint::None,
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
        details.insert("policies".to_owned(), total.to_string());
        details.insert("flagged".to_owned(), flagged.to_string());
        details.insert("phase".to_owned(), "phase-1-theoretical".to_owned());
        details.insert(
            "explanation".to_owned(),
            "T1566: theoretical phishing exposure based on declared mail-gateway policy".to_owned(),
        );

        let record = EvidenceRecord {
            technique_id: self.id().to_owned(),
            mode: ctx.mode,
            tenant_id: ctx.tenant_id,
            engagement_id: ctx.engagement_id,
            summary: format!("T1566 theoretical: {flagged}/{total} flagged"),
            details: details.clone(),
            recorded_at: time::OffsetDateTime::now_utc(),
        };
        ctx.evidence_sink.record(record).await?;

        Ok(StepResult::Simulated {
            summary: format!("T1566 theoretical: {flagged}/{total} flagged"),
            details,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{T1566Phishing, T1566PhishingEntry};
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
            mode: AttackMode::Theoretical,
            kill_switch_signal: Arc::new(Notify::new()),
            deadline: OffsetDateTime::now_utc() + Duration::seconds(30),
            evidence_sink: sink,
        }
    }

    #[tokio::test]
    async fn t1566_phishing_safe_mode_and_simulation_output() {
        let t = T1566Phishing::new(vec![
            T1566PhishingEntry {
                name: "a".into(),
                flagged: true,
            },
            T1566PhishingEntry {
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
                assert_eq!(details.get("policies").unwrap(), "2");
                assert_eq!(details.get("flagged").unwrap(), "1");
                assert!(details.contains_key("explanation"));
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
        assert_eq!(sink.len().await, 1);
        assert_eq!(t.mitre().technique_id, "T1566");
        assert_eq!(t.mitre().tactic_id, "TA0001");
    }
}
