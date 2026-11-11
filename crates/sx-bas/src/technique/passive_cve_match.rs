//! `PassiveCveMatch` — MITRE T1190 passive CVE confirmation.
//!
//! Input is a `Vec<CveId>` discovered for an asset; output is "would this
//! technique succeed against any of them?" based on a static decision table
//! mapping CVE → [`PoCAvailability`]. **No I/O whatsoever.**
//!
//! `max_mode = PassiveValidation`.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::CveId;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::simulation::{EvidenceRecord, SimulationStepContext, StepResult};
use crate::model::technique::{AttackTechnique, Capabilities, IntensityHint, MitreTag};

/// Whether a public PoC is known for a given CVE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoCAvailability {
    /// No public PoC.
    None,
    /// Theoretical PoC known.
    Theoretical,
    /// Working public PoC.
    Public,
    /// Weaponised exploit observed in the wild.
    Weaponised,
}

impl PoCAvailability {
    /// Returns `true` for `Public` or `Weaponised` — these are the cases the
    /// technique reports as "would-succeed".
    #[must_use]
    pub const fn is_actionable(self) -> bool {
        matches!(self, Self::Public | Self::Weaponised)
    }
}

/// Decision-table technique: maps CVE → PoC availability.
#[derive(Debug, Clone)]
pub struct PassiveCveMatch {
    table: HashMap<CveId, PoCAvailability>,
}

impl PassiveCveMatch {
    /// Construct with a CVE → availability table.
    #[must_use]
    pub const fn new(table: HashMap<CveId, PoCAvailability>) -> Self {
        Self { table }
    }

    /// Look up a single CVE.
    #[must_use]
    pub fn lookup(&self, cve: &CveId) -> PoCAvailability {
        self.table
            .get(cve)
            .copied()
            .unwrap_or(PoCAvailability::None)
    }

    /// Evaluate against a list of CVEs observed on the asset.
    #[must_use]
    pub fn evaluate(&self, observed: &[CveId]) -> Vec<(CveId, PoCAvailability)> {
        observed
            .iter()
            .map(|c| (c.clone(), self.lookup(c)))
            .collect()
    }
}

/// Optional in-step input passed via `details` placeholder. The orchestrator
/// constructs the technique with the observed CVE set baked into the
/// decision-table at registration time; for per-step targeting it uses a
/// derived technique. Here, the technique reports the static table.
#[async_trait]
impl AttackTechnique for PassiveCveMatch {
    fn id(&self) -> &'static str {
        "passive_cve_match_v1"
    }

    fn mitre(&self) -> MitreTag {
        MitreTag::new("TA0001", "T1190", None)
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
        let actionable: u32 = self
            .table
            .values()
            .filter(|v| v.is_actionable())
            .count()
            .try_into()
            .unwrap_or(u32::MAX);
        let total: u32 = self.table.len().try_into().unwrap_or(u32::MAX);

        let mut details = HashMap::new();
        details.insert("table_size".to_owned(), total.to_string());
        details.insert("actionable".to_owned(), actionable.to_string());

        let record = EvidenceRecord {
            technique_id: self.id().to_owned(),
            mode: ctx.mode,
            tenant_id: ctx.tenant_id,
            engagement_id: ctx.engagement_id,
            summary: format!("T1190 passive CVE match: {actionable}/{total} actionable"),
            details: details.clone(),
            recorded_at: time::OffsetDateTime::now_utc(),
        };
        ctx.evidence_sink.record(record).await?;

        Ok(StepResult::Simulated {
            summary: format!("passive_cve_match: {actionable}/{total} actionable"),
            details,
        })
    }
}

#[cfg(test)]
// Tests use `panic!` to assert on unexpected enum variants.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{PassiveCveMatch, PoCAvailability};
    use crate::model::mode::AttackMode;
    use crate::model::simulation::{InMemoryEvidenceSink, SimulationStepContext, StepResult};
    use crate::model::technique::AttackTechnique;
    use std::collections::HashMap;
    use std::sync::Arc;
    use sx_core::value_object::ids::{CveId, EngagementId, TenantId};
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
    async fn passive_cve_match_returns_simulated_outcome() {
        let mut table = HashMap::new();
        table.insert(
            CveId::new("CVE-2024-12345").unwrap(),
            PoCAvailability::Weaponised,
        );
        table.insert(CveId::new("CVE-2024-00001").unwrap(), PoCAvailability::None);
        let t = PassiveCveMatch::new(table);
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let out = t.step(ctx(sink.clone())).await.unwrap();
        match out {
            StepResult::Simulated { details, .. } => {
                assert_eq!(details.get("table_size").unwrap(), "2");
                assert_eq!(details.get("actionable").unwrap(), "1");
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
        assert_eq!(sink.len().await, 1);
    }

    #[test]
    fn poc_actionable_classification() {
        assert!(!PoCAvailability::None.is_actionable());
        assert!(!PoCAvailability::Theoretical.is_actionable());
        assert!(PoCAvailability::Public.is_actionable());
        assert!(PoCAvailability::Weaponised.is_actionable());
    }
}
