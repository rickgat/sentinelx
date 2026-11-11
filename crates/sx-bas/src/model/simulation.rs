//! Simulation request / outcome / per-step plumbing.
//!
//! - [`SimulationRequest`] is the input to
//!   [`crate::controller::run_simulation::RunSimulationUseCase`].
//! - [`SimulationStepContext`] is what each
//!   [`crate::model::technique::AttackTechnique`] step receives.
//! - [`StepResult`] is what each step returns; aggregated by the use case
//!   into a [`SimulationOutcome`].
//! - [`EvidenceSink`] is the trait techniques use to record findings. An
//!   in-memory implementation ([`InMemoryEvidenceSink`]) is provided for
//!   tests; production wiring lives in adapter crates.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::{EngagementId, TenantId};
use time::OffsetDateTime;
use tokio::sync::{Mutex, Notify};

use crate::error::BasError;
use crate::model::approval::{Approval, RulesOfEngagement};
use crate::model::mode::AttackMode;
use crate::model::window::ChangeWindow;

/// Input to [`crate::controller::run_simulation::RunSimulationUseCase`].
#[derive(Debug, Clone)]
pub struct SimulationRequest {
    /// Tenant under which this simulation runs.
    pub tenant_id: TenantId,
    /// Engagement that authorises this simulation.
    pub engagement_id: EngagementId,
    /// Identifier of the technique to execute.
    pub technique_id: String,
    /// Operating mode ceiling for this simulation run.
    pub mode: AttackMode,
    /// Change window (required for `ActiveExploit` and `RedTeam`).
    pub change_window: Option<ChangeWindow>,
    /// Signed RoE artifact (required for `ActiveExploit` and `RedTeam`).
    pub roe: Option<RulesOfEngagement>,
    /// Approver ledger.
    pub approvals: Vec<Approval>,
    /// Now-instant the safety pipeline should use for window/RoE checks.
    pub now: OffsetDateTime,
    /// Per-step deadline; techniques abort with [`BasError::DeadlineExceeded`]
    /// if exceeded.
    pub deadline: OffsetDateTime,
}

/// Per-step context handed to [`crate::model::technique::AttackTechnique::step`].
#[derive(Debug, Clone)]
pub struct SimulationStepContext {
    /// Tenant under which the step runs.
    pub tenant_id: TenantId,
    /// Engagement that authorises the step.
    pub engagement_id: EngagementId,
    /// Active operating mode (≤ technique `max_mode`).
    pub mode: AttackMode,
    /// Kill-switch signal. Techniques MUST poll this between sub-steps so
    /// the ≤ 5-second SLA is honoured.
    pub kill_switch_signal: Arc<Notify>,
    /// Per-step deadline.
    pub deadline: OffsetDateTime,
    /// Where techniques record evidence records.
    pub evidence_sink: Arc<dyn EvidenceSink>,
}

/// The status of a single step's execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StepResult {
    /// The step was simulated only (no real I/O).
    Simulated {
        /// Free-text summary; never contains payload material.
        summary: String,
        /// Structured details (e.g. which assets were reachable).
        details: HashMap<String, String>,
    },
    /// The step was skipped because the mode did not permit it.
    Skipped {
        /// Reason for skipping.
        reason: String,
    },
    /// The step actually executed (only possible in adapter crates with the
    /// `dangerous_execution` feature, which is never on in this crate).
    Executed {
        /// Summary.
        summary: String,
    },
}

/// Outcome of a complete simulation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SimulationOutcome {
    /// The step ran (or was simulated) and returned a result.
    Simulated {
        /// Identifier of the technique that ran.
        technique_id: String,
        /// Step result.
        step: StepResult,
    },
    /// The simulation was halted by the kill switch.
    Killed {
        /// Identifier of the technique that was interrupted.
        technique_id: String,
    },
    /// The safety pipeline denied the simulation; the rejection error is
    /// included for audit visibility.
    Denied {
        /// Identifier of the technique that was rejected.
        technique_id: String,
        /// Display form of the denial reason (safe to log).
        reason: String,
    },
}

/// Evidence record persisted via an [`EvidenceSink`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Identifier of the technique that produced this record.
    pub technique_id: String,
    /// Active operating mode when the record was produced.
    pub mode: AttackMode,
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Engagement scope.
    pub engagement_id: EngagementId,
    /// Free-text summary; never contains payload material.
    pub summary: String,
    /// Structured details.
    pub details: HashMap<String, String>,
    /// Instant the record was emitted.
    pub recorded_at: OffsetDateTime,
}

/// Where techniques record evidence records.
///
/// Production wires this to the audit/storage layer. The
/// [`InMemoryEvidenceSink`] in this module is sufficient for unit tests.
#[async_trait]
pub trait EvidenceSink: Send + Sync + std::fmt::Debug {
    /// Persist a single evidence record.
    async fn record(&self, record: EvidenceRecord) -> Result<(), BasError>;
}

/// In-memory implementation of [`EvidenceSink`] for tests.
#[derive(Debug, Default)]
pub struct InMemoryEvidenceSink {
    records: Mutex<Vec<EvidenceRecord>>,
}

impl InMemoryEvidenceSink {
    /// Construct an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }

    /// Snapshot the current records.
    pub async fn snapshot(&self) -> Vec<EvidenceRecord> {
        self.records.lock().await.clone()
    }

    /// Returns the current record count.
    pub async fn len(&self) -> usize {
        self.records.lock().await.len()
    }

    /// Returns `true` when no records have been written.
    pub async fn is_empty(&self) -> bool {
        self.records.lock().await.is_empty()
    }
}

#[async_trait]
impl EvidenceSink for InMemoryEvidenceSink {
    async fn record(&self, record: EvidenceRecord) -> Result<(), BasError> {
        self.records.lock().await.push(record);
        Ok(())
    }
}

#[cfg(test)]
// Tests construct fixed-size vectors and index them directly; that's fine here.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::{EvidenceRecord, EvidenceSink, InMemoryEvidenceSink};
    use crate::model::mode::AttackMode;
    use std::collections::HashMap;
    use sx_core::value_object::ids::{EngagementId, TenantId};
    use time::OffsetDateTime;

    #[tokio::test]
    async fn in_memory_sink_records_and_snapshots() {
        let sink = InMemoryEvidenceSink::new();
        assert!(sink.is_empty().await);
        let rec = EvidenceRecord {
            technique_id: "x".into(),
            mode: AttackMode::Theoretical,
            tenant_id: TenantId::new(),
            engagement_id: EngagementId::new(),
            summary: "s".into(),
            details: HashMap::new(),
            recorded_at: OffsetDateTime::UNIX_EPOCH,
        };
        sink.record(rec.clone()).await.unwrap();
        assert_eq!(sink.len().await, 1);
        let snap = sink.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0], rec);
    }
}
