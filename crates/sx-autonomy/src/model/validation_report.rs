//! Per-pass validation report emitted by the continuous validation engine.

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::{EngagementId, TenantId};
use time::OffsetDateTime;

/// Coarse outcome of a single technique run inside a validation pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    /// Technique completed successfully — no signal of compromise.
    Pass,
    /// Technique completed and identified a finding (or failed control).
    Fail,
    /// Technique was halted because the engagement kill switch tripped.
    Killed,
    /// Technique aborted for any other safety-pipeline reason.
    Aborted,
    /// Technique skipped (e.g. mode-ladder violation).
    Skipped,
}

/// Per-technique result inside a [`ValidationReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TechniqueOutcome {
    /// Stable technique id (matches `sx_bas::AttackTechnique::id`).
    pub technique_id: String,
    /// Outcome bucket for this technique on this pass.
    pub outcome: ValidationOutcome,
    /// Free-form note. Never carries secrets or evidence material.
    pub note: String,
}

impl TechniqueOutcome {
    /// Build a new per-technique outcome.
    #[must_use]
    pub fn new(
        technique_id: impl Into<String>,
        outcome: ValidationOutcome,
        note: impl Into<String>,
    ) -> Self {
        Self {
            technique_id: technique_id.into(),
            outcome,
            note: note.into(),
        }
    }
}

/// One pass of the continuous validation engine.
///
/// Reports are immutable once emitted; the engine forwards them to a
/// [`crate::service::validation_engine::ValidationReportSink`] for storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Tenant that owns the engagement being validated.
    pub tenant_id: TenantId,
    /// Engagement the report belongs to.
    pub engagement_id: EngagementId,
    /// When the pass started.
    pub started_at: OffsetDateTime,
    /// When the pass finished.
    pub finished_at: OffsetDateTime,
    /// Per-technique outcomes (one entry per configured technique id).
    pub outcomes: Vec<TechniqueOutcome>,
    /// Whether the pass terminated because the kill switch tripped.
    pub killed: bool,
}

impl ValidationReport {
    /// Build a new report.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        engagement_id: EngagementId,
        started_at: OffsetDateTime,
        finished_at: OffsetDateTime,
        outcomes: Vec<TechniqueOutcome>,
        killed: bool,
    ) -> Self {
        Self {
            tenant_id,
            engagement_id,
            started_at,
            finished_at,
            outcomes,
            killed,
        }
    }

    /// `true` when every technique outcome is `Pass`.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        !self.outcomes.is_empty()
            && self
                .outcomes
                .iter()
                .all(|o| o.outcome == ValidationOutcome::Pass)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn all_passed_requires_non_empty() {
        let r = ValidationReport::new(
            TenantId::new(),
            EngagementId::new(),
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc(),
            vec![],
            false,
        );
        assert!(!r.all_passed());
    }

    #[test]
    fn all_passed_detects_failures() {
        let r = ValidationReport::new(
            TenantId::new(),
            EngagementId::new(),
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc(),
            vec![
                TechniqueOutcome::new("t1", ValidationOutcome::Pass, ""),
                TechniqueOutcome::new("t2", ValidationOutcome::Fail, ""),
            ],
            false,
        );
        assert!(!r.all_passed());
    }
}
