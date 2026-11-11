//! AI copilot input + output value objects.

use serde::{Deserialize, Serialize};
use sx_core::prelude::{CveId, FindingId};
use url::Url;

/// Input handed to
/// [`crate::controller::remediation_copilot::RemediationCopilotUseCase::execute`].
///
/// Carries the (already-discovered) finding's identity plus the free-form
/// text excerpts the model may consume. Any PII or role markers in
/// `finding_summary` / `evidence_excerpt` are stripped by the use-case before
/// the prompt is built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRemediationInput {
    /// Finding being remediated.
    pub finding_id: FindingId,
    /// CVE that motivated this remediation request.
    pub cve_id: CveId,
    /// Short, human-readable description of the finding. Sanitised before
    /// prompt construction.
    pub finding_summary: String,
    /// Free-form evidence excerpt (e.g. scanner output). Sanitised before
    /// prompt construction. May be empty.
    pub evidence_excerpt: String,
}

impl AiRemediationInput {
    /// Build a new copilot input.
    #[must_use]
    pub fn new(
        finding_id: FindingId,
        cve_id: CveId,
        finding_summary: impl Into<String>,
        evidence_excerpt: impl Into<String>,
    ) -> Self {
        Self {
            finding_id,
            cve_id,
            finding_summary: finding_summary.into(),
            evidence_excerpt: evidence_excerpt.into(),
        }
    }
}

/// Output produced by the copilot.
///
/// The `references` list is constrained: every URL it contains MUST also
/// appear in the underlying advisories' reference set. The use-case verifies
/// this invariant after parsing the LLM response.
///
/// `Eq` is intentionally not implemented because [`Self::confidence`] is
/// `f32`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiRemediation {
    /// Short narrative summary (≤ 200 words by convention; the use-case
    /// does not hard-truncate but the system prompt asks the model to obey).
    pub summary: String,
    /// Ordered remediation steps. Each step is intended to be actionable in
    /// isolation; humans approve before execution.
    pub steps: Vec<String>,
    /// References cited by the model. Subset of the advisory URL set.
    pub references: Vec<Url>,
    /// Confidence in the recommendation, in `0.0..=1.0`.
    pub confidence: f32,
    /// Identifier of the model that produced the output (e.g.
    /// `"claude-opus-4-7-1m"`).
    pub model_id: String,
}

impl AiRemediation {
    /// Build a new remediation record.
    #[must_use]
    pub fn new(
        summary: impl Into<String>,
        steps: Vec<String>,
        references: Vec<Url>,
        confidence: f32,
        model_id: impl Into<String>,
    ) -> Self {
        Self {
            summary: summary.into(),
            steps,
            references,
            confidence: confidence.clamp(0.0, 1.0),
            model_id: model_id.into(),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::single_char_pattern
)]
mod tests {
    use super::*;

    #[test]
    fn input_constructs() {
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let i = AiRemediationInput::new(FindingId::new(), cve, "summary", "evidence");
        assert_eq!(i.finding_summary, "summary");
    }

    #[test]
    fn output_clamps_confidence() {
        let r = AiRemediation::new("s", vec![], vec![], 1.5, "claude-opus-4-7-1m");
        assert!((r.confidence - 1.0).abs() < f32::EPSILON);
        let r2 = AiRemediation::new("s", vec![], vec![], -0.5, "claude-opus-4-7-1m");
        assert!(r2.confidence.abs() < f32::EPSILON);
    }
}
