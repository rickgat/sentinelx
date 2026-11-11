//! [`Evidence`] — proof that a finding maps to a control was observed.
//!
//! Records are append-only and immutable once written. The
//! [`crate::controller::collect_evidence::CollectEvidenceUseCase`] is the
//! only sanctioned constructor for production use; it stamps the
//! `collected_at` timestamp and validates the input.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// A single evidence record attaching a finding to a control.
///
/// Stored append-only by the evidence sink. The crate makes no
/// assumptions about where the sink ultimately writes — production
/// implementations land in `sx-storage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Control identifier (`Control::id`) this evidence supports.
    pub control_id: String,
    /// Free-form reference to the originating finding (typically a UUID).
    pub finding_ref: String,
    /// Free-form reference to the observation that produced the finding
    /// (e.g. a scan run id, a log document id).
    pub observation_ref: String,
    /// Timestamp at which the evidence was collected (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub collected_at: OffsetDateTime,
}

impl Evidence {
    /// Construct a new [`Evidence`] record.
    #[must_use]
    pub fn new(
        control_id: impl Into<String>,
        finding_ref: impl Into<String>,
        observation_ref: impl Into<String>,
        collected_at: OffsetDateTime,
    ) -> Self {
        Self {
            control_id: control_id.into(),
            finding_ref: finding_ref.into(),
            observation_ref: observation_ref.into(),
            collected_at,
        }
    }
}
