//! [`SsvcDecisionView`] — serializable wrapper around [`SsvcDecision`].

use serde::{Deserialize, Serialize};

use crate::model::{SsvcDecision, SsvcInput};

/// JSON-friendly SSVC decision view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsvcDecisionView {
    /// Echoed input bundle (useful for auditing how the decision was
    /// reached).
    pub input: SsvcInput,
    /// The mapped decision label.
    pub decision: SsvcDecision,
}

impl SsvcDecisionView {
    /// Build the view.
    #[must_use]
    pub const fn new(input: SsvcInput, decision: SsvcDecision) -> Self {
        Self { input, decision }
    }
}
