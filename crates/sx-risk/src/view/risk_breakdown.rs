//! [`RiskBreakdownView`] — serializable shape for `sx-api` responses and
//! `sx-engagement` reports.

use serde::{Deserialize, Serialize};
use sx_core::value_object::severity::Severity;

use crate::model::{ComponentScore, RiskScore};

/// JSON-friendly view of a single computed risk score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskBreakdownView {
    /// Final composite score, `0.0..=100.0`.
    pub score: f64,
    /// Severity bucket derived from `score`.
    pub severity: Severity,
    /// Per-component contributions.
    pub components: ComponentScore,
    /// True iff the EPSS probability was at or above the
    /// `epss_threshold_act` configured policy.
    pub epss_act_threshold_breached: bool,
    /// True iff the underlying CVE is on the CISA KEV catalogue.
    pub kev: bool,
}

impl RiskBreakdownView {
    /// Build a [`RiskBreakdownView`] from the scorer outputs.
    #[must_use]
    pub const fn new(
        score: RiskScore,
        severity: Severity,
        components: ComponentScore,
        epss_act_threshold_breached: bool,
        kev: bool,
    ) -> Self {
        Self {
            score: score.value(),
            severity,
            components,
            epss_act_threshold_breached,
            kev,
        }
    }
}
