//! Per-component breakdown of a [`crate::model::RiskScore`].
//!
//! Each `*_part` field is the **post-weighting** contribution of that
//! component to the final score, so summing them recovers the composite
//! (modulo floating-point noise).

use serde::{Deserialize, Serialize};

/// Per-component breakdown of a composite risk score.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct ComponentScore {
    /// Contribution from CVSS / severity.
    pub severity_part: f64,
    /// Contribution from EPSS + KEV.
    pub exploit_part: f64,
    /// Contribution from asset exposure.
    pub exposure_part: f64,
    /// Contribution from asset criticality.
    pub criticality_part: f64,
    /// Contribution from business impact.
    pub business_part: f64,
    /// Contribution from attack-chain amplifier.
    pub chain_part: f64,
}

impl ComponentScore {
    /// Sum of all per-component contributions — should equal the composite
    /// score (modulo rounding).
    #[must_use]
    pub fn total(&self) -> f64 {
        self.severity_part
            + self.exploit_part
            + self.exposure_part
            + self.criticality_part
            + self.business_part
            + self.chain_part
    }
}
