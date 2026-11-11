//! RBA high-risk Block enrichment table (TOP5-#3-P2-005).
//!
//! Maps the one canonical RBA emission `check_id` —
//! `"rba:high-risk-block"` — to a curated [`RbaBlockEnrichment`] payload
//! (CWE class(es), MITRE ATT&CK technique(s), NIST 800-53 controls). The
//! payload feeds the synthetic Finding emitted by
//! `services/sx-monolith::adapters::rba` whenever the RBA engine returns
//! a `Block` decision whose composite score breaches the operator-set
//! threshold.
//!
//! ## Why a one-entry table
//!
//! The original Wave B audit decision (PO Option (b)) ruled that we emit
//! a SINGLE rule id for every high-risk Block — variation by `signal_kind`
//! goes in the Finding description, not in the `rule_id` — so the
//! enrichment table is intentionally tiny. Keeping the lookup behind the
//! same `_enrichment()` function shape as [`super::header_enrichment`]
//! gives downstream consumers (SOC dashboards, SARIF export) one
//! consistent way to materialise the canonical reference data per
//! `check_id`.
//!
//! ## Don't fabricate
//!
//! Same policy as the header table: where no authoritative CVSS mapping
//! exists (RBA decisions are operational signals, not a vulnerability),
//! we return `None` for `cvss` rather than inventing a value. The
//! Finding emitter sets `confidence` from the composite score
//! independently.

use crate::value_object::compliance::{ComplianceTags, NistControl};
use crate::value_object::cwe::CweId;
use crate::value_object::mitre_attack::MitreAttackTechnique;

/// Legacy colon-form `check_id` for every high-risk RBA Block decision.
///
/// Retained for backward-compat receive-side lookups (external consumers
/// may still pin this shape). Superseded on emit by
/// [`RBA_HIGH_RISK_BLOCK_DOTTED`].
pub const RBA_HIGH_RISK_BLOCK_CHECK_ID: &str = "rba:high-risk-block";

/// Canonical dotted-form `check_id` for the high-risk RBA Block finding
/// (TOP5-#3 Phase 3). Every fresh emit MUST use this shape; the enrichment
/// lookup accepts both forms.
pub const RBA_HIGH_RISK_BLOCK_DOTTED: &str = "RBA.HIGH_RISK_BLOCK";

/// Curated enrichment payload for the high-risk RBA Block finding.
///
/// All fields are optional or default-empty so a missing piece of
/// authoritative reference data simply omits the corresponding wire key
/// when projected onto the wider Finding DTO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RbaBlockEnrichment {
    /// CWE identifiers describing the underlying weakness class(es).
    pub cwe: Vec<CweId>,
    /// MITRE ATT&CK techniques / sub-techniques this finding maps to.
    pub mitre_attack: Vec<MitreAttackTechnique>,
    /// Compliance-framework control mappings (NIST 800-53 only for the
    /// RBA emission; ISO/PCI mappings would be speculative here and are
    /// intentionally omitted).
    pub compliance: ComplianceTags,
}

/// Build the enrichment payload for the supplied `check_id`. Returns
/// `None` for any id outside the curated one-entry table.
///
/// Accepts both the legacy colon-form (`rba:high-risk-block`) and the
/// canonical dotted-form (`RBA.HIGH_RISK_BLOCK`, TOP5-#3 Phase 3).
#[must_use]
pub fn rba_block_enrichment(check_id: &str) -> Option<RbaBlockEnrichment> {
    if check_id == RBA_HIGH_RISK_BLOCK_CHECK_ID || check_id == RBA_HIGH_RISK_BLOCK_DOTTED {
        Some(high_risk_block())
    } else {
        None
    }
}

/// `rba:high-risk-block` — RBA composite score breached the operator-set
/// block threshold and the engine rejected the sign-in.
///
/// References:
/// - CWE-1390 Weak Authentication
///   (<https://cwe.mitre.org/data/definitions/1390.html>).
/// - CWE-303 Incorrect Implementation of Authentication Algorithm
///   (<https://cwe.mitre.org/data/definitions/303.html>).
/// - MITRE ATT&CK TA0001 Initial Access via T1110 Brute Force — the
///   tactic the RBA layer guards against; per the Wave B audit spec
///   line. The Brute Force technique covers credential-stuffing,
///   password-spray, and login-anomaly signals that the RBA composite
///   collapses into a single Block decision.
/// - NIST SP 800-53 Rev 5 AC-7 Unsuccessful Logon Attempts.
/// - NIST SP 800-53 Rev 5 IA-8 Identification and Authentication.
fn high_risk_block() -> RbaBlockEnrichment {
    RbaBlockEnrichment {
        cwe: vec![cwe(1390), cwe(303)],
        mitre_attack: vec![attack("TA0001", "T1110", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("AC-7"), nist("IA-8")],
            ..Default::default()
        },
    }
}

fn cwe(id: u32) -> CweId {
    CweId::new(id).unwrap_or_else(|e| {
        unreachable!("RBA block enrichment table CWE id rejected by constructor: {e:?}")
    })
}

fn attack(tactic: &str, technique: &str, sub: Option<String>) -> MitreAttackTechnique {
    MitreAttackTechnique::new(tactic, technique, sub).unwrap_or_else(|e| {
        unreachable!("RBA block enrichment table ATT&CK rejected by constructor: {e:?}")
    })
}

fn nist(id: &str) -> NistControl {
    NistControl::new(id).unwrap_or_else(|e| {
        unreachable!("RBA block enrichment table NIST control rejected by constructor: {e:?}")
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn canonical_check_id_resolves_to_payload() {
        let e = rba_block_enrichment(RBA_HIGH_RISK_BLOCK_CHECK_ID).unwrap();
        assert!(
            e.cwe.iter().any(|c| c.as_u32() == 1390),
            "must reference CWE-1390 Weak Authentication"
        );
        assert!(
            e.cwe.iter().any(|c| c.as_u32() == 303),
            "must reference CWE-303 Incorrect Implementation of Authentication Algorithm"
        );
        assert!(
            e.mitre_attack.iter().any(|t| t.tactic == "TA0001"),
            "must map to MITRE ATT&CK TA0001 Initial Access"
        );
        assert!(
            e.compliance
                .nist_800_53
                .iter()
                .any(|c| c.as_str() == "AC-7"),
            "must cite NIST AC-7 Unsuccessful Logon Attempts"
        );
        assert!(
            e.compliance
                .nist_800_53
                .iter()
                .any(|c| c.as_str() == "IA-8"),
            "must cite NIST IA-8 Identification and Authentication"
        );
    }

    #[test]
    fn unknown_check_id_returns_none() {
        assert!(rba_block_enrichment("rba:allow").is_none());
        assert!(rba_block_enrichment("rba:step-up").is_none());
        assert!(rba_block_enrichment("missing-hsts").is_none());
        assert!(rba_block_enrichment("").is_none());
    }

    #[test]
    fn check_id_constant_is_the_canonical_form() {
        // Guard against an accidental rename of the check_id — the
        // string is part of the persisted metadata.rule_id contract.
        assert_eq!(RBA_HIGH_RISK_BLOCK_CHECK_ID, "rba:high-risk-block");
    }

    /// TOP5-#3 Phase 3: dotted-form must resolve to the same payload as
    /// the legacy colon-form via the alias map.
    #[test]
    fn dotted_form_resolves_to_same_payload() {
        let legacy =
            rba_block_enrichment(RBA_HIGH_RISK_BLOCK_CHECK_ID).expect("legacy id resolves");
        let dotted = rba_block_enrichment(RBA_HIGH_RISK_BLOCK_DOTTED).expect("dotted id resolves");
        assert_eq!(legacy, dotted);
        assert_eq!(RBA_HIGH_RISK_BLOCK_DOTTED, "RBA.HIGH_RISK_BLOCK");
        assert!(RBA_HIGH_RISK_BLOCK_DOTTED.contains('.'));
    }
}
