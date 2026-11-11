//! `AUDIT.*` audit-pipeline enrichment table (TOP5-#3 Phase 2 / P2-007).
//!
//! Maps `check_id`s emitted by the audit pipeline — today just
//! `audit:chain-break` (TOP5-#3-P2-007) — to a canonical
//! [`AuditEnrichment`] payload (CWE class, MITRE ATT&CK technique,
//! NIST 800-53 control). Sibling of
//! [`crate::reference::header_enrichment`] and shaped the same way so
//! every downstream emitter has one place to look for reference data.
//!
//! ## Why this lives in `sx-core`
//!
//! `sx-audit` (the chain-verifier crate) deliberately knows nothing
//! about [`crate::value_object::cwe::CweId`] or
//! [`sx_api::view::finding_view::FindingView`] — keeping it pure means
//! the verifier can be reused outside the `SentinelX` monolith without
//! pulling in the finding stack. The at-boundary observer wired in
//! `services/sx-monolith/src/adapters/audit_break_observer.rs` consumes
//! this table to translate a chain-break payload into a `FindingView`
//! before persisting via `FindingRepositoryPort::insert`.
//!
//! ## Don't fabricate
//!
//! Per the Phase 1 policy mirrored in `header_enrichment`: where no
//! authoritative mapping exists we return an empty
//! [`AuditEnrichment`] rather than inventing values. Every entry below
//! cites a specific public reference in its doc-comment.

use crate::value_object::compliance::{ComplianceTags, NistControl};
use crate::value_object::cwe::CweId;
use crate::value_object::mitre_attack::MitreAttackTechnique;

/// Curated enrichment payload for one audit-pipeline check.
///
/// All fields are vectors / default-empty containers so a missing piece
/// of authoritative reference data simply omits the corresponding wire
/// key (via `skip_serializing_if` on the consuming DTO/entity).
///
/// `Eq` is intentionally NOT derived to keep the shape symmetric with
/// the rest of the enrichment tables (which embed CVSS payloads carrying
/// `f64` base scores). Audit checks have no CVSS — chain-break is a
/// detection, not a vulnerability proof — so the CVSS slot is omitted
/// entirely from the struct.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditEnrichment {
    /// CWE identifiers describing the underlying weakness class(es).
    pub cwe: Vec<CweId>,
    /// MITRE ATT&CK techniques / sub-techniques this finding maps to.
    pub mitre_attack: Vec<MitreAttackTechnique>,
    /// Compliance-framework control mappings. NIST-only at present —
    /// audit-pipeline checks track regulatory log-integrity controls
    /// rather than ISO/PCI scopes.
    pub compliance: ComplianceTags,
}

/// Legacy colon-form `check_id` for the audit-chain-break detector
/// (CRIT-002 / TOP5-#3-P2-007). Retained for backward-compat receive-side
/// lookups (external consumers may still pin this shape).
pub const AUDIT_CHAIN_BREAK: &str = "audit:chain-break";

/// Canonical dotted-form `check_id` for the audit-chain-break detector
/// (TOP5-#3 Phase 3). Every fresh emit MUST use this shape; the
/// enrichment lookup accepts both forms.
pub const AUDIT_CHAIN_BROKEN_DOTTED: &str = "AUDIT.CHAIN.BROKEN";

/// Build the enrichment payload for the supplied `check_id`.
///
/// Accepts both the legacy colon-form (`audit:chain-break`) and the
/// canonical dotted-form (`AUDIT.CHAIN.BROKEN`, TOP5-#3 Phase 3).
///
/// Returns `None` for any id outside the curated table. The current
/// table has exactly one entry — [`AUDIT_CHAIN_BREAK`] — but is shaped
/// like [`crate::reference::header_enrichment`] so additional audit
/// detectors (anchor drift, TSA-fallback failure, sequence-gap fire,
/// etc.) can land follow-ups without restructuring the call sites.
#[must_use]
pub fn audit_enrichment(check_id: &str) -> Option<AuditEnrichment> {
    match check_id {
        AUDIT_CHAIN_BREAK | AUDIT_CHAIN_BROKEN_DOTTED => Some(audit_chain_break()),
        _ => None,
    }
}

/// `audit:chain-break` — audit hash chain divergence detected by the
/// background hot-tail verifier.
///
/// References:
/// - CWE-117 Improper Output Neutralization for Logs
///   (<https://cwe.mitre.org/data/definitions/117.html>).
/// - CWE-345 Insufficient Verification of Data Authenticity
///   (<https://cwe.mitre.org/data/definitions/345.html>).
/// - MITRE ATT&CK T1562.008 Impair Defenses: Disable or Modify Cloud Logs
///   under TA0005 Defense Evasion.
/// - NIST SP 800-53 Rev 5 AU-9 Protection of Audit Information.
///
/// CVSS is intentionally absent — a chain break is a detection signal
/// over a control surface, not a directly-exploitable vulnerability;
/// per the "don't fabricate" rule we leave the CVSS slot empty rather
/// than score a control-plane event against the wrong base metrics.
fn audit_chain_break() -> AuditEnrichment {
    AuditEnrichment {
        cwe: vec![cwe(117), cwe(345)],
        mitre_attack: vec![attack("TA0005", "T1562", Some("T1562.008".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("AU-9")],
            ..Default::default()
        },
    }
}

// ---------------------------------------------------------------------------
// Helpers — every constructor here is infallible on the values used above;
// failure would mean a typo in this file, which the unit tests catch.
// ---------------------------------------------------------------------------

fn cwe(id: u32) -> CweId {
    CweId::new(id).unwrap_or_else(|e| {
        unreachable!("AUDIT enrichment table CWE id rejected by constructor: {e:?}")
    })
}

fn attack(tactic: &str, technique: &str, sub: Option<String>) -> MitreAttackTechnique {
    MitreAttackTechnique::new(tactic, technique, sub).unwrap_or_else(|e| {
        unreachable!("AUDIT enrichment table ATT&CK rejected by constructor: {e:?}")
    })
}

fn nist(id: &str) -> NistControl {
    NistControl::new(id).unwrap_or_else(|e| {
        unreachable!("AUDIT enrichment table NIST control rejected by constructor: {e:?}")
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// Smoke test: the canonical id resolves and the constructors agree
    /// with the typed value-objects.
    #[test]
    fn chain_break_id_resolves_to_payload() {
        let e = audit_enrichment(AUDIT_CHAIN_BREAK).expect("chain-break must enrich");
        assert!(e.cwe.iter().any(|c| c.as_u32() == 117), "CWE-117 expected",);
        assert!(e.cwe.iter().any(|c| c.as_u32() == 345), "CWE-345 expected",);
        assert_eq!(e.mitre_attack.len(), 1);
        let m = &e.mitre_attack[0];
        assert_eq!(m.tactic, "TA0005");
        assert_eq!(m.technique, "T1562");
        assert_eq!(m.subtechnique.as_deref(), Some("T1562.008"));
        assert!(
            e.compliance
                .nist_800_53
                .iter()
                .any(|c| c.as_str() == "AU-9"),
            "NIST AU-9 expected",
        );
    }

    /// Unknown ids return `None` rather than fabricating an empty
    /// payload — matches the `hdr_enrichment` contract.
    #[test]
    fn unknown_id_returns_none() {
        assert!(audit_enrichment("audit:made-up").is_none());
        assert!(audit_enrichment("HDR.STRICT_TRANSPORT_SECURITY.MISSING").is_none());
    }

    /// TOP5-#3 Phase 3: dotted-form must resolve to the same payload as
    /// the legacy colon-form; alias-map keeps the receive side compatible.
    #[test]
    fn dotted_form_resolves_to_same_payload() {
        let legacy = audit_enrichment(AUDIT_CHAIN_BREAK).expect("legacy id resolves");
        let dotted = audit_enrichment(AUDIT_CHAIN_BROKEN_DOTTED).expect("dotted id resolves");
        assert_eq!(legacy, dotted);
        assert_eq!(AUDIT_CHAIN_BROKEN_DOTTED, "AUDIT.CHAIN.BROKEN");
        assert!(AUDIT_CHAIN_BROKEN_DOTTED.contains('.'));
    }
}
