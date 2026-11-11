//! SAML SP attack-detection enrichment table (TOP5-#3-P2-004).
//!
//! Four curated rows — one per attack class the SP verifier rejects via
//! the gate layer (`sx_iam::service::saml::fuzz_entry::pre_parse_gates`)
//! and the multi-`<Assertion>` defence:
//!
//! * `saml:xsw-detected` — XML Signature Wrapping.
//! * `saml:xee-detected` — XML External Entity (DOCTYPE / DTD).
//! * `saml:transform-bypass-detected` — XSLT / `XPath` / unknown transform
//!   URI, or a Reference URI that does not bind the signed subtree.
//! * `saml:c14n-violation` — legacy canonicalisation, mixed C14N
//!   versions, default-namespace re-declaration in `<SignedInfo>`.
//!
//! Confidence is fixed at `1.0` at the call site (FOUND-001 contract);
//! the gate-level rejection is deterministic, not probabilistic, so the
//! emitted finding's confidence cannot be calibrated lower without
//! lying about the wire signal. CVSS is intentionally absent — the
//! finding is a **detection signal** of an attempt, not a vulnerability
//! score of a running service.
//!
//! Per the project rule "zero I/O in `sx-core`": this is a compile-time
//! string table; no network, no file reads.

use crate::value_object::compliance::{ComplianceTags, NistControl};
use crate::value_object::cwe::CweId;
use crate::value_object::mitre_attack::MitreAttackTechnique;

/// Severity tier for a SAML attack-detection finding. The wire uses the
/// lower-case kebab strings auditors expect (`high`, `medium`, …) so
/// downstream SIEM rules match against these directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlAttackSeverity {
    /// `high` — wrapping / XEE / transform-bypass: signed-subtree
    /// integrity actually under threat.
    High,
    /// `medium` — C14N policy violation: canonicalisation drift
    /// surfaced before the digest reached an attacker-controlled
    /// shape; weaker signal.
    Medium,
}

impl SamlAttackSeverity {
    /// Lower-case kebab-case string used on the wire — the same set
    /// `FindingView::severity` already accepts.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
        }
    }
}

/// Curated enrichment payload for one SAML attack class.
///
/// Field shape mirrors `sx_api::view::scan_view::ScanFinding` /
/// `sx_core::sarif::SarifResult` to keep the wire consistent across
/// emitter surfaces (per SX-REVIEW-002 C1's "one source of truth"
/// principle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlAttackEnrichment {
    /// CWE identifiers describing the weakness class(es).
    pub cwe: Vec<CweId>,
    /// MITRE ATT&CK techniques / sub-techniques this attack maps to.
    pub mitre_attack: Vec<MitreAttackTechnique>,
    /// Compliance-framework control mappings.
    pub compliance: ComplianceTags,
    /// Severity tier (`high` / `medium`).
    pub severity: SamlAttackSeverity,
    /// Short audit-facing title (rendered on the dashboard / SIEM).
    pub title: &'static str,
    /// Long-form description — what the SP saw, what it means, why it
    /// was rejected.
    pub description: &'static str,
}

/// Canonical dotted-form `rule_id` constants for the SAML attack observer
/// (TOP5-#3 Phase 3). Every fresh emit MUST use these shapes.
pub const SAML_XSW_DOTTED: &str = "SAML.XSW";
/// Canonical dotted-form for XML External Entity detection.
pub const SAML_XEE_DOTTED: &str = "SAML.XEE";
/// Canonical dotted-form for XSLT transform-bypass detection.
pub const SAML_TRANSFORM_BYPASS_DOTTED: &str = "SAML.TRANSFORM_BYPASS";
/// Canonical dotted-form for C14N canonicalisation violation.
pub const SAML_C14N_DOTTED: &str = "SAML.C14N";

/// Look up the enrichment payload for a `rule_id` emitted by the SAML
/// observer. Returns `None` for any id outside the curated table.
///
/// Accepts both the legacy colon-form (FOUND-001 contract) and the
/// canonical dotted-form (TOP5-#3 Phase 3):
///
/// - `saml:xsw-detected` / `SAML.XSW`
/// - `saml:xee-detected` / `SAML.XEE`
/// - `saml:transform-bypass-detected` / `SAML.TRANSFORM_BYPASS`
/// - `saml:c14n-violation` / `SAML.C14N`
#[must_use]
pub fn saml_attack_enrichment(rule_id: &str) -> Option<SamlAttackEnrichment> {
    match rule_id {
        "saml:xsw-detected" | SAML_XSW_DOTTED => Some(xsw_detected()),
        "saml:xee-detected" | SAML_XEE_DOTTED => Some(xee_detected()),
        "saml:transform-bypass-detected" | SAML_TRANSFORM_BYPASS_DOTTED => {
            Some(transform_bypass_detected())
        }
        "saml:c14n-violation" | SAML_C14N_DOTTED => Some(c14n_violation()),
        _ => None,
    }
}

/// XML Signature Wrapping rejection.
///
/// References:
/// - CWE-347 Improper Verification of Cryptographic Signature
///   (<https://cwe.mitre.org/data/definitions/347.html>).
/// - CWE-345 Insufficient Verification of Data Authenticity
///   (<https://cwe.mitre.org/data/definitions/345.html>).
/// - MITRE ATT&CK T1556 Modify Authentication Process, sub-technique
///   T1556.007 Hybrid Identity (the SAML attack family lives here).
/// - NIST SP 800-53 Rev 5 SC-23 Session Authenticity.
fn xsw_detected() -> SamlAttackEnrichment {
    SamlAttackEnrichment {
        cwe: vec![cwe(347), cwe(345)],
        mitre_attack: vec![attack("TA0006", "T1556", Some("T1556.007".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-23")],
            ..Default::default()
        },
        severity: SamlAttackSeverity::High,
        title: "SAML XML Signature Wrapping (XSW) attempt rejected",
        description: "The SAML SP rejected an inbound assertion that exhibited an XML Signature \
             Wrapping shape: either multiple top-level <Assertion> / <Signature> elements \
             were present, or the embedded <Reference URI> did not bind the assertion subtree \
             the digest was computed over. The wire rejection stands; this finding records \
             the attempt for audit and SOC analysis.",
    }
}

/// XML External Entity rejection (DOCTYPE / DTD).
///
/// References:
/// - CWE-611 Improper Restriction of XML External Entity Reference
///   (<https://cwe.mitre.org/data/definitions/611.html>).
/// - MITRE ATT&CK T1190 Exploit Public-Facing Application.
/// - NIST SP 800-53 Rev 5 SI-10 Information Input Validation.
fn xee_detected() -> SamlAttackEnrichment {
    SamlAttackEnrichment {
        cwe: vec![cwe(611)],
        mitre_attack: vec![attack("TA0001", "T1190", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-10")],
            ..Default::default()
        },
        severity: SamlAttackSeverity::High,
        title: "SAML XML External Entity (XEE) attempt rejected",
        description: "The SAML SP rejected an inbound response that carried a DOCTYPE / DTD \
             declaration. XML External Entity expansion (Billion-Laughs, parameter-entity \
             exfiltration) is refused outright at the byte-level pre-parse gate.",
    }
}

/// Transform-allow-list bypass / Reference-URI drift.
///
/// References:
/// - CWE-91 XML Injection (a.k.a. Blind `XPath` Injection)
///   (<https://cwe.mitre.org/data/definitions/91.html>).
/// - CWE-352 Cross-Site Request Forgery — included because the
///   transform-bypass shape was historically used to forge IdP-asserted
///   identity in a relying-party trust boundary.
/// - MITRE ATT&CK T1190 Exploit Public-Facing Application.
/// - NIST SP 800-53 Rev 5 SC-7 Boundary Protection.
fn transform_bypass_detected() -> SamlAttackEnrichment {
    SamlAttackEnrichment {
        cwe: vec![cwe(91), cwe(352)],
        mitre_attack: vec![attack("TA0001", "T1190", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-7")],
            ..Default::default()
        },
        severity: SamlAttackSeverity::High,
        title: "SAML XML-DSig transform-bypass attempt rejected",
        description: "The SAML SP rejected an inbound assertion whose <Transform> chain used an \
             algorithm outside the closed allow-list (XSLT / XPath / unknown URI), or whose \
             <Reference URI> did not point at the embedded <Assertion>. Both shapes are \
             classical signature-bypass vectors: smuggle attacker-controlled bytes through a \
             transform the digest does not actually cover.",
    }
}

/// C14N policy violation.
///
/// References:
/// - CWE-345 Insufficient Verification of Data Authenticity
///   (<https://cwe.mitre.org/data/definitions/345.html>).
/// - MITRE ATT&CK T1574 Hijack Execution Flow — the canonicalisation
///   downgrade pattern aligns with the broader subversion family.
/// - NIST SP 800-53 Rev 5 AU-9 Protection of Audit Information.
fn c14n_violation() -> SamlAttackEnrichment {
    SamlAttackEnrichment {
        cwe: vec![cwe(345)],
        mitre_attack: vec![attack("TA0005", "T1574", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("AU-9")],
            ..Default::default()
        },
        severity: SamlAttackSeverity::Medium,
        title: "SAML XML-DSig canonicalisation policy violation",
        description:
            "The SAML SP rejected an inbound assertion whose canonicalisation declaration \
             was non-compliant: legacy xml-c14n (non-exclusive), mixed canonicalisation \
             versions across one document, default-namespace re-declaration inside \
             <SignedInfo>, or no <CanonicalizationMethod> at all. Surfaced at medium \
             severity because the digest can still be enforced — but the drift weakens the \
             signed-subtree guarantee and is an early indicator of XML manipulation.",
    }
}

// ---------------------------------------------------------------------------
// Helpers — every constructor here is infallible on the values used above;
// failure would mean a typo in this file, which the unit tests catch.
// ---------------------------------------------------------------------------

fn cwe(id: u32) -> CweId {
    CweId::new(id).unwrap_or_else(|e| {
        unreachable!("SAML attack enrichment CWE id rejected by constructor: {e:?}")
    })
}

fn attack(tactic: &str, technique: &str, sub: Option<String>) -> MitreAttackTechnique {
    MitreAttackTechnique::new(tactic, technique, sub).unwrap_or_else(|e| {
        unreachable!("SAML attack enrichment ATT&CK rejected by constructor: {e:?}")
    })
}

fn nist(id: &str) -> NistControl {
    NistControl::new(id).unwrap_or_else(|e| {
        unreachable!("SAML attack enrichment NIST control rejected by constructor: {e:?}")
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every `rule_id` we claim to enrich must produce a payload, and
    /// every payload's constructors must accept the curated strings.
    /// This is the regression net for typos.
    #[test]
    fn enrichment_table_is_well_formed() {
        let ids = [
            "saml:xsw-detected",
            "saml:xee-detected",
            "saml:transform-bypass-detected",
            "saml:c14n-violation",
        ];
        for id in ids {
            assert!(
                saml_attack_enrichment(id).is_some(),
                "missing enrichment for {id}"
            );
        }
    }

    #[test]
    fn unknown_rule_id_returns_none() {
        assert!(saml_attack_enrichment("saml:made-up").is_none());
        assert!(saml_attack_enrichment("xsw-detected").is_none()); // missing prefix
        assert!(saml_attack_enrichment("").is_none());
    }

    #[test]
    fn xsw_payload_has_signature_verification_cwes() {
        let e = saml_attack_enrichment("saml:xsw-detected").unwrap();
        assert!(
            e.cwe.contains(&cwe(347)),
            "XSW must cite CWE-347 (Improper Verification of Cryptographic Signature)"
        );
        assert!(
            e.cwe.contains(&cwe(345)),
            "XSW must cite CWE-345 (Insufficient Verification of Data Authenticity)"
        );
        assert!(e
            .mitre_attack
            .iter()
            .any(|t| t.technique == "T1556" && t.subtechnique.as_deref() == Some("T1556.007")));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "SC-23"));
        assert_eq!(e.severity, SamlAttackSeverity::High);
    }

    #[test]
    fn xee_payload_has_xxe_cwe() {
        let e = saml_attack_enrichment("saml:xee-detected").unwrap();
        assert!(e.cwe.contains(&cwe(611)));
        assert!(e.mitre_attack.iter().any(|t| t.technique == "T1190"));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "SI-10"));
        assert_eq!(e.severity, SamlAttackSeverity::High);
    }

    #[test]
    fn transform_bypass_payload_has_xml_injection_and_csrf() {
        let e = saml_attack_enrichment("saml:transform-bypass-detected").unwrap();
        assert!(e.cwe.contains(&cwe(91)));
        assert!(e.cwe.contains(&cwe(352)));
        assert!(e.mitre_attack.iter().any(|t| t.technique == "T1190"));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "SC-7"));
        assert_eq!(e.severity, SamlAttackSeverity::High);
    }

    #[test]
    fn c14n_violation_payload_is_medium_severity() {
        let e = saml_attack_enrichment("saml:c14n-violation").unwrap();
        assert!(e.cwe.contains(&cwe(345)));
        assert!(e.mitre_attack.iter().any(|t| t.technique == "T1574"));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "AU-9"));
        assert_eq!(e.severity, SamlAttackSeverity::Medium);
    }

    #[test]
    fn severity_wire_strings_are_lowercase_kebab() {
        assert_eq!(SamlAttackSeverity::High.as_wire(), "high");
        assert_eq!(SamlAttackSeverity::Medium.as_wire(), "medium");
    }

    /// TOP5-#3 Phase 3: the dotted-form `rule_id`s must resolve to the
    /// exact same payload as their legacy colon-form counterparts via
    /// the alias map.
    #[test]
    fn dotted_form_resolves_to_same_payload_as_legacy() {
        let pairs = [
            ("saml:xsw-detected", SAML_XSW_DOTTED),
            ("saml:xee-detected", SAML_XEE_DOTTED),
            (
                "saml:transform-bypass-detected",
                SAML_TRANSFORM_BYPASS_DOTTED,
            ),
            ("saml:c14n-violation", SAML_C14N_DOTTED),
        ];
        for (legacy, dotted) in pairs {
            let a = saml_attack_enrichment(legacy)
                .unwrap_or_else(|| panic!("legacy `{legacy}` resolves"));
            let b = saml_attack_enrichment(dotted)
                .unwrap_or_else(|| panic!("dotted `{dotted}` resolves"));
            assert_eq!(a, b, "legacy `{legacy}` must resolve equal to `{dotted}`");
            assert!(dotted.contains('.'), "dotted form contains `.`: {dotted}");
        }
    }

    #[test]
    fn dotted_constants_are_stable() {
        assert_eq!(SAML_XSW_DOTTED, "SAML.XSW");
        assert_eq!(SAML_XEE_DOTTED, "SAML.XEE");
        assert_eq!(SAML_TRANSFORM_BYPASS_DOTTED, "SAML.TRANSFORM_BYPASS");
        assert_eq!(SAML_C14N_DOTTED, "SAML.C14N");
    }
}
