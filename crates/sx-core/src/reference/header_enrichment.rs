//! HDR.* header-audit enrichment table (TOP5-#3 Phase 1, shared home).
//!
//! Maps every header / cookie / banner `check_id` we emit — both the
//! kebab-case legacy form (`missing-hsts`) used by the
//! [`crate`]-agnostic webapp DAST scanner in `sx-discovery`, and the
//! dotted live form (`HDR.STRICT_TRANSPORT_SECURITY.MISSING`) emitted
//! by the `services/sx-monolith` HTTP-header probe — to a curated
//! [`HdrEnrichment`] payload (CVSS v3.1 base score, CWE class, MITRE
//! ATT&CK technique(s), compliance-framework controls).
//!
//! ## Why this lives in `sx-core`
//!
//! Before SX-REVIEW-002 the table only existed inside
//! `sx-discovery::scanner::header_enrichment` and was reachable only by
//! the un-wired `WebAppScanner`. The live `/v1/scans/http-headers`
//! endpoint runs through a different scanner that has its own DTO
//! ([`sx_api::view::scan_view::ScanFinding`]), so the enriched payload
//! never reached the wire — the C1 critical finding from the senior
//! review. Promoting the table to `sx-core` lets both the discovery
//! crate and the monolith adapter call it without one depending on the
//! other.
//!
//! ## Don't fabricate
//!
//! Per the original Phase 1 policy: where no authoritative CWE / CVSS
//! mapping exists (permissions-policy in particular), we return an
//! empty [`HdrEnrichment`] rather than inventing values. The wire
//! payload then omits the enrichment keys via `skip_serializing_if`.

use crate::value_object::compliance::{ComplianceTags, IsoControl, NistControl, PciRequirement};
use crate::value_object::cvss_v31::{CvssV31, CvssV31Rating};
use crate::value_object::cwe::CweId;
use crate::value_object::mitre_attack::MitreAttackTechnique;

// ---------------------------------------------------------------------------
// Canonical dotted-form `check_id` constants (TOP5-#3 Phase 3 §8(c),
// Wave E3 discovery-side sweep). Every discovery-side + monolith emit
// site references these constants so there is a single on-disk source
// of truth. Legacy kebab-case ids remain accepted by
// [`hdr_enrichment`] for backward-compat.
// ---------------------------------------------------------------------------

/// Canonical dotted-form id for the HSTS-absent check.
pub const HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED: &str =
    "HDR.STRICT_TRANSPORT_SECURITY.MISSING";
/// Canonical dotted-form id for the CSP-absent check.
pub const HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED: &str = "HDR.CONTENT_SECURITY_POLICY.MISSING";
/// Canonical dotted-form id for the X-Frame-Options-absent check.
pub const HDR_X_FRAME_OPTIONS_MISSING_DOTTED: &str = "HDR.X_FRAME_OPTIONS.MISSING";
/// Canonical dotted-form id for the X-Content-Type-Options-absent check.
pub const HDR_X_CONTENT_TYPE_OPTIONS_MISSING_DOTTED: &str = "HDR.X_CONTENT_TYPE_OPTIONS.MISSING";
/// Canonical dotted-form id for the Referrer-Policy-absent check.
pub const HDR_REFERRER_POLICY_MISSING_DOTTED: &str = "HDR.REFERRER_POLICY.MISSING";
/// Canonical dotted-form id for the Permissions-Policy-absent check.
pub const HDR_PERMISSIONS_POLICY_MISSING_DOTTED: &str = "HDR.PERMISSIONS_POLICY.MISSING";
/// Canonical dotted-form id for the Server-header disclosure check.
pub const HDR_SERVER_FINGERPRINT_DOTTED: &str = "HDR.SERVER.FINGERPRINT";
/// Canonical dotted-form id for the X-Powered-By disclosure check.
pub const HDR_XPOWEREDBY_DISCLOSURE_DOTTED: &str = "HDR.XPOWEREDBY.DISCLOSURE";
/// Canonical dotted-form id for the plaintext-HTTP URL scheme audit.
///
/// Structurally an URL-scheme audit rather than a header check, but the
/// enrichment lives in this table because it shares the HSTS CWE family
/// (CWE-319) and MITRE technique (T1040).
pub const URL_SCHEME_PLAINTEXT_HTTP_DOTTED: &str = "URL.SCHEME.PLAINTEXT_HTTP";

/// Curated enrichment payload for one header / cookie / banner check.
///
/// All fields are optional or default-empty so a missing piece of
/// authoritative reference data simply omits the corresponding wire
/// key (via `skip_serializing_if` on the consuming DTO/entity).
// `Eq` is intentionally NOT derived: the embedded
// [`crate::value_object::cvss_v31::CvssV31`] holds an `f64` base score
// which only implements `PartialEq`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HdrEnrichment {
    /// CVSS v3.1 base metric payload, if a canonical mapping exists.
    pub cvss: Option<CvssV31>,
    /// CWE identifiers describing the underlying weakness class(es).
    pub cwe: Vec<CweId>,
    /// MITRE ATT&CK techniques / sub-techniques this finding maps to.
    pub mitre_attack: Vec<MitreAttackTechnique>,
    /// Compliance-framework control mappings.
    pub compliance: ComplianceTags,
}

/// Build the enrichment payload for the supplied `check_id`.
///
/// Accepts both check-id shapes the platform emits:
///
/// - kebab-case legacy form used by
///   `sx_discovery::scanner::webapp::WebAppScanner` (`missing-hsts`,
///   `missing-csp`, `plaintext-http`, …);
/// - dotted live form used by the monolith HTTP-header probe
///   (`HDR.STRICT_TRANSPORT_SECURITY.MISSING`,
///   `HDR.SERVER.FINGERPRINT`, …).
///
/// Returns `None` for any id outside the curated table.
#[must_use]
pub fn hdr_enrichment(check_id: &str) -> Option<HdrEnrichment> {
    // Map the live HDR.* dotted ids onto the canonical kebab-case
    // entry. Keeping the table keyed by one shape avoids drift when a
    // single check picks up a third id variant in the future.
    let canonical = match check_id {
        // Live HDR.* / URL.* aliases — Wave E3 (TOP5-#3 Phase 3 §8(c))
        // canonical shape used by both the monolith HTTP-header probe
        // and the discovery-side webapp scanner.
        HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED => "missing-hsts",
        HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED => "missing-csp",
        HDR_X_FRAME_OPTIONS_MISSING_DOTTED => "missing-x-frame-options",
        HDR_X_CONTENT_TYPE_OPTIONS_MISSING_DOTTED => "missing-x-content-type-options",
        HDR_REFERRER_POLICY_MISSING_DOTTED => "missing-referrer-policy",
        HDR_PERMISSIONS_POLICY_MISSING_DOTTED => "missing-permissions-policy",
        HDR_SERVER_FINGERPRINT_DOTTED => "server-header-disclosure",
        HDR_XPOWEREDBY_DISCLOSURE_DOTTED => "x-powered-by-disclosure",
        URL_SCHEME_PLAINTEXT_HTTP_DOTTED => "plaintext-http",
        // Already-canonical kebab-case ids fall through unchanged.
        other => other,
    };
    let e = match canonical {
        "missing-hsts" => missing_hsts(),
        "missing-csp" => missing_csp(),
        "missing-x-frame-options" => missing_x_frame_options(),
        "missing-x-content-type-options" => missing_x_content_type_options(),
        "missing-referrer-policy" => missing_referrer_policy(),
        "missing-permissions-policy" => missing_permissions_policy(),
        "server-header-disclosure" => server_header_disclosure(),
        "x-powered-by-disclosure" => x_powered_by_disclosure(),
        // Plaintext HTTP is structurally a header / transport check
        // (the URL scheme audit) and shares the HSTS CWE family.
        "plaintext-http" => plaintext_http(),
        _ => return None,
    };
    Some(e)
}

/// `HDR.STRICT_TRANSPORT_SECURITY.MISSING` — HSTS header absent on HTTPS.
///
/// References:
/// - CWE-319 Cleartext Transmission of Sensitive Information
///   (<https://cwe.mitre.org/data/definitions/319.html>).
/// - CVSS v3.1 vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (High).
/// - MITRE ATT&CK T1040 Network Sniffing in TA0009 Collection.
/// - NIST SP 800-53 Rev 5 SC-8 Transmission Confidentiality and Integrity.
/// - ISO/IEC 27001 A.13.1.1 Network controls.
/// - PCI DSS 4.0 §4.1 Strong cryptography on transmission of cardholder data.
fn missing_hsts() -> HdrEnrichment {
    HdrEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            7.5,
            CvssV31Rating::High,
        )),
        cwe: vec![cwe(319)],
        mitre_attack: vec![attack("TA0009", "T1040", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-8")],
            iso_27001: vec![iso("A.13.1.1")],
            pci_dss: vec![pci("4.1")],
            ..Default::default()
        },
    }
}

/// `HDR.CONTENT_SECURITY_POLICY.MISSING`.
fn missing_csp() -> HdrEnrichment {
    HdrEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            5.4,
            CvssV31Rating::Medium,
        )),
        cwe: vec![cwe(1021), cwe(79)],
        mitre_attack: vec![attack("TA0002", "T1059", Some("T1059.007".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-10")],
            iso_27001: vec![iso("A.14.2.5")],
            pci_dss: vec![pci("6.4.3")],
            ..Default::default()
        },
    }
}

/// `HDR.X_FRAME_OPTIONS.MISSING` — clickjacking exposure.
fn missing_x_frame_options() -> HdrEnrichment {
    HdrEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            4.3,
            CvssV31Rating::Medium,
        )),
        cwe: vec![cwe(1021)],
        mitre_attack: vec![attack("TA0009", "T1185", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-10")],
            iso_27001: vec![iso("A.14.2.5")],
            ..Default::default()
        },
    }
}

/// `HDR.X_CONTENT_TYPE_OPTIONS.MISSING` — MIME sniffing risk.
fn missing_x_content_type_options() -> HdrEnrichment {
    HdrEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
            3.1,
            CvssV31Rating::Low,
        )),
        cwe: vec![cwe(430)],
        mitre_attack: vec![],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-10")],
            iso_27001: vec![iso("A.14.2.5")],
            ..Default::default()
        },
    }
}

/// `HDR.REFERRER_POLICY.MISSING` — informational, no authoritative CVSS
/// or CWE mapping exists for missing Referrer-Policy. We cite the
/// relevant NIST control only.
fn missing_referrer_policy() -> HdrEnrichment {
    HdrEnrichment {
        cvss: None,
        cwe: vec![cwe(200)], // Information Exposure
        mitre_attack: vec![],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-8")],
            ..Default::default()
        },
    }
}

/// `HDR.PERMISSIONS_POLICY.MISSING` — informational hardening control
/// without authoritative CWE or CVSS mapping. Left empty per the
/// "don't fabricate" rule; TODO: revisit in Phase 2 when MDN / OWASP
/// publish a stable CWE assignment.
fn missing_permissions_policy() -> HdrEnrichment {
    HdrEnrichment::default()
}

/// `HDR.SERVER.FINGERPRINT` — Server banner reveals product+version.
fn server_header_disclosure() -> HdrEnrichment {
    HdrEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            5.3,
            CvssV31Rating::Medium,
        )),
        cwe: vec![cwe(200)],
        mitre_attack: vec![attack("TA0043", "T1592", Some("T1592.004".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-11")],
            iso_27001: vec![iso("A.14.2.5")],
            ..Default::default()
        },
    }
}

/// `HDR.X_POWERED_BY.DISCLOSURE` — X-Powered-By exposes platform.
fn x_powered_by_disclosure() -> HdrEnrichment {
    HdrEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            5.3,
            CvssV31Rating::Medium,
        )),
        cwe: vec![cwe(200)],
        mitre_attack: vec![attack("TA0043", "T1592", Some("T1592.004".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-11")],
            iso_27001: vec![iso("A.14.2.5")],
            ..Default::default()
        },
    }
}

/// `URL.SCHEME.PLAINTEXT_HTTP` — target served over HTTP, not HTTPS.
fn plaintext_http() -> HdrEnrichment {
    HdrEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            8.1,
            CvssV31Rating::High,
        )),
        cwe: vec![cwe(319)],
        mitre_attack: vec![
            attack("TA0006", "T1557", Some("T1557.002".into())),
            attack("TA0009", "T1040", None),
        ],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-8"), nist("SC-13")],
            iso_27001: vec![iso("A.13.1.1")],
            pci_dss: vec![pci("4.1")],
            ..Default::default()
        },
    }
}

// ---------------------------------------------------------------------------
// Helpers — every constructor here is infallible on the values used above;
// failure would mean a typo in this file, which the unit tests catch.
// ---------------------------------------------------------------------------

fn cvss_or_skip(vector: &str, score: f64, rating: CvssV31Rating) -> CvssV31 {
    CvssV31::new(vector, score, rating).unwrap_or_else(|e| {
        unreachable!("HDR enrichment table CVSS rejected by constructor: {e:?}")
    })
}

fn cwe(id: u32) -> CweId {
    CweId::new(id).unwrap_or_else(|e| {
        unreachable!("HDR enrichment table CWE id rejected by constructor: {e:?}")
    })
}

fn attack(tactic: &str, technique: &str, sub: Option<String>) -> MitreAttackTechnique {
    MitreAttackTechnique::new(tactic, technique, sub).unwrap_or_else(|e| {
        unreachable!("HDR enrichment table ATT&CK rejected by constructor: {e:?}")
    })
}

fn nist(id: &str) -> NistControl {
    NistControl::new(id).unwrap_or_else(|e| {
        unreachable!("HDR enrichment table NIST control rejected by constructor: {e:?}")
    })
}

fn iso(id: &str) -> IsoControl {
    IsoControl::new(id).unwrap_or_else(|e| {
        unreachable!("HDR enrichment table ISO control rejected by constructor: {e:?}")
    })
}

fn pci(id: &str) -> PciRequirement {
    PciRequirement::new(id).unwrap_or_else(|e| {
        unreachable!("HDR enrichment table PCI requirement rejected by constructor: {e:?}")
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every kebab-case `check_id` we claim to enrich must produce a
    /// payload, and every payload's constructors must accept the
    /// curated strings. This is the regression net for typos.
    #[test]
    fn enrichment_table_is_well_formed_legacy_ids() {
        let ids = [
            "missing-hsts",
            "missing-csp",
            "missing-x-frame-options",
            "missing-x-content-type-options",
            "missing-referrer-policy",
            "missing-permissions-policy",
            "server-header-disclosure",
            "x-powered-by-disclosure",
            "plaintext-http",
        ];
        for id in ids {
            assert!(hdr_enrichment(id).is_some(), "missing enrichment for {id}");
        }
    }

    /// Live `HDR.*` / `URL.*` ids emitted by both `services/sx-monolith`
    /// and the discovery-side webapp scanner (Wave E3) must resolve to
    /// the same canonical payload as their kebab-case counterparts. This
    /// is the regression net for SX-REVIEW-002 C1 + TOP5-#3 Phase 3 §8(c).
    #[test]
    fn live_hdr_ids_resolve_to_same_payload() {
        let pairs = [
            (HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED, "missing-hsts"),
            (HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED, "missing-csp"),
            (
                HDR_X_FRAME_OPTIONS_MISSING_DOTTED,
                "missing-x-frame-options",
            ),
            (
                HDR_X_CONTENT_TYPE_OPTIONS_MISSING_DOTTED,
                "missing-x-content-type-options",
            ),
            (
                HDR_REFERRER_POLICY_MISSING_DOTTED,
                "missing-referrer-policy",
            ),
            (
                HDR_PERMISSIONS_POLICY_MISSING_DOTTED,
                "missing-permissions-policy",
            ),
            (HDR_SERVER_FINGERPRINT_DOTTED, "server-header-disclosure"),
            (HDR_XPOWEREDBY_DISCLOSURE_DOTTED, "x-powered-by-disclosure"),
            (URL_SCHEME_PLAINTEXT_HTTP_DOTTED, "plaintext-http"),
        ];
        for (live, legacy) in pairs {
            let a = hdr_enrichment(live).unwrap_or_else(|| {
                panic!("live id {live} did not resolve to an enrichment payload")
            });
            let b = hdr_enrichment(legacy).unwrap();
            assert_eq!(a, b, "live id {live} did not match legacy id {legacy}");
        }
    }

    /// TOP5-#3 Phase 3 §8(c) Wave E3: every discovery-side dotted
    /// `check_id` we now emit from
    /// `crates/sx-discovery/src/scanner/webapp.rs` must resolve to a
    /// non-`None` enrichment payload. The Permissions-Policy row is
    /// intentionally empty per the "don't fabricate" rule and is
    /// exempt from the "non-empty payload" check (matches the
    /// wire-regression test at
    /// `crates/sx-api/tests/scan_enrichment_reaches_wire.rs`).
    #[test]
    fn every_discovery_side_dotted_id_resolves_to_a_payload() {
        let ids = [
            HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED,
            HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED,
            HDR_X_FRAME_OPTIONS_MISSING_DOTTED,
            HDR_X_CONTENT_TYPE_OPTIONS_MISSING_DOTTED,
            HDR_REFERRER_POLICY_MISSING_DOTTED,
            HDR_PERMISSIONS_POLICY_MISSING_DOTTED,
            HDR_SERVER_FINGERPRINT_DOTTED,
            HDR_XPOWEREDBY_DISCLOSURE_DOTTED,
            URL_SCHEME_PLAINTEXT_HTTP_DOTTED,
        ];
        for id in ids {
            let e = hdr_enrichment(id)
                .unwrap_or_else(|| panic!("dotted id `{id}` must resolve to a payload"));
            assert!(id.contains('.'), "id `{id}` must be dotted-form");
            if id != HDR_PERMISSIONS_POLICY_MISSING_DOTTED {
                assert!(
                    e.cvss.is_some() || !e.cwe.is_empty() || !e.compliance.is_empty(),
                    "dotted id `{id}` resolved to an empty enrichment payload",
                );
            }
        }
    }

    #[test]
    fn unknown_check_id_returns_none() {
        assert!(hdr_enrichment("missing-totally-fake-header").is_none());
        assert!(hdr_enrichment("directory-listing").is_none());
        assert!(hdr_enrichment("insecure-cookie-no-secure").is_none());
        assert!(hdr_enrichment("HDR.SOMETHING.NEW").is_none());
    }

    #[test]
    fn hsts_matches_brief_reference_data() {
        let e = hdr_enrichment("missing-hsts").unwrap();
        let cvss = e.cvss.expect("HSTS missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
        assert!((cvss.base_score - 7.5).abs() < f64::EPSILON);
        assert_eq!(cvss.severity, CvssV31Rating::High);
        assert_eq!(e.cwe, vec![cwe(319)]);
        assert!(e.mitre_attack.iter().any(|t| t.technique == "T1040"));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "SC-8"));
        assert!(e
            .compliance
            .iso_27001
            .iter()
            .any(|c| c.as_str() == "A.13.1.1"));
        assert!(e.compliance.pci_dss.iter().any(|c| c.as_str() == "4.1"));
    }

    #[test]
    fn permissions_policy_is_intentionally_empty() {
        let e = hdr_enrichment("missing-permissions-policy").unwrap();
        assert!(e.cvss.is_none());
        assert!(e.cwe.is_empty());
        assert!(e.mitre_attack.is_empty());
        assert!(e.compliance.is_empty());
    }
}
