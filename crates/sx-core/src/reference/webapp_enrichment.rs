//! Webapp DAST residual-check enrichment table (TOP5-#3 Phase 2, P2-002).
//!
//! Phase 1 covered the HDR.* header audits in
//! [`crate::reference::header_enrichment`]. The webapp DAST scanner in
//! `crates/sx-discovery/src/scanner/webapp.rs` also emits a handful of
//! non-header findings — cookie attribute audits, the body
//! directory-listing audit — that lacked CVSS/CWE/MITRE/compliance
//! enrichment. This module is the canonical lookup for those checks.
//!
//! ## Scope
//!
//! Covered (enriched):
//!
//! - `insecure-cookie-no-secure`
//! - `insecure-cookie-no-httponly`
//! - `directory-listing`
//!
//! Deliberately NOT covered (intel-only per
//! `docs/finding-enrichment.md` §5 Phase 2 row P2-002):
//!
//! - `server-banner` — fact, not a vulnerability. The product-and-version
//!   disclosure variant `server-header-disclosure` is enriched via
//!   [`crate::reference::header_enrichment`] instead.
//!
//! ## Don't fabricate
//!
//! Same policy as `header_enrichment`: every entry below cites the
//! authoritative reference (CWE, CVSS calculator, MITRE ATT&CK matrix,
//! NIST/ISO/PCI control catalogue) it derives from. If a defensible
//! mapping does not exist for a check we return an empty payload rather
//! than inventing values; consumers omit absent keys via
//! `skip_serializing_if`.

use crate::reference::header_enrichment::HdrEnrichment;
use crate::value_object::compliance::{ComplianceTags, IsoControl, NistControl, PciRequirement};
use crate::value_object::cvss_v31::{CvssV31, CvssV31Rating};
use crate::value_object::cwe::CweId;
use crate::value_object::mitre_attack::MitreAttackTechnique;

/// Canonical dotted-form `check_id` constants for the webapp DAST
/// scanner (TOP5-#3 Phase 3 §8(c), Wave E3 discovery-side sweep).
///
/// Every discovery-side emit site under
/// `crates/sx-discovery/src/scanner/webapp.rs` uses these constants so
/// there is one on-disk source of truth. Legacy kebab-case ids remain
/// accepted by [`webapp_enrichment`] for backward-compat.
pub const INSECURE_COOKIE_NO_SECURE_DOTTED: &str = "WEBAPP.INSECURE_COOKIE.NO_SECURE";
/// Canonical dotted-form id for `insecure-cookie-no-httponly`.
pub const INSECURE_COOKIE_NO_HTTPONLY_DOTTED: &str = "WEBAPP.INSECURE_COOKIE.NO_HTTPONLY";
/// Canonical dotted-form id for `directory-listing`.
pub const DIRECTORY_LISTING_DOTTED: &str = "WEBAPP.DIRECTORY_LISTING";
/// Canonical dotted-form id for the intel-only `server-banner` observation.
///
/// The banner emit is a fact, not a vulnerability — [`webapp_enrichment`]
/// deliberately returns `None` for it. The constant exists so the
/// discovery-side emit site can reference a single symbol instead of a
/// bare string literal.
pub const SERVER_BANNER_DOTTED: &str = "WEBAPP.SERVER.BANNER";

/// Curated enrichment payload for one webapp-DAST residual check.
///
/// Mirrors [`crate::reference::header_enrichment::HdrEnrichment`] in
/// shape so the call sites in `webapp.rs` can use the two lookups
/// interchangeably through a thin adapter.
// `Eq` is intentionally NOT derived: the embedded
// [`crate::value_object::cvss_v31::CvssV31`] holds an `f64` base score
// which only implements `PartialEq`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WebappEnrichment {
    /// CVSS v3.1 base metric payload, if a canonical mapping exists.
    pub cvss: Option<CvssV31>,
    /// CWE identifiers describing the underlying weakness class(es).
    pub cwe: Vec<CweId>,
    /// MITRE ATT&CK techniques / sub-techniques this finding maps to.
    pub mitre_attack: Vec<MitreAttackTechnique>,
    /// Compliance-framework control mappings.
    pub compliance: ComplianceTags,
}

/// Trivial conversion into [`HdrEnrichment`]. The two types are
/// structurally identical so call sites in
/// `crates/sx-discovery/src/scanner/webapp.rs` can keep using the
/// existing `push_finding_enriched(..., Option<HdrEnrichment>)`
/// signature without a second emit helper. Keeping the wrapper types
/// distinct preserves the audit story — readers see which table the
/// payload originated in — while costing one no-op move per emit.
impl From<WebappEnrichment> for HdrEnrichment {
    fn from(w: WebappEnrichment) -> Self {
        Self {
            cvss: w.cvss,
            cwe: w.cwe,
            mitre_attack: w.mitre_attack,
            compliance: w.compliance,
        }
    }
}

/// Build the enrichment payload for the supplied `check_id`.
///
/// Accepts both the legacy kebab-case shape (`insecure-cookie-no-secure`)
/// and the canonical dotted-form (`WEBAPP.INSECURE_COOKIE.NO_SECURE`,
/// TOP5-#3 Phase 3). Returns `None` for any id outside the curated table.
///
/// In particular, the intel-only `server-banner` check returns `None` by
/// design — its emitter does not look up enrichment.
#[must_use]
pub fn webapp_enrichment(check_id: &str) -> Option<WebappEnrichment> {
    // Canonicalise the dotted-form ids onto the kebab-case entry so the
    // table stays keyed by one shape and cannot drift when a new id
    // variant lands. `WEBAPP.SERVER.BANNER` is intentionally aliased to
    // the intel-only kebab id `server-banner`; both fall through to
    // `None` at the payload-match arm below.
    let canonical = match check_id {
        INSECURE_COOKIE_NO_SECURE_DOTTED => "insecure-cookie-no-secure",
        INSECURE_COOKIE_NO_HTTPONLY_DOTTED => "insecure-cookie-no-httponly",
        DIRECTORY_LISTING_DOTTED => "directory-listing",
        SERVER_BANNER_DOTTED => "server-banner",
        other => other,
    };
    let e = match canonical {
        "insecure-cookie-no-secure" => insecure_cookie_no_secure(),
        "insecure-cookie-no-httponly" => insecure_cookie_no_httponly(),
        "directory-listing" => directory_listing(),
        _ => return None,
    };
    Some(e)
}

/// `insecure-cookie-no-secure` — Set-Cookie issued over HTTPS without
/// the `Secure` attribute, so the cookie can leak to plaintext HTTP
/// links / downgrade redirects.
///
/// References:
/// - CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
///   (<https://cwe.mitre.org/data/definitions/614.html>).
/// - CVSS v3.1 vector AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N = 5.9 (Medium).
///   AC:H reflects the need for an MITM-able link or a same-origin
///   plaintext leak; impact is C:H because the session cookie is
///   directly exfiltrated.
/// - MITRE ATT&CK T1539 Steal Web Session Cookie in TA0006 Credential Access.
/// - NIST SP 800-53 Rev 5 SC-8 Transmission Confidentiality and Integrity.
/// - ISO/IEC 27001 A.13.1.1 Network controls.
/// - PCI DSS 4.0 §4.1 Strong cryptography on transmission of cardholder data.
fn insecure_cookie_no_secure() -> WebappEnrichment {
    WebappEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            5.9,
            CvssV31Rating::Medium,
        )),
        cwe: vec![cwe(614)],
        mitre_attack: vec![attack("TA0006", "T1539", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-8")],
            iso_27001: vec![iso("A.13.1.1")],
            pci_dss: vec![pci("4.1")],
            ..Default::default()
        },
    }
}

/// `insecure-cookie-no-httponly` — session cookie missing the
/// `HttpOnly` attribute, so JavaScript running in the page (including
/// XSS payloads) can read it.
///
/// References:
/// - CWE-1004 Sensitive Cookie Without '`HttpOnly`' Flag
///   (<https://cwe.mitre.org/data/definitions/1004.html>).
/// - CVSS v3.1 vector AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N = 5.0 (Medium).
///   AC:H and UI:R reflect that the attacker first needs a working XSS
///   primitive in the same origin; once present the cookie is fully
///   exfiltratable (C:H).
/// - MITRE ATT&CK T1059.007 JavaScript in TA0002 Execution — the
///   in-browser scripting vector that exploits the missing flag.
/// - NIST SP 800-53 Rev 5 SC-7 Boundary Protection (defence in depth
///   for browser-side trust boundaries).
fn insecure_cookie_no_httponly() -> WebappEnrichment {
    WebappEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
            5.0,
            CvssV31Rating::Medium,
        )),
        cwe: vec![cwe(1004)],
        mitre_attack: vec![attack("TA0002", "T1059", Some("T1059.007".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-7")],
            ..Default::default()
        },
    }
}

/// `directory-listing` — web server returns an auto-generated index of
/// a directory, exposing filenames and structure intended to be
/// private.
///
/// References:
/// - CWE-548 Exposure of Information Through Directory Listing
///   (<https://cwe.mitre.org/data/definitions/548.html>) as the
///   primary class; CWE-200 Exposure of Sensitive Information as the
///   parent.
/// - CVSS v3.1 vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (High).
///   Worst-case the listing reveals backup files, dotfiles, or
///   credentials (C:H); no integrity or availability impact.
/// - MITRE ATT&CK T1592 Gather Victim Host Information in TA0043
///   Reconnaissance (the listing supplies the inventory step of
///   pre-attack recon).
/// - NIST SP 800-53 Rev 5 SI-12 Information Management and Retention,
///   AC-3 Access Enforcement.
/// - ISO/IEC 27001 A.13.1.1 (parallel to other content-exposure
///   findings).
fn directory_listing() -> WebappEnrichment {
    WebappEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            7.5,
            CvssV31Rating::High,
        )),
        cwe: vec![cwe(548), cwe(200)],
        mitre_attack: vec![attack("TA0043", "T1592", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-12"), nist("AC-3")],
            iso_27001: vec![iso("A.13.1.1")],
            ..Default::default()
        },
    }
}

// ---------------------------------------------------------------------------
// Helpers — same shape as `header_enrichment.rs`. Every constructor here is
// infallible on the values used above; failure would mean a typo in this
// file, which the unit tests catch.
// ---------------------------------------------------------------------------

fn cvss_or_skip(vector: &str, score: f64, rating: CvssV31Rating) -> CvssV31 {
    CvssV31::new(vector, score, rating).unwrap_or_else(|e| {
        unreachable!("webapp enrichment table CVSS rejected by constructor: {e:?}")
    })
}

fn cwe(id: u32) -> CweId {
    CweId::new(id).unwrap_or_else(|e| {
        unreachable!("webapp enrichment table CWE id rejected by constructor: {e:?}")
    })
}

fn attack(tactic: &str, technique: &str, sub: Option<String>) -> MitreAttackTechnique {
    MitreAttackTechnique::new(tactic, technique, sub).unwrap_or_else(|e| {
        unreachable!("webapp enrichment table ATT&CK rejected by constructor: {e:?}")
    })
}

fn nist(id: &str) -> NistControl {
    NistControl::new(id).unwrap_or_else(|e| {
        unreachable!("webapp enrichment table NIST control rejected by constructor: {e:?}")
    })
}

fn iso(id: &str) -> IsoControl {
    IsoControl::new(id).unwrap_or_else(|e| {
        unreachable!("webapp enrichment table ISO control rejected by constructor: {e:?}")
    })
}

fn pci(id: &str) -> PciRequirement {
    PciRequirement::new(id).unwrap_or_else(|e| {
        unreachable!("webapp enrichment table PCI requirement rejected by constructor: {e:?}")
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every kebab-case `check_id` we claim to enrich must produce a
    /// payload, and every payload's constructors must accept the
    /// curated strings. Regression net for typos.
    #[test]
    fn enrichment_table_is_well_formed() {
        let ids = [
            "insecure-cookie-no-secure",
            "insecure-cookie-no-httponly",
            "directory-listing",
        ];
        for id in ids {
            assert!(
                webapp_enrichment(id).is_some(),
                "missing enrichment for {id}",
            );
        }
    }

    #[test]
    fn unknown_check_id_returns_none() {
        assert!(webapp_enrichment("missing-totally-fake-cookie").is_none());
        assert!(webapp_enrichment("HDR.SOMETHING.NEW").is_none());
        // Intel-only checks must NOT resolve from this table: their
        // payloads are deliberately empty.
        assert!(webapp_enrichment("server-banner").is_none());
        // HDR.* checks live in `header_enrichment`, not this table.
        assert!(webapp_enrichment("missing-hsts").is_none());
    }

    #[test]
    fn insecure_cookie_no_secure_matches_reference_data() {
        let e = webapp_enrichment("insecure-cookie-no-secure").unwrap();
        let cvss = e.cvss.expect("Secure-flag missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
        assert!((cvss.base_score - 5.9).abs() < f64::EPSILON);
        assert_eq!(cvss.severity, CvssV31Rating::Medium);
        assert!(e.cwe.iter().any(|c| c.as_u32() == 614));
        assert!(e.mitre_attack.iter().any(|t| t.technique == "T1539"));
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
    fn insecure_cookie_no_httponly_matches_reference_data() {
        let e = webapp_enrichment("insecure-cookie-no-httponly").unwrap();
        let cvss = e.cvss.expect("HttpOnly-flag missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N");
        assert!((cvss.base_score - 5.0).abs() < f64::EPSILON);
        assert_eq!(cvss.severity, CvssV31Rating::Medium);
        assert!(e.cwe.iter().any(|c| c.as_u32() == 1004));
        assert!(e.mitre_attack.iter().any(|t| t.technique == "T1059"));
        assert!(e
            .mitre_attack
            .iter()
            .any(|t| t.subtechnique.as_deref() == Some("T1059.007")));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "SC-7"));
    }

    #[test]
    fn directory_listing_matches_reference_data() {
        let e = webapp_enrichment("directory-listing").unwrap();
        let cvss = e.cvss.expect("directory-listing missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
        assert!((cvss.base_score - 7.5).abs() < f64::EPSILON);
        assert_eq!(cvss.severity, CvssV31Rating::High);
        assert!(e.cwe.iter().any(|c| c.as_u32() == 548));
        assert!(e.cwe.iter().any(|c| c.as_u32() == 200));
        assert!(e.mitre_attack.iter().any(|t| t.technique == "T1592"));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "SI-12"));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "AC-3"));
        assert!(e
            .compliance
            .iso_27001
            .iter()
            .any(|c| c.as_str() == "A.13.1.1"));
    }

    /// TOP5-#3 Phase 3: the WEBAPP.* dotted-form ids must resolve to
    /// the same payload as their kebab-case counterparts via the alias
    /// map on the receive side.
    #[test]
    fn dotted_form_resolves_to_same_payload_as_kebab() {
        let pairs = [
            (
                INSECURE_COOKIE_NO_SECURE_DOTTED,
                "insecure-cookie-no-secure",
            ),
            (
                INSECURE_COOKIE_NO_HTTPONLY_DOTTED,
                "insecure-cookie-no-httponly",
            ),
            (DIRECTORY_LISTING_DOTTED, "directory-listing"),
        ];
        for (dotted, kebab) in pairs {
            let a =
                webapp_enrichment(dotted).unwrap_or_else(|| panic!("dotted `{dotted}` resolves"));
            let b = webapp_enrichment(kebab).unwrap_or_else(|| panic!("kebab `{kebab}` resolves"));
            assert_eq!(a, b, "dotted `{dotted}` must match kebab `{kebab}`");
            assert!(dotted.contains('.'));
        }
    }

    /// TOP5-#3 Phase 3 §8(c) Wave E3: every discovery-side webapp
    /// dotted `check_id` we now emit from
    /// `crates/sx-discovery/src/scanner/webapp.rs` must resolve to a
    /// non-`None` enrichment payload — except the intel-only
    /// `WEBAPP.SERVER.BANNER`, which is deliberately un-enriched (it's
    /// a fact, not a vulnerability).
    #[test]
    fn every_discovery_side_dotted_id_resolves_to_a_payload() {
        let ids_with_enrichment = [
            INSECURE_COOKIE_NO_SECURE_DOTTED,
            INSECURE_COOKIE_NO_HTTPONLY_DOTTED,
            DIRECTORY_LISTING_DOTTED,
        ];
        for id in ids_with_enrichment {
            let e = webapp_enrichment(id)
                .unwrap_or_else(|| panic!("dotted id `{id}` must resolve to a payload"));
            assert!(id.contains('.'), "id `{id}` must be dotted-form");
            assert!(
                e.cvss.is_some() || !e.cwe.is_empty() || !e.compliance.is_empty(),
                "dotted id `{id}` resolved to an empty enrichment payload",
            );
        }
        // Intel-only WEBAPP.SERVER.BANNER MUST NOT resolve to a
        // payload; the discovery emitter routes through
        // `push_finding` (no enrichment lookup).
        assert!(
            webapp_enrichment(SERVER_BANNER_DOTTED).is_none(),
            "WEBAPP.SERVER.BANNER is intel-only; it must not resolve to an enrichment payload",
        );
    }

    /// Confirms every CVSS vector string we serve through the table
    /// passes the canonical [`CvssV31::new`] validator. This is the
    /// double-check that prevents a stray typo from shipping.
    #[test]
    fn all_cvss_vectors_round_trip_through_constructor() {
        let ids = [
            "insecure-cookie-no-secure",
            "insecure-cookie-no-httponly",
            "directory-listing",
        ];
        for id in ids {
            let e = webapp_enrichment(id).unwrap();
            let cvss = e.cvss.unwrap_or_else(|| panic!("no CVSS for {id}"));
            let again = CvssV31::new(&cvss.vector, cvss.base_score, cvss.severity)
                .unwrap_or_else(|err| panic!("CVSS for {id} failed re-validation: {err:?}"));
            assert_eq!(again, cvss, "round-trip mismatch for {id}");
        }
    }
}
