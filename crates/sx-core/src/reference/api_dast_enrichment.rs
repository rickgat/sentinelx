//! API.* API-DAST enrichment table (TOP5-#3 Phase 2 / P2-001).
//!
//! Mirrors [`crate::reference::header_enrichment`] for the REST / GraphQL
//! API DAST scanner in
//! [`sx_discovery::scanner::api_scanner`]. Each `check_id` emitted by that
//! scanner is mapped to a curated [`ApiDastEnrichment`] payload (CVSS
//! v3.1 base score, CWE class, MITRE ATT&CK technique(s),
//! compliance-framework controls).
//!
//! ## Why this lives in `sx-core`
//!
//! Same rationale as the HDR.* table — the lookup is pure reference data
//! and is consumed both by the `sx-discovery` scanner today and by any
//! future live-API monolith adapter that emits the same `check_id`s.
//! Keeping the curated payload in one crate prevents the SX-REVIEW-002
//! C1 "DTO drift" defect from recurring on the API-DAST surface.
//!
//! ## Don't fabricate
//!
//! Per the Phase 1 policy carried forward to Phase 2: where no
//! authoritative CWE / CVSS mapping exists (the informational
//! `api-missing-rate-limit-headers` signal, in particular), we leave the
//! CVSS field `None` rather than inventing a score. The wire payload
//! then omits the enrichment keys via `skip_serializing_if`.

use crate::value_object::compliance::{ComplianceTags, IsoControl, NistControl, PciRequirement};
use crate::value_object::cvss_v31::{CvssV31, CvssV31Rating};
use crate::value_object::cwe::CweId;
use crate::value_object::mitre_attack::MitreAttackTechnique;

/// Canonical dotted-form `check_id` constants for the API DAST scanner
/// (TOP5-#3 Phase 3 §8(c), Wave E3 discovery-side sweep).
///
/// Every discovery-side emit site under
/// `crates/sx-discovery/src/scanner/api_scanner.rs` uses these constants
/// so there is one on-disk source of truth. Legacy kebab-case ids remain
/// accepted by [`api_dast_enrichment`] for backward-compat.
pub const API_AUTH_MISSING_DOTTED: &str = "API.AUTH.MISSING";
/// Canonical dotted-form id for `api-cors-wildcard`.
pub const API_CORS_WILDCARD_DOTTED: &str = "API.CORS.WILDCARD_WITH_CREDENTIALS";
/// Canonical dotted-form id for `api-server-disclosure`.
pub const API_SERVER_FINGERPRINT_DOTTED: &str = "API.SERVER.FINGERPRINT";
/// Canonical dotted-form id for `api-verbose-error`.
pub const API_ERROR_VERBOSE_DOTTED: &str = "API.ERROR.VERBOSE";
/// Canonical dotted-form id for `api-missing-rate-limit-headers`.
pub const API_RATELIMIT_HEADERS_MISSING_DOTTED: &str = "API.RATELIMIT.HEADERS_MISSING";
/// Canonical dotted-form id for `api-graphql-introspection-enabled`.
pub const API_GRAPHQL_INTROSPECTION_ENABLED_DOTTED: &str = "API.GRAPHQL.INTROSPECTION_ENABLED";

/// Curated enrichment payload for one API DAST check.
///
/// All fields are optional or default-empty so a missing piece of
/// authoritative reference data simply omits the corresponding wire
/// key (via `skip_serializing_if` on the consuming DTO/entity).
// `Eq` is intentionally NOT derived: the embedded
// [`crate::value_object::cvss_v31::CvssV31`] holds an `f64` base score
// which only implements `PartialEq`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApiDastEnrichment {
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
/// Accepts both check-id shapes the platform may emit:
///
/// - kebab-case form used today by
///   `sx_discovery::scanner::api_scanner::ApiScanner` (`api-no-auth-required`,
///   `api-cors-wildcard`, `api-graphql-introspection-enabled`, …);
/// - dotted `API.*` live form reserved for a future
///   monolith adapter (mirrors the `HDR.*` alias pattern in
///   [`crate::reference::header_enrichment`]).
///
/// Returns `None` for any id outside the curated table.
#[must_use]
pub fn api_dast_enrichment(check_id: &str) -> Option<ApiDastEnrichment> {
    // Map any future API.* dotted ids onto the canonical kebab-case
    // entry. The aliases are pre-registered so a downstream monolith
    // adapter can adopt either shape without forcing this table to
    // grow a second copy of every payload.
    let canonical = match check_id {
        // Live API.* aliases — Wave E3 (TOP5-#3 Phase 3 §8(c)) canonical
        // shape used by `sx_discovery::scanner::api_scanner::ApiScanner`.
        API_AUTH_MISSING_DOTTED => "api-no-auth-required",
        API_CORS_WILDCARD_DOTTED => "api-cors-wildcard",
        API_SERVER_FINGERPRINT_DOTTED => "api-server-disclosure",
        API_ERROR_VERBOSE_DOTTED => "api-verbose-error",
        API_RATELIMIT_HEADERS_MISSING_DOTTED => "api-missing-rate-limit-headers",
        API_GRAPHQL_INTROSPECTION_ENABLED_DOTTED => "api-graphql-introspection-enabled",
        // Already-canonical kebab-case ids fall through unchanged.
        other => other,
    };
    let e = match canonical {
        "api-no-auth-required" => api_no_auth_required(),
        "api-cors-wildcard" => api_cors_wildcard(),
        "api-server-disclosure" => api_server_disclosure(),
        "api-verbose-error" => api_verbose_error(),
        "api-missing-rate-limit-headers" => api_missing_rate_limit_headers(),
        "api-graphql-introspection-enabled" => api_graphql_introspection_enabled(),
        _ => return None,
    };
    Some(e)
}

/// `api-no-auth-required` — endpoint returns 200 OK without an
/// Authorization header (treated as missing authentication on a
/// protected API surface).
///
/// References:
/// - CWE-306 Missing Authentication for Critical Function
///   (<https://cwe.mitre.org/data/definitions/306.html>).
/// - CVSS v3.1 vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical).
///   Reachable from the network, no privileges/UI, full CIA on the
///   exposed resource — the canonical "broken auth on internet-facing
///   endpoint" score.
/// - MITRE ATT&CK T1190 Exploit Public-Facing Application
///   (TA0001 Initial Access).
/// - NIST SP 800-53 Rev 5 AC-3 (Access Enforcement) and IA-2
///   (Identification and Authentication, Organizational Users).
/// - ISO/IEC 27001 A.5.15 Access control.
/// - PCI DSS 4.0 §8.2 Identify users / authenticate access.
fn api_no_auth_required() -> ApiDastEnrichment {
    ApiDastEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            9.8,
            CvssV31Rating::Critical,
        )),
        cwe: vec![cwe(306)],
        mitre_attack: vec![attack("TA0001", "T1190", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("AC-3"), nist("IA-2")],
            iso_27001: vec![iso("A.5.15")],
            pci_dss: vec![pci("8.2")],
            ..Default::default()
        },
    }
}

/// `api-cors-wildcard` — `Access-Control-Allow-Origin: *` combined with
/// `Access-Control-Allow-Credentials: true`, which most browsers refuse
/// but mis-configured proxies / SPAs can still rely on, exposing
/// cross-origin reads of authenticated responses.
///
/// References:
/// - CWE-942 Permissive Cross-domain Policy with Untrusted Domains
///   (<https://cwe.mitre.org/data/definitions/942.html>).
/// - CVSS v3.1 vector AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N = 8.6 (High).
///   Network reachable, no privileges, no UI required (the cross-origin
///   read fires from any malicious origin loaded in the victim's
///   browser); changed scope because the impact lands on the SPA /
///   user-agent boundary, not the API itself; confidentiality high.
/// - MITRE ATT&CK T1190 Exploit Public-Facing Application.
/// - NIST SP 800-53 Rev 5 AC-4 Information Flow Enforcement.
/// - ISO/IEC 27001 A.13.1.3 Segregation in networks.
fn api_cors_wildcard() -> ApiDastEnrichment {
    ApiDastEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            8.6,
            CvssV31Rating::High,
        )),
        cwe: vec![cwe(942)],
        mitre_attack: vec![attack("TA0001", "T1190", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("AC-4")],
            iso_27001: vec![iso("A.13.1.3")],
            ..Default::default()
        },
    }
}

/// `api-server-disclosure` — `Server` header reveals
/// `<product>/<major.minor>`, easing version-specific exploit
/// fingerprinting.
///
/// References:
/// - CWE-200 Exposure of Sensitive Information to an Unauthorized Actor.
/// - CVSS v3.1 vector AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 (Medium).
///   Low-confidentiality information leak (server banner is not secret
///   on its own, but accelerates the kill chain).
/// - MITRE ATT&CK T1592 Gather Victim Host Information (TA0043
///   Reconnaissance), sub-technique T1592.004 Client Configurations.
/// - NIST SP 800-53 Rev 5 SI-11 Error Handling (covers banner
///   suppression at the application boundary).
/// - ISO/IEC 27001 A.8.31 Separation of development, test and production
///   environments (production banners should not leak build info).
fn api_server_disclosure() -> ApiDastEnrichment {
    ApiDastEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            5.3,
            CvssV31Rating::Medium,
        )),
        cwe: vec![cwe(200)],
        mitre_attack: vec![attack("TA0043", "T1592", Some("T1592.004".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-11")],
            iso_27001: vec![iso("A.8.31")],
            ..Default::default()
        },
    }
}

/// `api-verbose-error` — response body carries stack traces / SQL error
/// markers, exposing internal class names, file paths, or schema info.
///
/// References:
/// - CWE-209 Generation of Error Message Containing Sensitive
///   Information (<https://cwe.mitre.org/data/definitions/209.html>).
/// - CVSS v3.1 vector AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 (Medium).
///   Same low-conf leak class as the banner disclosure but with richer
///   internal-state payload.
/// - MITRE ATT&CK T1592 Gather Victim Host Information (TA0043
///   Reconnaissance).
/// - NIST SP 800-53 Rev 5 SI-11 Error Handling.
/// - ISO/IEC 27001 A.8.31 Separation of development, test and production
///   environments.
fn api_verbose_error() -> ApiDastEnrichment {
    ApiDastEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            5.3,
            CvssV31Rating::Medium,
        )),
        cwe: vec![cwe(209)],
        mitre_attack: vec![attack("TA0043", "T1592", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-11")],
            iso_27001: vec![iso("A.8.31")],
            ..Default::default()
        },
    }
}

/// `api-missing-rate-limit-headers` — response lacks rate-limit
/// metadata (`RateLimit-Limit` / `X-RateLimit-Limit`).
///
/// This is an informational hardening signal, not a vulnerability on
/// its own — the absence of the headers does not imply the absence of
/// server-side throttling. We therefore leave CVSS `None` per the
/// "don't fabricate" rule and cite only the CWE for the underlying
/// weakness class plus the NIST mapping for the control auditors
/// expect to see referenced.
///
/// References:
/// - CWE-770 Allocation of Resources Without Limits or Throttling.
/// - NIST SP 800-53 Rev 5 SC-5 Denial of Service Protection.
fn api_missing_rate_limit_headers() -> ApiDastEnrichment {
    ApiDastEnrichment {
        cvss: None,
        cwe: vec![cwe(770)],
        mitre_attack: vec![],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-5")],
            ..Default::default()
        },
    }
}

/// `api-graphql-introspection-enabled` — `__schema` introspection
/// returns 200 on a production-style endpoint, exposing the full
/// schema (type names, mutations, hidden fields) to anyone who can
/// reach the URL.
///
/// References:
/// - CWE-200 Exposure of Sensitive Information to an Unauthorized
///   Actor. (CWE-540 Inclusion of Sensitive Information in Source
///   Code arguably also applies, but is narrower; CWE-200 is the
///   canonical parent and matches what most SAST/DAST taxonomies pick.)
/// - CVSS v3.1 vector AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 (Medium).
///   Network reach, no privileges, low-conf leak (the schema enables
///   targeted query crafting but is not itself a credential).
/// - MITRE ATT&CK T1592 Gather Victim Host Information (TA0043
///   Reconnaissance).
/// - NIST SP 800-53 Rev 5 SI-11 Error Handling (we treat the
///   introspection probe as an information-disclosure control surface
///   alongside other banner-suppression items).
fn api_graphql_introspection_enabled() -> ApiDastEnrichment {
    ApiDastEnrichment {
        cvss: Some(cvss_or_skip(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            5.3,
            CvssV31Rating::Medium,
        )),
        cwe: vec![cwe(200)],
        mitre_attack: vec![attack("TA0043", "T1592", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SI-11")],
            iso_27001: vec![iso("A.8.31")],
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
        unreachable!("API DAST enrichment table CVSS rejected by constructor: {e:?}")
    })
}

fn cwe(id: u32) -> CweId {
    CweId::new(id).unwrap_or_else(|e| {
        unreachable!("API DAST enrichment table CWE id rejected by constructor: {e:?}")
    })
}

fn attack(tactic: &str, technique: &str, sub: Option<String>) -> MitreAttackTechnique {
    MitreAttackTechnique::new(tactic, technique, sub).unwrap_or_else(|e| {
        unreachable!("API DAST enrichment table ATT&CK rejected by constructor: {e:?}")
    })
}

fn nist(id: &str) -> NistControl {
    NistControl::new(id).unwrap_or_else(|e| {
        unreachable!("API DAST enrichment table NIST control rejected by constructor: {e:?}")
    })
}

fn iso(id: &str) -> IsoControl {
    IsoControl::new(id).unwrap_or_else(|e| {
        unreachable!("API DAST enrichment table ISO control rejected by constructor: {e:?}")
    })
}

fn pci(id: &str) -> PciRequirement {
    PciRequirement::new(id).unwrap_or_else(|e| {
        unreachable!("API DAST enrichment table PCI requirement rejected by constructor: {e:?}")
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
            "api-no-auth-required",
            "api-cors-wildcard",
            "api-server-disclosure",
            "api-verbose-error",
            "api-missing-rate-limit-headers",
            "api-graphql-introspection-enabled",
        ];
        for id in ids {
            assert!(
                api_dast_enrichment(id).is_some(),
                "missing enrichment for {id}",
            );
        }
    }

    /// Reserved `API.*` ids resolve to the same canonical payload as
    /// their kebab-case counterparts. Mirrors the SX-REVIEW-002 C1
    /// regression net for the HDR.* alias map.
    #[test]
    fn live_api_ids_resolve_to_same_payload() {
        let pairs = [
            (API_AUTH_MISSING_DOTTED, "api-no-auth-required"),
            (API_CORS_WILDCARD_DOTTED, "api-cors-wildcard"),
            (API_SERVER_FINGERPRINT_DOTTED, "api-server-disclosure"),
            (API_ERROR_VERBOSE_DOTTED, "api-verbose-error"),
            (
                API_RATELIMIT_HEADERS_MISSING_DOTTED,
                "api-missing-rate-limit-headers",
            ),
            (
                API_GRAPHQL_INTROSPECTION_ENABLED_DOTTED,
                "api-graphql-introspection-enabled",
            ),
        ];
        for (live, legacy) in pairs {
            let a = api_dast_enrichment(live).unwrap_or_else(|| {
                panic!("live id {live} did not resolve to an enrichment payload")
            });
            let b = api_dast_enrichment(legacy).unwrap();
            assert_eq!(a, b, "live id {live} did not match legacy id {legacy}");
        }
    }

    /// TOP5-#3 Phase 3 §8(c) Wave E3: every discovery-side API dotted
    /// `check_id` we now emit from
    /// `crates/sx-discovery/src/scanner/api_scanner.rs` must resolve to
    /// a non-`None` enrichment payload. The
    /// `API.RATELIMIT.HEADERS_MISSING` entry intentionally omits CVSS
    /// (informational signal, "don't fabricate" rule) but still carries
    /// CWE + NIST control tags, so the "non-empty payload" check
    /// remains meaningful.
    #[test]
    fn every_discovery_side_dotted_id_resolves_to_a_payload() {
        let ids = [
            API_AUTH_MISSING_DOTTED,
            API_CORS_WILDCARD_DOTTED,
            API_SERVER_FINGERPRINT_DOTTED,
            API_ERROR_VERBOSE_DOTTED,
            API_RATELIMIT_HEADERS_MISSING_DOTTED,
            API_GRAPHQL_INTROSPECTION_ENABLED_DOTTED,
        ];
        for id in ids {
            let e = api_dast_enrichment(id)
                .unwrap_or_else(|| panic!("dotted id `{id}` must resolve to a payload"));
            assert!(id.contains('.'), "id `{id}` must be dotted-form");
            assert!(
                e.cvss.is_some() || !e.cwe.is_empty() || !e.compliance.is_empty(),
                "dotted id `{id}` resolved to an empty enrichment payload",
            );
        }
    }

    #[test]
    fn unknown_check_id_returns_none() {
        assert!(api_dast_enrichment("api-totally-fake-check").is_none());
        assert!(api_dast_enrichment("missing-hsts").is_none());
        assert!(api_dast_enrichment("API.SOMETHING.NEW").is_none());
        assert!(api_dast_enrichment("").is_none());
    }

    #[test]
    fn no_auth_required_matches_brief_reference_data() {
        let e = api_dast_enrichment("api-no-auth-required").unwrap();
        let cvss = e.cvss.expect("no-auth-required missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert!((cvss.base_score - 9.8).abs() < f64::EPSILON);
        assert_eq!(cvss.severity, CvssV31Rating::Critical);
        assert!(e.cwe.iter().any(|c| c.as_u32() == 306));
        assert!(e.mitre_attack.iter().any(|t| t.technique == "T1190"));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "AC-3"));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "IA-2"));
        assert!(e.compliance.pci_dss.iter().any(|c| c.as_str() == "8.2"));
    }

    #[test]
    fn cors_wildcard_carries_cwe_942_and_changed_scope_cvss() {
        let e = api_dast_enrichment("api-cors-wildcard").unwrap();
        let cvss = e.cvss.expect("cors-wildcard missing CVSS");
        assert!(cvss.vector.contains("S:C"), "expected changed scope");
        assert!((cvss.base_score - 8.6).abs() < f64::EPSILON);
        assert!(e.cwe.iter().any(|c| c.as_u32() == 942));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "AC-4"));
    }

    #[test]
    fn rate_limit_headers_is_intentionally_unscored() {
        // Informational signal: cite CWE + NIST control, leave CVSS None
        // per the "don't fabricate" rule.
        let e = api_dast_enrichment("api-missing-rate-limit-headers").unwrap();
        assert!(e.cvss.is_none());
        assert!(e.cwe.iter().any(|c| c.as_u32() == 770));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "SC-5"));
        assert!(e.mitre_attack.is_empty());
    }

    #[test]
    fn verbose_error_maps_to_cwe_209() {
        let e = api_dast_enrichment("api-verbose-error").unwrap();
        assert!(e.cwe.iter().any(|c| c.as_u32() == 209));
        assert!(e.cvss.is_some());
    }

    #[test]
    fn graphql_introspection_maps_to_cwe_200_and_t1592() {
        let e = api_dast_enrichment("api-graphql-introspection-enabled").unwrap();
        assert!(e.cwe.iter().any(|c| c.as_u32() == 200));
        assert!(e.mitre_attack.iter().any(|t| t.technique == "T1592"));
    }

    #[test]
    fn server_disclosure_maps_to_t1592_004() {
        let e = api_dast_enrichment("api-server-disclosure").unwrap();
        let sub = e
            .mitre_attack
            .iter()
            .find(|t| t.technique == "T1592")
            .and_then(|t| t.subtechnique.clone());
        assert_eq!(sub.as_deref(), Some("T1592.004"));
    }
}
