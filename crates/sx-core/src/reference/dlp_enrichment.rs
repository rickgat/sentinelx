//! DLP detection-event enrichment table (TOP5-#3 Phase 2, P2-003).
//!
//! Maps every [`sx_dlp::patterns::DlpMatchKind`] variant — in its stable
//! `snake_case` wire form (`DlpMatchKind::as_str()`) — to a curated
//! [`DlpEnrichment`] payload (CWE class, MITRE ATT&CK technique(s),
//! compliance-framework controls). DLP findings are detection events,
//! not vulnerability proofs, so we deliberately do NOT carry a CVSS v3.1
//! base score on this surface (matching the posture established for
//! `api-missing-rate-limit-headers` in TOP5-#3-P2-001).
//!
//! ## Why this lives in `sx-core` (and is keyed by `&str`)
//!
//! `sx-core` cannot depend on `sx-dlp` (the dependency arrow points the
//! other way). The natural lookup key — the `DlpMatchKind` enum — lives
//! in `sx-dlp`. Rather than mirror the enum here and risk drift, we key
//! the table by the stable `as_str()` form documented on the
//! `DlpMatchKind` declaration ("`snake_case` names that are stable across
//! versions: dashboards and integrations rely on these literal values").
//! Adapter callers do `dlp_enrichment(kind.as_str())` at the wire boundary.
//!
//! ## At-boundary enrichment, not in the domain crate
//!
//! Per the audit that produced TOP5-#3-P2-003, the cleanest hookup is in
//! [`services/sx-monolith::adapters::dlp`] where the adapter translates
//! [`sx_dlp::detector::DetectionEvent`] into the wire DTO
//! [`sx_api::port::DlpScanResultView`]. We do not pollute `sx-dlp` with
//! `sx-core` knowledge; we project enrichment in the monolith where the
//! wire DTO is built.
//!
//! ## Don't fabricate
//!
//! Where no authoritative CWE/MITRE/compliance mapping exists (the
//! detection of a bare `email` or `phone` number is informational
//! exposure with no canonical CVSS, but CWE-359 is broadly accepted for
//! PII; we cite it conservatively), we cite only the controls we can
//! defend. CVSS is left `None` for every DLP variant.
//!
//! ## CVSS posture for DLP
//!
//! DLP fires on the *presence* of sensitive data in scanned content
//! (logs, request bodies, code blobs). That is a **detection**, not a
//! vulnerability proof — a credit-card number in a log line is a control
//! gap, not an exploitable weakness on its own. CVSS v3.1 is calibrated
//! for vulnerability scoring (CIA impact under exploit), not for
//! data-exposure incidents. We therefore leave `cvss = None` for every
//! variant in this table; consumers that want a severity hint should use
//! the `severity` rollup the adapter already emits.

use crate::value_object::compliance::{
    ComplianceTags, HipaaSafeguard, NistControl, PciRequirement,
};
use crate::value_object::cvss_v31::CvssV31;
use crate::value_object::cwe::CweId;
use crate::value_object::mitre_attack::MitreAttackTechnique;

/// Curated enrichment payload for one DLP detection category.
///
/// All fields are optional or default-empty so a missing piece of
/// authoritative reference data simply omits the corresponding wire
/// key (via `skip_serializing_if` on the consuming DTO).
// `Eq` is intentionally NOT derived: the embedded
// [`crate::value_object::cvss_v31::CvssV31`] holds an `f64` base score
// which only implements `PartialEq`. The DLP table currently never
// populates `cvss`, but we keep the field for shape parity with
// [`crate::reference::header_enrichment::HdrEnrichment`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DlpEnrichment {
    /// CVSS v3.1 base metric payload — always `None` for DLP variants,
    /// see the module docstring "CVSS posture for DLP".
    pub cvss: Option<CvssV31>,
    /// CWE identifiers describing the underlying weakness class(es).
    pub cwe: Vec<CweId>,
    /// MITRE ATT&CK techniques / sub-techniques this finding maps to.
    pub mitre_attack: Vec<MitreAttackTechnique>,
    /// Compliance-framework control mappings.
    pub compliance: ComplianceTags,
}

/// Build the enrichment payload for the supplied DLP `kind`.
///
/// The key is the stable `snake_case` string returned by
/// [`sx_dlp::patterns::DlpMatchKind::as_str()`] — see the module
/// docstring "Why this lives in `sx-core` (and is keyed by `&str`)".
///
/// Returns `None` for any id outside the curated table. Two informational
/// kinds — `email` and `phone` — are intentionally outside the table:
/// CWE-359 (Exposure of Private Personal Information) arguably applies,
/// but absent business context (was this an internal log? a public bug
/// report?) we leave the enrichment blank rather than fabricate a
/// confidence-grade mapping. The wire DTO then omits the enrichment keys
/// via `skip_serializing_if`.
#[must_use]
pub fn dlp_enrichment(kind: &str) -> Option<DlpEnrichment> {
    let e = match kind {
        // ----- Payment-card data ------------------------------------------
        "credit_card" => credit_card(),
        // ----- US PII ------------------------------------------------------
        "ssn_us" => ssn_us(),
        // ----- Hard-coded credentials -------------------------------------
        "aws_access_key" | "aws_secret_key" | "github_pat" | "slack_token" => cloud_credential(),
        "jwt" => jwt_token(),
        "pem_private_key" | "gcp_service_account" => private_key_material(),
        // Bare email / phone / named-entity hits are detection-only and
        // carry no defensible authoritative mapping — return None so the
        // wire DTO omits the enrichment keys entirely.
        _ => return None,
    };
    Some(e)
}

/// `credit_card` — payment-card number (PAN) detected in scanned content.
///
/// References:
/// - CWE-311 Missing Encryption of Sensitive Data
///   (<https://cwe.mitre.org/data/definitions/311.html>).
/// - NIST SP 800-53 Rev 5 SC-28 Protection of Information at Rest +
///   SI-12 Information Management and Retention.
/// - PCI DSS 4.0 §3.4 / §3.5 (render PAN unreadable; protect cryptographic keys).
/// - MITRE ATT&CK T1552 Unsecured Credentials (TA0006 Credential Access).
fn credit_card() -> DlpEnrichment {
    DlpEnrichment {
        cvss: None,
        cwe: vec![cwe(311)],
        mitre_attack: vec![attack("TA0006", "T1552", None)],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-28"), nist("SI-12")],
            pci_dss: vec![pci("3.4"), pci("3.5")],
            ..Default::default()
        },
    }
}

/// `ssn_us` — US Social Security Number detected in scanned content.
///
/// References:
/// - CWE-359 Exposure of Private Personal Information
///   (<https://cwe.mitre.org/data/definitions/359.html>).
/// - NIST SP 800-53 Rev 5 PT-3 Personally Identifiable Information
///   Processing Purposes + SC-28 Protection of Information at Rest.
/// - HIPAA Security Rule 45 CFR §164.312(e)(2)(ii) Encryption.
fn ssn_us() -> DlpEnrichment {
    DlpEnrichment {
        cvss: None,
        cwe: vec![cwe(359)],
        mitre_attack: vec![],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("PT-3"), nist("SC-28")],
            hipaa: vec![hipaa("164.312(e)(2)(ii)")],
            ..Default::default()
        },
    }
}

/// Shared payload for cloud / `SaaS` bearer credentials —
/// `aws_access_key`, `aws_secret_key`, `github_pat`, `slack_token`.
///
/// All four are long-lived bearer tokens whose presence in scanned
/// content (logs, source, request bodies) is a hard-coded-credentials
/// leak.
///
/// References:
/// - CWE-798 Use of Hard-coded Credentials
///   (<https://cwe.mitre.org/data/definitions/798.html>).
/// - CWE-200 Exposure of Sensitive Information to an Unauthorized Actor.
/// - NIST SP 800-53 Rev 5 SC-12 Cryptographic Key Establishment +
///   IA-5 Authenticator Management.
/// - MITRE ATT&CK T1552.001 Credentials In Files (TA0006 Credential Access).
fn cloud_credential() -> DlpEnrichment {
    DlpEnrichment {
        cvss: None,
        cwe: vec![cwe(798), cwe(200)],
        mitre_attack: vec![attack("TA0006", "T1552", Some("T1552.001".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-12"), nist("IA-5")],
            ..Default::default()
        },
    }
}

/// `jwt` — JSON Web Token detected in scanned content.
///
/// JWTs are session-bearer tokens; a leaked JWT is materially identical
/// to a leaked password until the token expires. We share the credential
/// CWE mapping but call out the TA0006/T1552.001 sub-technique because
/// "Credentials In Files" applies one-to-one.
fn jwt_token() -> DlpEnrichment {
    DlpEnrichment {
        cvss: None,
        cwe: vec![cwe(798), cwe(200)],
        mitre_attack: vec![attack("TA0006", "T1552", Some("T1552.001".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("IA-5"), nist("SC-12")],
            ..Default::default()
        },
    }
}

/// Shared payload for asymmetric-key private material —
/// `pem_private_key`, `gcp_service_account`.
///
/// A PEM private-key block or a GCP service-account JSON containing the
/// `-----BEGIN PRIVATE KEY-----` block is a high-impact leak: the holder
/// can impersonate the principal without further authentication.
///
/// References:
/// - CWE-798 Use of Hard-coded Credentials
///   (<https://cwe.mitre.org/data/definitions/798.html>).
/// - CWE-321 Use of Hard-coded Cryptographic Key.
/// - NIST SP 800-53 Rev 5 SC-12 Cryptographic Key Establishment +
///   IA-5 Authenticator Management.
/// - MITRE ATT&CK T1552.004 Private Keys (TA0006 Credential Access).
fn private_key_material() -> DlpEnrichment {
    DlpEnrichment {
        cvss: None,
        cwe: vec![cwe(798), cwe(321)],
        mitre_attack: vec![attack("TA0006", "T1552", Some("T1552.004".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-12"), nist("IA-5")],
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
        unreachable!("DLP enrichment table CWE id rejected by constructor: {e:?}")
    })
}

fn attack(tactic: &str, technique: &str, sub: Option<String>) -> MitreAttackTechnique {
    MitreAttackTechnique::new(tactic, technique, sub).unwrap_or_else(|e| {
        unreachable!("DLP enrichment table ATT&CK rejected by constructor: {e:?}")
    })
}

fn nist(id: &str) -> NistControl {
    NistControl::new(id).unwrap_or_else(|e| {
        unreachable!("DLP enrichment table NIST control rejected by constructor: {e:?}")
    })
}

fn pci(id: &str) -> PciRequirement {
    PciRequirement::new(id).unwrap_or_else(|e| {
        unreachable!("DLP enrichment table PCI requirement rejected by constructor: {e:?}")
    })
}

fn hipaa(id: &str) -> HipaaSafeguard {
    HipaaSafeguard::new(id).unwrap_or_else(|e| {
        unreachable!("DLP enrichment table HIPAA safeguard rejected by constructor: {e:?}")
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every DLP kind we claim to enrich must produce a payload, and
    /// every payload's constructors must accept the curated strings.
    /// This is the regression net for typos and for new kinds added to
    /// `sx-dlp` without a corresponding entry here.
    #[test]
    fn enrichment_table_is_well_formed_for_curated_kinds() {
        let ids = [
            "credit_card",
            "ssn_us",
            "aws_access_key",
            "aws_secret_key",
            "github_pat",
            "slack_token",
            "jwt",
            "pem_private_key",
            "gcp_service_account",
        ];
        for id in ids {
            assert!(dlp_enrichment(id).is_some(), "missing enrichment for {id}",);
        }
    }

    /// Informational kinds (`email` / `phone` / `named_entity`) are
    /// intentionally outside the table — see the module docstring.
    #[test]
    fn informational_kinds_return_none() {
        assert!(dlp_enrichment("email").is_none());
        assert!(dlp_enrichment("phone").is_none());
        assert!(dlp_enrichment("named_entity").is_none());
    }

    /// Garbage / future kinds must return `None` rather than panic.
    #[test]
    fn unknown_kind_returns_none() {
        assert!(dlp_enrichment("totally_made_up").is_none());
        assert!(dlp_enrichment("").is_none());
        assert!(dlp_enrichment("CREDIT_CARD").is_none(), "case-sensitive");
    }

    /// CVSS is always `None` for DLP variants — the table is curated
    /// per the "CVSS posture for DLP" rule in the module docstring.
    #[test]
    fn every_enriched_kind_has_no_cvss() {
        let ids = [
            "credit_card",
            "ssn_us",
            "aws_access_key",
            "aws_secret_key",
            "github_pat",
            "slack_token",
            "jwt",
            "pem_private_key",
            "gcp_service_account",
        ];
        for id in ids {
            let e = dlp_enrichment(id).unwrap();
            assert!(e.cvss.is_none(), "DLP kind {id} should not carry CVSS");
        }
    }

    #[test]
    fn credit_card_matches_brief_reference_data() {
        let e = dlp_enrichment("credit_card").unwrap();
        assert!(e.cvss.is_none());
        assert_eq!(e.cwe, vec![cwe(311)]);
        assert!(e
            .mitre_attack
            .iter()
            .any(|t| t.technique == "T1552" && t.subtechnique.is_none()));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "SC-28"));
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "SI-12"));
        assert!(e.compliance.pci_dss.iter().any(|c| c.as_str() == "3.4"));
        assert!(e.compliance.pci_dss.iter().any(|c| c.as_str() == "3.5"));
    }

    #[test]
    fn ssn_us_matches_brief_reference_data() {
        let e = dlp_enrichment("ssn_us").unwrap();
        assert_eq!(e.cwe, vec![cwe(359)]);
        assert!(e
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "PT-3"));
        assert!(e
            .compliance
            .hipaa
            .iter()
            .any(|c| c.as_str() == "164.312(e)(2)(ii)"));
    }

    /// The four bearer-credential kinds share a single payload — assert
    /// the equality so a future contributor that diverges them gets a
    /// clear regression message.
    #[test]
    fn cloud_credentials_share_payload() {
        let aws_a = dlp_enrichment("aws_access_key").unwrap();
        let aws_s = dlp_enrichment("aws_secret_key").unwrap();
        let gh = dlp_enrichment("github_pat").unwrap();
        let slack = dlp_enrichment("slack_token").unwrap();
        assert_eq!(aws_a, aws_s);
        assert_eq!(aws_a, gh);
        assert_eq!(aws_a, slack);
        assert_eq!(aws_a.cwe, vec![cwe(798), cwe(200)]);
        assert!(aws_a
            .mitre_attack
            .iter()
            .any(|t| t.subtechnique.as_deref() == Some("T1552.001")));
    }

    #[test]
    fn private_key_material_shares_payload() {
        let pem = dlp_enrichment("pem_private_key").unwrap();
        let gcp = dlp_enrichment("gcp_service_account").unwrap();
        assert_eq!(pem, gcp);
        assert_eq!(pem.cwe, vec![cwe(798), cwe(321)]);
        assert!(pem
            .mitre_attack
            .iter()
            .any(|t| t.subtechnique.as_deref() == Some("T1552.004")));
    }

    #[test]
    fn jwt_carries_credential_subtechnique() {
        let jwt = dlp_enrichment("jwt").unwrap();
        assert_eq!(jwt.cwe, vec![cwe(798), cwe(200)]);
        assert!(jwt
            .mitre_attack
            .iter()
            .any(|t| t.subtechnique.as_deref() == Some("T1552.001")));
    }
}
