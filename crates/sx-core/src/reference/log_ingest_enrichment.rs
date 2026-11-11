//! Log-ingest rate-limit finding enrichment table (TOP5-#3 Phase 2,
//! ticket P2-008).
//!
//! Materialises the canonical CWE / MITRE ATT&CK / NIST control set we
//! attach to the synthetic `Finding` emitted when the per-tenant
//! token-bucket rate limiter on `POST /v1/logs/ingest` rejects a burst.
//!
//! The cardinality contract — one finding per
//! `(tenant_id, endpoint, 15-minute window)` — is enforced upstream at
//! the controller layer; this module is pure reference data and
//! deliberately mirrors the structure of the sibling
//! [`crate::reference::header_enrichment`] / [`dlp_enrichment`] tables
//! so future emitters can call all three through a single seam.
//!
//! ## References
//!
//! - CWE-770 Allocation of Resources Without Limits or Throttling
//!   (<https://cwe.mitre.org/data/definitions/770.html>) — the closest
//!   class match for a successful per-tenant burst-exhaustion event,
//!   since the bucket is precisely "limited resources" (tokens) being
//!   consumed faster than the policy allows.
//! - MITRE ATT&CK T1499.002 Endpoint Denial of Service: Service
//!   Exhaustion Flood, under tactic TA0040 Impact.
//! - NIST SP 800-53 Rev 5 SC-5 Denial of Service Protection.
//!
//! Per the original Phase 1 policy ("don't fabricate"), CVSS is left
//! unset — burst exhaustion is a soft-availability signal, not a
//! vulnerability, and forcing a base vector here would mislead
//! downstream consumers that key off `cvss.present`.

use crate::value_object::compliance::{ComplianceTags, NistControl};
use crate::value_object::cvss_v31::CvssV31;
use crate::value_object::cwe::CweId;
use crate::value_object::mitre_attack::MitreAttackTechnique;

/// Legacy colon-form rule id retained for backward-compat receive-side
/// lookups. Superseded on emit by [`RATE_LIMIT_RULE_ID_DOTTED`].
///
/// The FOUND-001 Postgres adapter requires the effective emit value to be
/// `NOT NULL` + length 1..=256 and the cardinality dedup logic in the
/// controller keys off it.
pub const RATE_LIMIT_RULE_ID: &str = "log-ingest:rate-limit-exceeded";

/// Canonical dotted-form rule id stamped on every rate-limit finding
/// (TOP5-#3 Phase 3). Every fresh emit MUST use this shape.
pub const RATE_LIMIT_RULE_ID_DOTTED: &str = "MED001.RATE_LIMITER.REJECT";

/// Canonical title stamped on the synthetic finding.
pub const RATE_LIMIT_FINDING_TITLE: &str = "Log ingest rate limit exceeded";

/// Curated enrichment payload for the log-ingest rate-limit emitter.
///
/// All fields mirror the [`crate::reference::header_enrichment`] /
/// [`crate::reference::dlp_enrichment`] shape so a downstream SARIF /
/// SOC adapter can pick the same projection helpers up unchanged.
// `Eq` is intentionally NOT derived: [`CvssV31`] embeds an `f64` base
// score which only implements `PartialEq`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LogIngestEnrichment {
    /// CVSS v3.1 base metric payload. Intentionally `None` for the
    /// rate-limit emitter — see the module docs.
    pub cvss: Option<CvssV31>,
    /// CWE identifiers describing the underlying weakness class.
    pub cwe: Vec<CweId>,
    /// MITRE ATT&CK techniques / sub-techniques.
    pub mitre_attack: Vec<MitreAttackTechnique>,
    /// Compliance-framework control mappings.
    pub compliance: ComplianceTags,
}

/// Build the canonical enrichment payload for the rate-limit-exceeded
/// finding.
///
/// Returns a fully-populated [`LogIngestEnrichment`]:
///
/// - `cwe`: `CWE-770` (resource allocation without limits/throttling).
/// - `mitre_attack`: `T1499.002` (Service Exhaustion Flood) under
///   tactic `TA0040` (Impact).
/// - `compliance.nist_800_53`: `SC-5` (Denial of Service Protection).
/// - `cvss`: `None` — see the module-level rationale.
#[must_use]
pub fn rate_limit_enrichment() -> LogIngestEnrichment {
    LogIngestEnrichment {
        cvss: None,
        cwe: vec![cwe(770)],
        mitre_attack: vec![attack("TA0040", "T1499", Some("T1499.002".into()))],
        compliance: ComplianceTags {
            nist_800_53: vec![nist("SC-5")],
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
        unreachable!("log-ingest enrichment table CWE id rejected by constructor: {e:?}")
    })
}

fn attack(tactic: &str, technique: &str, sub: Option<String>) -> MitreAttackTechnique {
    MitreAttackTechnique::new(tactic, technique, sub).unwrap_or_else(|e| {
        unreachable!("log-ingest enrichment table ATT&CK rejected by constructor: {e:?}")
    })
}

fn nist(id: &str) -> NistControl {
    NistControl::new(id).unwrap_or_else(|e| {
        unreachable!("log-ingest enrichment table NIST control rejected by constructor: {e:?}")
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn rule_id_matches_canonical_form() {
        // Pin the rule-id string so a refactor never silently breaks the
        // `(tenant_id, endpoint, window)` dedup key the controller
        // computes off it.
        assert_eq!(RATE_LIMIT_RULE_ID, "log-ingest:rate-limit-exceeded");
        // TOP5-#3 Phase 3: canonical dotted form on emit.
        assert_eq!(RATE_LIMIT_RULE_ID_DOTTED, "MED001.RATE_LIMITER.REJECT");
        assert!(RATE_LIMIT_RULE_ID_DOTTED.contains('.'));
    }

    #[test]
    fn enrichment_carries_cwe_770() {
        let e = rate_limit_enrichment();
        let ids: Vec<u32> = e.cwe.iter().map(|c| c.as_u32()).collect();
        assert_eq!(ids, vec![770]);
    }

    #[test]
    fn enrichment_carries_mitre_t1499_002_under_impact() {
        let e = rate_limit_enrichment();
        assert_eq!(e.mitre_attack.len(), 1);
        let t = &e.mitre_attack[0];
        assert_eq!(t.tactic, "TA0040");
        assert_eq!(t.technique, "T1499");
        assert_eq!(t.subtechnique.as_deref(), Some("T1499.002"));
    }

    #[test]
    fn enrichment_carries_nist_sc_5() {
        let e = rate_limit_enrichment();
        let controls: Vec<String> = e
            .compliance
            .nist_800_53
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect();
        assert_eq!(controls, vec!["SC-5"]);
    }

    #[test]
    fn enrichment_leaves_cvss_unset_per_dont_fabricate_rule() {
        let e = rate_limit_enrichment();
        assert!(
            e.cvss.is_none(),
            "burst-exhaustion is availability signal, not a CVSS-able vuln",
        );
    }

    #[test]
    fn enrichment_other_frameworks_are_empty() {
        // Only NIST 800-53 has a clean control match. ISO / PCI / SOC2 /
        // HIPAA stay empty rather than fabricated.
        let e = rate_limit_enrichment();
        assert!(e.compliance.iso_27001.is_empty());
        assert!(e.compliance.pci_dss.is_empty());
        assert!(e.compliance.soc2.is_empty());
        assert!(e.compliance.hipaa.is_empty());
    }
}
