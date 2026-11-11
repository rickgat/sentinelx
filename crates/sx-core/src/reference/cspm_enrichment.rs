//! CSPM (Prowler / CIS Benchmarks) finding enrichment helpers
//! (TOP5-#3 Phase 2, ticket P2-006).
//!
//! Unlike the HDR.* header-audit emitter, the CSPM scanner does not own a
//! hand-curated CVSS / CWE / MITRE table — Prowler ships its own check
//! catalogue (hundreds of entries, mapped to CIS Benchmarks and the major
//! compliance frameworks). Per the dispatch policy, we **project Prowler's
//! own enrichment data through** into the canonical `Finding`-style
//! enrichment surface (`ComplianceTags`, `Vec<CweId>`) and leave the
//! authoritative `CvssV31` field empty: Prowler does not emit CVSS.
//!
//! What this module does:
//!
//! - [`parse_prowler_compliance`] reads Prowler's OCSF `unmapped.compliance`
//!   (Prowler v4+) or top-level `compliance` (Prowler v3) object and
//!   projects framework keys onto our [`ComplianceTags`] aggregate. Only
//!   syntactically valid control identifiers are retained — bad entries
//!   are silently dropped so a single malformed control does not strip
//!   the whole framework.
//! - [`extract_cwe_from_text`] regex-scans an arbitrary free-text string
//!   (typically Prowler's `risk` / `risk_details` / `description` field)
//!   for `CWE-xxx` mentions and returns a deduped `Vec<CweId>`.
//!
//! No I/O. No allocation beyond what Prowler's payload requires.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::value_object::compliance::{
    ComplianceTags, HipaaSafeguard, IsoControl, NistControl, PciRequirement, Soc2Criterion,
};
use crate::value_object::cwe::CweId;

/// Regex matching `CWE-<digits>` mentions in free text, case-insensitive.
///
/// Anchored on a word boundary so `XCWE-1` does not match.
static CWE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bCWE-(\d+)\b")
        .unwrap_or_else(|e| unreachable!("CWE regex is a compile-time constant: {e}"))
});

/// Project a Prowler-style `compliance` JSON object into a
/// [`ComplianceTags`] aggregate.
///
/// Accepted Prowler framework keys (case-insensitive, hyphens / underscores
/// treated equivalently):
///
/// | Prowler key (prefix-match) | Target framework |
/// |---|---|
/// | `nist_800_53`, `nist-800-53`, `nist_sp_800_53` | NIST 800-53 |
/// | `iso_27001` (any revision suffix) | ISO/IEC 27001 |
/// | `pci_3_2_1`, `pci_4_0`, `pci_dss` | PCI DSS |
/// | `soc2`, `soc_2`, `aicpa_soc_2` | SOC 2 |
/// | `hipaa` | HIPAA |
///
/// Each framework entry is expected to be either an array of control id
/// strings (`["AC-3", "SC-7"]`) or an object whose values are arrays
/// (`{"AC": ["AC-3"]}`); both shapes are flattened.
///
/// Invalid control identifiers are skipped silently. The whole function is
/// tolerant of partial / malformed payloads — a missing or unrecognised
/// framework simply contributes nothing.
#[must_use]
pub fn parse_prowler_compliance(value: &Value) -> ComplianceTags {
    let Some(map) = value.as_object() else {
        return ComplianceTags::default();
    };

    let mut tags = ComplianceTags::default();
    for (key, entries) in map {
        let normalised = normalise_framework_key(key);
        let controls = collect_strings(entries);
        if controls.is_empty() {
            continue;
        }
        match normalised.as_str() {
            "nist_800_53" => {
                for c in controls {
                    if let Ok(v) = NistControl::new(c) {
                        tags.nist_800_53.push(v);
                    }
                }
            }
            "iso_27001" => {
                for c in controls {
                    if let Ok(v) = IsoControl::new(c) {
                        tags.iso_27001.push(v);
                    }
                }
            }
            "pci_dss" => {
                for c in controls {
                    if let Ok(v) = PciRequirement::new(c) {
                        tags.pci_dss.push(v);
                    }
                }
            }
            "soc_2" => {
                for c in controls {
                    if let Ok(v) = Soc2Criterion::new(c) {
                        tags.soc2.push(v);
                    }
                }
            }
            "hipaa" => {
                for c in controls {
                    if let Ok(v) = HipaaSafeguard::new(c) {
                        tags.hipaa.push(v);
                    }
                }
            }
            _ => {
                // Unrecognised framework — Prowler ships several
                // (CIS / ENS / FedRAMP / GDPR / MITRE) that don't have a
                // canonical newtype on our side yet. Silent drop.
            }
        }
    }

    // De-dup while preserving order: Prowler sometimes lists the same
    // control under two sub-objects (e.g. AC.AC-3 and AC-3).
    dedup_preserving_order(&mut tags.nist_800_53);
    dedup_preserving_order(&mut tags.iso_27001);
    dedup_preserving_order(&mut tags.pci_dss);
    dedup_preserving_order(&mut tags.soc2);
    dedup_preserving_order(&mut tags.hipaa);

    tags
}

/// Extract every distinct CWE id mentioned in `text`. Order of first
/// appearance is preserved.
#[must_use]
pub fn extract_cwe_from_text(text: &str) -> Vec<CweId> {
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut out: Vec<CweId> = Vec::new();
    for caps in CWE_RE.captures_iter(text) {
        let Some(num) = caps.get(1).and_then(|m| m.as_str().parse::<u32>().ok()) else {
            continue;
        };
        if !seen.insert(num) {
            continue;
        }
        if let Ok(id) = CweId::new(num) {
            out.push(id);
        }
    }
    out
}

/// Lower-case Prowler framework keys and strip framework-version suffixes
/// onto our canonical short tags.
fn normalise_framework_key(key: &str) -> String {
    let lower = key.to_ascii_lowercase().replace('-', "_");
    // NIST family — covers `nist_800_53`, `nist_800_53_revision_5`,
    // `nist_sp_800_53`, `nist_800_53_r5`, …
    if lower.starts_with("nist") && lower.contains("800_53") {
        return "nist_800_53".to_owned();
    }
    // ISO 27001 with any year/revision suffix.
    if lower.starts_with("iso_27001") || lower.starts_with("iso_iec_27001") {
        return "iso_27001".to_owned();
    }
    // PCI DSS — `pci_3_2_1`, `pci_4_0`, `pci_dss`, `pci_dss_4_0`.
    if lower.starts_with("pci") {
        return "pci_dss".to_owned();
    }
    // SOC 2 — `soc2`, `soc_2`, `aicpa_soc_2`.
    if lower == "soc2" || lower.contains("soc_2") {
        return "soc_2".to_owned();
    }
    if lower.starts_with("hipaa") {
        return "hipaa".to_owned();
    }
    lower
}

/// Pull every string value out of the (possibly nested) Prowler entry into
/// a flat ordered vector.
fn collect_strings(value: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    walk_strings(value, &mut out);
    out
}

fn walk_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_owned());
            }
        }
        Value::Array(arr) => {
            for v in arr {
                walk_strings(v, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                walk_strings(v, out);
            }
        }
        _ => {}
    }
}

fn dedup_preserving_order<T: Eq + std::hash::Hash + Clone>(v: &mut Vec<T>) {
    let mut seen: std::collections::HashSet<T> = std::collections::HashSet::new();
    v.retain(|item| seen.insert(item.clone()));
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

    #[test]
    fn extract_cwe_returns_empty_when_absent() {
        assert!(extract_cwe_from_text("").is_empty());
        assert!(extract_cwe_from_text("nothing to see here").is_empty());
    }

    #[test]
    fn extract_cwe_picks_up_single_mention() {
        let cwes = extract_cwe_from_text(
            "Permits cleartext transmission; see CWE-319 for the underlying weakness.",
        );
        assert_eq!(cwes.len(), 1);
        assert_eq!(cwes[0].as_u32(), 319);
    }

    #[test]
    fn extract_cwe_case_insensitive_and_dedups() {
        let cwes =
            extract_cwe_from_text("cwe-79 surfaces here, then CWE-79 again, and CWE-352 too.");
        let nums: Vec<u32> = cwes.iter().map(|c| c.as_u32()).collect();
        assert_eq!(nums, vec![79, 352]);
    }

    #[test]
    fn extract_cwe_ignores_partial_matches() {
        // `XCWE-1` and `CWEX-1` must not match — we anchor on word boundary.
        assert!(extract_cwe_from_text("XCWE-1 CWEX-1 CWE_1").is_empty());
    }

    #[test]
    fn parse_compliance_handles_v4_array_shape() {
        let v: Value = serde_json::from_str(
            r#"{
                "nist_800_53_revision_5": ["AC-3", "SC-7"],
                "pci_3_2_1": ["1.2", "10.2.1"],
                "iso_27001_2013": ["A.9.1.1"]
            }"#,
        )
        .unwrap();
        let tags = parse_prowler_compliance(&v);
        assert_eq!(
            tags.nist_800_53
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect::<Vec<_>>(),
            vec!["AC-3", "SC-7"],
        );
        assert_eq!(
            tags.pci_dss
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect::<Vec<_>>(),
            vec!["1.2", "10.2.1"],
        );
        assert_eq!(
            tags.iso_27001
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect::<Vec<_>>(),
            vec!["A.9.1.1"],
        );
        assert!(tags.soc2.is_empty());
        assert!(tags.hipaa.is_empty());
    }

    #[test]
    fn parse_compliance_handles_nested_object_shape() {
        // Prowler sometimes nests controls under a family key.
        let v: Value = serde_json::from_str(
            r#"{
                "NIST-800-53-Revision-5": {
                    "AC": ["AC-3"],
                    "SC": ["SC-7", "SC-8"]
                }
            }"#,
        )
        .unwrap();
        let tags = parse_prowler_compliance(&v);
        let nist: Vec<String> = tags
            .nist_800_53
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect();
        assert_eq!(nist, vec!["AC-3", "SC-7", "SC-8"]);
    }

    #[test]
    fn parse_compliance_dedups_repeated_controls() {
        let v: Value = serde_json::from_str(
            r#"{
                "nist_800_53": ["AC-3", "AC-3", "SC-7"],
                "nist-800-53": ["AC-3"]
            }"#,
        )
        .unwrap();
        let tags = parse_prowler_compliance(&v);
        let nist: Vec<String> = tags
            .nist_800_53
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect();
        assert_eq!(nist, vec!["AC-3", "SC-7"]);
    }

    #[test]
    fn parse_compliance_drops_invalid_controls() {
        let v: Value = serde_json::from_str(
            r#"{
                "nist_800_53": ["AC-3", "not-a-control", "SC-7"],
                "pci_dss": ["4.1", "X.Y"]
            }"#,
        )
        .unwrap();
        let tags = parse_prowler_compliance(&v);
        let nist: Vec<String> = tags
            .nist_800_53
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect();
        assert_eq!(nist, vec!["AC-3", "SC-7"]);
        let pci: Vec<String> = tags.pci_dss.iter().map(|c| c.as_str().to_owned()).collect();
        assert_eq!(pci, vec!["4.1"]);
    }

    #[test]
    fn parse_compliance_silently_ignores_unknown_frameworks() {
        // CIS / ENS / FedRAMP aren't on the canonical newtype list yet —
        // they must not panic, they must just produce nothing.
        let v: Value = serde_json::from_str(
            r#"{
                "cis_aws_1_4": ["1.13"],
                "ens_rd2022": ["mp.com.1.aws.iam.6"],
                "fedramp_moderate_revision_4": ["AC-3"]
            }"#,
        )
        .unwrap();
        let tags = parse_prowler_compliance(&v);
        assert!(tags.is_empty());
    }

    #[test]
    fn parse_compliance_tolerates_non_object_input() {
        assert!(parse_prowler_compliance(&Value::Null).is_empty());
        assert!(parse_prowler_compliance(&Value::String("oops".into())).is_empty());
        assert!(parse_prowler_compliance(&serde_json::json!([1, 2, 3])).is_empty());
    }

    #[test]
    fn parse_compliance_soc2_and_hipaa() {
        let v: Value = serde_json::from_str(
            r#"{
                "soc_2": ["CC6.1", "CC7.2"],
                "hipaa": ["164.308(a)(1)(i)"]
            }"#,
        )
        .unwrap();
        let tags = parse_prowler_compliance(&v);
        assert_eq!(
            tags.soc2
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect::<Vec<_>>(),
            vec!["CC6.1", "CC7.2"],
        );
        assert_eq!(
            tags.hipaa
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect::<Vec<_>>(),
            vec!["164.308(a)(1)(i)"],
        );
    }
}
