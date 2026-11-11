//! SARIF v2.1.0 export for [`Finding`]s.
//!
//! Generates a [Static Analysis Results Interchange Format
//! (SARIF) 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
//! document from a slice of [`Finding`]s. The output is the same shape
//! consumed by GitHub Code Scanning, GitLab Security Dashboard, and
//! Microsoft Defender for Cloud, which makes it the lingua franca of
//! enterprise SOC pipelines.
//!
//! ## Mapping conventions
//!
//! | Finding field          | SARIF location                                                                        |
//! |------------------------|---------------------------------------------------------------------------------------|
//! | `rule_id`              | `runs[].results[].ruleId` + an entry in `runs[].tool.driver.rules[]`                  |
//! | `title`                | `runs[].tool.driver.rules[].shortDescription.text`                                    |
//! | `description`          | `runs[].tool.driver.rules[].fullDescription.text` + `results[].message.text`          |
//! | `severity`             | `runs[].results[].level` (`none|note|warning|error`)                                  |
//! | `cvss.base_score`      | `runs[].results[].properties.security-severity` (GitHub Code Scanning convention)     |
//! | `cvss.vector`          | `runs[].results[].properties.cvss_v3_vector`                                          |
//! | `cwe[]`                | `runs[].tool.driver.rules[].relationships[]` referencing the `CWE` taxonomy (`taxa`)  |
//! | `mitre_attack[]`       | `runs[].results[].properties.tags` (e.g. `["TA0009", "T1040"]`)                       |
//! | `compliance.*`         | `runs[].results[].properties.tags` (control ids prefixed with framework name)         |
//! | `confidence`           | `runs[].results[].properties.confidence`                                              |
//! | `evidence_refs[].uri`  | `runs[].results[].locations[].physicalLocation.artifactLocation.uri`                  |
//! | `evidence_refs[].line` | `runs[].results[].locations[].physicalLocation.region.startLine`                      |
//! | `evidence_refs[].column` | `runs[].results[].locations[].physicalLocation.region.startColumn`                  |
//! | `id`                   | `runs[].results[].guid`                                                               |
//!
//! The SARIF taxonomy reference uses the well-known `CWE` toolComponent —
//! one entry per distinct CWE seen in the input set is emitted in
//! `tool.driver.supportingTaxonomies`/`taxonomies`.
//!
//! ## Release-channel metadata (TOP5-#3 Phase 3)
//!
//! `runs[].tool.driver.organization` and `runs[].tool.driver.downloadUri`
//! are optional per SARIF §3.19.16 and §3.19.18. The
//! [`findings_to_sarif`] entry point takes both as `Option<&str>`
//! parameters so callers wire them from `sx-config`'s
//! [`release_channel`] section without any breaking-change to legacy
//! call sites (both default to `None`). When `None`, the fields are
//! omitted from the envelope entirely — legacy consumers see the exact
//! byte-for-byte output they saw before Phase 3.
//!
//! ## Validation posture
//!
//! Per the dispatch brief, this module emits a `serde_json::Value` and
//! does NOT pull in a JSON-schema validator dependency. Round-trip tests
//! parse the value back, assert structural keys, and verify the
//! SARIF-version envelope.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::entity::finding::Finding;
use crate::value_object::severity::Severity;

/// Build a SARIF v2.1.0 log from a slice of findings.
///
/// `tool_name` and `tool_version` populate `runs[0].tool.driver.name`/
/// `version`. Pass your crate / scanner identifier.
///
/// `organization` and `download_uri` are optional (TOP5-#3 Phase 3): when
/// `Some`, they populate `runs[0].tool.driver.organization` and
/// `runs[0].tool.driver.downloadUri` respectively per SARIF §3.19.16 and
/// §3.19.18. Callers that do not have a release-channel URL yet pass
/// `None` and the fields are omitted, preserving the legacy envelope
/// shape byte-for-byte.
#[must_use]
pub fn findings_to_sarif(
    findings: &[Finding],
    tool_name: &str,
    tool_version: &str,
    organization: Option<&str>,
    download_uri: Option<&str>,
) -> Value {
    let (rules, rule_index) = build_rules(findings);
    let cwe_taxa = build_cwe_taxonomy(findings);

    let mut driver = Map::new();
    driver.insert("name".into(), Value::String(tool_name.to_owned()));
    driver.insert("version".into(), Value::String(tool_version.to_owned()));
    driver.insert(
        "informationUri".into(),
        Value::String("https://github.com/sentinelx/sentinelx".into()),
    );
    if let Some(org) = organization {
        driver.insert("organization".into(), Value::String(org.to_owned()));
    }
    if let Some(uri) = download_uri {
        driver.insert("downloadUri".into(), Value::String(uri.to_owned()));
    }
    driver.insert("rules".into(), Value::Array(rules));
    if !cwe_taxa.is_empty() {
        driver.insert(
            "supportingTaxonomies".into(),
            Value::Array(vec![json!({
                "name": "CWE",
                "guid": CWE_TAXONOMY_GUID,
                "informationUri": "https://cwe.mitre.org/",
            })]),
        );
    }

    let mut tool = Map::new();
    tool.insert("driver".into(), Value::Object(driver));

    let results: Vec<Value> = findings
        .iter()
        .map(|f| finding_to_result(f, &rule_index))
        .collect();

    let mut run = Map::new();
    run.insert("tool".into(), Value::Object(tool));
    if !cwe_taxa.is_empty() {
        run.insert(
            "taxonomies".into(),
            Value::Array(vec![json!({
                "name": "CWE",
                "guid": CWE_TAXONOMY_GUID,
                "informationUri": "https://cwe.mitre.org/",
                "taxa": cwe_taxa,
            })]),
        );
    }
    run.insert("results".into(), Value::Array(results));

    json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [Value::Object(run)],
    })
}

/// Stable GUID for the CWE supporting taxonomy. Generated once and frozen
/// so consumers can de-duplicate across `SentinelX` SARIF outputs.
const CWE_TAXONOMY_GUID: &str = "f6a7b3c0-9e74-4d4f-9c5d-2c4b3e9c5d2c";

/// Build the per-rule descriptor list plus an index from `rule_id` to
/// the rule's position in the array (for `result.ruleIndex`).
fn build_rules(findings: &[Finding]) -> (Vec<Value>, BTreeMap<String, usize>) {
    // De-duplicate by `rule_id` so a rule that fires N times still gets
    // one descriptor.
    let mut seen: BTreeMap<String, &Finding> = BTreeMap::new();
    for f in findings {
        seen.entry(f.rule_id.clone()).or_insert(f);
    }

    let mut rules = Vec::with_capacity(seen.len());
    let mut index = BTreeMap::new();
    for (i, (rule_id, sample)) in seen.iter().enumerate() {
        let mut descriptor = Map::new();
        descriptor.insert("id".into(), Value::String(rule_id.clone()));
        descriptor.insert("shortDescription".into(), json!({ "text": sample.title }));
        if !sample.description.is_empty() {
            descriptor.insert(
                "fullDescription".into(),
                json!({ "text": sample.description }),
            );
        }
        descriptor.insert(
            "defaultConfiguration".into(),
            json!({ "level": severity_to_level(sample.severity) }),
        );
        if !sample.cwe.is_empty() {
            descriptor.insert(
                "relationships".into(),
                Value::Array(
                    sample
                        .cwe
                        .iter()
                        .map(|c| {
                            json!({
                                "target": {
                                    "id": c.to_string(),
                                    "toolComponent": { "name": "CWE", "guid": CWE_TAXONOMY_GUID },
                                },
                                "kinds": ["superset"],
                            })
                        })
                        .collect(),
                ),
            );
        }
        rules.push(Value::Object(descriptor));
        index.insert(rule_id.clone(), i);
    }
    (rules, index)
}

/// Build the de-duplicated `taxa` array of CWE entries referenced by any
/// finding in the input set.
fn build_cwe_taxonomy(findings: &[Finding]) -> Vec<Value> {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for f in findings {
        for c in &f.cwe {
            ids.insert(c.to_string());
        }
    }
    ids.into_iter()
        .map(|id| {
            json!({
                "id": id,
                "guid": cwe_taxon_guid(&id),
            })
        })
        .collect()
}

/// Deterministic synthetic GUID per CWE id. SARIF readers use the GUID +
/// `id` pair to dedupe; we synthesize a stable v5-style hex string from
/// the id digits so the same input produces the same SARIF.
fn cwe_taxon_guid(id: &str) -> String {
    // Pad the numeric portion to make a stable 8-4-4-4-12 hex form. This
    // is NOT a real RFC4122 GUID — readers treat the taxon GUID as an
    // opaque string keyed alongside the `id`.
    let digits: String = id.chars().filter(char::is_ascii_digit).collect();
    let padded = format!("{digits:0>32}");
    format!(
        "{}-{}-{}-{}-{}",
        &padded[0..8],
        &padded[8..12],
        &padded[12..16],
        &padded[16..20],
        &padded[20..32],
    )
}

/// Build one SARIF `result` from a finding.
fn finding_to_result(f: &Finding, rule_index: &BTreeMap<String, usize>) -> Value {
    let mut result = Map::new();
    result.insert("ruleId".into(), Value::String(f.rule_id.clone()));
    if let Some(idx) = rule_index.get(&f.rule_id) {
        result.insert("ruleIndex".into(), Value::Number((*idx).into()));
    }
    result.insert("guid".into(), Value::String(f.id.to_string()));
    result.insert(
        "level".into(),
        Value::String(severity_to_level(f.severity).into()),
    );
    result.insert(
        "message".into(),
        json!({ "text": if f.description.is_empty() { f.title.clone() } else { f.description.clone() } }),
    );

    // Locations from evidence URIs. Emit a `region.startLine` /
    // `region.startColumn` sub-object per SARIF §3.30.4 when the
    // evidence carries source-aware line/column (TOP5-#3 Phase 3);
    // legacy evidence with only a URI keeps the pre-Phase-3 shape.
    if !f.evidence_refs.is_empty() {
        let locations: Vec<Value> = f
            .evidence_refs
            .iter()
            .map(|ev| {
                let mut physical = Map::new();
                physical.insert("artifactLocation".into(), json!({ "uri": ev.uri }));
                if ev.line.is_some() || ev.column.is_some() {
                    let mut region = Map::new();
                    if let Some(l) = ev.line {
                        region.insert("startLine".into(), Value::Number(l.into()));
                    }
                    if let Some(c) = ev.column {
                        region.insert("startColumn".into(), Value::Number(c.into()));
                    }
                    physical.insert("region".into(), Value::Object(region));
                }
                json!({ "physicalLocation": Value::Object(physical) })
            })
            .collect();
        result.insert("locations".into(), Value::Array(locations));
    }

    // Properties bag — `security-severity` (GitHub convention), tags
    // (MITRE ATT&CK + compliance), confidence.
    let mut props = Map::new();
    if let Some(cvss) = &f.cvss {
        // GitHub Code Scanning reads `security-severity` as a numeric
        // string in `0..=10`.
        props.insert(
            "security-severity".into(),
            Value::String(format!("{:.1}", cvss.base_score)),
        );
        props.insert("cvss_v3_vector".into(), Value::String(cvss.vector.clone()));
        props.insert(
            "cvss_v3_rating".into(),
            Value::String(cvss.severity.as_str().into()),
        );
    }
    let mut tags: Vec<String> = Vec::new();
    for t in &f.mitre_attack {
        tags.push(t.tactic.clone());
        tags.push(t.technique.clone());
        if let Some(s) = &t.subtechnique {
            tags.push(s.clone());
        }
    }
    for c in &f.compliance.nist_800_53 {
        tags.push(format!("NIST-800-53:{}", c.as_str()));
    }
    for c in &f.compliance.iso_27001 {
        tags.push(format!("ISO-27001:{}", c.as_str()));
    }
    for c in &f.compliance.pci_dss {
        tags.push(format!("PCI-DSS:{}", c.as_str()));
    }
    for c in &f.compliance.soc2 {
        tags.push(format!("SOC2:{}", c.as_str()));
    }
    for c in &f.compliance.hipaa {
        tags.push(format!("HIPAA:{}", c.as_str()));
    }
    if !tags.is_empty() {
        props.insert(
            "tags".into(),
            Value::Array(tags.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(c) = f.confidence {
        // serde_json::Number can fail for non-finite; we already validated.
        if let Some(num) = serde_json::Number::from_f64(c) {
            props.insert("confidence".into(), Value::Number(num));
        }
    }
    if !props.is_empty() {
        result.insert("properties".into(), Value::Object(props));
    }
    Value::Object(result)
}

/// Map [`Severity`] to the SARIF `level` enum
/// (`none|note|warning|error`).
const fn severity_to_level(s: Severity) -> &'static str {
    match s {
        Severity::Info => "note",
        Severity::Low | Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::indexing_slicing
)]
mod tests {
    use time::OffsetDateTime;

    use super::*;
    use crate::entity::finding::Finding;
    use crate::value_object::compliance::{
        ComplianceTags, IsoControl, NistControl, PciRequirement,
    };
    use crate::value_object::cvss_v31::{CvssV31, CvssV31Rating};
    use crate::value_object::cwe::CweId;
    use crate::value_object::ids::{AssetId, TenantId};
    use crate::value_object::mitre_attack::MitreAttackTechnique;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn unenriched() -> Finding {
        Finding::new(
            TenantId::new(),
            AssetId::new(),
            "HDR.DUMMY",
            "Some title",
            "Some description",
            Severity::Low,
            now(),
        )
        .unwrap()
    }

    fn enriched_hsts_missing() -> Finding {
        Finding::new(
            TenantId::new(),
            AssetId::new(),
            "HDR.STRICT_TRANSPORT_SECURITY.MISSING",
            "Missing HSTS (Strict-Transport-Security)",
            "HTTPS response is missing the Strict-Transport-Security header; downgrade attacks possible.",
            Severity::High,
            now(),
        )
        .unwrap()
        .with_cvss(
            CvssV31::new(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                7.5,
                CvssV31Rating::High,
            )
            .unwrap(),
        )
        .with_cwe(vec![CweId::new(319).unwrap()])
        .with_mitre_attack(vec![
            MitreAttackTechnique::new("TA0009", "T1040", None).unwrap(),
        ])
        .with_compliance(ComplianceTags {
            nist_800_53: vec![NistControl::new("SC-8").unwrap()],
            iso_27001: vec![IsoControl::new("A.13.1.1").unwrap()],
            pci_dss: vec![PciRequirement::new("4.1").unwrap()],
            ..Default::default()
        })
        .with_confidence(0.95)
        .unwrap()
    }

    #[test]
    fn envelope_carries_version_2_1_0() {
        let v = findings_to_sarif(&[enriched_hsts_missing()], "sx-test", "0.0.0", None, None);
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].is_string());
        assert!(v["runs"].is_array());
    }

    #[test]
    fn rule_descriptor_is_emitted_once_per_distinct_rule_id() {
        let f1 = enriched_hsts_missing();
        let mut f2 = enriched_hsts_missing();
        f2.id = crate::value_object::ids::FindingId::new(); // different finding, same rule
        let v = findings_to_sarif(&[f1, f2], "sx-test", "0.0.0", None, None);
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "HDR.STRICT_TRANSPORT_SECURITY.MISSING");
    }

    #[test]
    fn cvss_base_score_maps_to_security_severity() {
        let v = findings_to_sarif(&[enriched_hsts_missing()], "sx-test", "0.0.0", None, None);
        let r = &v["runs"][0]["results"][0];
        assert_eq!(r["properties"]["security-severity"], "7.5");
        assert!(r["properties"]["cvss_v3_vector"]
            .as_str()
            .unwrap()
            .starts_with("CVSS:3.1/"));
    }

    #[test]
    fn cwe_appears_in_rule_relationships_and_taxonomy() {
        let v = findings_to_sarif(&[enriched_hsts_missing()], "sx-test", "0.0.0", None, None);
        let rule = &v["runs"][0]["tool"]["driver"]["rules"][0];
        let rels = rule["relationships"].as_array().unwrap();
        assert_eq!(rels[0]["target"]["id"], "CWE-319");
        assert_eq!(rels[0]["target"]["toolComponent"]["name"], "CWE",);

        let taxa = v["runs"][0]["taxonomies"][0]["taxa"].as_array().unwrap();
        assert!(taxa.iter().any(|t| t["id"] == "CWE-319"));
    }

    #[test]
    fn mitre_attack_and_compliance_appear_in_tags() {
        let v = findings_to_sarif(&[enriched_hsts_missing()], "sx-test", "0.0.0", None, None);
        let tags = v["runs"][0]["results"][0]["properties"]["tags"]
            .as_array()
            .unwrap();
        let tags: Vec<&str> = tags.iter().filter_map(Value::as_str).collect();
        assert!(tags.contains(&"TA0009"));
        assert!(tags.contains(&"T1040"));
        assert!(tags.contains(&"NIST-800-53:SC-8"));
        assert!(tags.contains(&"ISO-27001:A.13.1.1"));
        assert!(tags.contains(&"PCI-DSS:4.1"));
    }

    #[test]
    fn level_derived_from_severity() {
        let v = findings_to_sarif(&[enriched_hsts_missing()], "sx-test", "0.0.0", None, None);
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn unenriched_finding_still_serialises_cleanly() {
        let v = findings_to_sarif(&[unenriched()], "sx-test", "0.0.0", None, None);
        // Envelope keys still present.
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "HDR.DUMMY");
        assert_eq!(v["runs"][0]["results"][0]["level"], "warning");
        // No security-severity, no tags, no relationships.
        let r = &v["runs"][0]["results"][0];
        assert!(
            r.get("properties").is_none() || r["properties"].get("security-severity").is_none()
        );
        let rule = &v["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(rule.get("relationships").is_none());
        // No CWE taxonomy when no finding has CWE refs.
        assert!(v["runs"][0].get("taxonomies").is_none());
    }

    #[test]
    fn empty_input_yields_zero_results() {
        let v = findings_to_sarif(&[], "sx-test", "0.0.0", None, None);
        assert_eq!(v["version"], "2.1.0");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert!(rules.is_empty());
    }

    // ----- TOP5-#3 Phase 3: organization + downloadUri + region --------

    #[test]
    fn driver_organization_populates_when_supplied() {
        let v = findings_to_sarif(
            &[enriched_hsts_missing()],
            "sx-test",
            "0.0.0",
            Some("SentinelX"),
            None,
        );
        let driver = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["organization"], "SentinelX");
        assert!(
            driver.get("downloadUri").is_none(),
            "downloadUri omitted when caller supplies None",
        );
    }

    #[test]
    fn driver_organization_omitted_when_none() {
        let v = findings_to_sarif(&[enriched_hsts_missing()], "sx-test", "0.0.0", None, None);
        let driver = &v["runs"][0]["tool"]["driver"];
        assert!(
            driver.get("organization").is_none(),
            "organization key omitted when caller supplies None (legacy shape preserved)",
        );
    }

    #[test]
    fn driver_download_uri_populates_when_supplied() {
        let v = findings_to_sarif(
            &[enriched_hsts_missing()],
            "sx-test",
            "0.0.0",
            Some("SentinelX"),
            Some("https://releases.sentinelx.example/latest.zip"),
        );
        let driver = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["organization"], "SentinelX");
        assert_eq!(
            driver["downloadUri"],
            "https://releases.sentinelx.example/latest.zip",
        );
    }

    #[test]
    fn driver_download_uri_omitted_when_none() {
        let v = findings_to_sarif(
            &[enriched_hsts_missing()],
            "sx-test",
            "0.0.0",
            Some("SentinelX"),
            None,
        );
        let driver = &v["runs"][0]["tool"]["driver"];
        assert!(driver.get("downloadUri").is_none());
    }

    #[test]
    fn region_start_line_column_emitted_when_evidence_carries_them() {
        use crate::entity::finding::EvidenceRef;
        let mut f = unenriched();
        let ev = EvidenceRef::new("s3://scans/config.yaml", None, None)
            .unwrap()
            .with_region(42, 7)
            .unwrap();
        f.add_evidence(ev);
        let v = findings_to_sarif(&[f], "sx-test", "0.0.0", None, None);
        let loc = &v["runs"][0]["results"][0]["locations"][0];
        assert_eq!(
            loc["physicalLocation"]["artifactLocation"]["uri"],
            "s3://scans/config.yaml"
        );
        assert_eq!(loc["physicalLocation"]["region"]["startLine"], 42);
        assert_eq!(loc["physicalLocation"]["region"]["startColumn"], 7);
    }

    #[test]
    fn region_omitted_when_evidence_has_no_line_or_column() {
        use crate::entity::finding::EvidenceRef;
        let mut f = unenriched();
        let ev = EvidenceRef::new("s3://scans/audit.log", None, None).unwrap();
        f.add_evidence(ev);
        let v = findings_to_sarif(&[f], "sx-test", "0.0.0", None, None);
        let loc = &v["runs"][0]["results"][0]["locations"][0];
        assert_eq!(
            loc["physicalLocation"]["artifactLocation"]["uri"],
            "s3://scans/audit.log"
        );
        assert!(
            loc["physicalLocation"].get("region").is_none(),
            "region omitted when neither line nor column set — legacy shape preserved",
        );
    }
}
