//! `(asset_id, check_id)` deduplication.
//!
//! Scanner exports routinely contain repeated detections — multiple
//! credentialed plugin runs or repeated scan sweeps. The ingest pipeline
//! reduces them to a unique set keyed by `(asset_id, check_id)`. When two
//! findings collide the highest-severity record is kept; ties keep the
//! first observed record (parse order).

use std::collections::HashMap;

use crate::model::{NormalizedFinding, Severity};

/// Dedup outcome — the unique set plus the count dropped.
#[derive(Debug, Clone, PartialEq)]
pub struct DedupReport {
    /// Deduplicated finding set.
    pub findings: Vec<NormalizedFinding>,
    /// Number of duplicate inputs dropped.
    pub dropped: usize,
}

const fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Deduplicate `findings` keyed by `(asset_id, check_id)`.
///
/// Iteration order of the input is preserved for first-write-wins on ties.
#[must_use]
pub fn deduplicate(findings: Vec<NormalizedFinding>) -> DedupReport {
    let mut index: HashMap<(String, String), usize> = HashMap::with_capacity(findings.len());
    let mut out: Vec<NormalizedFinding> = Vec::with_capacity(findings.len());
    let mut dropped = 0_usize;

    for f in findings {
        let key = (f.asset_id.clone(), f.check_id.clone());
        if let Some(&existing) = index.get(&key) {
            // Compare severities; replace only on strict-higher severity.
            let current = out.get(existing);
            let replace = match current {
                Some(cur) => severity_rank(f.severity) > severity_rank(cur.severity),
                None => false,
            };
            if replace {
                if let Some(slot) = out.get_mut(existing) {
                    *slot = f;
                }
            }
            dropped += 1;
        } else {
            index.insert(key, out.len());
            out.push(f);
        }
    }

    DedupReport {
        findings: out,
        dropped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceFormat;

    fn finding(asset: &str, check: &str, severity: Severity) -> NormalizedFinding {
        NormalizedFinding {
            check_id: check.into(),
            external_id: check.into(),
            asset_id: asset.into(),
            severity,
            title: format!("{check} on {asset}"),
            description: "x".into(),
            cve: None,
            cvss_v3: None,
            remediation: None,
            source: SourceFormat::Nessus,
        }
    }

    #[test]
    fn deduplicates_exact_collisions() {
        let input = vec![
            finding("10.0.0.1", "NESSUS.1", Severity::Medium),
            finding("10.0.0.1", "NESSUS.1", Severity::Medium),
            finding("10.0.0.1", "NESSUS.1", Severity::Medium),
        ];
        let out = deduplicate(input);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.dropped, 2);
    }

    #[test]
    fn keeps_highest_severity_on_collision() {
        let input = vec![
            finding("10.0.0.1", "NESSUS.1", Severity::Low),
            finding("10.0.0.1", "NESSUS.1", Severity::Critical),
            finding("10.0.0.1", "NESSUS.1", Severity::Medium),
        ];
        let out = deduplicate(input);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.dropped, 2);
        assert_eq!(out.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn distinct_assets_are_kept() {
        let input = vec![
            finding("10.0.0.1", "NESSUS.1", Severity::Medium),
            finding("10.0.0.2", "NESSUS.1", Severity::Medium),
            finding("10.0.0.3", "NESSUS.1", Severity::Medium),
        ];
        let out = deduplicate(input);
        assert_eq!(out.findings.len(), 3);
        assert_eq!(out.dropped, 0);
    }

    #[test]
    fn distinct_checks_on_one_asset_are_kept() {
        let input = vec![
            finding("10.0.0.1", "NESSUS.1", Severity::Medium),
            finding("10.0.0.1", "NESSUS.2", Severity::Medium),
        ];
        let out = deduplicate(input);
        assert_eq!(out.findings.len(), 2);
    }

    #[test]
    fn empty_input_returns_empty_report() {
        let out = deduplicate(Vec::new());
        assert_eq!(out.findings.len(), 0);
        assert_eq!(out.dropped, 0);
    }

    #[test]
    fn first_wins_on_tie() {
        let mut a = finding("10.0.0.1", "NESSUS.1", Severity::Medium);
        a.title = "first".into();
        let mut b = finding("10.0.0.1", "NESSUS.1", Severity::Medium);
        b.title = "second".into();
        let out = deduplicate(vec![a, b]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].title, "first");
    }
}
