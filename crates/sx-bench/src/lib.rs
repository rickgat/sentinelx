//! Detection-accuracy benchmark harness (SELL-P0-07).
//!
//! Measures how accurately the platform's scanners detect what they should.
//! A team records a scan's findings and a hand-labelled ground-truth
//! dataset; this harness matches the two and reports precision, recall and
//! F1 — plus the exact false-positive and false-negative lists so a
//! regression is actionable, not just a number.
//!
//! The harness is deliberately transport-agnostic: it scores
//! already-collected [`FindingLabel`]s, so it runs fully offline in CI and
//! does not depend on any scanner, network target, or database. Findings
//! are matched on the normalised `(asset, check_id)` pair.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error loading or validating a dataset / run-results document.
#[derive(Debug, Error)]
pub enum BenchError {
    /// The JSON could not be parsed into the expected shape.
    #[error("json parse error: {0}")]
    Json(String),
    /// The dataset was structurally invalid (e.g. empty / duplicate ids).
    #[error("invalid dataset: {0}")]
    Invalid(String),
}

/// One labelled finding — the unit matched between expected and actual.
///
/// Identity is the normalised `(asset, check_id)` pair; `severity` is
/// carried for reporting only and never affects matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingLabel {
    /// Asset the finding is about (host, URL, resource id, …).
    pub asset: String,
    /// Stable check identifier (e.g. `HDR.HSTS.MISSING`, `net.risky_port.redis`).
    pub check_id: String,
    /// Optional severity tag, for reporting only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

impl FindingLabel {
    /// Normalised match key: trimmed, case-folded `(asset, check_id)`.
    #[must_use]
    fn key(&self) -> (String, String) {
        (
            self.asset.trim().to_ascii_lowercase(),
            self.check_id.trim().to_ascii_lowercase(),
        )
    }
}

/// One labelled case: a target and the findings a correct scan must produce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    /// Unique case id within the dataset.
    pub id: String,
    /// Human-readable target description (not used for matching).
    #[serde(default)]
    pub target: String,
    /// The ground-truth findings expected for this case.
    #[serde(default)]
    pub expected: Vec<FindingLabel>,
}

/// A labelled ground-truth dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// Dataset name (appears in the report).
    pub name: String,
    /// The labelled cases.
    pub cases: Vec<Case>,
}

impl Dataset {
    /// Parse a dataset from JSON.
    ///
    /// # Errors
    /// Returns [`BenchError::Json`] on malformed input.
    pub fn from_json(s: &str) -> Result<Self, BenchError> {
        serde_json::from_str(s).map_err(|e| BenchError::Json(e.to_string()))
    }

    /// Validate structural invariants: non-empty, unique, non-blank case ids.
    ///
    /// # Errors
    /// Returns [`BenchError::Invalid`] when a case id is blank or duplicated.
    pub fn validate(&self) -> Result<(), BenchError> {
        let mut seen = std::collections::BTreeSet::new();
        for case in &self.cases {
            if case.id.trim().is_empty() {
                return Err(BenchError::Invalid("a case has a blank id".to_owned()));
            }
            if !seen.insert(case.id.as_str()) {
                return Err(BenchError::Invalid(format!(
                    "duplicate case id '{}'",
                    case.id
                )));
            }
        }
        Ok(())
    }
}

/// The findings a scan actually produced, keyed by case id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunResults {
    /// case id → findings observed for that case.
    pub cases: BTreeMap<String, Vec<FindingLabel>>,
}

impl RunResults {
    /// Parse run results from JSON.
    ///
    /// # Errors
    /// Returns [`BenchError::Json`] on malformed input.
    pub fn from_json(s: &str) -> Result<Self, BenchError> {
        serde_json::from_str(s).map_err(|e| BenchError::Json(e.to_string()))
    }
}

/// Confusion counts for detection (there is no enumerable true-negative
/// space for findings, so only TP / FP / FN are tracked).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Expected findings that were produced.
    pub true_positives: u64,
    /// Produced findings that were not expected (noise).
    pub false_positives: u64,
    /// Expected findings that were missed.
    pub false_negatives: u64,
}

/// Convert a count to `f64` without tripping the precision-loss lint;
/// detection counts never approach `u32::MAX` in practice.
fn as_f64(v: u64) -> f64 {
    f64::from(u32::try_from(v).unwrap_or(u32::MAX))
}

impl Counts {
    const fn add(&mut self, other: Self) {
        self.true_positives += other.true_positives;
        self.false_positives += other.false_positives;
        self.false_negatives += other.false_negatives;
    }

    /// Precision = TP / (TP + FP); `0.0` when nothing was produced.
    #[must_use]
    pub fn precision(&self) -> f64 {
        let denom = as_f64(self.true_positives + self.false_positives);
        if denom > 0.0 {
            as_f64(self.true_positives) / denom
        } else {
            0.0
        }
    }

    /// Recall = TP / (TP + FN); `0.0` when nothing was expected.
    #[must_use]
    pub fn recall(&self) -> f64 {
        let denom = as_f64(self.true_positives + self.false_negatives);
        if denom > 0.0 {
            as_f64(self.true_positives) / denom
        } else {
            0.0
        }
    }

    /// Harmonic mean of precision and recall; `0.0` when either is `0.0`.
    #[must_use]
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p > 0.0 && r > 0.0 {
            2.0 * p * r / (p + r)
        } else {
            0.0
        }
    }
}

/// Per-case scoring result, including the actionable FP / FN lists.
#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    /// The case id scored.
    pub case_id: String,
    /// Confusion counts for this case.
    pub counts: Counts,
    /// Findings produced but not expected.
    pub false_positives: Vec<FindingLabel>,
    /// Findings expected but not produced.
    pub false_negatives: Vec<FindingLabel>,
}

/// Aggregate accuracy report over a whole dataset.
#[derive(Debug, Clone, Serialize)]
pub struct AccuracyReport {
    /// Dataset name.
    pub dataset: String,
    /// Summed confusion counts across every case.
    pub total: Counts,
    /// Overall precision.
    pub precision: f64,
    /// Overall recall.
    pub recall: f64,
    /// Overall F1.
    pub f1: f64,
    /// Per-case breakdown.
    pub cases: Vec<CaseResult>,
    /// Dataset case ids with no corresponding run results (treated as all
    /// expected findings missed, so they count against recall).
    pub missing_cases: Vec<String>,
}

/// Score a run against a labelled dataset.
///
/// Findings match on the normalised `(asset, check_id)` pair. A dataset
/// case with no run-results entry is scored as every expected finding
/// missed (a full set of false negatives) and recorded in
/// [`AccuracyReport::missing_cases`], so a scan that simply did not run is
/// never silently rewarded.
#[must_use]
pub fn evaluate(dataset: &Dataset, run: &RunResults) -> AccuracyReport {
    let mut cases = Vec::with_capacity(dataset.cases.len());
    let mut total = Counts::default();
    let mut missing = Vec::new();

    for case in &dataset.cases {
        let expected: BTreeMap<(String, String), FindingLabel> =
            case.expected.iter().map(|f| (f.key(), f.clone())).collect();

        let actual_findings = run.cases.get(&case.id).map_or_else(
            || {
                missing.push(case.id.clone());
                Vec::new()
            },
            Clone::clone,
        );
        let actual: BTreeMap<(String, String), FindingLabel> = actual_findings
            .iter()
            .map(|f| (f.key(), f.clone()))
            .collect();

        let mut counts = Counts::default();
        let mut false_positives = Vec::new();
        let mut false_negatives = Vec::new();

        for (k, v) in &actual {
            if expected.contains_key(k) {
                counts.true_positives += 1;
            } else {
                counts.false_positives += 1;
                false_positives.push(v.clone());
            }
        }
        for (k, v) in &expected {
            if !actual.contains_key(k) {
                counts.false_negatives += 1;
                false_negatives.push(v.clone());
            }
        }

        total.add(counts);
        cases.push(CaseResult {
            case_id: case.id.clone(),
            counts,
            false_positives,
            false_negatives,
        });
    }

    AccuracyReport {
        dataset: dataset.name.clone(),
        total,
        precision: total.precision(),
        recall: total.recall(),
        f1: total.f1(),
        cases,
        missing_cases: missing,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::float_cmp)]
mod tests {
    use super::*;

    const SAMPLE_DATASET: &str = include_str!("../fixtures/sample_dataset.json");
    const SAMPLE_FINDINGS: &str = include_str!("../fixtures/sample_findings.json");

    fn label(asset: &str, check: &str) -> FindingLabel {
        FindingLabel {
            asset: asset.to_owned(),
            check_id: check.to_owned(),
            severity: None,
        }
    }

    #[test]
    fn counts_metrics_are_correct() {
        let c = Counts {
            true_positives: 2,
            false_positives: 1,
            false_negatives: 1,
        };
        assert!((c.precision() - 2.0 / 3.0).abs() < 1e-9);
        assert!((c.recall() - 2.0 / 3.0).abs() < 1e-9);
        assert!((c.f1() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn zero_denominator_metrics_are_zero_not_nan() {
        let empty = Counts::default();
        assert_eq!(empty.precision(), 0.0);
        assert_eq!(empty.recall(), 0.0);
        assert_eq!(empty.f1(), 0.0);
    }

    #[test]
    fn evaluate_computes_tp_fp_fn_and_lists() {
        let dataset = Dataset {
            name: "unit".to_owned(),
            cases: vec![Case {
                id: "web-1".to_owned(),
                target: "https://app.example".to_owned(),
                expected: vec![
                    label("app.example", "HDR.HSTS.MISSING"),
                    label("app.example", "TLS.WEAK_PROTOCOL"),
                ],
            }],
        };
        let mut run = RunResults::default();
        run.cases.insert(
            "web-1".to_owned(),
            vec![
                // TP (case-insensitive match), FP (unexpected CSP).
                label("app.example", "hdr.hsts.missing"),
                label("app.example", "HDR.CSP.MISSING"),
            ],
        );

        let report = evaluate(&dataset, &run);
        assert_eq!(report.total.true_positives, 1);
        assert_eq!(report.total.false_positives, 1);
        assert_eq!(report.total.false_negatives, 1);
        let case = &report.cases[0];
        assert_eq!(case.false_positives[0].check_id, "HDR.CSP.MISSING");
        assert_eq!(case.false_negatives[0].check_id, "TLS.WEAK_PROTOCOL");
    }

    #[test]
    fn missing_run_results_count_as_false_negatives() {
        let dataset = Dataset {
            name: "unit".to_owned(),
            cases: vec![Case {
                id: "net-1".to_owned(),
                target: "10.0.0.5".to_owned(),
                expected: vec![label("10.0.0.5", "net.risky_port.redis")],
            }],
        };
        let report = evaluate(&dataset, &RunResults::default());
        assert_eq!(report.total.false_negatives, 1);
        assert_eq!(report.total.true_positives, 0);
        assert_eq!(report.missing_cases, vec!["net-1".to_owned()]);
        assert_eq!(report.recall, 0.0);
    }

    #[test]
    fn fixtures_load_and_score_to_known_metrics() {
        let dataset = Dataset::from_json(SAMPLE_DATASET).unwrap();
        dataset.validate().unwrap();
        let run = RunResults::from_json(SAMPLE_FINDINGS).unwrap();
        let report = evaluate(&dataset, &run);
        // Ground truth of the shipped fixture: TP=2, FP=1, FN=1.
        assert_eq!(report.total.true_positives, 2);
        assert_eq!(report.total.false_positives, 1);
        assert_eq!(report.total.false_negatives, 1);
        assert!((report.precision - 2.0 / 3.0).abs() < 1e-9);
        assert!((report.recall - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn duplicate_case_id_is_invalid() {
        let dataset = Dataset {
            name: "dup".to_owned(),
            cases: vec![
                Case {
                    id: "a".to_owned(),
                    target: String::new(),
                    expected: vec![],
                },
                Case {
                    id: "a".to_owned(),
                    target: String::new(),
                    expected: vec![],
                },
            ],
        };
        assert!(dataset.validate().is_err());
    }
}
