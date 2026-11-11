# sx-bench — detection-accuracy benchmark harness

Measures how accurately SentinelX's scanners detect what they *should*, so
accuracy can be tracked over time and regressions caught in CI. It scores a
recorded scan against a hand-labelled ground-truth dataset and reports
**precision**, **recall** and **F1** — plus the exact **false-positive** and
**false-negative** finding lists so a drop is actionable.

The harness is offline and transport-agnostic: it compares already-collected
findings, so it never needs a live target, scanner, or database.

## Matching

A finding is identified by its normalised `(asset, check_id)` pair
(trimmed, case-folded). `severity` is carried for reporting only and does
not affect matching. Per case:

- **TP** — an expected finding that was produced
- **FP** — a produced finding that was not expected (noise)
- **FN** — an expected finding that was missed

A dataset case with **no** run-results entry is scored as every expected
finding missed, and listed under `missing_cases`, so a scan that simply did
not run is never silently rewarded.

## Inputs

**Ground-truth dataset** (`fixtures/sample_dataset.json`):

```json
{
  "name": "my-groundtruth-v1",
  "cases": [
    { "id": "web-1", "target": "https://app.example",
      "expected": [
        { "asset": "app.example", "check_id": "HDR.HSTS.MISSING", "severity": "medium" }
      ] }
  ]
}
```

**Recorded run results** (`fixtures/sample_findings.json`) — the findings a
scan actually produced, keyed by case id:

```json
{ "cases": { "web-1": [ { "asset": "app.example", "check_id": "HDR.HSTS.MISSING" } ] } }
```

## Usage

```rust
use sx_bench::{Dataset, RunResults, evaluate};

let dataset = Dataset::from_json(&std::fs::read_to_string("groundtruth.json")?)?;
dataset.validate()?;
let run = RunResults::from_json(&std::fs::read_to_string("findings.json")?)?;

let report = evaluate(&dataset, &run);
println!("precision={:.3} recall={:.3} f1={:.3}", report.precision, report.recall, report.f1);
for case in &report.cases {
    for fp in &case.false_positives { eprintln!("FP {}: {}", case.case_id, fp.check_id); }
    for fn_ in &case.false_negatives { eprintln!("FN {}: {}", case.case_id, fn_.check_id); }
}
```

`AccuracyReport` is `Serialize`, so it can be emitted as JSON for a CI gate
(e.g. fail the build when `report.recall` drops below an agreed threshold).
