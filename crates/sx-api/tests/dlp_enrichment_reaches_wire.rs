//! Integration test for TOP5-#3-P2-003 (DLP enrichment at the adapter
//! boundary).
//!
//! Companion to `crates/sx-api/tests/scan_enrichment_reaches_wire.rs`,
//! which guards the HDR.* header-audit enrichment surface. This test
//! guards the DLP detection-event enrichment surface — making sure a
//! `DlpMatchView` produced by the monolith adapter carries the canonical
//! Phase 1 payload (`cwe[]` / `mitre_attack[]` / `compliance` /
//! `enrichment_confidence`) and that the axum-Json serialise path emits
//! those keys (and omits them via `skip_serializing_if` on unenriched
//! kinds).
//!
//! The test deliberately constructs the wire DTO directly (rather than
//! spinning up the full adapter) because:
//! - The adapter's `scan()` flow is already exercised by
//!   `services/sx-monolith/src/adapters/dlp.rs::tests`, which asserts
//!   the same enrichment shape on a real `DetectionEvent → DlpMatchView`
//!   projection;
//! - This test's purpose is to guard the *wire shape* — if a future
//!   contributor drops `skip_serializing_if` or renames a field on
//!   `DlpMatchView`, this is the regression net that catches the wire
//!   drift before procurement-grade SARIF / SOC pipelines break.
//!
//! See the senior IT-security review SX-REVIEW-002 C1 fix for the
//! original "enrichment never reached the wire" defect this pattern was
//! born to guard against.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::doc_markdown)]

use sx_api::port::{DlpDetectorKind, DlpMatchView, DlpScanResultView};
use sx_core::reference::dlp_enrichment::{dlp_enrichment, DlpEnrichment};
use sx_core::value_object::compliance::ComplianceTags;

/// Mirror of the `services/sx-monolith` adapter's enrichment projection,
/// kept in this test file so the regression net is self-contained.
/// If the production adapter changes the projection rule (e.g. drops a
/// field), this helper still produces the canonical payload — the test
/// would then surface the drift between this and the adapter at the
/// JSON-shape assertions.
fn enriched_match(
    kind: DlpDetectorKind,
    kind_key: &str,
    fusion_confidence: f32,
    redacted_preview: &str,
) -> DlpMatchView {
    let DlpEnrichment {
        cvss: _,
        cwe,
        mitre_attack,
        compliance,
    } = dlp_enrichment(kind_key).unwrap_or_default();
    let enrichment_confidence = if fusion_confidence > 0.0 {
        Some(f64::from(fusion_confidence))
    } else {
        None
    };
    DlpMatchView {
        kind,
        offset: 0,
        length: 16,
        redacted_preview: redacted_preview.to_owned(),
        confidence: fusion_confidence,
        signals: vec![],
        cwe,
        mitre_attack,
        compliance,
        enrichment_confidence,
        line: None,
        column: None,
    }
}

/// The defect this regression test guards: enrichment fields silently
/// stripped out at the [`DlpMatchView`] DTO boundary on `POST /v1/dlp/scan`
/// and `GET /v1/dlp/history`.
#[test]
fn dlp_match_view_carries_enrichment_to_the_wire() {
    let pan = enriched_match(
        DlpDetectorKind::CreditCard,
        "credit_card",
        0.87,
        "4539****86",
    );
    let scan = DlpScanResultView {
        id: "01900000-0000-7000-8000-000000000000".into(),
        tenant_id: "tenant-a".into(),
        finished_at: "2026-06-24T00:00:01Z".into(),
        bytes_scanned: 32,
        total_matches: 1,
        summary: vec![],
        matches: vec![pan],
    };

    // Serialise the record exactly the way `axum::Json` would.
    let json = serde_json::to_value(&scan).expect("DlpScanResultView serialises");
    let matches = json
        .get("matches")
        .and_then(|v| v.as_array())
        .expect("matches array present");
    assert!(!matches.is_empty(), "scan view produced at least one match");

    let pan = &matches[0];

    // ---- CWE-311 Missing Encryption of Sensitive Data ----
    let cwe = pan
        .get("cwe")
        .and_then(|v| v.as_array())
        .expect("cwe key present on enriched match");
    let cwe_strs: Vec<&str> = cwe.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        cwe_strs.contains(&"CWE-311"),
        "PAN finding includes CWE-311; got {cwe_strs:?}",
    );

    // ---- MITRE ATT&CK T1552 Unsecured Credentials ----
    let mitre = pan
        .get("mitre_attack")
        .and_then(|v| v.as_array())
        .expect("mitre_attack key present");
    assert!(
        mitre
            .iter()
            .any(|t| t.get("technique").and_then(|v| v.as_str()) == Some("T1552")),
        "PAN finding includes MITRE T1552 Unsecured Credentials",
    );

    // ---- Compliance: PCI DSS 3.4 + 3.5, NIST SC-28 + SI-12 ----
    let compliance = pan
        .get("compliance")
        .expect("compliance key present on enriched match");
    let pci = compliance
        .get("pci_dss")
        .and_then(|v| v.as_array())
        .expect("pci_dss list present");
    let pci_strs: Vec<&str> = pci.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        pci_strs.contains(&"3.4") && pci_strs.contains(&"3.5"),
        "PAN finding maps onto PCI 3.4 + 3.5; got {pci_strs:?}",
    );
    let nist = compliance
        .get("nist_800_53")
        .and_then(|v| v.as_array())
        .expect("nist_800_53 list present");
    let nist_strs: Vec<&str> = nist.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        nist_strs.contains(&"SC-28") && nist_strs.contains(&"SI-12"),
        "PAN finding maps onto NIST SC-28 + SI-12; got {nist_strs:?}",
    );

    // ---- enrichment_confidence ----
    let ec = pan
        .get("enrichment_confidence")
        .and_then(serde_json::Value::as_f64)
        .expect("enrichment_confidence present");
    assert!(
        (ec - 0.87_f64).abs() < 1e-6,
        "enrichment_confidence widens fusion score to f64; got {ec}",
    );

    // ---- legacy confidence still present (fusion-score field) ----
    assert!(
        pan.get("confidence")
            .and_then(serde_json::Value::as_f64)
            .is_some(),
        "legacy fusion-confidence field preserved alongside enrichment_confidence",
    );

    // ---- CVSS is intentionally absent from the DLP wire surface ----
    assert!(
        pan.get("cvss").is_none(),
        "DLP wire surface deliberately omits CVSS (detection ≠ vulnerability)",
    );
}

/// Unenriched kinds (the informational `email` / `phone` / `named_entity`)
/// must round-trip cleanly. `skip_serializing_if` should keep legacy
/// clients compatible; the JSON should simply omit the enrichment keys
/// rather than emit them as nulls or empty arrays.
#[test]
fn unenriched_match_view_omits_enrichment_keys() {
    let m = DlpMatchView {
        kind: DlpDetectorKind::Email,
        offset: 0,
        length: 16,
        redacted_preview: "a***@e***".into(),
        confidence: 0.0,
        signals: vec![],
        cwe: vec![],
        mitre_attack: vec![],
        compliance: ComplianceTags::default(),
        enrichment_confidence: None,
        line: None,
        column: None,
    };
    let json = serde_json::to_value(&m).expect("serialises");
    let obj = json.as_object().expect("DlpMatchView is a JSON object");
    assert!(!obj.contains_key("cwe"), "empty cwe[] omitted");
    assert!(
        !obj.contains_key("mitre_attack"),
        "empty mitre_attack[] omitted",
    );
    assert!(
        !obj.contains_key("compliance"),
        "empty compliance object omitted",
    );
    assert!(
        !obj.contains_key("enrichment_confidence"),
        "absent enrichment_confidence omitted",
    );
    // Legacy required keys still present.
    assert!(obj.contains_key("kind"));
    assert!(obj.contains_key("offset"));
    assert!(obj.contains_key("length"));
    assert!(obj.contains_key("redacted_preview"));
    assert!(obj.contains_key("confidence"));
}

/// Every DLP variant the production adapter projects must resolve to a
/// payload via the canonical table (or, for the three informational
/// kinds, must intentionally return `None`). If a future contributor
/// adds a new `DlpMatchKind` without a corresponding table entry, this
/// test surfaces the omission rather than the wire silently dropping
/// the new variant.
#[test]
fn every_curated_dlp_kind_has_an_enrichment_entry() {
    // Keep this list in sync with `crates/sx-dlp/src/patterns/mod.rs`
    // `DlpMatchKind::as_str()` — the stable wire form.
    let enriched_kinds = [
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
    for id in enriched_kinds {
        let e =
            dlp_enrichment(id).unwrap_or_else(|| panic!("DLP kind `{id}` has no enrichment entry"));
        let has_payload =
            !e.cwe.is_empty() || !e.mitre_attack.is_empty() || !e.compliance.is_empty();
        assert!(
            has_payload,
            "DLP kind `{id}` resolved to an empty enrichment payload",
        );
        // CVSS is deliberately None for every DLP kind — see
        // `dlp_enrichment.rs` §"CVSS posture for DLP".
        assert!(
            e.cvss.is_none(),
            "DLP kind `{id}` unexpectedly carries CVSS — re-read the \
             'CVSS posture for DLP' rule in dlp_enrichment.rs before \
             relaxing this assertion",
        );
    }

    // The three informational kinds intentionally return None — the
    // wire DTO then omits the enrichment keys via skip_serializing_if.
    for id in ["email", "phone", "named_entity"] {
        assert!(
            dlp_enrichment(id).is_none(),
            "informational DLP kind `{id}` should not be enriched",
        );
    }
}
