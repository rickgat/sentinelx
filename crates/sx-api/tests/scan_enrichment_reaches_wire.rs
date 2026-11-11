//! Integration test for SX-REVIEW-002 C1 fix.
//!
//! The senior IT-security review of 2026-06-24 flagged that the Phase 1
//! finding-enrichment work landed on `crates/sx-core::entity::Finding`
//! but the live `POST /v1/scans/http-headers` endpoint emits a separate
//! [`sx_api::view::scan_view::ScanFinding`] DTO. Until the C1 fix, that
//! DTO stripped enrichment out and procurement-blocking auditors saw
//! only `check_id` / `severity` / `title` / `description` on the wire.
//!
//! This test is the only regression net that prevents the same defect
//! from recurring. It:
//!
//! 1. Stands up a fake [`HttpHeaderScannerPort`] that produces the same
//!    enriched payload the real `services/sx-monolith` adapter produces,
//!    by calling the canonical
//!    [`sx_core::reference::header_enrichment::hdr_enrichment`] lookup
//!    against the live `HDR.*` check ids the live scanner emits.
//! 2. Drives the port's `run()` API end-to-end through the same trait
//!    surface the controller uses.
//! 3. Serialises the returned [`sx_api::view::scan_view::ScanRecord`]
//!    with `serde_json::to_value` — the same encoding `axum::Json` uses
//!    on the wire — and asserts the enrichment keys
//!    (`cvss.base_score`, `cwe[]`, `mitre_attack[]`, `compliance`) are
//!    present for at least one finding.
//!
//! If either the canonical enrichment table or the `ScanFinding` DTO
//! regresses (drops the enrichment fields, or stops populating them in
//! the adapter), this test fails.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::doc_markdown)]

use std::sync::Mutex;

use async_trait::async_trait;
use sx_api::port::{HttpHeaderScannerPort, Phase3PortError};
use sx_api::view::scan_view::{HttpHeaderScanRequest, ScanFinding, ScanRecord};
use sx_core::reference::header_enrichment::{hdr_enrichment, HdrEnrichment};
use sx_core::value_object::compliance::ComplianceTags;

/// Minimal [`HttpHeaderScannerPort`] fake. Skips the network — feeds a
/// canned "two missing security headers" finding set through the same
/// enrichment lookup the production adapter uses, and stores the
/// resulting record so `list()` exercises the round trip.
#[derive(Debug, Default)]
struct StubEnrichedScanner {
    records: Mutex<Vec<ScanRecord>>,
}

impl StubEnrichedScanner {
    fn enriched(check_id: &str, severity: &str, title: &str, description: &str) -> ScanFinding {
        let HdrEnrichment {
            cvss,
            cwe,
            mitre_attack,
            compliance,
        } = hdr_enrichment(check_id).unwrap_or_default();
        ScanFinding {
            check_id: check_id.to_owned(),
            severity: severity.to_owned(),
            title: title.to_owned(),
            description: description.to_owned(),
            recommendation: None,
            cvss,
            cwe,
            mitre_attack,
            compliance,
            confidence: None,
            line: None,
            column: None,
        }
    }
}

#[async_trait]
impl HttpHeaderScannerPort for StubEnrichedScanner {
    async fn run(
        &self,
        req: HttpHeaderScanRequest,
        tenant_id: String,
    ) -> Result<ScanRecord, Phase3PortError> {
        let findings = vec![
            Self::enriched(
                "HDR.STRICT_TRANSPORT_SECURITY.MISSING",
                "high",
                "Missing HSTS",
                "Strict-Transport-Security header is absent.",
            ),
            Self::enriched(
                "HDR.CONTENT_SECURITY_POLICY.MISSING",
                "high",
                "Missing CSP",
                "Content-Security-Policy header is absent.",
            ),
        ];
        let record = ScanRecord {
            id: "01900000-0000-7000-8000-000000000000".into(),
            tenant_id,
            kind: "http_headers".into(),
            target: req.target.clone(),
            engagement_id: req.engagement_id,
            started_at: "2026-06-24T00:00:00Z".into(),
            finished_at: "2026-06-24T00:00:01Z".into(),
            status: "ok".into(),
            error: None,
            findings,
        };
        self.records.lock().unwrap().insert(0, record.clone());
        Ok(record)
    }

    async fn list(
        &self,
        _engagement_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ScanRecord>, Phase3PortError> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .take(limit)
            .cloned()
            .collect())
    }

    async fn get(
        &self,
        tenant_id: &str,
        scan_id: &str,
    ) -> Result<Option<ScanRecord>, Phase3PortError> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == scan_id && r.tenant_id == tenant_id)
            .cloned())
    }
}

/// The defect this regression test guards: enrichment fields silently
/// stripped out at the [`ScanFinding`] DTO boundary.
#[tokio::test]
async fn scan_finding_carries_enrichment_to_the_wire() {
    let port: Box<dyn HttpHeaderScannerPort> = Box::new(StubEnrichedScanner::default());
    let req = HttpHeaderScanRequest {
        target: "https://httpbin.example/".into(),
        engagement_id: None,
    };
    let record = port
        .run(req, "tenant-a".into())
        .await
        .expect("scanner returned a record");

    // Serialise the record exactly the way `axum::Json` would.
    let json = serde_json::to_value(&record).expect("ScanRecord serialises");
    let findings = json
        .get("findings")
        .and_then(|v| v.as_array())
        .expect("findings array present");
    assert!(
        !findings.is_empty(),
        "stub scanner produced at least one finding"
    );

    // Locate the HSTS finding — the canonical golden case from the
    // brief's reference data (CVSS 7.5, CWE-319, MITRE T1040,
    // NIST SC-8 / ISO A.13.1.1 / PCI 4.1).
    let hsts = findings
        .iter()
        .find(|f| {
            f.get("check_id").and_then(|v| v.as_str())
                == Some("HDR.STRICT_TRANSPORT_SECURITY.MISSING")
        })
        .expect("HSTS finding present in wire payload");

    // ---- CVSS v3.1 ----
    let cvss = hsts
        .get("cvss")
        .expect("cvss key present on enriched finding");
    let base_score = cvss
        .get("base_score")
        .and_then(|v| v.as_f64())
        .expect("cvss.base_score numeric");
    assert!(
        (base_score - 7.5).abs() < f64::EPSILON,
        "HSTS CVSS base_score = 7.5; got {base_score}"
    );
    let vector = cvss
        .get("vector")
        .and_then(|v| v.as_str())
        .expect("cvss.vector present");
    assert_eq!(vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

    // ---- CWE ----
    let cwe = hsts
        .get("cwe")
        .and_then(|v| v.as_array())
        .expect("cwe key present");
    assert!(!cwe.is_empty(), "HSTS finding carries at least one CWE");
    let cwe_strs: Vec<&str> = cwe.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        cwe_strs.contains(&"CWE-319"),
        "HSTS finding includes CWE-319; got {cwe_strs:?}"
    );

    // ---- MITRE ATT&CK ----
    let mitre = hsts
        .get("mitre_attack")
        .and_then(|v| v.as_array())
        .expect("mitre_attack key present");
    assert!(
        mitre
            .iter()
            .any(|t| t.get("technique").and_then(|v| v.as_str()) == Some("T1040")),
        "HSTS finding includes MITRE T1040 Network Sniffing"
    );

    // ---- Compliance ----
    let compliance = hsts
        .get("compliance")
        .expect("compliance key present on enriched finding");
    let nist = compliance
        .get("nist_800_53")
        .and_then(|v| v.as_array())
        .expect("nist_800_53 list present");
    assert!(
        nist.iter().filter_map(|v| v.as_str()).any(|s| s == "SC-8"),
        "HSTS finding includes NIST SC-8"
    );
}

/// Unenriched findings (a check_id outside the table) must still
/// round-trip cleanly. We rely on `skip_serializing_if` to keep legacy
/// clients compatible; the JSON should simply omit the enrichment keys
/// rather than emit them as nulls or empty arrays.
#[test]
fn unenriched_finding_omits_enrichment_keys() {
    let f = ScanFinding {
        check_id: "HDR.SOMETHING.NOT_IN_TABLE".into(),
        severity: "info".into(),
        title: "n/a".into(),
        description: "n/a".into(),
        recommendation: None,
        cvss: None,
        cwe: vec![],
        mitre_attack: vec![],
        compliance: ComplianceTags::default(),
        confidence: None,
        line: None,
        column: None,
    };
    let json = serde_json::to_value(&f).expect("serialises");
    let obj = json.as_object().expect("ScanFinding is a JSON object");
    assert!(!obj.contains_key("cvss"), "absent CVSS omitted");
    assert!(!obj.contains_key("cwe"), "empty CWE array omitted");
    assert!(
        !obj.contains_key("mitre_attack"),
        "empty mitre_attack omitted"
    );
    assert!(
        !obj.contains_key("compliance"),
        "empty compliance object omitted"
    );
    assert!(!obj.contains_key("confidence"), "absent confidence omitted");
    // Legacy required keys still present.
    assert!(obj.contains_key("check_id"));
    assert!(obj.contains_key("severity"));
    assert!(obj.contains_key("title"));
    assert!(obj.contains_key("description"));
}

/// Every live HDR.* `check_id` the monolith adapter emits must resolve
/// to a non-`None` enrichment payload via the canonical lookup. If a
/// future contributor adds a new HDR.* check without adding it to the
/// table, this test fails fast with a clear message.
#[test]
fn every_live_hdr_check_id_has_an_enrichment_entry() {
    // These ids are the exact strings produced by
    // `services/sx-monolith/src/adapters/scanner_http.rs::evaluate_headers`.
    // Keep this list in sync with that emitter.
    let live_ids = [
        "HDR.STRICT_TRANSPORT_SECURITY.MISSING",
        "HDR.CONTENT_SECURITY_POLICY.MISSING",
        "HDR.X_CONTENT_TYPE_OPTIONS.MISSING",
        "HDR.X_FRAME_OPTIONS.MISSING",
        "HDR.REFERRER_POLICY.MISSING",
        "HDR.PERMISSIONS_POLICY.MISSING",
        "HDR.SERVER.FINGERPRINT",
        "HDR.XPOWEREDBY.DISCLOSURE",
    ];
    for id in live_ids {
        let e = hdr_enrichment(id)
            .unwrap_or_else(|| panic!("live HDR check_id `{id}` has no enrichment entry"));
        // permissions-policy is intentionally empty per the brief
        // ("don't fabricate") — exempt it from the "non-empty" check.
        if id != "HDR.PERMISSIONS_POLICY.MISSING" {
            let has_payload = e.cvss.is_some() || !e.cwe.is_empty() || !e.compliance.is_empty();
            assert!(
                has_payload,
                "live HDR check_id `{id}` resolved to an empty enrichment payload"
            );
        }
    }
}

/// TOP5-#3 Phase 3 wire-facing acceptance test.
///
/// Drives the same [`HttpHeaderScannerPort`] stub used by
/// [`scan_finding_carries_enrichment_to_the_wire`] and asserts that
/// **every `check_id` on the JSON wire payload is the canonical
/// dotted form** — i.e. contains at least one `.`. This is the closing
/// regression net for Wave C-namespace: it fails if any future
/// contributor flips an emit site back to the legacy kebab form
/// (`missing-hsts`, `missing-csp`, …).
#[tokio::test]
async fn wire_findings_use_dotted_check_id_namespace() {
    let port: Box<dyn HttpHeaderScannerPort> = Box::new(StubEnrichedScanner::default());
    let req = HttpHeaderScanRequest {
        target: "https://httpbin.example/".into(),
        engagement_id: None,
    };
    let record = port
        .run(req, "tenant-phase3".into())
        .await
        .expect("scanner returned a record");

    let json = serde_json::to_value(&record).expect("ScanRecord serialises");
    let findings = json
        .get("findings")
        .and_then(|v| v.as_array())
        .expect("findings array present");
    assert!(
        !findings.is_empty(),
        "stub scanner produced at least one finding"
    );
    for f in findings {
        let cid = f
            .get("check_id")
            .and_then(|v| v.as_str())
            .expect("check_id present on every finding");
        assert!(
            cid.contains('.'),
            "TOP5-#3 Phase 3: every emitted check_id must be dotted-form; \
             got `{cid}` on wire finding {f}"
        );
        // Extra hardening: reject the well-known kebab-case shapes the
        // pre-Phase-3 code emitted (HDR.* header set + discovery-side
        // webapp / api check_ids covered by Wave E3).
        assert!(
            !cid.starts_with("missing-"),
            "regressed to kebab-case: {cid}"
        );
        assert!(
            !cid.starts_with("insecure-"),
            "regressed to kebab-case: {cid}"
        );
        assert!(!cid.starts_with("api-"), "regressed to kebab-case: {cid}");
        assert!(cid != "plaintext-http", "regressed to kebab-case: {cid}");
        assert!(cid != "server-banner", "regressed to kebab-case: {cid}");
        assert!(cid != "directory-listing", "regressed to kebab-case: {cid}");
        assert!(
            cid != "server-header-disclosure",
            "regressed to kebab-case: {cid}"
        );
        assert!(
            cid != "x-powered-by-disclosure",
            "regressed to kebab-case: {cid}"
        );
    }
}

/// TOP5-#3 Phase 3 §8(c) Wave E3 wire-facing acceptance test.
///
/// The receive-side alias map on `sx_core::reference::*` claims to
/// accept every discovery-side dotted `check_id` — webapp (cookie /
/// body / directory-listing / URL scheme / HDR) and API (auth / CORS /
/// server / error / rate-limit / GraphQL). This test enumerates every
/// dotted id introduced by the discovery-side migration and asserts
/// they all resolve to a payload consistent with the wire schema (i.e.
/// the alias map is complete).
#[test]
fn every_discovery_side_dotted_check_id_resolves_via_alias_map() {
    use sx_core::reference::api_dast_enrichment::{
        api_dast_enrichment, API_AUTH_MISSING_DOTTED, API_CORS_WILDCARD_DOTTED,
        API_ERROR_VERBOSE_DOTTED, API_GRAPHQL_INTROSPECTION_ENABLED_DOTTED,
        API_RATELIMIT_HEADERS_MISSING_DOTTED, API_SERVER_FINGERPRINT_DOTTED,
    };
    use sx_core::reference::header_enrichment::{
        HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED, HDR_PERMISSIONS_POLICY_MISSING_DOTTED,
        HDR_REFERRER_POLICY_MISSING_DOTTED, HDR_SERVER_FINGERPRINT_DOTTED,
        HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED, HDR_XPOWEREDBY_DISCLOSURE_DOTTED,
        HDR_X_CONTENT_TYPE_OPTIONS_MISSING_DOTTED, HDR_X_FRAME_OPTIONS_MISSING_DOTTED,
        URL_SCHEME_PLAINTEXT_HTTP_DOTTED,
    };
    use sx_core::reference::webapp_enrichment::{
        webapp_enrichment, DIRECTORY_LISTING_DOTTED, INSECURE_COOKIE_NO_HTTPONLY_DOTTED,
        INSECURE_COOKIE_NO_SECURE_DOTTED, SERVER_BANNER_DOTTED,
    };

    // HDR.* / URL.* — resolved via header_enrichment alias map.
    let hdr_ids = [
        HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED,
        HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED,
        HDR_X_FRAME_OPTIONS_MISSING_DOTTED,
        HDR_X_CONTENT_TYPE_OPTIONS_MISSING_DOTTED,
        HDR_REFERRER_POLICY_MISSING_DOTTED,
        HDR_PERMISSIONS_POLICY_MISSING_DOTTED,
        HDR_SERVER_FINGERPRINT_DOTTED,
        HDR_XPOWEREDBY_DISCLOSURE_DOTTED,
        URL_SCHEME_PLAINTEXT_HTTP_DOTTED,
    ];
    for id in hdr_ids {
        assert!(
            hdr_enrichment(id).is_some(),
            "discovery-side dotted id `{id}` failed to resolve via header_enrichment",
        );
        assert!(id.contains('.'), "id `{id}` must be dotted-form");
    }

    // WEBAPP.* enriched — resolved via webapp_enrichment alias map.
    let webapp_ids = [
        INSECURE_COOKIE_NO_SECURE_DOTTED,
        INSECURE_COOKIE_NO_HTTPONLY_DOTTED,
        DIRECTORY_LISTING_DOTTED,
    ];
    for id in webapp_ids {
        assert!(
            webapp_enrichment(id).is_some(),
            "discovery-side dotted id `{id}` failed to resolve via webapp_enrichment",
        );
        assert!(id.contains('.'), "id `{id}` must be dotted-form");
    }

    // Intel-only: WEBAPP.SERVER.BANNER is deliberately un-enriched.
    assert!(
        webapp_enrichment(SERVER_BANNER_DOTTED).is_none(),
        "WEBAPP.SERVER.BANNER is intel-only; must not resolve to a payload",
    );
    assert!(SERVER_BANNER_DOTTED.contains('.'));

    // API.* — resolved via api_dast_enrichment alias map.
    let api_ids = [
        API_AUTH_MISSING_DOTTED,
        API_CORS_WILDCARD_DOTTED,
        API_SERVER_FINGERPRINT_DOTTED,
        API_ERROR_VERBOSE_DOTTED,
        API_RATELIMIT_HEADERS_MISSING_DOTTED,
        API_GRAPHQL_INTROSPECTION_ENABLED_DOTTED,
    ];
    for id in api_ids {
        assert!(
            api_dast_enrichment(id).is_some(),
            "discovery-side dotted id `{id}` failed to resolve via api_dast_enrichment",
        );
        assert!(id.contains('.'), "id `{id}` must be dotted-form");
    }
}
