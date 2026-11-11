//! Integration test for the `GET /v1/scans/{id}.sarif` endpoint
//! (TOP5-#3-P2-SARIF-API).
//!
//! Stands up a stub [`HttpHeaderScannerPort`] returning a [`ScanRecord`]
//! with two enriched findings (HSTS missing + X-Content-Type-Options
//! missing), drives the SARIF-export handler via a minimal axum router,
//! and asserts the wire surface:
//!
//! * HTTP 200 on the happy path.
//! * `Content-Type: application/sarif+json` (per SARIF v2.1.0 §3.1).
//! * Body parses as JSON with `$schema`, `version: "2.1.0"`,
//!   `runs[0].results[]` carrying two entries.
//! * The first result's `ruleId` matches the canonical HSTS check id
//!   produced by `services/sx-monolith::adapters::scanner_http`.
//! * Enrichment survives the wire (CVSS as `security-severity`, CWE in
//!   the rule's `relationships`).
//! * Unknown scan id → 404, mirroring the JSON list endpoint's
//!   not-found posture.
//!
//! ## Why not exercise `AppState` end-to-end?
//!
//! [`sx_api::state::AppState`] carries ~100 trait-object ports. Building
//! one outside the composition root (`services/sx-monolith`) would
//! require re-implementing every other port as a stub, which has no
//! testing value for this endpoint. The handler is therefore split into
//! a thin `State<AppState>` wrapper and a port-driven
//! [`sx_api::controller::scan::build_sarif_response`] core; this test
//! drives the core through axum so the path extractor (`.sarif`
//! suffix), the content-type header, and the response body are all
//! exercised exactly as the production handler ships them.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::similar_names)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use sx_api::controller::scan::build_sarif_response;
use sx_api::error::ApiError;
use sx_api::port::{HttpHeaderScannerPort, Phase3PortError};
use sx_api::view::scan_view::{HttpHeaderScanRequest, ScanFinding, ScanRecord};
use sx_core::reference::header_enrichment::{hdr_enrichment, HdrEnrichment};
use tower::util::ServiceExt; // brings `Router::oneshot` into scope

const TENANT_ID: &str = "01900000-0000-7000-8000-000000000010";
const SCAN_ID: &str = "01900000-0000-7000-8000-000000000001";

/// Tenant-aware fake port. Hands back the canned record only when the
/// scan id AND tenant match — exercises the `get` adapter's two-key
/// scoping contract.
#[derive(Debug)]
struct FakeScanner {
    record: ScanRecord,
}

impl FakeScanner {
    fn enriched(check_id: &str, severity: &str, title: &str) -> ScanFinding {
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
            description: format!("Description for {check_id}"),
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

    fn seeded() -> Self {
        let findings = vec![
            Self::enriched(
                "HDR.STRICT_TRANSPORT_SECURITY.MISSING",
                "high",
                "Missing HSTS",
            ),
            Self::enriched(
                "HDR.X_CONTENT_TYPE_OPTIONS.MISSING",
                "medium",
                "Missing X-Content-Type-Options",
            ),
        ];
        let record = ScanRecord {
            id: SCAN_ID.into(),
            tenant_id: TENANT_ID.into(),
            kind: "http_headers".into(),
            target: "https://example.test/".into(),
            engagement_id: None,
            started_at: "2026-06-24T00:00:00Z".into(),
            finished_at: "2026-06-24T00:00:01Z".into(),
            status: "ok".into(),
            error: None,
            findings,
        };
        Self { record }
    }
}

#[async_trait]
impl HttpHeaderScannerPort for FakeScanner {
    async fn run(
        &self,
        _req: HttpHeaderScanRequest,
        _tenant_id: String,
    ) -> Result<ScanRecord, Phase3PortError> {
        unreachable!("run is not exercised by the SARIF endpoint test")
    }

    async fn list(
        &self,
        _engagement_id: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<ScanRecord>, Phase3PortError> {
        Ok(vec![self.record.clone()])
    }

    async fn get(
        &self,
        tenant_id: &str,
        scan_id: &str,
    ) -> Result<Option<ScanRecord>, Phase3PortError> {
        if tenant_id == self.record.tenant_id && scan_id == self.record.id {
            Ok(Some(self.record.clone()))
        } else {
            Ok(None)
        }
    }
}

/// Router state bundle. Carries the port plus the release-channel
/// values so tests can drive `runs[].tool.driver.organization` and
/// `.downloadUri` end-to-end without threading `AppState` in.
#[derive(Clone)]
struct RouterState {
    port: Arc<dyn HttpHeaderScannerPort>,
    organization: Option<String>,
    download_uri: Option<String>,
}

/// Build a minimal axum router that exposes only the SARIF endpoint.
///
/// The production router glues the same handler to the full
/// [`sx_api::state::AppState`] + bearer-auth middleware. We omit auth in
/// this test by calling [`build_sarif_response`] directly with a
/// hard-coded tenant id — the auth posture is asserted separately in
/// `crates/sx-api/src/controller/scan.rs` unit tests for
/// `require_permission`.
fn router(port: Arc<dyn HttpHeaderScannerPort>) -> Router {
    router_with_release_channel(port, None, None)
}

/// Build the router with release-channel metadata (TOP5-#3 Phase 3)
/// so tests can assert `runs[].tool.driver.organization` and
/// `.downloadUri` populate from the injected values.
fn router_with_release_channel(
    port: Arc<dyn HttpHeaderScannerPort>,
    organization: Option<&str>,
    download_uri: Option<&str>,
) -> Router {
    // Mirror the production route registration. axum 0.7's matchit does
    // not accept `<param>.<literal>` in a single segment, so the
    // production handler captures the suffixed segment as `:id_sarif`
    // and strips `.sarif` itself (see
    // `sx_api::controller::scan::get_scan_sarif`). We replicate that
    // here so the test exercises the same wire shape.
    let state = RouterState {
        port,
        organization: organization.map(str::to_owned),
        download_uri: download_uri.map(str::to_owned),
    };
    Router::new()
        .route("/v1/scans/:id_sarif", get(handler))
        .with_state(state)
}

async fn handler(
    State(state): State<RouterState>,
    Path(id_sarif): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    let id = id_sarif.strip_suffix(".sarif").ok_or(ApiError::NotFound)?;
    build_sarif_response(
        state.port.as_ref(),
        TENANT_ID,
        id,
        state.organization.as_deref(),
        state.download_uri.as_deref(),
    )
    .await
}

#[tokio::test]
async fn sarif_endpoint_returns_two_enriched_results() {
    let port: Arc<dyn HttpHeaderScannerPort> = Arc::new(FakeScanner::seeded());
    let router = router(port);

    let uri = format!("/v1/scans/{SCAN_ID}.sarif");
    let req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    let res = router.oneshot(req).await.expect("router responds");

    assert_eq!(res.status(), StatusCode::OK, "expected 200 on happy path");

    let content_type = res
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .expect("Content-Type header present")
        .to_str()
        .expect("Content-Type header is ASCII");
    assert_eq!(
        content_type, "application/sarif+json",
        "SARIF v2.1.0 §3.1 mandates application/sarif+json",
    );

    let body_bytes = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body collected");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("body parses as JSON");

    // Envelope ---------------------------------------------------------
    assert!(
        body.get("$schema").and_then(|v| v.as_str()).is_some(),
        "SARIF envelope carries $schema",
    );
    assert_eq!(body["version"], "2.1.0", "SARIF version pinned to 2.1.0");

    // Runs / results ---------------------------------------------------
    let results = body["runs"][0]["results"]
        .as_array()
        .expect("results array present");
    assert_eq!(
        results.len(),
        2,
        "two enriched findings produce two results"
    );

    // First result is the HSTS finding — same order the stub returns them.
    let first = &results[0];
    assert_eq!(
        first["ruleId"], "HDR.STRICT_TRANSPORT_SECURITY.MISSING",
        "first result wires the canonical HDR check id",
    );

    // CVSS 7.5 surfaces as `security-severity` per GitHub's convention,
    // which `findings_to_sarif` emits when CVSS enrichment is present.
    let sec_severity = first["properties"]["security-severity"]
        .as_str()
        .expect("security-severity property present");
    assert_eq!(
        sec_severity, "7.5",
        "HSTS CVSS base score (7.5) surfaces as GitHub `security-severity`",
    );

    // CWE-319 surfaces in the rule's `relationships`.
    let rules = body["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array present");
    let hsts_rule = rules
        .iter()
        .find(|r| r["id"] == "HDR.STRICT_TRANSPORT_SECURITY.MISSING")
        .expect("HSTS rule descriptor present");
    let rels = hsts_rule["relationships"]
        .as_array()
        .expect("HSTS rule carries CWE relationships");
    assert!(
        rels.iter().any(|rel| rel["target"]["id"] == "CWE-319"),
        "HSTS rule references CWE-319 (Cleartext Transmission of Sensitive Information)",
    );
}

#[tokio::test]
async fn sarif_endpoint_404_on_unknown_id() {
    let port: Arc<dyn HttpHeaderScannerPort> = Arc::new(FakeScanner::seeded());
    let router = router(port);

    let req = Request::builder()
        .uri("/v1/scans/00000000-0000-0000-0000-000000000000.sarif")
        .body(Body::empty())
        .expect("request builds");
    let res = router.oneshot(req).await.expect("router responds");

    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "unknown scan id surfaces as 404, not 403, so we never leak existence of \
         foreign-tenant scan ids",
    );
}

#[tokio::test]
async fn sarif_endpoint_404_when_suffix_missing() {
    let port: Arc<dyn HttpHeaderScannerPort> = Arc::new(FakeScanner::seeded());
    let router = router(port);

    // Hit the exact recorded id but without the `.sarif` suffix — the
    // production handler treats the un-suffixed shape as not-found
    // because the documented JSON list endpoint lives at `/v1/scans`,
    // not at `/v1/scans/{id}`.
    let uri = format!("/v1/scans/{SCAN_ID}");
    let req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    let res = router.oneshot(req).await.expect("router responds");

    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "un-suffixed segment is not the SARIF endpoint",
    );
}

// ============================================================================
// TOP5-#3 Phase 3 — richer SARIF location + tool.driver.organization / downloadUri
// ============================================================================

/// Drive the SARIF endpoint with a non-`None` release-channel config and
/// assert both `runs[0].tool.driver.organization` and
/// `runs[0].tool.driver.downloadUri` land in the emitted envelope.
///
/// User-facing contract: `GET /v1/scans/{id}.sarif` must surface the
/// operator-configured `release_channel.organization` and
/// `release_channel.download_uri` so SOC pipelines can dedupe on a
/// stable `(organization, downloadUri)` pair.
#[tokio::test]
async fn sarif_envelope_carries_tool_organization_and_download_uri_from_config() {
    let port: Arc<dyn HttpHeaderScannerPort> = Arc::new(FakeScanner::seeded());
    let router = router_with_release_channel(
        port,
        Some("Acme Security"),
        Some("https://releases.acme.example/sentinelx/1.0.0.zip"),
    );

    let uri = format!("/v1/scans/{SCAN_ID}.sarif");
    let req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    let res = router.oneshot(req).await.expect("router responds");
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body collected");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("body parses as JSON");

    let driver = &body["runs"][0]["tool"]["driver"];
    assert_eq!(
        driver["organization"], "Acme Security",
        "organization surfaced from release_channel config",
    );
    assert_eq!(
        driver["downloadUri"], "https://releases.acme.example/sentinelx/1.0.0.zip",
        "downloadUri surfaced from release_channel config",
    );
}

/// Drive one line-oriented (DLP-shaped) finding through the endpoint
/// and assert
/// `runs[0].results[0].locations[0].physicalLocation.region.startLine` +
/// `.startColumn` land on the emitted envelope. The synthetic finding
/// carries `line: 12, column: 4` — the numbers pass through
/// `scan_finding_to_finding` unchanged, so this test guards the whole
/// pipeline: `ScanFinding.line/column` → `EvidenceRef.line/column` →
/// SARIF `region.startLine/.startColumn`.
#[tokio::test]
async fn sarif_result_carries_line_column_for_source_aware_finding() {
    let scan_id = "01900000-0000-7000-8000-0000000000ff";
    let dlp_finding = ScanFinding {
        check_id: "DLP.CREDIT_CARD".into(),
        severity: "high".into(),
        title: "PAN detected in config".into(),
        description: "Luhn-valid PAN found in scanned config file".into(),
        recommendation: None,
        cvss: None,
        cwe: vec![],
        mitre_attack: vec![],
        compliance: sx_core::value_object::compliance::ComplianceTags::default(),
        confidence: Some(0.87),
        line: Some(12),
        column: Some(4),
    };
    let record = ScanRecord {
        id: scan_id.into(),
        tenant_id: TENANT_ID.into(),
        kind: "http_headers".into(),
        target: "https://example.test/config.yaml".into(),
        engagement_id: None,
        started_at: "2026-07-04T00:00:00Z".into(),
        finished_at: "2026-07-04T00:00:01Z".into(),
        status: "ok".into(),
        error: None,
        findings: vec![dlp_finding],
    };
    let port: Arc<dyn HttpHeaderScannerPort> = Arc::new(SingleRecordScanner { record });
    let router = router(port);

    let uri = format!("/v1/scans/{scan_id}.sarif");
    let req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    let res = router.oneshot(req).await.expect("router responds");
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body collected");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("body parses as JSON");

    let region = &body["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
    assert_eq!(
        region["startLine"], 12,
        "1-indexed source line surfaces as SARIF region.startLine",
    );
    assert_eq!(
        region["startColumn"], 4,
        "1-indexed source column surfaces as SARIF region.startColumn",
    );
    // Bonus: the artifactLocation URI is the scan target (the config
    // file that was scanned) — legacy consumers still get an anchor.
    assert_eq!(
        body["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            ["uri"],
        "https://example.test/config.yaml",
    );
}

/// Minimal port stub that hands back a single canned record — used by
/// the source-aware SARIF test to keep the assertion focused on the
/// line/column projection without the two-finding HSTS/XCTO noise.
#[derive(Debug)]
struct SingleRecordScanner {
    record: ScanRecord,
}

#[async_trait]
impl HttpHeaderScannerPort for SingleRecordScanner {
    async fn run(
        &self,
        _req: HttpHeaderScanRequest,
        _tenant_id: String,
    ) -> Result<ScanRecord, Phase3PortError> {
        unreachable!("run is not exercised by this test")
    }

    async fn list(
        &self,
        _engagement_id: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<ScanRecord>, Phase3PortError> {
        Ok(vec![self.record.clone()])
    }

    async fn get(
        &self,
        tenant_id: &str,
        scan_id: &str,
    ) -> Result<Option<ScanRecord>, Phase3PortError> {
        if tenant_id == self.record.tenant_id && scan_id == self.record.id {
            Ok(Some(self.record.clone()))
        } else {
            Ok(None)
        }
    }
}
