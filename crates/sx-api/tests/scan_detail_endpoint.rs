//! Integration test for the unified `GET /v1/scans/{any_id}` dispatcher
//! (QC-SCAN-2026-06-25 fix c).
//!
//! Asserts that a single registered route serves both:
//!
//! * `GET /v1/scans/{id}` → 200 `application/json` with the
//!   `ApiResponse<ScanRecord>` envelope.
//! * `GET /v1/scans/{id}.sarif` → 200 `application/sarif+json` (the
//!   SARIF v2.1.0 envelope already covered by
//!   `scan_sarif_endpoint.rs` — re-asserted here to lock the dispatcher
//!   contract).
//! * `GET /v1/scans/{unknown}` → 404 (tenant scoping enforced inside
//!   the port — a foreign-tenant id must also surface as 404 so we
//!   never leak existence).
//!
//! Why a dispatcher? axum 0.7 / matchit 0.7 cannot bind `:id.sarif` in
//! a single segment, so both routes share a single capture. The
//! controller's `get_scan_dispatch` then splits on the `.sarif` suffix.

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
use sx_api::controller::scan::{build_json_detail_response, build_sarif_response};
use sx_api::error::ApiError;
use sx_api::port::{HttpHeaderScannerPort, Phase3PortError};
use sx_api::view::scan_view::{HttpHeaderScanRequest, ScanFinding, ScanRecord};
use sx_core::reference::header_enrichment::{hdr_enrichment, HdrEnrichment};
use tower::util::ServiceExt;

const TENANT_ID: &str = "01900000-0000-7000-8000-000000000010";
const SCAN_ID: &str = "01900000-0000-7000-8000-000000000001";

/// Same fake port pattern the SARIF endpoint test uses.
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
        let findings = vec![Self::enriched(
            "HDR.STRICT_TRANSPORT_SECURITY.MISSING",
            "high",
            "Missing HSTS",
        )];
        let record = ScanRecord {
            id: SCAN_ID.into(),
            tenant_id: TENANT_ID.into(),
            kind: "http_headers".into(),
            target: "https://example.test/".into(),
            engagement_id: None,
            started_at: "2026-06-25T00:00:00Z".into(),
            finished_at: "2026-06-25T00:00:01Z".into(),
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
        unreachable!("run is not exercised by the detail dispatcher test")
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

/// Replicate the production dispatcher's route + handler. The handler
/// reads `:any_id`, strips `.sarif` if present, and delegates to the
/// corresponding builder. Auth is omitted — the production controller
/// wraps these helpers with `require_permission("scans:read")`.
fn router(port: Arc<dyn HttpHeaderScannerPort>) -> Router {
    Router::new()
        .route("/v1/scans/:any_id", get(handler))
        .with_state(port)
}

async fn handler(
    State(port): State<Arc<dyn HttpHeaderScannerPort>>,
    Path(any_id): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    if let Some(id) = any_id.strip_suffix(".sarif") {
        return build_sarif_response(port.as_ref(), TENANT_ID, id, None, None).await;
    }
    build_json_detail_response(port.as_ref(), TENANT_ID, &any_id).await
}

#[tokio::test]
async fn json_detail_returns_scan_record_envelope() {
    let port: Arc<dyn HttpHeaderScannerPort> = Arc::new(FakeScanner::seeded());
    let router = router(port);

    let uri = format!("/v1/scans/{SCAN_ID}");
    let req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    let res = router.oneshot(req).await.expect("router responds");

    assert_eq!(res.status(), StatusCode::OK, "JSON detail path returns 200");

    let content_type = res
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .expect("Content-Type header present")
        .to_str()
        .expect("Content-Type is ASCII");
    assert!(
        content_type.starts_with("application/json"),
        "JSON detail path returns application/json; got `{content_type}`",
    );

    let body_bytes = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body collected");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("body parses as JSON");

    // ApiResponse<T> envelope shape: { "data": <T>, ... }.
    let data = body
        .get("data")
        .expect("ApiResponse envelope carries `data` field");
    assert_eq!(
        data["id"], SCAN_ID,
        "ScanRecord.id surfaces under the data envelope",
    );
    assert_eq!(data["tenant_id"], TENANT_ID, "tenant_id surfaces");
    assert_eq!(data["status"], "ok", "scan record status surfaces");
    let findings = data["findings"].as_array().expect("findings array present");
    assert_eq!(findings.len(), 1, "one seeded finding present");
    assert_eq!(
        findings[0]["check_id"], "HDR.STRICT_TRANSPORT_SECURITY.MISSING",
        "check_id surfaces with the seeded value",
    );
    // Enrichment payload survives the wire — CVSS lives under `cvss`.
    assert!(
        findings[0].get("cvss").is_some(),
        "JSON detail body retains the enrichment payload (cvss)",
    );
}

#[tokio::test]
async fn sarif_path_still_returns_sarif_envelope() {
    let port: Arc<dyn HttpHeaderScannerPort> = Arc::new(FakeScanner::seeded());
    let router = router(port);

    let uri = format!("/v1/scans/{SCAN_ID}.sarif");
    let req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    let res = router.oneshot(req).await.expect("router responds");

    assert_eq!(res.status(), StatusCode::OK, "SARIF path returns 200");
    let content_type = res
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .expect("Content-Type header present")
        .to_str()
        .expect("Content-Type is ASCII");
    assert_eq!(
        content_type, "application/sarif+json",
        "dispatcher still routes `.sarif` suffix to the SARIF envelope",
    );
}

#[tokio::test]
async fn json_detail_unknown_id_returns_404() {
    let port: Arc<dyn HttpHeaderScannerPort> = Arc::new(FakeScanner::seeded());
    let router = router(port);

    let req = Request::builder()
        .uri("/v1/scans/00000000-0000-0000-0000-000000000000")
        .body(Body::empty())
        .expect("request builds");
    let res = router.oneshot(req).await.expect("router responds");

    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "unknown scan id surfaces as 404",
    );
}
