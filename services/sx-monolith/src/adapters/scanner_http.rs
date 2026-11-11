//! Passive HTTP-header security scanner adapter.
//!
//! Probes a single target via `reqwest`, inspects the response headers
//! for missing security controls, fingerprints the server, and emits a
//! self-contained [`ScanRecord`]. Records are kept in an in-memory ring
//! (cap 1000, newest-first) so `GET /v1/scans` can render history across
//! reloads of the dashboard. NOT a persistent finding-repository write —
//! engagement-bound findings come from heavier scanners (grype, nuclei).

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use sx_api::port::{HttpHeaderScannerPort, Phase3PortError};
use sx_api::view::scan_view::{HttpHeaderScanRequest, ScanFinding, ScanRecord};
use sx_core::reference::header_enrichment::{hdr_enrichment, HdrEnrichment};
use sx_core::reference::url_guard::validate_scan_target;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

const CAP: usize = 1000;

/// Required security headers the scanner checks for.
const REQUIRED_HEADERS: &[(&str, &str, &str, &str)] = &[
    (
        "strict-transport-security",
        "high",
        "Missing HSTS (Strict-Transport-Security)",
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    ),
    (
        "content-security-policy",
        "high",
        "Missing Content-Security-Policy",
        "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
    ),
    (
        "x-content-type-options",
        "medium",
        "Missing X-Content-Type-Options",
        "X-Content-Type-Options: nosniff",
    ),
    (
        "x-frame-options",
        "medium",
        "Missing X-Frame-Options (clickjacking)",
        "X-Frame-Options: DENY",
    ),
    (
        "referrer-policy",
        "low",
        "Missing Referrer-Policy",
        "Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "permissions-policy",
        "low",
        "Missing Permissions-Policy",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
];

/// In-memory scanner backed by a shared `reqwest::Client`.
#[derive(Debug)]
pub(crate) struct HttpHeaderScanner {
    http: Client,
    records: Mutex<Vec<ScanRecord>>,
}

impl HttpHeaderScanner {
    /// Build a new scanner. The caller supplies the workspace HTTP client
    /// so the connection pool is shared with the rest of the monolith.
    pub(crate) fn new(http: Client) -> Self {
        Self {
            http,
            records: Mutex::new(Vec::new()),
        }
    }

    /// Defense-in-depth SSRF guard at the adapter boundary
    /// (QC-SCAN-2026-06-25 fixes a + b).
    ///
    /// The `sx-api` controller already runs
    /// [`sx_core::reference::url_guard::validate_scan_target`] before
    /// invoking [`Self::run`]; this method repeats the validation so a
    /// direct port-level caller (integration tests, future internal
    /// orchestrators) cannot bypass the policy. Returns a structured
    /// [`Phase3PortError::Invalid`] on rejection — the controller layer
    /// translates that into HTTP 422, but the SSRF surface is already
    /// covered by the 400 the controller emits on its own pre-check.
    async fn normalise_target(target: &str) -> Result<String, Phase3PortError> {
        let url = validate_scan_target(target)
            .await
            .map_err(|e| Phase3PortError::Invalid(e.to_string()))?;
        Ok(url.to_string())
    }

    fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
    }

    fn severity_rank(s: &str) -> u8 {
        match s {
            "critical" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            "info" => 1,
            _ => 0,
        }
    }

    /// Build a [`ScanFinding`] for the given check, looking up the
    /// enrichment payload (CVSS / CWE / MITRE / compliance) from the
    /// canonical table in
    /// [`sx_core::reference::header_enrichment`]. SX-REVIEW-002 C1
    /// fix: the live `/v1/scans/http-headers` endpoint now emits the
    /// same enrichment surface as the discovery-side webapp DAST
    /// scanner, so auditors and SOC pipelines consume the wire payload
    /// directly without re-keying findings into a secondary store.
    fn enriched_finding(
        check_id: &str,
        severity: &str,
        title: impl Into<String>,
        description: String,
        recommendation: Option<String>,
    ) -> ScanFinding {
        let HdrEnrichment {
            cvss,
            cwe,
            mitre_attack,
            compliance,
        } = hdr_enrichment(check_id).unwrap_or_default();
        ScanFinding {
            check_id: check_id.to_owned(),
            severity: severity.to_owned(),
            title: title.into(),
            description,
            recommendation,
            cvss,
            cwe,
            mitre_attack,
            compliance,
            confidence: None,
            // Header-audit findings are not line-oriented — the target
            // is the URL, not a source file — so line/column stay `None`
            // and SARIF emits only `artifactLocation.uri`.
            line: None,
            column: None,
        }
    }

    fn evaluate_headers(resp: &reqwest::Response) -> Vec<ScanFinding> {
        let headers = resp.headers();
        let mut out: Vec<ScanFinding> = Vec::new();

        for (name, severity, title, rec) in REQUIRED_HEADERS {
            if !headers.contains_key(*name) {
                let check_id = format!("HDR.{}.MISSING", name.to_uppercase().replace('-', "_"));
                out.push(Self::enriched_finding(
                    &check_id,
                    severity,
                    *title,
                    format!(
                        "The response did not include the `{name}` header. Without it the browser cannot apply the corresponding protection."
                    ),
                    Some((*rec).into()),
                ));
            }
        }

        // Server fingerprint disclosure.
        if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
            if server.chars().any(|c| c.is_ascii_digit())
                || server.to_ascii_lowercase().contains("ubuntu")
                || server.to_ascii_lowercase().contains("debian")
            {
                out.push(Self::enriched_finding(
                    "HDR.SERVER.FINGERPRINT",
                    "medium",
                    "Server header discloses version / distro",
                    format!(
                        "The `Server: {server}` header reveals the upstream version, easing targeted CVE lookup by an attacker."
                    ),
                    Some("Set `server_tokens off;` (nginx) or equivalent.".into()),
                ));
            }
        }

        // X-Powered-By disclosure.
        if let Some(xpb) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
            out.push(Self::enriched_finding(
                "HDR.XPOWEREDBY.DISCLOSURE",
                "low",
                "X-Powered-By discloses runtime",
                format!("The `X-Powered-By: {xpb}` header reveals server runtime."),
                Some("Strip the X-Powered-By response header at the edge.".into()),
            ));
        }

        out.sort_by(|a, b| Self::severity_rank(&b.severity).cmp(&Self::severity_rank(&a.severity)));
        out
    }

    async fn probe(&self, url: &str) -> Result<reqwest::Response, reqwest::Error> {
        self.http
            .get(url)
            .header("User-Agent", "SentinelX-HttpHeaderScanner/0.1")
            .timeout(Duration::from_secs(10))
            .send()
            .await
    }
}

#[async_trait]
impl HttpHeaderScannerPort for HttpHeaderScanner {
    async fn run(
        &self,
        req: HttpHeaderScanRequest,
        tenant_id: String,
    ) -> Result<ScanRecord, Phase3PortError> {
        let url = Self::normalise_target(&req.target).await?;
        let started_at = Self::now_rfc3339();

        let probe = self.probe(&url).await;
        let finished_at = Self::now_rfc3339();

        let (status, error, findings) = match probe {
            Ok(resp) => ("ok".to_owned(), None, Self::evaluate_headers(&resp)),
            Err(e) => (
                "error".to_owned(),
                Some(format!("probe failed: {e}")),
                Vec::new(),
            ),
        };

        let record = ScanRecord {
            id: Uuid::now_v7().to_string(),
            tenant_id,
            kind: "http_headers".into(),
            target: url,
            engagement_id: req.engagement_id,
            started_at,
            finished_at,
            status,
            error,
            findings,
        };

        // Persist newest-first; cap to CAP.
        let mut guard = self
            .records
            .lock()
            .map_err(|_| Phase3PortError::Internal("scanner store poisoned".into()))?;
        guard.insert(0, record.clone());
        if guard.len() > CAP {
            guard.truncate(CAP);
        }
        Ok(record)
    }

    async fn list(
        &self,
        engagement_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ScanRecord>, Phase3PortError> {
        let guard = self
            .records
            .lock()
            .map_err(|_| Phase3PortError::Internal("scanner store poisoned".into()))?;
        Ok(guard
            .iter()
            .filter(|r| match engagement_id {
                Some(want) => r.engagement_id.as_deref() == Some(want),
                None => true,
            })
            .take(limit)
            .cloned()
            .collect())
    }

    async fn get(
        &self,
        tenant_id: &str,
        scan_id: &str,
    ) -> Result<Option<ScanRecord>, Phase3PortError> {
        let guard = self
            .records
            .lock()
            .map_err(|_| Phase3PortError::Internal("scanner store poisoned".into()))?;
        Ok(guard
            .iter()
            .find(|r| r.id == scan_id && r.tenant_id == tenant_id)
            .cloned())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn normalise_target_prepends_https() {
        // Both `example.com` and `x.test` resolve via the system
        // resolver to public addresses; the SSRF guard accepts those.
        // The `url::Url::to_string()` form always emits a trailing
        // slash on the empty path, so the assertions reflect that.
        assert_eq!(
            HttpHeaderScanner::normalise_target("example.com")
                .await
                .expect("public host accepted"),
            "https://example.com/"
        );
        assert_eq!(
            HttpHeaderScanner::normalise_target("https://example.com/path")
                .await
                .expect("public host accepted"),
            "https://example.com/path"
        );
    }

    #[tokio::test]
    async fn normalise_target_rejects_file_scheme() {
        let err = HttpHeaderScanner::normalise_target("file:///etc/passwd")
            .await
            .expect_err("file:// scheme must be rejected at the adapter boundary");
        assert!(
            matches!(err, Phase3PortError::Invalid(_)),
            "expected Phase3PortError::Invalid for file://; got {err:?}"
        );
    }

    #[tokio::test]
    async fn normalise_target_rejects_loopback() {
        let err = HttpHeaderScanner::normalise_target("http://127.0.0.1")
            .await
            .expect_err("loopback must be rejected at the adapter boundary");
        assert!(
            matches!(err, Phase3PortError::Invalid(_)),
            "expected Phase3PortError::Invalid for loopback; got {err:?}"
        );
    }

    #[test]
    fn severity_rank_orders_correctly() {
        assert!(
            HttpHeaderScanner::severity_rank("critical") > HttpHeaderScanner::severity_rank("high")
        );
        assert!(HttpHeaderScanner::severity_rank("low") > HttpHeaderScanner::severity_rank("info"));
    }

    /// SX-REVIEW-002 C1 regression net.
    ///
    /// Drives the live [`HttpHeaderScanner`] against a `wiremock` target
    /// that omits the canonical security headers and asserts the
    /// resulting [`ScanFinding`] entries each carry the enrichment
    /// payload the canonical
    /// [`sx_core::reference::header_enrichment`] table publishes.
    /// Bypasses only the network — the rest of the adapter (header
    /// evaluation, enrichment lookup, [`ScanRecord`] assembly) runs
    /// exactly as it would behind `POST /v1/scans/http-headers`.
    ///
    /// QC-SCAN-2026-06-25 fix b note: `wiremock` binds to a loopback
    /// address, which the new SSRF guard correctly refuses at the
    /// adapter's [`Self::run`] boundary. To keep this enrichment-
    /// regression test exercising the same enrichment surface, we drive
    /// [`Self::probe`] + [`Self::evaluate_headers`] directly and
    /// reassemble a [`ScanRecord`] by hand — the SSRF guard itself has
    /// dedicated tests (`normalise_target_rejects_*`).
    #[tokio::test]
    async fn live_adapter_emits_enrichment_for_missing_headers() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 200 OK with NO security headers — every required-header check
        // should fire.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
            .mount(&server)
            .await;

        let scanner = HttpHeaderScanner::new(Client::builder().build().unwrap());
        // Drive the header-evaluation path directly. The SSRF guard in
        // `normalise_target` would (correctly) reject `wiremock`'s
        // loopback URL; the enrichment-on-wire regression net does not
        // depend on the guard, so we step around it here.
        let resp = scanner
            .probe(&server.uri())
            .await
            .expect("probe wiremock target");
        let findings = HttpHeaderScanner::evaluate_headers(&resp);

        let record = ScanRecord {
            id: Uuid::now_v7().to_string(),
            tenant_id: "tenant-c1".into(),
            kind: "http_headers".into(),
            target: server.uri(),
            engagement_id: None,
            started_at: HttpHeaderScanner::now_rfc3339(),
            finished_at: HttpHeaderScanner::now_rfc3339(),
            status: "ok".into(),
            error: None,
            findings,
        };

        assert_eq!(record.status, "ok", "scan must succeed against wiremock");
        assert!(
            !record.findings.is_empty(),
            "wiremock returned no security headers; expected at least one finding"
        );

        // Walk every finding and assert the canonical enrichment lookup
        // populated each DTO. Permissions-policy is documented as
        // empty-by-design ("don't fabricate"); referrer-policy ships
        // CWE only (no CVSS); the rest must carry CVSS+CWE+compliance.
        let mut saw_enriched_with_cvss = false;
        for f in &record.findings {
            match f.check_id.as_str() {
                "HDR.PERMISSIONS_POLICY.MISSING" => {
                    assert!(f.cvss.is_none(), "permissions-policy has no CVSS by design");
                    assert!(f.cwe.is_empty(), "permissions-policy has no CWE by design");
                }
                "HDR.REFERRER_POLICY.MISSING" => {
                    assert!(
                        f.cvss.is_none(),
                        "referrer-policy: no authoritative CVSS in the table"
                    );
                    assert!(
                        !f.cwe.is_empty(),
                        "referrer-policy still carries CWE-200; got {:?}",
                        f.cwe
                    );
                }
                _ => {
                    assert!(
                        f.cvss.is_some(),
                        "{} should carry a CVSS score; live adapter dropped enrichment",
                        f.check_id
                    );
                    assert!(
                        !f.cwe.is_empty(),
                        "{} should carry at least one CWE; live adapter dropped enrichment",
                        f.check_id
                    );
                    saw_enriched_with_cvss = true;
                }
            }
        }
        assert!(
            saw_enriched_with_cvss,
            "no finding carried a CVSS payload — enrichment did not reach the wire"
        );

        // Spot-check the canonical HSTS golden case end-to-end.
        let hsts = record
            .findings
            .iter()
            .find(|f| f.check_id == "HDR.STRICT_TRANSPORT_SECURITY.MISSING")
            .expect("HSTS finding emitted by live adapter");
        let cvss = hsts.cvss.as_ref().expect("HSTS finding has CVSS");
        assert!((cvss.base_score - 7.5).abs() < f64::EPSILON);
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
        assert!(
            hsts.cwe.iter().any(|c| c.as_u32() == 319),
            "HSTS finding includes CWE-319"
        );
        assert!(
            hsts.mitre_attack.iter().any(|t| t.technique == "T1040"),
            "HSTS finding includes MITRE T1040"
        );
        assert!(
            hsts.compliance
                .nist_800_53
                .iter()
                .any(|c| c.as_str() == "SC-8"),
            "HSTS finding includes NIST SC-8"
        );

        // Serialise to JSON and verify the wire shape — the same path
        // `axum::Json(record)` would take.
        let json = serde_json::to_value(&record).expect("ScanRecord serialises");
        let hsts_json = json
            .get("findings")
            .and_then(|v| v.as_array())
            .expect("findings array")
            .iter()
            .find(|f| {
                f.get("check_id").and_then(|v| v.as_str())
                    == Some("HDR.STRICT_TRANSPORT_SECURITY.MISSING")
            })
            .expect("HSTS finding present in wire payload");
        assert!(
            hsts_json.get("cvss").is_some(),
            "wire payload includes cvss"
        );
        assert!(hsts_json.get("cwe").is_some(), "wire payload includes cwe");
        assert!(
            hsts_json.get("compliance").is_some(),
            "wire payload includes compliance"
        );
    }
}
