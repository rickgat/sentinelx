//! Lightweight REST / GraphQL API scanner.
//!
//! Issues a small number of non-intrusive HTTP requests against an
//! `http(s)://` target and runs a fixed set of header / body / GraphQL
//! audits over the responses. Each failing check emits an
//! [`Observation::HttpVulnerability`] with a stable `check_id`, a severity
//! tag, the URL evaluated, a short message, and an optional remediation
//! hint.
//!
//! The scanner is explicitly read-only:
//! - one `GET` against the target URL (no auth header),
//! - one optional `POST` only when the path ends in `/graphql`,
//! - no path traversal, no auth probing, no body manipulation,
//! - body audits only inspect the first `cfg.max_body_bytes` of the
//!   response payload.
//!
//! Each outgoing request acquires exactly one rate-limit token.

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use serde_json::Value;
use sx_core::reference::api_dast_enrichment::{
    api_dast_enrichment, ApiDastEnrichment, API_AUTH_MISSING_DOTTED, API_CORS_WILDCARD_DOTTED,
    API_ERROR_VERBOSE_DOTTED, API_GRAPHQL_INTROSPECTION_ENABLED_DOTTED,
    API_RATELIMIT_HEADERS_MISSING_DOTTED, API_SERVER_FINGERPRINT_DOTTED,
};
use sx_core::value_object::compliance::ComplianceTags;
use time::OffsetDateTime;
use url::Url;

use crate::contracts::{ScanIntensity, ScopeTarget};
use crate::error::DiscoveryError;
use crate::model::observation::Observation;
use crate::model::scan_result::ScanResult;
use crate::service::scanner::{ScanContext, Scanner, ScannerCapabilities, ScannerId, TargetKind};

/// Stable id used to register / look up this scanner.
pub const API_SCANNER_ID: ScannerId = ScannerId::new("api_rest_v1");

/// `User-Agent` string sent on each audit request.
const USER_AGENT_VALUE: &str = "SentinelX-Api/0.1";

/// GraphQL introspection probe payload.
const GRAPHQL_INTROSPECTION_QUERY: &str = "{\"query\":\"{ __schema { queryType { name } } }\"}";

/// Stack-trace marker substrings used by the verbose-error audit.
const STACK_TRACE_MARKERS: &[&str] = &[
    "Traceback",
    "Exception",
    "at java.",
    "at net.",
    "error: SQLSTATE",
];

/// Configuration for [`ApiScanner`].
#[derive(Debug, Clone)]
pub struct ApiScannerConfig {
    /// Pre-built `reqwest` client. The scanner sets its own `User-Agent`
    /// per request and applies its own timeout, so the client only needs
    /// network plumbing (TLS, proxies, etc.).
    pub http_client: Client,
    /// Total per-request timeout.
    pub request_timeout: Duration,
    /// Hard cap on the number of body bytes inspected by content audits.
    pub max_body_bytes: usize,
}

impl ApiScannerConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        if self.request_timeout.is_zero() {
            return Err(DiscoveryError::config(
                "api scanner request_timeout must be > 0",
            ));
        }
        if self.max_body_bytes == 0 {
            return Err(DiscoveryError::config(
                "api scanner max_body_bytes must be > 0",
            ));
        }
        Ok(())
    }
}

/// REST / GraphQL API scanner.
#[derive(Debug)]
pub struct ApiScanner {
    cfg: ApiScannerConfig,
}

impl ApiScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: ApiScannerConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        Ok(Self { cfg })
    }

    fn validate_target(target: &ScopeTarget) -> Result<Url, DiscoveryError> {
        match target {
            ScopeTarget::Url(u) => {
                let scheme = u.scheme();
                if scheme == "http" || scheme == "https" {
                    Ok(u.clone())
                } else {
                    Err(DiscoveryError::config(format!(
                        "api scanner requires http(s) URL, got scheme '{scheme}'",
                    )))
                }
            }
            other => Err(DiscoveryError::config(format!(
                "api scanner accepts only Url targets, got {other}",
            ))),
        }
    }

    fn user_agent_header() -> Result<HeaderValue, DiscoveryError> {
        HeaderValue::from_str(USER_AGENT_VALUE)
            .map_err(|e| DiscoveryError::internal(format!("invalid static user-agent: {e}")))
    }
}

#[async_trait]
impl Scanner for ApiScanner {
    fn id(&self) -> ScannerId {
        API_SCANNER_ID
    }

    fn capabilities(&self) -> ScannerCapabilities {
        let mut kinds = HashSet::new();
        kinds.insert(TargetKind::Url);
        ScannerCapabilities {
            max_intensity: ScanIntensity::Light,
            target_kinds: kinds,
            max_throughput_obs_per_sec: 4,
        }
    }

    async fn scan(
        &self,
        ctx: ScanContext,
        target: ScopeTarget,
    ) -> Result<ScanResult, DiscoveryError> {
        let url = Self::validate_target(&target)?;
        let url_string = url.to_string();
        let target_key = target.canonical_key();

        let started_at = OffsetDateTime::now_utc();
        tracing::info!(
            scanner_id = %self.id(),
            target = %target,
            "api scan begin",
        );

        let ua = Self::user_agent_header()?;
        let mut observations: Vec<Observation> = Vec::new();

        // --- request 1: GET <target> (one rate-limit token) ---
        {
            let _permit = ctx.rate_limiter.acquire(&target_key).await?;
            let response = match tokio::time::timeout(
                self.cfg.request_timeout,
                self.cfg
                    .http_client
                    .get(url.clone())
                    .header(USER_AGENT, ua.clone())
                    .send(),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) if e.is_timeout() => return Err(DiscoveryError::Timeout),
                Ok(Err(e)) => return Err(DiscoveryError::io(e.to_string())),
                Err(_elapsed) => return Err(DiscoveryError::Timeout),
            };

            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body_bytes =
                match tokio::time::timeout(self.cfg.request_timeout, response.bytes()).await {
                    Ok(Ok(b)) => b,
                    Ok(Err(e)) => return Err(DiscoveryError::io(e.to_string())),
                    Err(_elapsed) => return Err(DiscoveryError::Timeout),
                };
            let body_slice_len = body_bytes.len().min(self.cfg.max_body_bytes);
            let body_slice = body_bytes.get(..body_slice_len).unwrap_or(&[]);
            let body = String::from_utf8_lossy(body_slice);

            check_no_auth_required(status, &url_string, &mut observations);
            check_cors_wildcard(&headers, &url_string, &mut observations);
            check_server_disclosure(&headers, &url_string, &mut observations);
            check_verbose_error(body.as_ref(), &url_string, &mut observations);
            check_missing_rate_limit_headers(&headers, &url_string, &mut observations);
        }

        // --- request 2: optional graphql introspection ---
        if path_ends_with_graphql(&url) {
            let _permit = ctx.rate_limiter.acquire(&target_key).await?;
            let post = self
                .cfg
                .http_client
                .post(url.clone())
                .header(USER_AGENT, ua)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(GRAPHQL_INTROSPECTION_QUERY);
            if let Ok(Ok(r)) = tokio::time::timeout(self.cfg.request_timeout, post.send()).await {
                let status = r.status().as_u16();
                let body_bytes_opt =
                    match tokio::time::timeout(self.cfg.request_timeout, r.bytes()).await {
                        Ok(Ok(b)) => Some(b),
                        Ok(Err(_)) | Err(_) => None,
                    };
                if let Some(body_bytes) = body_bytes_opt {
                    let slice_len = body_bytes.len().min(self.cfg.max_body_bytes);
                    let body_slice = body_bytes.get(..slice_len).unwrap_or(&[]);
                    check_graphql_introspection(status, body_slice, &url_string, &mut observations);
                }
            }
        }

        let ended_at = OffsetDateTime::now_utc();
        tracing::info!(
            scanner_id = %self.id(),
            target = %target,
            findings = observations.len(),
            "api scan end",
        );

        Ok(ScanResult {
            scanner_id: self.id(),
            target,
            observations,
            started_at,
            ended_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers — pure functions over the captured response. Each mutates the
// shared `out` vector so the order of emitted observations is deterministic.
// ---------------------------------------------------------------------------

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Thin shim retained so the per-audit call sites stay zero-touch.
///
/// TOP5-#3 Phase 2 (P2-001) rewired this to delegate to
/// [`push_finding_enriched`], which performs the `check_id` lookup against
/// the canonical [`api_dast_enrichment`] table in `sx-core`. Every
/// existing call site automatically picks up CVSS / CWE / MITRE ATT&CK /
/// compliance enrichment when a curated mapping exists; unknown ids
/// fall through with the empty enrichment payload (so the wire JSON
/// omits the empty keys via `skip_serializing_if`).
fn push_finding(
    out: &mut Vec<Observation>,
    check_id: &str,
    severity: &str,
    url: &str,
    message: impl Into<String>,
    remediation: Option<&str>,
) {
    push_finding_enriched(
        out,
        check_id,
        severity,
        url,
        message,
        remediation,
        api_dast_enrichment(check_id),
    );
}

/// Enrichment-aware emitter. Mirrors the
/// `sx_discovery::scanner::webapp::push_finding_enriched` pattern landed
/// in TOP5-#3 Phase 1 (and tightened by the SX-REVIEW-002 C1 fix).
///
/// Callers that have already looked up the enrichment payload — or want
/// to inject a curated override — pass it through `enrichment`. Callers
/// that don't care pass `None` and the resulting `HttpVulnerability`
/// carries the empty enrichment fields (which serialise to omitted JSON
/// keys).
fn push_finding_enriched(
    out: &mut Vec<Observation>,
    check_id: &str,
    severity: &str,
    url: &str,
    message: impl Into<String>,
    remediation: Option<&str>,
    enrichment: Option<ApiDastEnrichment>,
) {
    let (cvss, cwe, mitre, compliance) = match enrichment {
        Some(e) => (e.cvss, e.cwe, e.mitre_attack, e.compliance),
        None => (None, Vec::new(), Vec::new(), ComplianceTags::default()),
    };
    out.push(Observation::HttpVulnerability {
        check_id: check_id.to_owned(),
        severity: severity.to_owned(),
        url: url.to_owned(),
        message: message.into(),
        remediation: remediation.map(str::to_owned),
        cvss,
        cwe,
        mitre_attack: mitre,
        compliance,
    });
}

fn check_no_auth_required(status: u16, url: &str, out: &mut Vec<Observation>) {
    if status == 200 {
        push_finding(
            out,
            API_AUTH_MISSING_DOTTED,
            "high",
            url,
            "API returned 200 OK without an Authorization header.",
            Some("Require authentication on API endpoints; reject unauthenticated requests with 401."),
        );
    }
}

fn check_cors_wildcard(headers: &HeaderMap, url: &str, out: &mut Vec<Observation>) {
    let origin = header_value(headers, "access-control-allow-origin").unwrap_or("");
    let creds = header_value(headers, "access-control-allow-credentials").unwrap_or("");
    if origin.trim() == "*" && creds.trim().eq_ignore_ascii_case("true") {
        push_finding(
            out,
            API_CORS_WILDCARD_DOTTED,
            "medium",
            url,
            "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
            Some("Echo a specific allow-listed origin, or remove credentials from CORS responses."),
        );
    }
}

fn check_server_disclosure(headers: &HeaderMap, url: &str, out: &mut Vec<Observation>) {
    if let Some(server) = header_value(headers, "server") {
        if server_value_includes_versioned_product(server) {
            push_finding(
                out,
                API_SERVER_FINGERPRINT_DOTTED,
                "low",
                url,
                format!("Server header discloses product/version: {server}"),
                Some("Strip or generalise the Server header at the gateway / reverse proxy."),
            );
        }
    }
}

/// Returns `true` if the header value contains a `<word>/<digit.digit>` token,
/// matching the spec's `[A-Za-z]+/\d+\.\d+` regex without taking a regex
/// dependency.
fn server_value_includes_versioned_product(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Find a `/` preceded by ASCII letters.
        let Some(&c) = bytes.get(i) else { break };
        if c == b'/' && i > 0 {
            let mut alpha_len = 0usize;
            let mut k = i;
            while k > 0 {
                let Some(&b) = bytes.get(k.saturating_sub(1)) else {
                    break;
                };
                if b.is_ascii_alphabetic() {
                    alpha_len = alpha_len.saturating_add(1);
                    k = k.saturating_sub(1);
                } else {
                    break;
                }
            }
            if alpha_len > 0 {
                // Match `<digit+>.<digit+>` following the slash.
                let mut j = i.saturating_add(1);
                let mut leading_digits = 0usize;
                while let Some(&b) = bytes.get(j) {
                    if b.is_ascii_digit() {
                        leading_digits = leading_digits.saturating_add(1);
                        j = j.saturating_add(1);
                    } else {
                        break;
                    }
                }
                if leading_digits > 0 && bytes.get(j) == Some(&b'.') {
                    j = j.saturating_add(1);
                    let mut trailing_digits = 0usize;
                    while let Some(&b) = bytes.get(j) {
                        if b.is_ascii_digit() {
                            trailing_digits = trailing_digits.saturating_add(1);
                            j = j.saturating_add(1);
                        } else {
                            break;
                        }
                    }
                    if trailing_digits > 0 {
                        return true;
                    }
                }
            }
        }
        i = i.saturating_add(1);
    }
    false
}

fn check_verbose_error(body: &str, url: &str, out: &mut Vec<Observation>) {
    if STACK_TRACE_MARKERS
        .iter()
        .any(|marker| body.contains(marker))
    {
        push_finding(
            out,
            API_ERROR_VERBOSE_DOTTED,
            "medium",
            url,
            "Response body contains stack-trace / SQL-error markers.",
            Some("Disable verbose error responses in production; return generic error envelopes."),
        );
    }
}

fn check_missing_rate_limit_headers(headers: &HeaderMap, url: &str, out: &mut Vec<Observation>) {
    if !headers.contains_key("x-ratelimit-limit") && !headers.contains_key("ratelimit-limit") {
        push_finding(
            out,
            API_RATELIMIT_HEADERS_MISSING_DOTTED,
            "info",
            url,
            "Response is missing rate-limit headers (X-RateLimit-Limit / RateLimit-Limit).",
            Some("Expose rate-limit metadata so clients can implement backoff."),
        );
    }
}

fn path_ends_with_graphql(url: &Url) -> bool {
    let path = url.path().trim_end_matches('/');
    path.ends_with("/graphql")
}

fn check_graphql_introspection(
    status: u16,
    body_bytes: &[u8],
    url: &str,
    out: &mut Vec<Observation>,
) {
    if status != 200 {
        return;
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(body_bytes) else {
        return;
    };
    let has_schema = parsed.get("data").and_then(|d| d.get("__schema")).is_some();
    if has_schema {
        push_finding(
            out,
            API_GRAPHQL_INTROSPECTION_ENABLED_DOTTED,
            "medium",
            url,
            "GraphQL introspection is enabled on a production-style endpoint.",
            Some("Disable introspection in production GraphQL deployments."),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
mod tests {
    use std::sync::Arc;

    use reqwest::Client;
    use tokio::sync::Notify;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::contracts::{EngagementId, KillSwitchScope, ScanIntensity, ScopeTarget, TenantId};
    use crate::service::rate_limiter::{RateLimiter, RateLimiterConfig};
    use crate::service::scanner::ScanContext;

    fn permissive_config() -> ApiScannerConfig {
        ApiScannerConfig {
            http_client: Client::builder().build().unwrap(),
            request_timeout: Duration::from_secs(5),
            max_body_bytes: 16 * 1024,
        }
    }

    fn rate_limiter() -> Arc<RateLimiter> {
        Arc::new(
            RateLimiter::new(RateLimiterConfig {
                max_concurrent_probes: 4,
                per_target_rps_limit: 100,
                per_target_burst: 100,
            })
            .unwrap(),
        )
    }

    fn ctx(rl: Arc<RateLimiter>) -> ScanContext {
        let tenant = TenantId::new();
        let engagement = EngagementId::new();
        ScanContext {
            tenant_id: tenant,
            engagement_id: engagement,
            intensity: ScanIntensity::Light,
            rate_limiter: rl,
            kill_signal: Arc::new(Notify::new()),
            kill_scopes: vec![
                KillSwitchScope::Global,
                KillSwitchScope::Tenant(tenant),
                KillSwitchScope::Engagement(engagement),
            ],
            deadline: OffsetDateTime::now_utc() + time::Duration::seconds(30),
        }
    }

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap();
            map.append(name, HeaderValue::from_str(v).unwrap());
        }
        map
    }

    fn finding_ids(out: &[Observation]) -> Vec<&str> {
        out.iter()
            .filter_map(|o| match o {
                Observation::HttpVulnerability { check_id, .. } => Some(check_id.as_str()),
                _ => None,
            })
            .collect()
    }

    // -------- configuration validation --------

    #[test]
    fn config_rejects_zero_timeout() {
        let cfg = ApiScannerConfig {
            http_client: Client::builder().build().unwrap(),
            request_timeout: Duration::from_secs(0),
            max_body_bytes: 1024,
        };
        assert!(matches!(
            ApiScanner::new(cfg),
            Err(DiscoveryError::Config(_))
        ));
    }

    #[test]
    fn config_rejects_zero_body_cap() {
        let cfg = ApiScannerConfig {
            http_client: Client::builder().build().unwrap(),
            request_timeout: Duration::from_secs(1),
            max_body_bytes: 0,
        };
        assert!(matches!(
            ApiScanner::new(cfg),
            Err(DiscoveryError::Config(_))
        ));
    }

    // -------- target validation --------

    #[test]
    fn target_validator_accepts_https() {
        let t = ScopeTarget::Url(Url::parse("https://api.example.com/v1").unwrap());
        let u = ApiScanner::validate_target(&t).unwrap();
        assert_eq!(u.scheme(), "https");
    }

    #[test]
    fn target_validator_accepts_http() {
        let t = ScopeTarget::Url(Url::parse("http://api.example.com/v1").unwrap());
        assert!(ApiScanner::validate_target(&t).is_ok());
    }

    #[test]
    fn target_validator_rejects_oci_scheme() {
        let t = ScopeTarget::Url(Url::parse("oci://alpine/3.20").unwrap());
        assert!(matches!(
            ApiScanner::validate_target(&t),
            Err(DiscoveryError::Config(_))
        ));
    }

    #[test]
    fn target_validator_rejects_non_url() {
        let t =
            ScopeTarget::Domain(crate::contracts::Fqdn::new("example.com").expect("static input"));
        assert!(matches!(
            ApiScanner::validate_target(&t),
            Err(DiscoveryError::Config(_))
        ));
    }

    // -------- individual audits --------

    #[test]
    fn no_auth_required_flags_200() {
        let mut out = Vec::new();
        check_no_auth_required(200, "http://api/", &mut out);
        assert!(finding_ids(&out).contains(&API_AUTH_MISSING_DOTTED));
    }

    #[test]
    fn no_auth_required_skips_401() {
        let mut out = Vec::new();
        check_no_auth_required(401, "http://api/", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn cors_wildcard_flags_combination() {
        let mut out = Vec::new();
        let h = header_map(&[
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
        ]);
        check_cors_wildcard(&h, "http://api/", &mut out);
        assert!(finding_ids(&out).contains(&API_CORS_WILDCARD_DOTTED));
    }

    #[test]
    fn cors_wildcard_skips_origin_only() {
        let mut out = Vec::new();
        let h = header_map(&[("access-control-allow-origin", "*")]);
        check_cors_wildcard(&h, "http://api/", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn server_disclosure_flags_versioned_product() {
        let mut out = Vec::new();
        let h = header_map(&[("server", "nginx/1.27")]);
        check_server_disclosure(&h, "http://api/", &mut out);
        assert!(finding_ids(&out).contains(&API_SERVER_FINGERPRINT_DOTTED));
    }

    #[test]
    fn server_disclosure_skips_plain_product() {
        let mut out = Vec::new();
        let h = header_map(&[("server", "nginx")]);
        check_server_disclosure(&h, "http://api/", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn verbose_error_flags_traceback_marker() {
        let mut out = Vec::new();
        check_verbose_error(
            "Traceback (most recent call last):\n  File ...",
            "http://api/",
            &mut out,
        );
        assert!(finding_ids(&out).contains(&API_ERROR_VERBOSE_DOTTED));
    }

    #[test]
    fn verbose_error_flags_sqlstate_marker() {
        let mut out = Vec::new();
        check_verbose_error("error: SQLSTATE[42S02]", "http://api/", &mut out);
        assert!(finding_ids(&out).contains(&API_ERROR_VERBOSE_DOTTED));
    }

    #[test]
    fn verbose_error_skips_clean_body() {
        let mut out = Vec::new();
        check_verbose_error("{\"data\":\"hello\"}", "http://api/", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn missing_rate_limit_flags_empty_headers() {
        let mut out = Vec::new();
        check_missing_rate_limit_headers(&HeaderMap::new(), "http://api/", &mut out);
        assert!(finding_ids(&out).contains(&API_RATELIMIT_HEADERS_MISSING_DOTTED));
    }

    #[test]
    fn missing_rate_limit_skips_when_present() {
        let mut out = Vec::new();
        let h = header_map(&[("x-ratelimit-limit", "1000")]);
        check_missing_rate_limit_headers(&h, "http://api/", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn graphql_introspection_flags_schema_payload() {
        let mut out = Vec::new();
        check_graphql_introspection(
            200,
            br#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#,
            "http://api/graphql",
            &mut out,
        );
        assert!(finding_ids(&out).contains(&API_GRAPHQL_INTROSPECTION_ENABLED_DOTTED));
    }

    #[test]
    fn graphql_introspection_skips_non_200() {
        let mut out = Vec::new();
        check_graphql_introspection(
            400,
            br#"{"errors":[{"message":"oops"}]}"#,
            "http://api/graphql",
            &mut out,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn graphql_path_detection() {
        let u1 = Url::parse("https://api.example.com/graphql").unwrap();
        let u2 = Url::parse("https://api.example.com/graphql/").unwrap();
        let u3 = Url::parse("https://api.example.com/v1/").unwrap();
        assert!(path_ends_with_graphql(&u1));
        assert!(path_ends_with_graphql(&u2));
        assert!(!path_ends_with_graphql(&u3));
    }

    // -------- end-to-end (wiremock) --------

    // -------- TOP5-#3 Phase 2 (P2-001): enrichment payload on API.* findings ----

    /// Locate the first `HttpVulnerability` observation with the given
    /// `check_id` and return its enrichment fields.
    #[allow(clippy::type_complexity)]
    fn enrichment_of<'a>(
        out: &'a [Observation],
        id: &str,
    ) -> Option<(
        &'a Option<sx_core::value_object::cvss_v31::CvssV31>,
        &'a Vec<sx_core::value_object::cwe::CweId>,
        &'a Vec<sx_core::value_object::mitre_attack::MitreAttackTechnique>,
        &'a sx_core::value_object::compliance::ComplianceTags,
    )> {
        out.iter().find_map(|o| match o {
            Observation::HttpVulnerability {
                check_id,
                cvss,
                cwe,
                mitre_attack,
                compliance,
                ..
            } if check_id == id => Some((cvss, cwe, mitre_attack, compliance)),
            _ => None,
        })
    }

    #[test]
    fn no_auth_required_finding_carries_full_enrichment() {
        let mut out = Vec::new();
        check_no_auth_required(200, "http://api/", &mut out);
        let (cvss, cwe, mitre, comp) =
            enrichment_of(&out, API_AUTH_MISSING_DOTTED).expect("no-auth finding must be present");
        let cvss = cvss.as_ref().expect("no-auth missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert!((cvss.base_score - 9.8).abs() < f64::EPSILON);
        assert!(cwe.iter().any(|c| c.as_u32() == 306));
        assert!(mitre.iter().any(|t| t.technique == "T1190"));
        assert!(comp.nist_800_53.iter().any(|c| c.as_str() == "AC-3"));
        assert!(comp.pci_dss.iter().any(|c| c.as_str() == "8.2"));
    }

    #[test]
    fn cors_wildcard_finding_carries_cwe_942() {
        let mut out = Vec::new();
        let h = header_map(&[
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
        ]);
        check_cors_wildcard(&h, "http://api/", &mut out);
        let (cvss, cwe, _mitre, _comp) =
            enrichment_of(&out, API_CORS_WILDCARD_DOTTED).expect("cors finding must be present");
        assert!(cvss.is_some());
        assert!(cwe.iter().any(|c| c.as_u32() == 942));
    }

    #[test]
    fn missing_rate_limit_finding_has_no_cvss_but_carries_cwe_770() {
        // Informational signal: enrichment table intentionally leaves CVSS
        // None per the "don't fabricate" rule, but CWE-770 + NIST SC-5
        // still attach.
        let mut out = Vec::new();
        check_missing_rate_limit_headers(&HeaderMap::new(), "http://api/", &mut out);
        let (cvss, cwe, _mitre, comp) = enrichment_of(&out, API_RATELIMIT_HEADERS_MISSING_DOTTED)
            .expect("rate-limit finding must be present");
        assert!(cvss.is_none());
        assert!(cwe.iter().any(|c| c.as_u32() == 770));
        assert!(comp.nist_800_53.iter().any(|c| c.as_str() == "SC-5"));
    }

    #[test]
    fn enriched_finding_serialises_with_payload_keys() {
        // End-to-end JSON contract for downstream pipelines (GitHub Code
        // Scanning, GitLab Security Dashboard).
        let mut out = Vec::new();
        check_no_auth_required(200, "http://api/", &mut out);
        let finding = out
            .iter()
            .find(|o| matches!(o, Observation::HttpVulnerability { check_id, .. } if check_id == API_AUTH_MISSING_DOTTED))
            .expect("no-auth finding must be present");
        let json = serde_json::to_string(finding).unwrap();
        assert!(json.contains("\"cvss\""), "json = {json}");
        assert!(json.contains("CVSS:3.1/"), "json = {json}");
        assert!(json.contains("\"cwe\""), "json = {json}");
        assert!(json.contains("CWE-306"), "json = {json}");
        assert!(json.contains("\"mitre_attack\""), "json = {json}");
        assert!(json.contains("T1190"), "json = {json}");
        assert!(json.contains("\"compliance\""), "json = {json}");
        assert!(json.contains("AC-3"), "json = {json}");
    }

    #[tokio::test]
    async fn end_to_end_minimal_response_emits_multiple_findings() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("server", "nginx/1.27")
                    .set_body_string("hello"),
            )
            .mount(&server)
            .await;

        let scanner = ApiScanner::new(permissive_config()).unwrap();
        let target = ScopeTarget::Url(Url::parse(&server.uri()).unwrap());
        let result = scanner.scan(ctx(rate_limiter()), target.clone()).await;
        let result = result.unwrap();
        let ids = finding_ids(&result.observations);
        assert!(
            ids.contains(&API_AUTH_MISSING_DOTTED),
            "expected no-auth finding in {ids:?}",
        );
        assert!(
            ids.contains(&API_SERVER_FINGERPRINT_DOTTED),
            "expected server-disclosure finding in {ids:?}",
        );
        assert!(
            ids.contains(&API_RATELIMIT_HEADERS_MISSING_DOTTED),
            "expected rate-limit finding in {ids:?}",
        );
        // End-to-end enrichment landing — the no-auth finding must
        // carry the curated CVSS/CWE/MITRE/compliance payload all the
        // way through the live scanner.
        let (cvss, cwe, _mitre, _comp) =
            enrichment_of(&result.observations, API_AUTH_MISSING_DOTTED)
                .expect("no-auth finding must be in the scan result");
        assert!(
            cvss.as_ref()
                .is_some_and(|c| (c.base_score - 9.8).abs() < f64::EPSILON),
            "expected CVSS 9.8 on API.AUTH.MISSING, got {cvss:?}",
        );
        assert!(cwe.iter().any(|c| c.as_u32() == 306));
        assert_eq!(result.scanner_id, API_SCANNER_ID);
        assert_eq!(result.target, target);
    }

    /// TOP5-#3 Phase 3 §8(c) Wave E3: every discovery-side API emit
    /// must use the dotted-form namespace on `check_id`. This is the
    /// user-facing regression net for the discovery API layer.
    #[tokio::test]
    async fn every_emitted_check_id_uses_dotted_namespace() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("server", "nginx/1.27")
                    .insert_header("access-control-allow-origin", "*")
                    .insert_header("access-control-allow-credentials", "true")
                    .set_body_string("Traceback (most recent call last):"),
            )
            .mount(&server)
            .await;

        let scanner = ApiScanner::new(permissive_config()).unwrap();
        let target = ScopeTarget::Url(Url::parse(&server.uri()).unwrap());
        let result = scanner
            .scan(ctx(rate_limiter()), target.clone())
            .await
            .unwrap();

        let ids = finding_ids(&result.observations);
        assert!(!ids.is_empty(), "scanner emitted at least one finding");
        for cid in &ids {
            assert!(
                cid.contains('.'),
                "check_id `{cid}` must be dotted-form (Wave E3 discovery migration)",
            );
            assert!(!cid.starts_with("api-"), "regressed to kebab-case: {cid}",);
        }
    }
}
