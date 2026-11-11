//! Lightweight Web Application DAST scanner.
//!
//! Issues a **single** non-intrusive HTTP `GET` against an `http(s)://`
//! target and runs a fixed set of header / cookie / body audits over the
//! response. Each failing check emits an
//! [`Observation::HttpVulnerability`] with a stable `check_id`, a severity
//! tag, the URL evaluated, a short message, and an optional remediation
//! hint.
//!
//! The scanner is explicitly read-only:
//! - exactly one request per scan (one rate-limit token consumed),
//! - no path traversal, no auth probing, no body manipulation,
//! - body audits only inspect the first `cfg.max_body_bytes` of the
//!   response payload.

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use sx_core::reference::header_enrichment::{
    hdr_enrichment, HdrEnrichment, HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED,
    HDR_PERMISSIONS_POLICY_MISSING_DOTTED, HDR_REFERRER_POLICY_MISSING_DOTTED,
    HDR_SERVER_FINGERPRINT_DOTTED, HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED,
    HDR_XPOWEREDBY_DISCLOSURE_DOTTED, HDR_X_CONTENT_TYPE_OPTIONS_MISSING_DOTTED,
    HDR_X_FRAME_OPTIONS_MISSING_DOTTED, URL_SCHEME_PLAINTEXT_HTTP_DOTTED,
};
use sx_core::reference::webapp_enrichment::{
    webapp_enrichment, DIRECTORY_LISTING_DOTTED, INSECURE_COOKIE_NO_HTTPONLY_DOTTED,
    INSECURE_COOKIE_NO_SECURE_DOTTED, SERVER_BANNER_DOTTED,
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
pub const WEBAPP_SCANNER_ID: ScannerId = ScannerId::new("webapp_dast_v1");

/// `User-Agent` string sent on the audit request.
const USER_AGENT_VALUE: &str = "SentinelX-WebApp/0.1";

/// Substrings (matched case-insensitively against the cookie name) that
/// classify a `Set-Cookie` as a likely session cookie.
const SESSION_COOKIE_NAME_MARKERS: &[&str] = &["session", "sid", "auth", "jwt"];

/// Configuration for [`WebAppScanner`].
#[derive(Debug, Clone)]
pub struct WebAppScannerConfig {
    /// Pre-built `reqwest` client. The scanner sets its own `User-Agent`
    /// per request and applies its own timeout, so the client only needs
    /// network plumbing (TLS, proxies, etc.).
    pub http_client: Client,
    /// Total per-request timeout.
    pub request_timeout: Duration,
    /// Hard cap on the number of body bytes inspected by content audits.
    pub max_body_bytes: usize,
}

impl WebAppScannerConfig {
    /// Validate the configuration.
    fn check(&self) -> Result<(), DiscoveryError> {
        if self.request_timeout.is_zero() {
            return Err(DiscoveryError::config(
                "webapp scanner request_timeout must be > 0",
            ));
        }
        if self.max_body_bytes == 0 {
            return Err(DiscoveryError::config(
                "webapp scanner max_body_bytes must be > 0",
            ));
        }
        Ok(())
    }
}

/// Web-application DAST scanner.
#[derive(Debug)]
pub struct WebAppScanner {
    cfg: WebAppScannerConfig,
}

impl WebAppScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: WebAppScannerConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        Ok(Self { cfg })
    }

    /// Confirm `target` is an `http://` or `https://` URL. Any other
    /// `ScopeTarget` variant or URL scheme is rejected with
    /// [`DiscoveryError::Config`].
    fn validate_target(target: &ScopeTarget) -> Result<Url, DiscoveryError> {
        match target {
            ScopeTarget::Url(u) => {
                let scheme = u.scheme();
                if scheme == "http" || scheme == "https" {
                    Ok(u.clone())
                } else {
                    Err(DiscoveryError::config(format!(
                        "webapp scanner requires http(s) URL, got scheme '{scheme}'",
                    )))
                }
            }
            other => Err(DiscoveryError::config(format!(
                "webapp scanner accepts only Url targets, got {other}",
            ))),
        }
    }

    fn user_agent_header() -> Result<HeaderValue, DiscoveryError> {
        HeaderValue::from_str(USER_AGENT_VALUE)
            .map_err(|e| DiscoveryError::internal(format!("invalid static user-agent: {e}")))
    }
}

#[async_trait]
impl Scanner for WebAppScanner {
    fn id(&self) -> ScannerId {
        WEBAPP_SCANNER_ID
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
        let scheme = url.scheme().to_owned();
        let url_string = url.to_string();

        let _permit = ctx.rate_limiter.acquire(&target.canonical_key()).await?;

        let started_at = OffsetDateTime::now_utc();
        tracing::info!(
            scanner_id = %self.id(),
            target = %target,
            url = %url,
            "webapp scan begin",
        );

        let ua = Self::user_agent_header()?;
        let request = self.cfg.http_client.get(url.clone()).header(USER_AGENT, ua);

        let response = match tokio::time::timeout(self.cfg.request_timeout, request.send()).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.is_timeout() => {
                tracing::warn!(
                    scanner_id = %self.id(),
                    target = %target,
                    "webapp request timed out (reqwest)",
                );
                return Err(DiscoveryError::Timeout);
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    scanner_id = %self.id(),
                    target = %target,
                    error = %e,
                    "webapp request failed",
                );
                return Err(DiscoveryError::io(e.to_string()));
            }
            Err(_elapsed) => {
                tracing::warn!(
                    scanner_id = %self.id(),
                    target = %target,
                    "webapp request timed out (wall clock)",
                );
                return Err(DiscoveryError::Timeout);
            }
        };

        let headers = response.headers().clone();
        let body_bytes =
            match tokio::time::timeout(self.cfg.request_timeout, response.bytes()).await {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => {
                    tracing::warn!(
                        scanner_id = %self.id(),
                        target = %target,
                        error = %e,
                        "webapp body read failed",
                    );
                    return Err(DiscoveryError::io(e.to_string()));
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        scanner_id = %self.id(),
                        target = %target,
                        "webapp body read timed out",
                    );
                    return Err(DiscoveryError::Timeout);
                }
            };
        let body_slice_len = body_bytes.len().min(self.cfg.max_body_bytes);
        let body_slice = body_bytes.get(..body_slice_len).unwrap_or(&[]);
        let body = String::from_utf8_lossy(body_slice);

        let mut observations: Vec<Observation> = Vec::new();
        check_url_scheme(&scheme, &url_string, &mut observations);
        check_security_headers(&scheme, &url_string, &headers, &mut observations);
        check_cookies(&scheme, &url_string, &headers, &mut observations);
        check_body(&url_string, body.as_ref(), &mut observations);

        let ended_at = OffsetDateTime::now_utc();
        tracing::info!(
            scanner_id = %self.id(),
            target = %target,
            findings = observations.len(),
            "webapp scan end",
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

fn missing_header(headers: &HeaderMap, name: &str) -> bool {
    !headers.contains_key(name)
}

/// Intel-only emitter shim.
///
/// Used by the `server-banner` observation (a fact, not a
/// vulnerability) and by any future check that is intentionally not
/// enrichable. Every other emit site routes through
/// [`push_finding_enriched`] with a payload from
/// [`hdr_enrichment`] (HDR.* table) or
/// [`webapp_enrichment`] (cookie / body / directory-listing table) —
/// see `docs/finding-enrichment.md` §5.
fn push_finding(
    out: &mut Vec<Observation>,
    check_id: &str,
    severity: &str,
    url: &str,
    message: impl Into<String>,
    remediation: Option<&str>,
) {
    push_finding_enriched(out, check_id, severity, url, message, remediation, None);
}

/// Enrichment-aware variant of [`push_finding`].
///
/// Header-audit emitters under [`check_security_headers`] call this
/// with an `enrichment` payload supplied by [`hdr_enrichment`]; the
/// cookie / body / directory-listing audits pass payloads supplied by
/// [`webapp_enrichment`] (converted via the
/// `From<WebappEnrichment> for HdrEnrichment` impl in `sx-core`).
/// Intel-only emitters pass `None` and the resulting
/// `HttpVulnerability` carries empty enrichment fields (which serialise
/// to omitted JSON keys).
fn push_finding_enriched(
    out: &mut Vec<Observation>,
    check_id: &str,
    severity: &str,
    url: &str,
    message: impl Into<String>,
    remediation: Option<&str>,
    enrichment: Option<HdrEnrichment>,
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

fn check_url_scheme(scheme: &str, url: &str, out: &mut Vec<Observation>) {
    if scheme.eq_ignore_ascii_case("http") {
        push_finding_enriched(
            out,
            URL_SCHEME_PLAINTEXT_HTTP_DOTTED,
            "high",
            url,
            "Target served over plaintext HTTP; traffic is not confidential or integrity-protected.",
            Some("Redirect all HTTP traffic to HTTPS and serve the site exclusively over TLS."),
            hdr_enrichment(URL_SCHEME_PLAINTEXT_HTTP_DOTTED),
        );
    }
}

// TOP5-#3 Phase 1: every HDR.* emitter call here also looks up its
// curated enrichment payload from `header_enrichment::hdr_enrichment`,
// pushing the per-line count past the default 100-line threshold. The
// alternative (split into one helper per check) buries the structure
// auditors want to read top-to-bottom.
#[allow(clippy::too_many_lines)]
fn check_security_headers(
    scheme: &str,
    url: &str,
    headers: &HeaderMap,
    out: &mut Vec<Observation>,
) {
    let is_https = scheme.eq_ignore_ascii_case("https");

    // 1. HDR.STRICT_TRANSPORT_SECURITY.MISSING — only meaningful on HTTPS.
    if is_https && missing_header(headers, "strict-transport-security") {
        push_finding_enriched(
            out,
            HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED,
            "medium",
            url,
            "HTTPS response is missing the Strict-Transport-Security header.",
            Some("Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all HTTPS responses."),
            hdr_enrichment(HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED),
        );
    }

    // 2. HDR.CONTENT_SECURITY_POLICY.MISSING
    if missing_header(headers, "content-security-policy") {
        push_finding_enriched(
            out,
            HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED,
            "medium",
            url,
            "Response is missing the Content-Security-Policy header.",
            Some("Configure a Content-Security-Policy header that restricts script, style, and frame sources."),
            hdr_enrichment(HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED),
        );
    }

    // 3. HDR.X_FRAME_OPTIONS.MISSING — only flag when CSP frame-ancestors is also absent.
    let csp_value = header_value(headers, "content-security-policy").unwrap_or("");
    let csp_has_frame_ancestors = csp_value.to_ascii_lowercase().contains("frame-ancestors");
    if missing_header(headers, "x-frame-options") && !csp_has_frame_ancestors {
        push_finding_enriched(
            out,
            HDR_X_FRAME_OPTIONS_MISSING_DOTTED,
            "low",
            url,
            "Response lacks both X-Frame-Options and CSP frame-ancestors directive; clickjacking protection is absent.",
            Some("Set `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`."),
            hdr_enrichment(HDR_X_FRAME_OPTIONS_MISSING_DOTTED),
        );
    }

    // 4. HDR.X_CONTENT_TYPE_OPTIONS.MISSING
    let xcto = header_value(headers, "x-content-type-options").unwrap_or("");
    if !xcto.eq_ignore_ascii_case("nosniff") {
        push_finding_enriched(
            out,
            HDR_X_CONTENT_TYPE_OPTIONS_MISSING_DOTTED,
            "low",
            url,
            "Response is missing `X-Content-Type-Options: nosniff`; the browser may MIME-sniff responses.",
            Some("Add `X-Content-Type-Options: nosniff` to every response."),
            hdr_enrichment(HDR_X_CONTENT_TYPE_OPTIONS_MISSING_DOTTED),
        );
    }

    // 5. HDR.REFERRER_POLICY.MISSING
    if missing_header(headers, "referrer-policy") {
        push_finding_enriched(
            out,
            HDR_REFERRER_POLICY_MISSING_DOTTED,
            "info",
            url,
            "Response is missing the Referrer-Policy header; default browser behaviour may leak the URL.",
            Some("Set a conservative `Referrer-Policy` such as `strict-origin-when-cross-origin` or `no-referrer`."),
            hdr_enrichment(HDR_REFERRER_POLICY_MISSING_DOTTED),
        );
    }

    // 6. HDR.PERMISSIONS_POLICY.MISSING
    if missing_header(headers, "permissions-policy") {
        push_finding_enriched(
            out,
            HDR_PERMISSIONS_POLICY_MISSING_DOTTED,
            "info",
            url,
            "Response is missing the Permissions-Policy header.",
            Some("Define a Permissions-Policy header to opt out of browser features the site does not need."),
            hdr_enrichment(HDR_PERMISSIONS_POLICY_MISSING_DOTTED),
        );
    }

    // 7. HDR.SERVER.FINGERPRINT & 13. WEBAPP.SERVER.BANNER
    if let Some(server_value) = header_value(headers, "server") {
        // Always record the server banner as intel.
        push_finding(
            out,
            SERVER_BANNER_DOTTED,
            "info",
            url,
            format!("Server header observed: {server_value}"),
            None,
        );
        if server_reveals_product_and_version(server_value) {
            push_finding_enriched(
                out,
                HDR_SERVER_FINGERPRINT_DOTTED,
                "low",
                url,
                format!("Server header discloses product and version: {server_value}"),
                Some(
                    "Strip or generalise the `Server` header at the reverse proxy / web-server layer.",
                ),
                hdr_enrichment(HDR_SERVER_FINGERPRINT_DOTTED),
            );
        }
    }

    // 8. HDR.XPOWEREDBY.DISCLOSURE
    if let Some(xpb) = header_value(headers, "x-powered-by") {
        push_finding_enriched(
            out,
            HDR_XPOWEREDBY_DISCLOSURE_DOTTED,
            "low",
            url,
            format!("X-Powered-By header exposes platform: {xpb}"),
            Some("Disable the X-Powered-By header in the application / framework configuration."),
            hdr_enrichment(HDR_XPOWEREDBY_DISCLOSURE_DOTTED),
        );
    }
}

/// Returns `true` if a `Server` header value looks like `product/version`
/// (e.g. `nginx/1.27.0`, `Apache/2.4.58`).
fn server_reveals_product_and_version(value: &str) -> bool {
    // Look for `<word>/<digit-or-dot>+` anywhere in the value.
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes.get(i) == Some(&b'/') {
            // Need at least one alphanumeric char before the slash.
            let before_ok = i > 0
                && bytes
                    .get(i.saturating_sub(1))
                    .is_some_and(u8::is_ascii_alphanumeric);
            // And at least one digit somewhere in the suffix token.
            let mut j = i + 1;
            let mut saw_digit = false;
            while j < bytes.len() {
                let Some(&b) = bytes.get(j) else { break };
                if b == b' ' || b == b',' || b == b';' {
                    break;
                }
                if b.is_ascii_digit() {
                    saw_digit = true;
                }
                j = j.saturating_add(1);
            }
            if before_ok && saw_digit {
                return true;
            }
        }
        i = i.saturating_add(1);
    }
    false
}

fn check_cookies(scheme: &str, url: &str, headers: &HeaderMap, out: &mut Vec<Observation>) {
    let is_https = scheme.eq_ignore_ascii_case("https");
    for raw in headers.get_all("set-cookie") {
        let Ok(value) = raw.to_str() else { continue };
        let attrs = parse_cookie_attributes(value);
        let cookie_name = cookie_name(value).unwrap_or("");

        // 9. WEBAPP.INSECURE_COOKIE.NO_SECURE — only meaningful on HTTPS.
        if is_https && !attrs.has_secure {
            push_finding_enriched(
                out,
                INSECURE_COOKIE_NO_SECURE_DOTTED,
                "medium",
                url,
                format!(
                    "Set-Cookie '{cookie_name}' is missing the Secure attribute on an HTTPS response.",
                ),
                Some("Add the `Secure` attribute to every Set-Cookie issued over HTTPS."),
                webapp_enrichment(INSECURE_COOKIE_NO_SECURE_DOTTED).map(HdrEnrichment::from),
            );
        }

        // 10. WEBAPP.INSECURE_COOKIE.NO_HTTPONLY — only for session-name cookies.
        if is_session_cookie_name(cookie_name) && !attrs.has_httponly {
            push_finding_enriched(
                out,
                INSECURE_COOKIE_NO_HTTPONLY_DOTTED,
                "medium",
                url,
                format!("Session cookie '{cookie_name}' is missing the HttpOnly attribute.",),
                Some("Add the `HttpOnly` attribute to session cookies to block JavaScript access."),
                webapp_enrichment(INSECURE_COOKIE_NO_HTTPONLY_DOTTED).map(HdrEnrichment::from),
            );
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct CookieAttributes {
    has_secure: bool,
    has_httponly: bool,
}

fn parse_cookie_attributes(set_cookie: &str) -> CookieAttributes {
    let mut attrs = CookieAttributes::default();
    for part in set_cookie.split(';').skip(1) {
        let token = part.trim();
        if token.eq_ignore_ascii_case("secure") {
            attrs.has_secure = true;
        } else if token.eq_ignore_ascii_case("httponly") {
            attrs.has_httponly = true;
        }
    }
    attrs
}

fn cookie_name(set_cookie: &str) -> Option<&str> {
    let first = set_cookie.split(';').next()?;
    let (name, _value) = first.split_once('=')?;
    Some(name.trim())
}

fn is_session_cookie_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    SESSION_COOKIE_NAME_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn check_body(url: &str, body: &str, out: &mut Vec<Observation>) {
    let apache = body.contains("<title>Index of /</title>");
    let nginx = body.contains("<h1>Index of /</h1>");
    if apache || nginx {
        let flavour = if apache {
            "Apache-style"
        } else {
            "Nginx autoindex"
        };
        push_finding_enriched(
            out,
            DIRECTORY_LISTING_DOTTED,
            "medium",
            url,
            format!("Response body contains {flavour} directory-listing markup."),
            Some(
                "Disable automatic directory indexing on the web server (e.g. `Options -Indexes` / `autoindex off`).",
            ),
            webapp_enrichment(DIRECTORY_LISTING_DOTTED).map(HdrEnrichment::from),
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

    fn permissive_config() -> WebAppScannerConfig {
        WebAppScannerConfig {
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

    fn empty_headers() -> HeaderMap {
        HeaderMap::new()
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
        let cfg = WebAppScannerConfig {
            http_client: Client::builder().build().unwrap(),
            request_timeout: Duration::from_secs(0),
            max_body_bytes: 1024,
        };
        let r = WebAppScanner::new(cfg);
        assert!(matches!(r, Err(DiscoveryError::Config(_))));
    }

    #[test]
    fn config_rejects_zero_body_cap() {
        let cfg = WebAppScannerConfig {
            http_client: Client::builder().build().unwrap(),
            request_timeout: Duration::from_secs(1),
            max_body_bytes: 0,
        };
        let r = WebAppScanner::new(cfg);
        assert!(matches!(r, Err(DiscoveryError::Config(_))));
    }

    // -------- target validation --------

    #[test]
    fn target_validator_accepts_https() {
        let target = ScopeTarget::Url(Url::parse("https://example.com/").unwrap());
        let u = WebAppScanner::validate_target(&target).unwrap();
        assert_eq!(u.scheme(), "https");
    }

    #[test]
    fn target_validator_accepts_http() {
        let target = ScopeTarget::Url(Url::parse("http://example.com/").unwrap());
        let u = WebAppScanner::validate_target(&target).unwrap();
        assert_eq!(u.scheme(), "http");
    }

    #[test]
    fn target_validator_rejects_oci_scheme() {
        let target = ScopeTarget::Url(Url::parse("oci://alpine/3.20").unwrap());
        let r = WebAppScanner::validate_target(&target);
        assert!(matches!(r, Err(DiscoveryError::Config(_))));
    }

    // -------- header audits --------

    #[test]
    fn header_audit_flags_missing_hsts_on_https() {
        let mut out = Vec::new();
        check_security_headers("https", "https://example.com/", &empty_headers(), &mut out);
        assert!(finding_ids(&out).contains(&HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED));
    }

    #[test]
    fn header_audit_skips_hsts_on_http_target() {
        let mut out = Vec::new();
        check_security_headers("http", "http://example.com/", &empty_headers(), &mut out);
        assert!(
            !finding_ids(&out).contains(&HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED),
            "HSTS audit must not fire on plaintext HTTP responses",
        );
    }

    #[test]
    fn header_audit_flags_missing_csp() {
        let mut out = Vec::new();
        check_security_headers("https", "https://example.com/", &empty_headers(), &mut out);
        assert!(finding_ids(&out).contains(&HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED));
    }

    #[test]
    fn header_audit_flags_server_disclosure_with_version() {
        let mut out = Vec::new();
        let headers = header_map(&[("server", "nginx/1.27.0")]);
        check_security_headers("https", "https://example.com/", &headers, &mut out);
        let ids = finding_ids(&out);
        assert!(ids.contains(&HDR_SERVER_FINGERPRINT_DOTTED));
        assert!(ids.contains(&SERVER_BANNER_DOTTED));
    }

    #[test]
    fn header_audit_skips_csp_frame_ancestors_when_present() {
        let mut out = Vec::new();
        let headers = header_map(&[("content-security-policy", "frame-ancestors 'none'")]);
        check_security_headers("https", "https://example.com/", &headers, &mut out);
        assert!(!finding_ids(&out).contains(&HDR_X_FRAME_OPTIONS_MISSING_DOTTED));
    }

    #[test]
    fn header_audit_flags_x_powered_by() {
        let mut out = Vec::new();
        let headers = header_map(&[("x-powered-by", "PHP/8.3")]);
        check_security_headers("https", "https://example.com/", &headers, &mut out);
        assert!(finding_ids(&out).contains(&HDR_XPOWEREDBY_DISCLOSURE_DOTTED));
    }

    // -------- cookie audits --------

    #[test]
    fn cookie_audit_flags_missing_secure_on_https() {
        let mut out = Vec::new();
        let headers = header_map(&[("set-cookie", "tracking=abc; Path=/")]);
        check_cookies("https", "https://example.com/", &headers, &mut out);
        assert!(finding_ids(&out).contains(&INSECURE_COOKIE_NO_SECURE_DOTTED));
    }

    #[test]
    fn cookie_audit_skips_secure_on_http_target() {
        let mut out = Vec::new();
        let headers = header_map(&[("set-cookie", "tracking=abc; Path=/")]);
        check_cookies("http", "http://example.com/", &headers, &mut out);
        assert!(!finding_ids(&out).contains(&INSECURE_COOKIE_NO_SECURE_DOTTED));
    }

    #[test]
    fn cookie_audit_flags_missing_httponly_for_session_cookie() {
        let mut out = Vec::new();
        let headers = header_map(&[("set-cookie", "SESSIONID=xyz; Secure")]);
        check_cookies("https", "https://example.com/", &headers, &mut out);
        assert!(finding_ids(&out).contains(&INSECURE_COOKIE_NO_HTTPONLY_DOTTED));
    }

    #[test]
    fn cookie_audit_ignores_httponly_when_cookie_is_not_session() {
        let mut out = Vec::new();
        let headers = header_map(&[("set-cookie", "tracking=abc; Secure")]);
        check_cookies("https", "https://example.com/", &headers, &mut out);
        assert!(!finding_ids(&out).contains(&INSECURE_COOKIE_NO_HTTPONLY_DOTTED));
    }

    // -------- body audits --------

    #[test]
    fn body_audit_flags_apache_directory_listing() {
        let mut out = Vec::new();
        check_body(
            "http://example.com/",
            "<html><head><title>Index of /</title></head></html>",
            &mut out,
        );
        assert!(finding_ids(&out).contains(&DIRECTORY_LISTING_DOTTED));
    }

    #[test]
    fn body_audit_flags_nginx_autoindex() {
        let mut out = Vec::new();
        check_body(
            "http://example.com/",
            "<html><body><h1>Index of /</h1></body></html>",
            &mut out,
        );
        assert!(finding_ids(&out).contains(&DIRECTORY_LISTING_DOTTED));
    }

    // -------- URL scheme audit --------

    #[test]
    fn plaintext_http_is_high_severity() {
        let mut out = Vec::new();
        check_url_scheme("http", "http://example.com/", &mut out);
        let mut saw = false;
        for o in &out {
            if let Observation::HttpVulnerability {
                check_id, severity, ..
            } = o
            {
                if check_id == URL_SCHEME_PLAINTEXT_HTTP_DOTTED {
                    assert_eq!(severity, "high");
                    saw = true;
                }
            }
        }
        assert!(saw, "URL.SCHEME.PLAINTEXT_HTTP finding should be emitted",);
    }

    // -------- end-to-end (wiremock) --------

    #[tokio::test]
    async fn end_to_end_minimal_response_emits_multiple_findings() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Hello world"))
            .mount(&server)
            .await;

        let scanner = WebAppScanner::new(permissive_config()).unwrap();
        let target = ScopeTarget::Url(Url::parse(&server.uri()).unwrap());
        let result = scanner
            .scan(ctx(rate_limiter()), target.clone())
            .await
            .unwrap();

        // A bare HTTP Hello-world response should trip at least:
        //   URL.SCHEME.PLAINTEXT_HTTP, HDR.CONTENT_SECURITY_POLICY.MISSING,
        //   HDR.X_FRAME_OPTIONS.MISSING, HDR.X_CONTENT_TYPE_OPTIONS.MISSING,
        //   HDR.REFERRER_POLICY.MISSING, HDR.PERMISSIONS_POLICY.MISSING.
        let ids = finding_ids(&result.observations);
        assert!(
            ids.len() >= 3,
            "expected 3+ HttpVulnerability findings, got {ids:?}",
        );
        assert!(ids.contains(&URL_SCHEME_PLAINTEXT_HTTP_DOTTED));
        assert!(ids.contains(&HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED));
        assert_eq!(result.scanner_id, WEBAPP_SCANNER_ID);
        assert_eq!(result.target, target);
    }

    /// TOP5-#3 Phase 3 §8(c) Wave E3: every discovery-side emit must
    /// use the dotted-form namespace on `check_id`. This is the
    /// user-facing regression net for the discovery layer.
    #[tokio::test]
    async fn every_emitted_check_id_uses_dotted_namespace() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("server", "nginx/1.27.0")
                    .insert_header("set-cookie", "SESSIONID=xyz; Path=/")
                    .insert_header("x-powered-by", "PHP/8.3")
                    .set_body_string("<html><body><h1>Index of /</h1></body></html>"),
            )
            .mount(&server)
            .await;

        let scanner = WebAppScanner::new(permissive_config()).unwrap();
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
            assert!(
                !cid.starts_with("missing-"),
                "regressed to kebab-case: {cid}",
            );
            assert!(
                !cid.starts_with("insecure-"),
                "regressed to kebab-case: {cid}",
            );
            assert!(cid != &"plaintext-http", "regressed to kebab-case: {cid}");
            assert!(cid != &"server-banner", "regressed to kebab-case: {cid}",);
            assert!(
                cid != &"directory-listing",
                "regressed to kebab-case: {cid}",
            );
        }
    }

    // -------- TOP5-#3 Phase 1: enrichment payload on HDR.* findings ----

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
    fn hsts_finding_carries_full_enrichment() {
        let mut out = Vec::new();
        check_security_headers("https", "https://example.com/", &empty_headers(), &mut out);
        let (cvss, cwe, mitre, comp) =
            enrichment_of(&out, HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED)
                .expect("HSTS finding must be present");
        let cvss = cvss.as_ref().expect("HSTS missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",);
        assert!((cvss.base_score - 7.5).abs() < f64::EPSILON);
        assert!(cwe.iter().any(|c| c.as_u32() == 319));
        assert!(mitre.iter().any(|t| t.technique == "T1040"));
        assert!(comp.nist_800_53.iter().any(|c| c.as_str() == "SC-8"));
        assert!(comp.iso_27001.iter().any(|c| c.as_str() == "A.13.1.1"));
        assert!(comp.pci_dss.iter().any(|c| c.as_str() == "4.1"));
    }

    #[test]
    fn csp_finding_carries_enrichment() {
        let mut out = Vec::new();
        check_security_headers("https", "https://example.com/", &empty_headers(), &mut out);
        let (cvss, cwe, _mitre, _comp) =
            enrichment_of(&out, HDR_CONTENT_SECURITY_POLICY_MISSING_DOTTED)
                .expect("CSP finding must be present");
        assert!(cvss.is_some());
        assert!(cwe.iter().any(|c| c.as_u32() == 1021));
        assert!(cwe.iter().any(|c| c.as_u32() == 79));
    }

    #[test]
    fn plaintext_http_finding_carries_enrichment() {
        let mut out = Vec::new();
        check_url_scheme("http", "http://example.com/", &mut out);
        let (cvss, cwe, mitre, comp) = enrichment_of(&out, URL_SCHEME_PLAINTEXT_HTTP_DOTTED)
            .expect("URL.SCHEME.PLAINTEXT_HTTP finding must be present");
        assert!(cvss.is_some());
        assert!(cwe.iter().any(|c| c.as_u32() == 319));
        assert!(mitre.iter().any(|t| t.tactic == "TA0006"));
        assert!(comp.pci_dss.iter().any(|c| c.as_str() == "4.1"));
    }

    #[test]
    fn server_banner_intel_carries_no_enrichment() {
        // The plain WEBAPP.SERVER.BANNER observation is intel-only; it
        // must NOT carry an enrichment payload (no CVSS, no CWE, etc.)
        // — it's a fact, not a vulnerability.
        let mut out = Vec::new();
        let headers = header_map(&[("server", "nginx/1.27.0")]);
        check_security_headers("https", "https://example.com/", &headers, &mut out);
        let banner = out.iter().find_map(|o| match o {
            Observation::HttpVulnerability {
                check_id,
                cvss,
                cwe,
                mitre_attack,
                compliance,
                ..
            } if check_id == SERVER_BANNER_DOTTED => Some((cvss, cwe, mitre_attack, compliance)),
            _ => None,
        });
        let (cvss, cwe, mitre, comp) = banner.expect("server-banner must be present");
        assert!(cvss.is_none());
        assert!(cwe.is_empty());
        assert!(mitre.is_empty());
        assert!(comp.is_empty());
    }

    #[test]
    fn enriched_observation_serialises_with_all_payload_keys() {
        // End-to-end JSON contract for downstream pipelines (GitHub Code
        // Scanning, GitLab Security Dashboard).
        let mut out = Vec::new();
        check_security_headers("https", "https://example.com/", &empty_headers(), &mut out);
        let hsts = out
            .iter()
            .find(|o| matches!(o, Observation::HttpVulnerability { check_id, .. } if check_id == HDR_STRICT_TRANSPORT_SECURITY_MISSING_DOTTED))
            .expect("HSTS finding must be present");
        let json = serde_json::to_string(hsts).unwrap();
        assert!(json.contains("\"cvss\""), "json = {json}");
        assert!(json.contains("CVSS:3.1/"), "json = {json}");
        assert!(json.contains("\"cwe\""), "json = {json}");
        assert!(json.contains("CWE-319"), "json = {json}");
        assert!(json.contains("\"mitre_attack\""), "json = {json}");
        assert!(json.contains("T1040"), "json = {json}");
        assert!(json.contains("\"compliance\""), "json = {json}");
        assert!(json.contains("SC-8"), "json = {json}");
        assert!(json.contains("A.13.1.1"), "json = {json}");

        // Round-trip back.
        let back: Observation = serde_json::from_str(&json).unwrap();
        match back {
            Observation::HttpVulnerability {
                cvss,
                cwe,
                mitre_attack,
                compliance,
                ..
            } => {
                assert!(cvss.is_some());
                assert!(!cwe.is_empty());
                assert!(!mitre_attack.is_empty());
                assert!(!compliance.is_empty());
            }
            other => panic!("expected HttpVulnerability, got {other:?}"),
        }
    }

    // -------- TOP5-#3 Phase 2 (P2-002): cookie + body enrichment -----

    #[test]
    fn insecure_cookie_no_secure_carries_enrichment() {
        let mut out = Vec::new();
        let headers = header_map(&[("set-cookie", "tracking=abc; Path=/")]);
        check_cookies("https", "https://example.com/", &headers, &mut out);
        let (cvss, cwe, mitre, comp) = enrichment_of(&out, INSECURE_COOKIE_NO_SECURE_DOTTED)
            .expect("cookie-no-secure finding must be present");
        let cvss = cvss.as_ref().expect("Secure-flag missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
        assert!((cvss.base_score - 5.9).abs() < f64::EPSILON);
        assert!(cwe.iter().any(|c| c.as_u32() == 614));
        assert!(mitre.iter().any(|t| t.technique == "T1539"));
        assert!(comp.nist_800_53.iter().any(|c| c.as_str() == "SC-8"));
        assert!(comp.iso_27001.iter().any(|c| c.as_str() == "A.13.1.1"));
        assert!(comp.pci_dss.iter().any(|c| c.as_str() == "4.1"));
    }

    #[test]
    fn insecure_cookie_no_httponly_carries_enrichment() {
        let mut out = Vec::new();
        let headers = header_map(&[("set-cookie", "SESSIONID=xyz; Secure")]);
        check_cookies("https", "https://example.com/", &headers, &mut out);
        let (cvss, cwe, mitre, comp) = enrichment_of(&out, INSECURE_COOKIE_NO_HTTPONLY_DOTTED)
            .expect("cookie-no-httponly finding must be present");
        let cvss = cvss.as_ref().expect("HttpOnly-flag missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N");
        assert!((cvss.base_score - 5.0).abs() < f64::EPSILON);
        assert!(cwe.iter().any(|c| c.as_u32() == 1004));
        assert!(mitre.iter().any(|t| t.technique == "T1059"));
        assert!(mitre
            .iter()
            .any(|t| t.subtechnique.as_deref() == Some("T1059.007")));
        assert!(comp.nist_800_53.iter().any(|c| c.as_str() == "SC-7"));
    }

    #[test]
    fn directory_listing_carries_enrichment() {
        let mut out = Vec::new();
        check_body(
            "http://example.com/",
            "<html><body><h1>Index of /</h1></body></html>",
            &mut out,
        );
        let (cvss, cwe, mitre, comp) = enrichment_of(&out, DIRECTORY_LISTING_DOTTED)
            .expect("directory-listing finding must be present");
        let cvss = cvss.as_ref().expect("directory-listing missing CVSS");
        assert_eq!(cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
        assert!((cvss.base_score - 7.5).abs() < f64::EPSILON);
        assert!(cwe.iter().any(|c| c.as_u32() == 548));
        assert!(cwe.iter().any(|c| c.as_u32() == 200));
        assert!(mitre.iter().any(|t| t.technique == "T1592"));
        assert!(comp.nist_800_53.iter().any(|c| c.as_str() == "SI-12"));
        assert!(comp.nist_800_53.iter().any(|c| c.as_str() == "AC-3"));
        assert!(comp.iso_27001.iter().any(|c| c.as_str() == "A.13.1.1"));
    }

    #[test]
    fn intel_only_server_banner_still_omits_enrichment_keys_on_wire() {
        // P2-002 deliberately leaves WEBAPP.SERVER.BANNER un-enriched
        // (it's intel, not a vulnerability). Confirm the JSON payload
        // still omits the empty enrichment keys via
        // `skip_serializing_if`.
        let mut out = Vec::new();
        let headers = header_map(&[("server", "nginx/1.27.0")]);
        check_security_headers("https", "https://example.com/", &headers, &mut out);
        let banner = out
            .iter()
            .find(|o| {
                matches!(
                    o,
                    Observation::HttpVulnerability { check_id, .. }
                        if check_id == SERVER_BANNER_DOTTED,
                )
            })
            .expect("server-banner intel must be present");
        let json = serde_json::to_string(banner).unwrap();
        assert!(!json.contains("\"cvss\""), "json = {json}");
        assert!(!json.contains("\"cwe\""), "json = {json}");
        assert!(!json.contains("\"mitre_attack\""), "json = {json}");
        assert!(!json.contains("\"compliance\""), "json = {json}");
    }
}
