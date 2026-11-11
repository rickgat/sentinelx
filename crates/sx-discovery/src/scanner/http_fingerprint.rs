//! Non-intrusive HTTP fingerprint scanner.
//!
//! Issues a **single** `GET /` against a URL target. Captures the response
//! status code, a sanitised header map, and the best-effort `server` /
//! `x-powered-by` hints. The `set-cookie` header is **never** stored
//! verbatim — only its count and presence flag are kept.
//!
//! There are no follow-up requests, no JS execution, no path mutation, no
//! authentication probing. The scanner is designed to be safe to run by
//! default at Phase 1 intensity.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use time::OffsetDateTime;
use url::Url;

use crate::contracts::{Fqdn, ScanIntensity, ScopeTarget};
use crate::error::DiscoveryError;
use crate::model::observation::Observation;
use crate::model::scan_result::ScanResult;
use crate::service::scanner::{ScanContext, Scanner, ScannerCapabilities, ScannerId, TargetKind};

/// Stable id used to register / look up this scanner.
pub const HTTP_FINGERPRINT_ID: ScannerId = ScannerId::new("http_fingerprint_v1");

/// Placeholder kept in stored headers in place of `set-cookie` values.
pub const SET_COOKIE_PLACEHOLDER_PREFIX: &str = "<redacted: ";

/// Configuration for the HTTP fingerprint scanner.
#[derive(Debug, Clone)]
pub struct HttpFingerprintConfig {
    /// `User-Agent` header sent with every probe. Must be non-empty.
    pub user_agent: String,
    /// Total request timeout.
    pub request_timeout: Duration,
    /// Maximum number of redirects to follow.
    pub max_redirects: usize,
    /// If the target is a [`ScopeTarget::Domain`], use this scheme (`http` /
    /// `https`) to build the probe URL.
    pub default_scheme: String,
}

impl HttpFingerprintConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        if self.user_agent.trim().is_empty() {
            return Err(DiscoveryError::config(
                "http fingerprint user_agent must be non-empty",
            ));
        }
        if self.request_timeout.is_zero() {
            return Err(DiscoveryError::config(
                "http fingerprint request_timeout must be > 0",
            ));
        }
        if self.default_scheme != "http" && self.default_scheme != "https" {
            return Err(DiscoveryError::config(
                "http fingerprint default_scheme must be 'http' or 'https'",
            ));
        }
        Ok(())
    }
}

/// HTTP fingerprint scanner.
#[derive(Debug)]
pub struct HttpFingerprintScanner {
    cfg: HttpFingerprintConfig,
    client: Client,
}

impl HttpFingerprintScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: HttpFingerprintConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        let ua = HeaderValue::from_str(&cfg.user_agent)
            .map_err(|e| DiscoveryError::config(format!("invalid user-agent: {e}")))?;
        let mut default_headers = HeaderMap::new();
        default_headers.insert(USER_AGENT, ua);
        let client = Client::builder()
            .timeout(cfg.request_timeout)
            .redirect(reqwest::redirect::Policy::limited(cfg.max_redirects))
            .default_headers(default_headers)
            .build()
            .map_err(|e| DiscoveryError::config(format!("reqwest client build failed: {e}")))?;
        Ok(Self { cfg, client })
    }

    fn target_to_url(&self, target: &ScopeTarget) -> Result<Url, DiscoveryError> {
        match target {
            ScopeTarget::Url(u) => Ok(u.clone()),
            ScopeTarget::Domain(d) => {
                let raw = format!("{}://{}/", self.cfg.default_scheme, d.as_str());
                Url::parse(&raw)
                    .map_err(|e| DiscoveryError::config(format!("bad probe url '{raw}': {e}")))
            }
            other => Err(DiscoveryError::Config(format!(
                "http fingerprint requires a url / domain target, got {other}",
            ))),
        }
    }
}

#[async_trait]
impl Scanner for HttpFingerprintScanner {
    fn id(&self) -> ScannerId {
        HTTP_FINGERPRINT_ID
    }

    fn capabilities(&self) -> ScannerCapabilities {
        let mut kinds = std::collections::HashSet::new();
        kinds.insert(TargetKind::Url);
        kinds.insert(TargetKind::Domain);
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
        let url = self.target_to_url(&target)?;
        let _permit = ctx.rate_limiter.acquire(&target.canonical_key()).await?;

        let started_at = OffsetDateTime::now_utc();
        tracing::info!(scanner_id = %self.id(), target = %target, url = %url, "http fingerprint begin");

        let response = match self.client.get(url.clone()).send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() => {
                tracing::warn!(scanner_id = %self.id(), target = %target, "request timed out");
                return Err(DiscoveryError::Timeout);
            }
            Err(e) => {
                tracing::warn!(scanner_id = %self.id(), target = %target, error = %e, "request failed");
                return Err(DiscoveryError::io(e.to_string()));
            }
        };

        let status = response.status().as_u16();
        let raw_headers = response.headers().clone();
        let (headers, set_cookie_count) = sanitise_headers(&raw_headers);

        let server = headers.get("server").cloned();
        let framework = headers.get("x-powered-by").cloned();

        let mut observations = vec![Observation::HttpResponse {
            status,
            url: url.to_string(),
            headers,
            server,
            framework,
        }];

        if set_cookie_count > 0 {
            observations.push(Observation::HttpResponse {
                status,
                url: url.to_string(),
                headers: {
                    let mut m = BTreeMap::new();
                    m.insert(
                        "set-cookie".to_owned(),
                        format!("{SET_COOKIE_PLACEHOLDER_PREFIX}{set_cookie_count} value(s)>"),
                    );
                    m
                },
                server: None,
                framework: None,
            });
        }

        let ended_at = OffsetDateTime::now_utc();
        tracing::info!(
            scanner_id = %self.id(),
            target = %target,
            status,
            "http fingerprint end",
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

fn sanitise_headers(src: &HeaderMap) -> (BTreeMap<String, String>, usize) {
    let mut out = BTreeMap::new();
    let mut set_cookie_count = 0_usize;
    for (name, value) in src {
        let key = name.as_str().to_ascii_lowercase();
        if key == "set-cookie" {
            set_cookie_count += 1;
            continue;
        }
        let val = value
            .to_str()
            .map_or_else(|_| "<binary>".to_owned(), str::to_owned);
        out.insert(key, val);
    }
    (out, set_cookie_count)
}

/// Convenience helper used by integration tests — equivalent to
/// `Fqdn::new` but in this module so consumers don't need to import the
/// contracts module just to build a domain target.
pub fn domain_target(host: &str) -> Result<ScopeTarget, DiscoveryError> {
    Ok(ScopeTarget::Domain(Fqdn::new(host)?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_user_agent_rejected() {
        let r = HttpFingerprintScanner::new(HttpFingerprintConfig {
            user_agent: "  ".into(),
            request_timeout: Duration::from_secs(1),
            max_redirects: 1,
            default_scheme: "http".into(),
        });
        assert!(matches!(r, Err(DiscoveryError::Config(_))));
    }

    #[test]
    fn bad_scheme_rejected() {
        let r = HttpFingerprintScanner::new(HttpFingerprintConfig {
            user_agent: "test/1.0".into(),
            request_timeout: Duration::from_secs(1),
            max_redirects: 1,
            default_scheme: "gopher".into(),
        });
        assert!(matches!(r, Err(DiscoveryError::Config(_))));
    }

    #[test]
    fn target_url_from_domain() {
        let s = HttpFingerprintScanner::new(HttpFingerprintConfig {
            user_agent: "test/1.0".into(),
            request_timeout: Duration::from_secs(1),
            max_redirects: 1,
            default_scheme: "https".into(),
        })
        .unwrap();
        let t = domain_target("example.com").unwrap();
        let u = s.target_to_url(&t).unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), Some("example.com"));
    }

    #[test]
    fn sanitise_drops_set_cookie_value() {
        let mut h = HeaderMap::new();
        h.insert(
            reqwest::header::SET_COOKIE,
            "session=secret".parse().unwrap(),
        );
        h.insert(reqwest::header::SERVER, "nginx/1.27".parse().unwrap());
        let (out, count) = sanitise_headers(&h);
        assert_eq!(count, 1);
        assert!(!out.contains_key("set-cookie"));
        assert_eq!(out.get("server").map(String::as_str), Some("nginx/1.27"));
    }
}
