//! Certificate Transparency (CT) log monitor.
//!
//! Polls a `crt.sh`-compatible HTTP endpoint for certificates issued under a
//! monitored domain and surfaces records issued after a caller-supplied
//! cut-off. The probe is a single GET (`/?output=json&q=<domain>`) and never
//! follows redirects or sends auth.
//!
//! Each emitted [`CtRecord`] is the projection of a single CT log entry:
//! `common_name`, `issuer`, `not_before`, `not_after`, and the set of SAN
//! DNS names parsed from the `name_value` field. Duplicate SANs are
//! preserved in iteration order — callers downstream may dedupe.
//!
//! Failure model: all errors map onto [`DiscoveryError`]. JSON parse
//! failures (malformed `crt.sh` payload, unexpected schema) map onto
//! [`DiscoveryError::Internal`] with the prefix `"ct_monitor: parse"`,
//! which downstream tests pattern-match to assert a parse error rather
//! than a transport one.

use reqwest::Client;
use serde::Deserialize;
use time::format_description::well_known::Iso8601;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};
use url::Url;

use crate::error::DiscoveryError;

/// HTTP query-string parameter name used by `crt.sh` for the issuer/domain
/// search term.
const QUERY_PARAM_DOMAIN: &str = "q";

/// HTTP query-string parameter name used by `crt.sh` to ask for JSON output.
const QUERY_PARAM_OUTPUT: &str = "output";

/// Value of [`QUERY_PARAM_OUTPUT`] (constant — the monitor only knows how
/// to parse JSON).
const QUERY_VALUE_JSON: &str = "json";

/// A single Certificate Transparency record, projected from a `crt.sh` row.
///
/// All timestamps are interpreted as UTC. `sans` contains the DNS names
/// parsed out of the multi-line `name_value` field (the `crt.sh` column
/// that flattens the certificate's CN + Subject Alternative Names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtRecord {
    /// Subject common name (`CN=...`) of the certificate.
    pub common_name: String,
    /// Issuer organisation as returned by `crt.sh` (`issuer_name`).
    pub issuer: String,
    /// `notBefore` timestamp parsed from the row.
    pub not_before: OffsetDateTime,
    /// `notAfter` timestamp parsed from the row.
    pub not_after: OffsetDateTime,
    /// DNS names extracted from `name_value` (CN + SANs, in source order).
    pub sans: Vec<String>,
}

/// CT log monitor.
///
/// The monitor holds a pre-built [`Client`] (caller controls TLS, proxy,
/// timeouts) and the `crt.sh`-compatible `base_url`. Tests inject a
/// `wiremock` URL into `base_url` to fake the upstream.
#[derive(Debug, Clone)]
pub struct CtLogMonitor {
    /// HTTP client used to issue the JSON query. Caller-built so the
    /// monitor never has to know about TLS roots, proxies, etc.
    pub http: Client,
    /// Endpoint base URL. Path / query are appended by [`Self::list_new`].
    pub base_url: Url,
}

impl CtLogMonitor {
    /// Construct a new monitor.
    #[must_use]
    pub const fn new(http: Client, base_url: Url) -> Self {
        Self { http, base_url }
    }

    /// Build the query URL `<base>/?output=json&q=<domain>` for a domain.
    fn build_query_url(&self, domain: &str) -> Url {
        let mut url = self.base_url.clone();
        url.query_pairs_mut()
            .append_pair(QUERY_PARAM_OUTPUT, QUERY_VALUE_JSON)
            .append_pair(QUERY_PARAM_DOMAIN, domain);
        url
    }

    /// Poll `crt.sh` for certificates whose `not_before` is at or after
    /// `since_ts`, scoped to `domain`.
    ///
    /// Returns the parsed records in the order they appear in the upstream
    /// response.
    ///
    /// # Errors
    ///
    /// * [`DiscoveryError::Io`]   — transport-level failure.
    /// * [`DiscoveryError::Timeout`] — the request timed out (the client's
    ///   own timeout, if any, drives this).
    /// * [`DiscoveryError::Internal`] — JSON could not be parsed or did
    ///   not match the expected schema.
    pub async fn list_new(
        &self,
        domain: &str,
        since_ts: OffsetDateTime,
    ) -> Result<Vec<CtRecord>, DiscoveryError> {
        let url = self.build_query_url(domain);
        tracing::debug!(domain, url = %url, "ct_monitor query");

        let response = match self.http.get(url).send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() => return Err(DiscoveryError::Timeout),
            Err(e) => return Err(DiscoveryError::io(format!("ct_monitor: request: {e}"))),
        };

        if !response.status().is_success() {
            return Err(DiscoveryError::io(format!(
                "ct_monitor: upstream returned status {}",
                response.status().as_u16(),
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| DiscoveryError::io(format!("ct_monitor: read body: {e}")))?;

        let records = parse_crtsh_payload(&body)?;
        Ok(records
            .into_iter()
            .filter(|r| r.not_before >= since_ts)
            .collect())
    }
}

/// Raw `crt.sh` row shape — every field is optional because the upstream
/// schema has historically added/removed columns; we only require the four
/// we project to [`CtRecord`].
#[derive(Debug, Deserialize)]
struct CrtShRow {
    #[serde(default)]
    common_name: Option<String>,
    #[serde(default)]
    issuer_name: Option<String>,
    #[serde(default)]
    name_value: Option<String>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

/// Parse the body of a `crt.sh` JSON response into a list of [`CtRecord`].
///
/// Mapping (crt.sh field → `CtRecord` field):
/// * `common_name`  → `common_name`
/// * `issuer_name`  → `issuer`
/// * `not_before`   → `not_before` (parsed as UTC)
/// * `not_after`    → `not_after`  (parsed as UTC)
/// * `name_value`   → `sans` (split on `\n`, trimmed, blanks dropped)
fn parse_crtsh_payload(body: &str) -> Result<Vec<CtRecord>, DiscoveryError> {
    let rows: Vec<CrtShRow> = serde_json::from_str(body)
        .map_err(|e| DiscoveryError::internal(format!("ct_monitor: parse: {e}")))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let common_name = row.common_name.unwrap_or_default();
        let issuer = row.issuer_name.unwrap_or_default();
        let not_before = parse_crtsh_ts(row.not_before.as_deref())?;
        let not_after = parse_crtsh_ts(row.not_after.as_deref())?;
        let sans = row
            .name_value
            .map(|s| {
                s.split('\n')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        out.push(CtRecord {
            common_name,
            issuer,
            not_before,
            not_after,
            sans,
        });
    }
    Ok(out)
}

/// Parse a `crt.sh` timestamp.
///
/// crt.sh emits two shapes in the wild:
/// * `"2024-01-15T00:00:00"` (naive, treated as UTC)
/// * `"2024-01-15T00:00:00Z"` / `"2024-01-15T00:00:00+00:00"` (ISO 8601)
///
/// Both decode to a UTC [`OffsetDateTime`].
fn parse_crtsh_ts(raw: Option<&str>) -> Result<OffsetDateTime, DiscoveryError> {
    let raw =
        raw.ok_or_else(|| DiscoveryError::internal("ct_monitor: parse: missing timestamp"))?;
    if let Ok(odt) = OffsetDateTime::parse(raw, &Iso8601::DEFAULT) {
        return Ok(odt);
    }
    let naive_fmt = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    let pdt = PrimitiveDateTime::parse(raw, naive_fmt)
        .map_err(|e| DiscoveryError::internal(format!("ct_monitor: parse: ts '{raw}': {e}")))?;
    Ok(pdt.assume_offset(UtcOffset::UTC))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use time::macros::datetime;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client() -> Client {
        Client::builder().build().unwrap()
    }

    const THREE_RECORDS: &str = r#"[
        {
            "common_name": "a.example.com",
            "issuer_name": "Let's Encrypt R3",
            "name_value": "a.example.com\nwww.a.example.com",
            "not_before": "2024-01-15T00:00:00",
            "not_after": "2024-04-15T00:00:00"
        },
        {
            "common_name": "b.example.com",
            "issuer_name": "DigiCert TLS",
            "name_value": "b.example.com",
            "not_before": "2024-02-20T12:00:00Z",
            "not_after": "2024-05-20T12:00:00Z"
        },
        {
            "common_name": "c.example.com",
            "issuer_name": "Sectigo",
            "name_value": "c.example.com\napi.c.example.com\nmail.c.example.com",
            "not_before": "2024-03-01T08:30:00",
            "not_after": "2024-06-01T08:30:00"
        }
    ]"#;

    #[tokio::test]
    async fn parses_three_records() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(THREE_RECORDS))
            .mount(&server)
            .await;

        let base = Url::parse(&server.uri()).unwrap();
        let mon = CtLogMonitor::new(client(), base);
        let recs = mon
            .list_new("example.com", datetime!(2000-01-01 0:00 UTC))
            .await
            .unwrap();

        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].common_name, "a.example.com");
        assert_eq!(recs[0].issuer, "Let's Encrypt R3");
        assert_eq!(recs[0].sans, vec!["a.example.com", "www.a.example.com"]);
        assert_eq!(recs[1].sans, vec!["b.example.com"]);
        assert_eq!(recs[2].sans.len(), 3);
    }

    #[tokio::test]
    async fn empty_array_yields_empty_vec() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;
        let mon = CtLogMonitor::new(client(), Url::parse(&server.uri()).unwrap());
        let recs = mon
            .list_new("nothing.example", datetime!(2000-01-01 0:00 UTC))
            .await
            .unwrap();
        assert!(recs.is_empty());
    }

    #[tokio::test]
    async fn malformed_json_is_parse_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not json"))
            .mount(&server)
            .await;
        let mon = CtLogMonitor::new(client(), Url::parse(&server.uri()).unwrap());
        let err = mon
            .list_new("x.example", datetime!(2000-01-01 0:00 UTC))
            .await
            .unwrap_err();
        match err {
            DiscoveryError::Internal(msg) => {
                assert!(msg.starts_with("ct_monitor: parse"), "got {msg}");
            }
            other => panic!("expected Internal parse error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn since_ts_filters_records() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(THREE_RECORDS))
            .mount(&server)
            .await;
        let mon = CtLogMonitor::new(client(), Url::parse(&server.uri()).unwrap());
        // Keep only records issued from 2024-02-15 onward → drops the first.
        let recs = mon
            .list_new("example.com", datetime!(2024-02-15 0:00 UTC))
            .await
            .unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].common_name, "b.example.com");
        assert_eq!(recs[1].common_name, "c.example.com");
    }

    #[test]
    fn build_query_url_appends_params() {
        let mon = CtLogMonitor::new(client(), Url::parse("https://crt.sh/").unwrap());
        let url = mon.build_query_url("example.com");
        let s = url.as_str();
        assert!(s.contains("output=json"));
        assert!(s.contains("q=example.com"));
    }

    #[test]
    fn parses_ts_both_shapes() {
        let a = parse_crtsh_ts(Some("2024-01-15T00:00:00")).unwrap();
        let b = parse_crtsh_ts(Some("2024-02-20T12:00:00Z")).unwrap();
        assert_eq!(a, datetime!(2024-01-15 0:00 UTC));
        assert_eq!(b, datetime!(2024-02-20 12:00 UTC));
    }
}
