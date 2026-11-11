//! NVD CVE 2.0 API client (P0-006).
//!
//! Pulls CVE descriptive metadata + CVSS v3/v4 vectors and scores from the
//! NIST National Vulnerability Database REST API. Paginates by
//! `startIndex` / `resultsPerPage`, respecting NVD's published rate limits:
//!
//! | Auth state | Quota |
//! |---|---|
//! | No `apiKey` header | 5 requests / 30 s |
//! | With `apiKey` header | 50 requests / 30 s |
//!
//! [`NvdFetcher`] enforces these via a [`crate::rate_limit::TokenBucket`]
//! shared across pages. Callers configure the API key via
//! [`NvdFetcher::with_api_key`]; the key is wrapped in
//! [`secrecy::SecretString`] and only exposed inside the `apiKey` header
//! at the moment a request is sent — never logged.
//!
//! ## Backfill
//!
//! [`NvdFetcher::fetch_since`] is the incremental sweeper: it takes a
//! high-water-mark and pulls every CVE last-modified at-or-after that
//! timestamp. For the historical 5-year backfill the scheduler simply
//! calls `fetch_since(now - 5y)`; for subsequent incremental sweeps it
//! calls `fetch_since(last_synced_at)`.

use std::time::Duration;

use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{debug, warn};

use crate::cve_master::{CveMasterError, CveMasterRow};
use crate::rate_limit::TokenBucket;

/// Default base URL for the NVD CVE 2.0 API.
pub const NVD_DEFAULT_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// NVD page size. The API caps this at 2000; 200 balances roundtrips
/// against the 5 req / 30 s unauth rate limit.
pub const NVD_PAGE_SIZE: u32 = 200;

/// Header name carrying the NVD API key.
const NVD_API_KEY_HEADER: &str = "apiKey";

/// Fetcher for the NVD CVE 2.0 API.
///
/// Cheap to clone. Holds a `reqwest::Client`, a base URL, an optional
/// `apiKey` secret, and a shared [`TokenBucket`] sized for the matching
/// rate-limit tier.
#[derive(Debug, Clone)]
pub struct NvdFetcher {
    http: Client,
    base: String,
    api_key: Option<SecretString>,
    bucket: TokenBucket,
}

impl NvdFetcher {
    /// Construct a fetcher pointed at the public NVD endpoint, with the
    /// conservative unauthenticated rate-limit bucket (5 req / 30 s).
    #[must_use]
    pub fn new(http: Client) -> Self {
        Self {
            http,
            base: NVD_DEFAULT_BASE.to_owned(),
            api_key: None,
            bucket: TokenBucket::nvd_unauth(),
        }
    }

    /// Override the API base URL. Used by tests to point at a mock server.
    #[must_use]
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    /// Attach an NVD API key. Upgrades the internal rate-limit bucket
    /// from 5 req / 30 s to 50 req / 30 s.
    ///
    /// The key is wrapped in [`SecretString`] and only exposed inside the
    /// `apiKey` header at the moment the request is sent.
    #[must_use]
    pub fn with_api_key(mut self, api_key: SecretString) -> Self {
        self.api_key = Some(api_key);
        self.bucket = TokenBucket::nvd_with_key();
        self
    }

    /// Replace the internal token bucket. Tests use this to bypass the
    /// rate limiter (zero-capacity bucket would never serve a token, so
    /// this is also how operators inject a faster bucket if NVD raises
    /// the limit upstream).
    #[must_use]
    pub fn with_bucket(mut self, bucket: TokenBucket) -> Self {
        self.bucket = bucket;
        self
    }

    /// Whether the fetcher is configured with an API key.
    #[must_use]
    pub const fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    /// Fetch every CVE last-modified on or after `since`, paginating until
    /// the API reports no further results.
    ///
    /// Each request acquires a token from the shared bucket *before*
    /// sending, so a multi-page sweep automatically smears requests across
    /// the rate-limit window.
    #[allow(clippy::cognitive_complexity)]
    pub async fn fetch_since(
        &self,
        since: OffsetDateTime,
    ) -> Result<Vec<CveMasterRow>, CveMasterError> {
        let since_str = since
            .format(&Rfc3339)
            .map_err(|e| CveMasterError::BadTimestamp(since.to_string(), e.to_string()))?;
        let mut out = Vec::new();
        let mut start_index: u32 = 0;
        let mut page_no: u32 = 0;
        loop {
            // Wait for a token *before* every request, including the
            // first — the bucket starts full so the first burst is free.
            self.bucket.acquire().await;

            let url = format!(
                "{base}?lastModStartDate={since}&resultsPerPage={size}&startIndex={start}",
                base = self.base,
                since = since_str,
                size = NVD_PAGE_SIZE,
                start = start_index,
            );
            debug!(%url, page = page_no, "NVD page fetch");
            let mut req = self.http.get(&url);
            if let Some(key) = &self.api_key {
                req = req.header(NVD_API_KEY_HEADER, key.expose_secret());
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                // 403/429 most commonly indicate we burst over the soft
                // limit. Surface the status; the caller can decide whether
                // to retry with a wider window.
                if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
                    warn!(%status, "NVD rate-limit response — caller should retry");
                }
                return Err(CveMasterError::Status { status });
            }
            let body: NvdResponse = resp.json().await?;
            let count = u32::try_from(body.vulnerabilities.len()).unwrap_or(u32::MAX);
            for v in body.vulnerabilities {
                match nvd_to_row(&v.cve) {
                    Ok(row) => out.push(row),
                    Err(e) => warn!(error = %e, "skipping malformed NVD CVE row"),
                }
            }
            page_no = page_no.saturating_add(1);
            start_index = start_index.saturating_add(count);
            let total = body.total_results;
            if count == 0 || start_index >= total {
                break;
            }
        }
        Ok(out)
    }
}

/// Default minimum delay between unauthenticated NVD pages. Surface kept
/// for backwards-compatibility with older callers; the modern code path
/// uses the [`TokenBucket`] internally.
pub const NVD_UNAUTH_DELAY: Duration = Duration::from_millis(6_500);

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default, rename = "totalResults")]
    total_results: u32,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnEnvelope>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnEnvelope {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(default, rename = "lastModified")]
    last_modified: Option<String>,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: Option<NvdMetrics>,
    #[serde(default)]
    configurations: Vec<NvdConfiguration>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Default, Deserialize)]
#[allow(clippy::struct_field_names)]
struct NvdMetrics {
    #[serde(default, rename = "cvssMetricV31")]
    cvss_v31: Vec<NvdCvssEntry>,
    #[serde(default, rename = "cvssMetricV30")]
    cvss_v30: Vec<NvdCvssEntry>,
    #[serde(default, rename = "cvssMetricV40")]
    cvss_v40: Vec<NvdCvssEntry>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssEntry {
    #[serde(default, rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Default, Deserialize)]
struct NvdCvssData {
    #[serde(default, rename = "baseScore")]
    base_score: Option<f32>,
    #[serde(default, rename = "vectorString")]
    vector_string: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdConfiguration {
    #[serde(default)]
    nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
struct NvdNode {
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<NvdCpeMatch>,
    #[serde(default)]
    children: Vec<Self>,
}

#[derive(Debug, Deserialize)]
struct NvdCpeMatch {
    #[serde(default)]
    criteria: Option<String>,
}

fn nvd_to_row(cve: &NvdCve) -> Result<CveMasterRow, CveMasterError> {
    let published_raw = cve
        .published
        .as_deref()
        .ok_or_else(|| CveMasterError::BadTimestamp(cve.id.clone(), "missing published".into()))?;
    let last_modified_raw = cve.last_modified.as_deref().ok_or_else(|| {
        CveMasterError::BadTimestamp(cve.id.clone(), "missing lastModified".into())
    })?;
    let published_at = parse_nvd_timestamp(published_raw)?;
    let last_modified_at = parse_nvd_timestamp(last_modified_raw)?;

    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang.eq_ignore_ascii_case("en"))
        .map(|d| d.value.clone())
        .unwrap_or_default();

    let (cvss_v3_score, cvss_v3_vector) = cve
        .metrics
        .as_ref()
        .and_then(|m| first_cvss(&m.cvss_v31).or_else(|| first_cvss(&m.cvss_v30)))
        .map_or((None, None), |(s, v)| (Some(s), Some(v)));

    let (cvss_v4_score, cvss_v4_vector) = cve
        .metrics
        .as_ref()
        .and_then(|m| first_cvss(&m.cvss_v40))
        .map_or((None, None), |(s, v)| (Some(s), Some(v)));

    let mut cpes: Vec<String> = Vec::new();
    for cfg in &cve.configurations {
        for node in &cfg.nodes {
            collect_cpes(node, &mut cpes);
        }
    }
    cpes.sort();
    cpes.dedup();

    Ok(CveMasterRow {
        cve_id: cve.id.clone(),
        published_at,
        last_modified_at,
        cvss_v3_score,
        cvss_v3_vector,
        cvss_v4_score,
        cvss_v4_vector,
        epss: 0.0,
        epss_percentile: 0.0,
        kev: false,
        kev_added_at: None,
        description,
        cpes,
    })
}

fn first_cvss(entries: &[NvdCvssEntry]) -> Option<(f32, String)> {
    entries.iter().find_map(|e| {
        match (e.cvss_data.base_score, e.cvss_data.vector_string.as_ref()) {
            (Some(s), Some(v)) => Some((s, v.clone())),
            _ => None,
        }
    })
}

fn collect_cpes(node: &NvdNode, out: &mut Vec<String>) {
    for m in &node.cpe_match {
        if let Some(c) = &m.criteria {
            out.push(c.clone());
        }
    }
    for child in &node.children {
        collect_cpes(child, out);
    }
}

/// NVD emits timestamps like `2024-06-01T12:34:56.789` (no offset) and
/// occasionally `2024-06-01T12:34:56.789Z`. Try strict RFC 3339 first,
/// then fall back to appending `Z`.
fn parse_nvd_timestamp(raw: &str) -> Result<OffsetDateTime, CveMasterError> {
    if let Ok(t) = OffsetDateTime::parse(raw, &Rfc3339) {
        return Ok(t);
    }
    let with_z = format!("{raw}Z");
    OffsetDateTime::parse(&with_z, &Rfc3339)
        .map_err(|e| CveMasterError::BadTimestamp(raw.to_owned(), e.to_string()))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use time::macros::datetime;
    use wiremock::matchers::{header, header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn http() -> Client {
        Client::new()
    }

    fn fast_bucket() -> TokenBucket {
        TokenBucket::new(100, Duration::from_millis(1))
    }

    fn nvd_envelope_single() -> serde_json::Value {
        serde_json::json!({
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-06-01T12:00:00.000",
                    "lastModified": "2024-06-02T12:00:00.000",
                    "descriptions": [
                        { "lang": "en", "value": "Test CVE description." },
                        { "lang": "es", "value": "Descripción de prueba." }
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                            }
                        }],
                        "cvssMetricV40": [{
                            "cvssData": {
                                "baseScore": 8.2,
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
                            }
                        }]
                    },
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [
                                { "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*" }
                            ],
                            "children": []
                        }]
                    }]
                }
            }]
        })
    }

    #[tokio::test]
    async fn fetch_since_happy_single_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("startIndex", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_envelope_single()))
            .expect(1)
            .mount(&server)
            .await;

        let fetcher = NvdFetcher::new(http())
            .with_base(server.uri())
            .with_bucket(fast_bucket());
        let rows = fetcher
            .fetch_since(datetime!(2024-01-01 0:00 UTC))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.cve_id, "CVE-2024-0001");
        assert_eq!(row.description, "Test CVE description.");
        assert_eq!(row.cvss_v3_score, Some(7.5));
        assert!(row
            .cvss_v3_vector
            .as_deref()
            .unwrap()
            .starts_with("CVSS:3.1"));
        assert_eq!(row.cvss_v4_score, Some(8.2));
        assert_eq!(row.cpes, vec!["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]);
        assert!(!row.kev);
        assert_eq!(row.epss, 0.0);
    }

    #[tokio::test]
    async fn fetch_since_paginates() {
        let server = MockServer::start().await;

        let page_one = serde_json::json!({
            "totalResults": 2,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-06-01T12:00:00.000",
                    "lastModified": "2024-06-02T12:00:00.000",
                    "descriptions": [{ "lang": "en", "value": "first" }],
                    "configurations": []
                }
            }]
        });
        let page_two = serde_json::json!({
            "totalResults": 2,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0002",
                    "published": "2024-06-03T12:00:00.000",
                    "lastModified": "2024-06-04T12:00:00.000",
                    "descriptions": [{ "lang": "en", "value": "second" }],
                    "configurations": []
                }
            }]
        });

        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("startIndex", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page_one))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("startIndex", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page_two))
            .expect(1)
            .mount(&server)
            .await;

        let fetcher = NvdFetcher::new(http())
            .with_base(server.uri())
            .with_bucket(fast_bucket());
        let rows = fetcher
            .fetch_since(datetime!(2024-01-01 0:00 UTC))
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].cve_id, "CVE-2024-0001");
        assert_eq!(rows[1].cve_id, "CVE-2024-0002");
    }

    #[tokio::test]
    async fn fetch_with_api_key_sends_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .and(header_exists("apiKey"))
            .and(header("apiKey", "test-key-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_envelope_single()))
            .expect(1)
            .mount(&server)
            .await;

        let fetcher = NvdFetcher::new(http())
            .with_base(server.uri())
            .with_api_key(SecretString::from("test-key-123".to_owned()))
            .with_bucket(fast_bucket());
        assert!(fetcher.has_api_key());
        let rows = fetcher
            .fetch_since(datetime!(2024-01-01 0:00 UTC))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn fetch_propagates_rate_limit_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(429))
            .expect(1)
            .mount(&server)
            .await;

        let fetcher = NvdFetcher::new(http())
            .with_base(server.uri())
            .with_bucket(fast_bucket());
        let err = fetcher
            .fetch_since(datetime!(2024-01-01 0:00 UTC))
            .await
            .unwrap_err();
        match err {
            CveMasterError::Status { status } => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
