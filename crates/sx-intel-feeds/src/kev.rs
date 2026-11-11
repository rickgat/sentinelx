//! CISA KEV (Known Exploited Vulnerabilities) catalogue fetcher (P0-006).
//!
//! Single GET against
//! <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>.
//! No pagination, no auth, no rate limit. The scheduler refreshes the
//! catalogue on a 1-hour cadence.
//!
//! The output is `(cve_id, kev_added_at)` per row — the merger in
//! [`crate::cve_master`] joins it against the NVD slice and flips the
//! `kev` flag.

use reqwest::Client;
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{debug, warn};

use crate::cve_master::CveMasterError;

/// Default URL for the CISA KEV catalogue.
pub const KEV_DEFAULT_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Fetcher for the CISA KEV catalogue.
#[derive(Debug, Clone)]
pub struct KevFetcher {
    http: Client,
    url: String,
}

impl KevFetcher {
    /// Construct a fetcher pointed at the public CISA KEV URL.
    #[must_use]
    pub fn new(http: Client) -> Self {
        Self {
            http,
            url: KEV_DEFAULT_URL.to_owned(),
        }
    }

    /// Override the KEV URL. Used by tests.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    /// Pull the KEV catalogue. Returns `(cve_id, kev_added_at)` for each row.
    pub async fn fetch(&self) -> Result<Vec<(String, OffsetDateTime)>, CveMasterError> {
        debug!(url = %self.url, "KEV fetch");
        let resp = self.http.get(&self.url).send().await?;
        if !resp.status().is_success() {
            return Err(CveMasterError::Status {
                status: resp.status(),
            });
        }
        let body: KevCatalog = resp.json().await?;
        let mut out = Vec::with_capacity(body.vulnerabilities.len());
        for v in body.vulnerabilities {
            match parse_kev_date(&v.date_added) {
                Ok(t) => out.push((v.cve_id, t)),
                Err(e) => warn!(cve = %v.cve_id, error = %e, "skipping KEV row with bad dateAdded"),
            }
        }
        Ok(out)
    }
}

#[derive(Debug, Deserialize)]
struct KevCatalog {
    #[serde(default)]
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
}

/// KEV `dateAdded` is `YYYY-MM-DD` — promote to midnight UTC.
fn parse_kev_date(raw: &str) -> Result<OffsetDateTime, CveMasterError> {
    let with_time = format!("{raw}T00:00:00Z");
    OffsetDateTime::parse(&with_time, &Rfc3339)
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn http() -> Client {
        Client::new()
    }

    #[tokio::test]
    async fn fetch_happy() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "title": "CISA KEV",
            "vulnerabilities": [
                { "cveID": "CVE-2024-0001", "dateAdded": "2024-06-10",
                  "vendorProject": "v", "product": "p", "vulnerabilityName": "n",
                  "shortDescription": "s", "requiredAction": "r", "dueDate": "2024-07-01" },
                { "cveID": "CVE-2023-9999", "dateAdded": "2023-12-31",
                  "vendorProject": "v", "product": "p", "vulnerabilityName": "n",
                  "shortDescription": "s", "requiredAction": "r", "dueDate": "2024-01-31" }
            ]
        });
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let fetcher = KevFetcher::new(http()).with_url(format!("{}/kev.json", server.uri()));
        let rows = fetcher.fetch().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "CVE-2024-0001");
        assert_eq!(rows[0].1, datetime!(2024-06-10 0:00 UTC));
        assert_eq!(rows[1].0, "CVE-2023-9999");
        assert_eq!(rows[1].1, datetime!(2023-12-31 0:00 UTC));
    }

    #[tokio::test]
    async fn fetch_non_2xx_returns_status_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let fetcher = KevFetcher::new(http()).with_url(format!("{}/kev.json", server.uri()));
        let err = fetcher.fetch().await.unwrap_err();
        match err {
            CveMasterError::Status { status } => assert_eq!(status.as_u16(), 503),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_skips_rows_with_bad_dates() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "vulnerabilities": [
                { "cveID": "CVE-2024-0001", "dateAdded": "2024-06-10" },
                { "cveID": "CVE-2024-0002", "dateAdded": "not-a-date" }
            ]
        });
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let fetcher = KevFetcher::new(http()).with_url(format!("{}/kev.json", server.uri()));
        let rows = fetcher.fetch().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "CVE-2024-0001");
    }
}
