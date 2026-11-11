//! FIRST EPSS daily score fetcher (P0-006).
//!
//! Pulls the EPSS (Exploit Prediction Scoring System) daily CSV from
//! `https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz`. The blob is
//! gzipped, no authentication, no rate limit. Parsed via the `csv` crate
//! and surfaced as `(cve_id, epss, percentile)` tuples.
//!
//! The feed is published once per day around 04:00 UTC. The scheduler
//! polls on a daily cadence — operators may set a custom cadence via the
//! `intel_feeds.poll_interval_secs` configuration knob (which also governs
//! the NVD incremental sweep).

use std::io::Read;

use reqwest::Client;
use tracing::{debug, warn};

use crate::cve_master::CveMasterError;

/// Default URL template for the daily EPSS scores CSV.
///
/// `{date}` is replaced with `YYYY-MM-DD`.
pub const EPSS_DEFAULT_TEMPLATE: &str = "https://epss.cyentia.com/epss_scores-{date}.csv.gz";

/// Fetcher for the FIRST EPSS daily score CSV.
#[derive(Debug, Clone)]
pub struct EpssFetcher {
    http: Client,
    template: String,
}

impl EpssFetcher {
    /// Construct a fetcher with the public EPSS URL template.
    #[must_use]
    pub fn new(http: Client) -> Self {
        Self {
            http,
            template: EPSS_DEFAULT_TEMPLATE.to_owned(),
        }
    }

    /// Override the URL template (must contain `{date}`). Used by tests.
    #[must_use]
    pub fn with_template(mut self, template: impl Into<String>) -> Self {
        self.template = template.into();
        self
    }

    /// Pull the EPSS CSV for `date` (formatted as `YYYY-MM-DD`).
    ///
    /// Returns `(cve_id, epss, percentile)` per row. Rows whose numeric
    /// fields fail to parse are dropped with a warning.
    pub async fn fetch_for_date(
        &self,
        date: &str,
    ) -> Result<Vec<(String, f32, f32)>, CveMasterError> {
        // The template carries a literal `{date}` placeholder substituted
        // by `replace` — it is not consumed by `format!`.
        #[allow(clippy::literal_string_with_formatting_args)]
        let url = self.template.replace("{date}", date);
        debug!(%url, "EPSS fetch");
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(CveMasterError::Status {
                status: resp.status(),
            });
        }
        let body = resp.bytes().await?;
        parse_epss_csv_gz(&body)
    }
}

/// Decode the gzipped EPSS CSV blob and parse it.
///
/// Exposed `pub(crate)` so tests can exercise the parser without setting
/// up a mock HTTP server.
pub(crate) fn parse_epss_csv_gz(blob: &[u8]) -> Result<Vec<(String, f32, f32)>, CveMasterError> {
    let mut decoder = flate2::read::GzDecoder::new(blob);
    let mut raw = String::new();
    decoder
        .read_to_string(&mut raw)
        .map_err(CveMasterError::Gzip)?;
    parse_epss_csv(&raw)
}

/// Parse a decompressed EPSS CSV string. The official feed has a comment
/// header line beginning with `#` and a column header line
/// `cve,epss,percentile`.
pub(crate) fn parse_epss_csv(raw: &str) -> Result<Vec<(String, f32, f32)>, CveMasterError> {
    // Strip leading comment lines (the feed starts with `#model_version:…`).
    let cleaned: String = raw
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(cleaned.as_bytes());
    let mut out = Vec::new();
    for record in rdr.records() {
        let r = record?;
        let cve = r.get(0).unwrap_or("").trim().to_owned();
        let epss_raw = r.get(1).unwrap_or("").trim();
        let pct_raw = r.get(2).unwrap_or("").trim();
        if cve.is_empty() {
            continue;
        }
        let epss = match epss_raw.parse::<f32>() {
            Ok(v) => v,
            Err(e) => {
                warn!(cve, value = epss_raw, error = %e, "skipping EPSS row with bad epss");
                continue;
            }
        };
        let pct = match pct_raw.parse::<f32>() {
            Ok(v) => v,
            Err(e) => {
                warn!(cve, value = pct_raw, error = %e, "skipping EPSS row with bad percentile");
                continue;
            }
        };
        out.push((cve, epss, pct));
    }
    Ok(out)
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
    use std::io::Write;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn http() -> Client {
        Client::new()
    }

    fn gzip_csv(csv: &str) -> Vec<u8> {
        let mut gz = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            encoder.write_all(csv.as_bytes()).unwrap();
            encoder.finish().unwrap();
        }
        gz
    }

    #[test]
    fn parse_csv_gz_round_trip() {
        let csv = "\
#model_version:v2024.04.25,score_date:2024-06-12T00:00:00+0000
cve,epss,percentile
CVE-2024-0001,0.12345,0.98765
CVE-2024-0002,0.00100,0.50000
";
        let rows = parse_epss_csv_gz(&gzip_csv(csv)).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "CVE-2024-0001");
        assert!((rows[0].1 - 0.123_45_f32).abs() < 1e-5);
        assert!((rows[0].2 - 0.987_65_f32).abs() < 1e-5);
        assert_eq!(rows[1].0, "CVE-2024-0002");
    }

    #[test]
    fn parse_csv_skips_unparseable_numeric_fields() {
        let csv = "\
cve,epss,percentile
CVE-2024-0001,0.5,0.5
CVE-2024-0002,bad,0.5
CVE-2024-0003,0.5,bad
";
        let rows = parse_epss_csv(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "CVE-2024-0001");
    }

    #[tokio::test]
    async fn fetch_for_date_downloads_and_decodes() {
        let server = MockServer::start().await;
        let csv = "\
cve,epss,percentile
CVE-2024-1111,0.7,0.95
";
        let body = gzip_csv(csv);
        Mock::given(method("GET"))
            .and(path("/epss_scores-2024-06-12.csv.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(1)
            .mount(&server)
            .await;
        let template = format!("{}/epss_scores-{{date}}.csv.gz", server.uri());
        let fetcher = EpssFetcher::new(http()).with_template(template);
        let rows = fetcher.fetch_for_date("2024-06-12").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "CVE-2024-1111");
    }

    #[tokio::test]
    async fn fetch_for_date_propagates_status_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let template = format!("{}/epss_scores-{{date}}.csv.gz", server.uri());
        let fetcher = EpssFetcher::new(http()).with_template(template);
        let err = fetcher.fetch_for_date("1999-01-01").await.unwrap_err();
        assert!(matches!(err, CveMasterError::Status { .. }));
    }
}
