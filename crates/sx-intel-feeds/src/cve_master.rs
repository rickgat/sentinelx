//! CVE master shared types and merger (P0-006).
//!
//! This module hosts the cross-source primitives consumed by the three
//! per-source fetchers ([`crate::nvd::NvdFetcher`], [`crate::kev::KevFetcher`],
//! [`crate::epss::EpssFetcher`]):
//!
//! * [`CveMasterRow`] — one row of the `cve_master` table.
//! * [`CveMasterError`] — the error enum shared by every fetcher.
//! * [`merge`] — joins an NVD slice with KEV + EPSS side-channels.
//!
//! The split into per-source modules keeps each file's blast radius small:
//! a change to the EPSS CSV format only touches `epss.rs`, an NVD schema
//! tweak only touches `nvd.rs`, etc. The merger is symmetric in the two
//! side-channels: presence flips `kev`/`epss`, absence leaves the column
//! default. Rows present in KEV/EPSS but missing from the NVD slice are
//! dropped — we never invent NVD metadata.

use std::collections::HashMap;

use reqwest::StatusCode;
use thiserror::Error;
use time::OffsetDateTime;

// Re-export the public surfaces from the per-source modules so the
// shorter `sx_intel_feeds::cve_master::NvdFetcher` path keeps compiling
// for existing callers.
pub use crate::epss::{EpssFetcher, EPSS_DEFAULT_TEMPLATE};
pub use crate::kev::{KevFetcher, KEV_DEFAULT_URL};
pub use crate::nvd::{NvdFetcher, NVD_DEFAULT_BASE, NVD_PAGE_SIZE, NVD_UNAUTH_DELAY};

/// One row in the `cve_master` table.
///
/// Mirrors the DDL in `crates/sx-storage/migrations/20260801000000_create_cve_master.sql`
/// 1:1, with optional columns expressed as `Option`s.
#[derive(Debug, Clone, PartialEq)]
pub struct CveMasterRow {
    /// CVE identifier, e.g. `CVE-2024-12345`.
    pub cve_id: String,
    /// First-published timestamp from NVD.
    pub published_at: OffsetDateTime,
    /// Most-recent-modification timestamp from NVD.
    pub last_modified_at: OffsetDateTime,
    /// CVSS v3 base score, if NVD provides one.
    pub cvss_v3_score: Option<f32>,
    /// CVSS v3 vector string, if NVD provides one.
    pub cvss_v3_vector: Option<String>,
    /// CVSS v4 base score, if NVD provides one.
    pub cvss_v4_score: Option<f32>,
    /// CVSS v4 vector string, if NVD provides one.
    pub cvss_v4_vector: Option<String>,
    /// EPSS probability in `[0.0, 1.0]`. Defaults to `0.0` when EPSS has no row.
    pub epss: f32,
    /// EPSS percentile in `[0.0, 1.0]`. Defaults to `0.0` when EPSS has no row.
    pub epss_percentile: f32,
    /// Whether the CVE appears in the CISA KEV catalogue.
    pub kev: bool,
    /// CISA KEV "date added" timestamp, if the CVE is in the catalogue.
    pub kev_added_at: Option<OffsetDateTime>,
    /// Human-readable description (English `en` from NVD's `descriptions[]`).
    pub description: String,
    /// All CPEs covered by the CVE's NVD `configurations[]` tree.
    pub cpes: Vec<String>,
}

impl CveMasterRow {
    /// Compute the canonical `SentinelX` severity bucket for this CVE.
    ///
    /// Priority order:
    /// 1. KEV-listed CVEs always rank `Critical` (CISA's risk model).
    /// 2. CVSS v4 base score (if NVD has one) maps via the FIRST.org
    ///    severity bands.
    /// 3. CVSS v3 base score (if NVD has one) maps via the same bands.
    /// 4. Otherwise `Severity::Info`.
    #[must_use]
    pub fn severity(&self) -> Severity {
        if self.kev {
            return Severity::Critical;
        }
        if let Some(s) = self.cvss_v4_score {
            return Severity::from_cvss(f64::from(s));
        }
        if let Some(s) = self.cvss_v3_score {
            return Severity::from_cvss(f64::from(s));
        }
        Severity::Info
    }
}

/// Canonical `SentinelX` severity bucket.
///
/// Wire-compatible with [`sx_vuln_ingest::Severity`] (`snake_case`
/// serialisation, identical variants), so the recompute hook can copy it
/// across crate boundaries via `as_str()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Informational — no impact, advisory only.
    Info,
    /// Low — defence-in-depth class.
    Low,
    /// Medium — exploitable under non-default conditions.
    Medium,
    /// High — exploitable with material impact.
    High,
    /// Critical — remote unauthenticated exploit, RCE, or KEV-listed.
    Critical,
}

impl Severity {
    /// Wire/storage string representation (`snake_case`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Map a CVSS-style score (0.0..=10.0) onto the enum using the
    /// FIRST.org severity bands.
    #[must_use]
    pub fn from_cvss(score: f64) -> Self {
        if score < 0.1 {
            Self::Info
        } else if score < 4.0 {
            Self::Low
        } else if score < 7.0 {
            Self::Medium
        } else if score < 9.0 {
            Self::High
        } else {
            Self::Critical
        }
    }
}

/// Errors surfaced by the CVE master fetchers and merger.
#[derive(Debug, Error)]
pub enum CveMasterError {
    /// Underlying HTTP transport failure.
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),
    /// Upstream returned a non-2xx status.
    #[error("upstream returned status {status}")]
    Status {
        /// HTTP status code returned by the upstream.
        status: StatusCode,
    },
    /// Response body was not valid JSON of the expected shape.
    #[error("malformed JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A timestamp string was syntactically invalid.
    #[error("bad timestamp `{0}`: {1}")]
    BadTimestamp(String, String),
    /// CSV parsing failed (EPSS).
    #[error("malformed CSV: {0}")]
    Csv(#[from] csv::Error),
    /// gzip decoding failed (EPSS).
    #[error("gzip decode error: {0}")]
    Gzip(std::io::Error),
    /// URL parsing failed.
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
}

/// Join an NVD slice with the KEV + EPSS side-channels.
///
/// * `nvd` is the authoritative list of CVEs. The output preserves its
///   ordering and length — rows present in `kev` or `epss` but missing
///   from `nvd` are dropped.
/// * `kev` maps `cve_id → kev_added_at`. Presence flips the `kev` flag.
/// * `epss` maps `cve_id → (epss, percentile)`. Absence leaves both at
///   `0.0` (the column defaults).
///
/// The `HashMap`s are taken by reference and may use any hasher.
#[must_use]
pub fn merge<S>(
    nvd: Vec<CveMasterRow>,
    kev: &HashMap<String, OffsetDateTime, S>,
    epss: &HashMap<String, (f32, f32), S>,
) -> Vec<CveMasterRow>
where
    S: std::hash::BuildHasher,
{
    nvd.into_iter()
        .map(|mut row| {
            if let Some(added_at) = kev.get(&row.cve_id) {
                row.kev = true;
                row.kev_added_at = Some(*added_at);
            }
            if let Some((score, pct)) = epss.get(&row.cve_id) {
                row.epss = *score;
                row.epss_percentile = *pct;
            }
            row
        })
        .collect()
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

    fn nvd_row(cve_id: &str, v3: Option<f32>) -> CveMasterRow {
        CveMasterRow {
            cve_id: cve_id.to_owned(),
            published_at: datetime!(2024-06-01 0:00 UTC),
            last_modified_at: datetime!(2024-06-01 0:00 UTC),
            cvss_v3_score: v3,
            cvss_v3_vector: v3.map(|_| "CVSS:3.1/…".to_owned()),
            cvss_v4_score: None,
            cvss_v4_vector: None,
            epss: 0.0,
            epss_percentile: 0.0,
            kev: false,
            kev_added_at: None,
            description: cve_id.to_owned(),
            cpes: vec![],
        }
    }

    #[test]
    fn merge_joins_by_cve_id() {
        let nvd = vec![
            nvd_row("CVE-2024-0001", Some(7.5)),
            nvd_row("CVE-2024-0002", None),
        ];

        let mut kev = HashMap::new();
        kev.insert("CVE-2024-0001".to_owned(), datetime!(2024-06-10 0:00 UTC));
        // CVE-2024-9999 has no NVD counterpart → must be dropped.
        kev.insert("CVE-2024-9999".to_owned(), datetime!(2024-06-11 0:00 UTC));

        let mut epss = HashMap::new();
        epss.insert("CVE-2024-0002".to_owned(), (0.42_f32, 0.88_f32));
        epss.insert("CVE-2024-9999".to_owned(), (0.99_f32, 0.99_f32));

        let merged = merge(nvd, &kev, &epss);
        assert_eq!(merged.len(), 2, "merger must not invent rows");

        let r1 = &merged[0];
        assert_eq!(r1.cve_id, "CVE-2024-0001");
        assert!(r1.kev);
        assert_eq!(r1.kev_added_at, Some(datetime!(2024-06-10 0:00 UTC)));
        assert_eq!(r1.epss, 0.0);

        let r2 = &merged[1];
        assert_eq!(r2.cve_id, "CVE-2024-0002");
        assert!(!r2.kev);
        assert_eq!(r2.kev_added_at, None);
        assert!((r2.epss - 0.42_f32).abs() < 1e-5);
        assert!((r2.epss_percentile - 0.88_f32).abs() < 1e-5);
    }

    #[test]
    fn severity_prefers_kev_over_cvss() {
        let mut r = nvd_row("CVE-2024-0001", Some(2.0));
        assert_eq!(r.severity(), Severity::Low);
        r.kev = true;
        assert_eq!(r.severity(), Severity::Critical);
    }

    #[test]
    fn severity_prefers_v4_over_v3() {
        let mut r = nvd_row("CVE-2024-0001", Some(2.0)); // Low band
        r.cvss_v4_score = Some(9.5); // Critical band
        assert_eq!(r.severity(), Severity::Critical);
    }

    #[test]
    fn severity_default_info() {
        let r = nvd_row("CVE-2024-0001", None);
        assert_eq!(r.severity(), Severity::Info);
    }

    #[test]
    fn severity_from_cvss_bands() {
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
        assert_eq!(Severity::from_cvss(3.9), Severity::Low);
        assert_eq!(Severity::from_cvss(4.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(6.9), Severity::Medium);
        assert_eq!(Severity::from_cvss(7.0), Severity::High);
        assert_eq!(Severity::from_cvss(8.9), Severity::High);
        assert_eq!(Severity::from_cvss(9.0), Severity::Critical);
        assert_eq!(Severity::from_cvss(10.0), Severity::Critical);
    }
}
