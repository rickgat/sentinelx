//! Ubuntu Security Notice (USN) advisory source.
//!
//! USN documents are available at
//! `https://ubuntu.com/security/notices/<USN>.json`. The trait contract
//! looks up advisories *by CVE*, so this source consults the public CVE
//! lookup
//! `https://ubuntu.com/security/cves/<CVE>.json` and follows the
//! `notices` field. We collapse that two-step into a single async path.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use sx_core::prelude::CveId;
use time::OffsetDateTime;
use url::Url;

use crate::error::RemediationError;
use crate::model::advisory::{Patch, VendorAdvisory};
use crate::service::source::VendorAdvisorySource;
use crate::service::{DEFAULT_TIMEOUT_SECS, USER_AGENT};

/// Slug used by [`VendorAdvisorySource::vendor`].
pub const VENDOR: &str = "ubuntu";

const BASE_CVE_URL: &str = "https://ubuntu.com/security/cves/";
const BASE_NOTICE_URL: &str = "https://ubuntu.com/security/notices/";

/// Ubuntu USN advisory source.
#[derive(Debug, Clone)]
pub struct UbuntuSource {
    http: reqwest::Client,
    base_cve: String,
    base_notice: String,
}

impl UbuntuSource {
    /// Build with the standard client.
    pub fn new() -> Result<Self, RemediationError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;
        Ok(Self {
            http,
            base_cve: BASE_CVE_URL.to_string(),
            base_notice: BASE_NOTICE_URL.to_string(),
        })
    }

    /// Build with a supplied client (tests).
    #[must_use]
    pub fn with_client(http: reqwest::Client) -> Self {
        Self {
            http,
            base_cve: BASE_CVE_URL.to_string(),
            base_notice: BASE_NOTICE_URL.to_string(),
        }
    }

    /// Override both base URLs (tests).
    #[must_use]
    pub fn with_base_urls(
        mut self,
        base_cve: impl Into<String>,
        base_notice: impl Into<String>,
    ) -> Self {
        self.base_cve = base_cve.into();
        self.base_notice = base_notice.into();
        self
    }

    fn build_cve_url(&self, cve: &CveId) -> Result<Url, RemediationError> {
        let raw = format!("{}{}.json", self.base_cve, cve.as_str());
        Url::parse(&raw).map_err(|e| RemediationError::UrlBuild(e.to_string()))
    }

    fn build_notice_url(&self, usn: &str) -> Result<Url, RemediationError> {
        let raw = format!("{}{}.json", self.base_notice, usn);
        Url::parse(&raw).map_err(|e| RemediationError::UrlBuild(e.to_string()))
    }

    /// Parse a USN payload.
    pub fn parse_notice(cve: &CveId, payload: &str) -> Result<VendorAdvisory, RemediationError> {
        let parsed: UbuntuNotice = serde_json::from_str(payload)
            .map_err(|e| RemediationError::malformed(VENDOR, e.to_string()))?;

        let id = parsed
            .id
            .clone()
            .unwrap_or_else(|| format!("USN:{}", cve.as_str()));

        let references: Vec<Url> = parsed
            .references
            .iter()
            .filter_map(|r| Url::parse(r).ok())
            .collect();

        let patches: Vec<Patch> = parsed
            .release_packages
            .iter()
            .flat_map(|(release, pkgs)| {
                pkgs.iter().map(move |p| {
                    Patch::new(
                        format!("{}:{}", release, p.name),
                        p.version.clone().unwrap_or_default(),
                        None,
                    )
                })
            })
            .collect();

        let published_at = parsed
            .published
            .as_deref()
            .and_then(|s| {
                OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
            })
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);

        Ok(VendorAdvisory::new(
            VENDOR,
            id,
            vec![cve.clone()],
            patches,
            references,
            published_at,
        ))
    }
}

#[async_trait]
impl VendorAdvisorySource for UbuntuSource {
    fn vendor(&self) -> &'static str {
        VENDOR
    }

    async fn fetch_by_cve(&self, cve: &CveId) -> Result<Vec<VendorAdvisory>, RemediationError> {
        let cve_url = self.build_cve_url(cve)?;
        let cve_resp = self
            .http
            .get(cve_url)
            .send()
            .await
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;

        let status = cve_resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(RemediationError::NotFound(VENDOR));
        }
        if !status.is_success() {
            return Err(RemediationError::transport(
                VENDOR,
                format!("status {status}"),
            ));
        }

        let cve_body = cve_resp
            .text()
            .await
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;
        let cve_doc: UbuntuCve = serde_json::from_str(&cve_body)
            .map_err(|e| RemediationError::malformed(VENDOR, e.to_string()))?;

        let mut out = Vec::with_capacity(cve_doc.notices.len());
        for usn in &cve_doc.notices {
            let url = self.build_notice_url(usn)?;
            let resp = self
                .http
                .get(url)
                .send()
                .await
                .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;
            if !resp.status().is_success() {
                tracing::warn!(target: "sx_remediation::ubuntu", usn = %usn, status = %resp.status(), "skipping notice");
                continue;
            }
            let body = resp
                .text()
                .await
                .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;
            out.push(Self::parse_notice(cve, &body)?);
        }
        Ok(out)
    }
}

#[derive(Debug, Deserialize)]
struct UbuntuCve {
    #[serde(default)]
    notices: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UbuntuNotice {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    release_packages: std::collections::BTreeMap<String, Vec<UbuntuPackage>>,
}

#[derive(Debug, Deserialize)]
struct UbuntuPackage {
    name: String,
    #[serde(default)]
    version: Option<String>,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::single_char_pattern,
    clippy::single_char_add_str,
    clippy::float_cmp,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    const USN_FIXTURE: &str = r#"
    {
        "id": "USN-1234-1",
        "published": "2024-03-04T08:00:00Z",
        "references": [
            "https://ubuntu.com/security/notices/USN-1234-1",
            "https://ubuntu.com/security/CVE-2024-12345"
        ],
        "release_packages": {
            "jammy": [{"name": "openssl", "version": "3.0.13-1"}],
            "focal": [{"name": "openssl", "version": "1.1.1n-0ubuntu1"}]
        }
    }
    "#;

    #[test]
    fn ubuntu_parses_notice() {
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let adv = UbuntuSource::parse_notice(&cve, USN_FIXTURE).unwrap();
        assert_eq!(adv.vendor, "ubuntu");
        assert_eq!(adv.advisory_id, "USN-1234-1");
        assert_eq!(adv.references.len(), 2);
        assert_eq!(adv.patches.len(), 2);
    }

    #[test]
    fn ubuntu_url_builders() {
        let s = UbuntuSource::with_client(reqwest::Client::new());
        let cve = CveId::new("CVE-2024-12345").unwrap();
        assert!(s
            .build_cve_url(&cve)
            .unwrap()
            .as_str()
            .ends_with("CVE-2024-12345.json"));
        assert!(s
            .build_notice_url("USN-1234-1")
            .unwrap()
            .as_str()
            .ends_with("USN-1234-1.json"));
    }
}
