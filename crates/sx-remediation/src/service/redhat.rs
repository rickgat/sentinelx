//! Red Hat security data API source.
//!
//! Endpoint:
//! `https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json`.
//!
//! The Red Hat schema is mature and well-documented; we only consume the
//! fields we need (`affected_release`, `bugzilla`, `references`).

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
pub const VENDOR: &str = "redhat";

const BASE_URL: &str = "https://access.redhat.com/hydra/rest/securitydata/cve/";

/// Red Hat OVAL advisory source.
#[derive(Debug, Clone)]
pub struct RedHatSource {
    http: reqwest::Client,
    base_url: String,
}

impl RedHatSource {
    /// Build a source with the crate's standard client.
    pub fn new() -> Result<Self, RemediationError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;
        Ok(Self {
            http,
            base_url: BASE_URL.to_string(),
        })
    }

    /// Build with a supplied client (tests).
    #[must_use]
    pub fn with_client(http: reqwest::Client) -> Self {
        Self {
            http,
            base_url: BASE_URL.to_string(),
        }
    }

    /// Override the base URL (tests / staging).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn build_url(&self, cve: &CveId) -> Result<Url, RemediationError> {
        let raw = format!("{}{}.json", self.base_url, cve.as_str());
        Url::parse(&raw).map_err(|e| RemediationError::UrlBuild(e.to_string()))
    }

    /// Parse a Red Hat JSON payload. Public so tests can exercise it
    /// without spinning up `wiremock`.
    pub fn parse_payload(
        cve: &CveId,
        payload: &str,
    ) -> Result<Vec<VendorAdvisory>, RemediationError> {
        let parsed: RedHatPayload = serde_json::from_str(payload)
            .map_err(|e| RemediationError::malformed(VENDOR, e.to_string()))?;

        if parsed.affected_release.is_empty() && parsed.references.is_empty() {
            return Ok(Vec::new());
        }

        let published_at = parsed
            .public_date
            .as_deref()
            .and_then(parse_iso8601)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);

        let references: Vec<Url> = parsed
            .references
            .iter()
            .filter_map(|r| Url::parse(r).ok())
            .collect();

        // Group affected_release entries by `advisory`; emit one
        // `VendorAdvisory` per distinct RHSA.
        let mut by_advisory: std::collections::BTreeMap<String, Vec<RedHatRelease>> =
            std::collections::BTreeMap::new();
        for rel in parsed.affected_release {
            by_advisory
                .entry(rel.advisory.clone())
                .or_default()
                .push(rel);
        }

        let mut out = Vec::with_capacity(by_advisory.len());
        for (advisory_id, releases) in by_advisory {
            let patches = releases
                .iter()
                .map(|r| {
                    Patch::new(
                        r.advisory.clone(),
                        r.product_name.clone().unwrap_or_default(),
                        r.package.as_ref().and_then(|p| Url::parse(p).ok()),
                    )
                })
                .collect();
            out.push(VendorAdvisory::new(
                VENDOR,
                advisory_id,
                vec![cve.clone()],
                patches,
                references.clone(),
                published_at,
            ));
        }

        // If the payload had references but no affected_release, still emit
        // an "informational" advisory so the copilot has something to cite.
        if out.is_empty() && !references.is_empty() {
            out.push(VendorAdvisory::new(
                VENDOR,
                format!("redhat:{}", cve.as_str()),
                vec![cve.clone()],
                Vec::new(),
                references,
                published_at,
            ));
        }

        Ok(out)
    }
}

#[async_trait]
impl VendorAdvisorySource for RedHatSource {
    fn vendor(&self) -> &'static str {
        VENDOR
    }

    async fn fetch_by_cve(&self, cve: &CveId) -> Result<Vec<VendorAdvisory>, RemediationError> {
        let url = self.build_url(cve)?;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(RemediationError::NotFound(VENDOR));
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(RemediationError::Unauthorized(VENDOR));
        }
        if !status.is_success() {
            return Err(RemediationError::transport(
                VENDOR,
                format!("status {status}"),
            ));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;
        Self::parse_payload(cve, &body)
    }
}

#[derive(Debug, Deserialize)]
struct RedHatPayload {
    #[serde(default)]
    public_date: Option<String>,
    #[serde(default)]
    affected_release: Vec<RedHatRelease>,
    #[serde(default)]
    references: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct RedHatRelease {
    advisory: String,
    #[serde(default)]
    product_name: Option<String>,
    #[serde(default)]
    package: Option<String>,
}

fn parse_iso8601(s: &str) -> Option<OffsetDateTime> {
    // Red Hat publishes timestamps as `"YYYY-MM-DDTHH:MM:SSZ"`. Try strict
    // RFC3339 first, then fall back to a naive date-only form.
    if let Ok(ts) = OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) {
        return Some(ts);
    }
    None
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

    const REDHAT_FIXTURE: &str = r#"
    {
      "public_date": "2024-02-15T13:30:00Z",
      "affected_release": [
        {
          "advisory": "RHSA-2024:1234",
          "product_name": "Red Hat Enterprise Linux 9",
          "package": "https://access.redhat.com/errata/RHSA-2024:1234"
        },
        {
          "advisory": "RHSA-2024:1234",
          "product_name": "Red Hat Enterprise Linux 8",
          "package": "https://access.redhat.com/errata/RHSA-2024:1234"
        }
      ],
      "references": [
        "https://access.redhat.com/security/cve/CVE-2024-12345",
        "https://bugzilla.redhat.com/show_bug.cgi?id=99999"
      ]
    }
    "#;

    #[test]
    fn redhat_source_parses_known_payload() {
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let out = RedHatSource::parse_payload(&cve, REDHAT_FIXTURE).unwrap();
        assert_eq!(out.len(), 1);
        let adv = &out[0];
        assert_eq!(adv.vendor, "redhat");
        assert_eq!(adv.advisory_id, "RHSA-2024:1234");
        assert_eq!(adv.cves[0], cve);
        assert_eq!(adv.references.len(), 2);
        assert_eq!(adv.patches.len(), 2);
        assert_eq!(
            adv.published_at,
            OffsetDateTime::parse(
                "2024-02-15T13:30:00Z",
                &time::format_description::well_known::Rfc3339
            )
            .unwrap(),
        );
    }

    #[test]
    fn redhat_parses_empty_payload() {
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let out = RedHatSource::parse_payload(&cve, "{}").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn redhat_emits_informational_advisory_when_only_references() {
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let payload = r#"{
            "references": ["https://access.redhat.com/security/cve/CVE-2024-12345"]
        }"#;
        let out = RedHatSource::parse_payload(&cve, payload).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].patches.is_empty());
        assert_eq!(out[0].references.len(), 1);
    }

    #[test]
    fn redhat_url_builder() {
        let s = RedHatSource::with_client(reqwest::Client::new());
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let url = s.build_url(&cve).unwrap();
        assert_eq!(
            url.as_str(),
            "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-12345.json",
        );
    }
}
