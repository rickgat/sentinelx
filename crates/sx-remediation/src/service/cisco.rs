//! Cisco PSIRT advisory source.
//!
//! Endpoint:
//! `https://apix.cisco.com/security/advisories/v2/cvrf/cve/<CVE>`.
//!
//! The PSIRT API is token-gated. When [`CiscoSource`] is constructed
//! *without* a bearer token, [`CiscoSource::fetch_by_cve`] returns the
//! [`RemediationError::NotFound`] stub — the registry will quietly drop
//! the source. When constructed with a token, the request is issued with
//! an `Authorization: Bearer …` header.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sx_core::prelude::CveId;
use time::OffsetDateTime;
use url::Url;

use crate::error::RemediationError;
use crate::model::advisory::{Patch, VendorAdvisory};
use crate::service::source::VendorAdvisorySource;
use crate::service::{DEFAULT_TIMEOUT_SECS, USER_AGENT};

/// Slug used by [`VendorAdvisorySource::vendor`].
pub const VENDOR: &str = "cisco";

const BASE_URL: &str = "https://apix.cisco.com/security/advisories/v2/cvrf/cve/";

/// Cisco PSIRT advisory source.
pub struct CiscoSource {
    http: reqwest::Client,
    base_url: String,
    bearer: Option<SecretString>,
}

impl std::fmt::Debug for CiscoSource {
    // Custom Debug intentionally omits `http`; redacts `bearer`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CiscoSource")
            .field("base_url", &self.base_url)
            .field(
                "bearer",
                &if self.bearer.is_some() {
                    "<set>"
                } else {
                    "<unset>"
                },
            )
            .finish_non_exhaustive()
    }
}

impl CiscoSource {
    /// Build with the standard client and an optional bearer token.
    pub fn new(bearer: Option<SecretString>) -> Result<Self, RemediationError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;
        Ok(Self {
            http,
            base_url: BASE_URL.to_string(),
            bearer,
        })
    }

    /// Build with a supplied client (tests).
    #[must_use]
    pub fn with_client(http: reqwest::Client, bearer: Option<SecretString>) -> Self {
        Self {
            http,
            base_url: BASE_URL.to_string(),
            bearer,
        }
    }

    /// Override the base URL (tests).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn build_url(&self, cve: &CveId) -> Result<Url, RemediationError> {
        let raw = format!("{}{}", self.base_url, cve.as_str());
        Url::parse(&raw).map_err(|e| RemediationError::UrlBuild(e.to_string()))
    }

    /// Parse a PSIRT CVRF-JSON payload.
    pub fn parse_payload(
        cve: &CveId,
        payload: &str,
    ) -> Result<Vec<VendorAdvisory>, RemediationError> {
        let parsed: CiscoPayload = serde_json::from_str(payload)
            .map_err(|e| RemediationError::malformed(VENDOR, e.to_string()))?;
        let mut out = Vec::with_capacity(parsed.advisories.len());
        for a in parsed.advisories {
            let references: Vec<Url> = a
                .url
                .iter()
                .chain(a.publication_url.iter())
                .filter_map(|u| Url::parse(u).ok())
                .collect();
            let published_at = a
                .first_published
                .as_deref()
                .and_then(|s| {
                    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
                })
                .unwrap_or(OffsetDateTime::UNIX_EPOCH);
            let patches = a
                .ips_signatures
                .into_iter()
                .map(|p| Patch::new(p.id, p.description.unwrap_or_default(), None))
                .collect();
            out.push(VendorAdvisory::new(
                VENDOR,
                a.advisory_id,
                vec![cve.clone()],
                patches,
                references,
                published_at,
            ));
        }
        Ok(out)
    }
}

#[async_trait]
impl VendorAdvisorySource for CiscoSource {
    fn vendor(&self) -> &'static str {
        VENDOR
    }

    async fn fetch_by_cve(&self, cve: &CveId) -> Result<Vec<VendorAdvisory>, RemediationError> {
        let Some(bearer) = self.bearer.as_ref() else {
            // Phase-2 stub: no token, no traffic. Return the canonical
            // "no record" signal so the registry treats Cisco as silently
            // absent.
            return Err(RemediationError::NotFound(VENDOR));
        };
        let url = self.build_url(cve)?;
        let resp = self
            .http
            .get(url)
            .bearer_auth(bearer.expose_secret())
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
struct CiscoPayload {
    #[serde(default)]
    advisories: Vec<CiscoAdvisory>,
}

#[derive(Debug, Deserialize)]
struct CiscoAdvisory {
    #[serde(rename = "advisoryId")]
    advisory_id: String,
    #[serde(default, rename = "firstPublished")]
    first_published: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "publicationUrl")]
    publication_url: Option<String>,
    #[serde(default, rename = "ipsSignatures")]
    ips_signatures: Vec<CiscoSignature>,
}

#[derive(Debug, Deserialize)]
struct CiscoSignature {
    id: String,
    #[serde(default)]
    description: Option<String>,
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

    #[tokio::test]
    async fn cisco_without_token_returns_not_found_stub() {
        let s = CiscoSource::with_client(reqwest::Client::new(), None);
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let err = s.fetch_by_cve(&cve).await.unwrap_err();
        match err {
            RemediationError::NotFound(v) => assert_eq!(v, "cisco"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cisco_url_builder() {
        let s = CiscoSource::with_client(reqwest::Client::new(), None);
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let url = s.build_url(&cve).unwrap();
        assert!(url.as_str().ends_with("CVE-2024-12345"));
    }

    #[test]
    fn cisco_parses_payload() {
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let payload = r#"{
            "advisories": [{
                "advisoryId": "cisco-sa-2024-rce",
                "firstPublished": "2024-04-01T00:00:00Z",
                "url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-2024-rce",
                "ipsSignatures": []
            }]
        }"#;
        let out = CiscoSource::parse_payload(&cve, payload).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].advisory_id, "cisco-sa-2024-rce");
        assert_eq!(out[0].references.len(), 1);
    }

    #[test]
    fn debug_does_not_leak_bearer() {
        let s = CiscoSource::with_client(
            reqwest::Client::new(),
            Some(SecretString::from("super-secret".to_string())),
        );
        let d = format!("{s:?}");
        assert!(!d.contains("super-secret"));
    }
}
