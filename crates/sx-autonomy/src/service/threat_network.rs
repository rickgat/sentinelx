//! Opt-in anonymised threat-network client.
//!
//! [`ThreatNetworkClient`] forwards aggregated, anonymised
//! vulnerability-frequency observations to a global ledger. The client
//! enforces:
//!
//! - the endpoint must be `https://...` — `http://` is refused before
//!   any network traffic;
//! - the caller must supply a [`TenantConsent`] whose [`SharingScope`]
//!   includes vulnerability-frequency sharing;
//! - tenant identifiers and asset-kind classifiers are hashed with the
//!   per-platform pepper before transmission; the wire body contains no
//!   raw tenant id or asset descriptor;
//! - non-2xx responses surface as [`AutonomyError::NetworkSubmissionFailed`].

use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tracing::{debug, info, warn};
use url::Url;

use crate::error::AutonomyError;
use crate::model::consent::TenantConsent;
use crate::model::threat_share::{AnonymisedObservation, ThreatObservation, ThreatShareBundle};

/// Opt-in client that posts anonymised vulnerability-frequency
/// observations to the configured threat-network endpoint.
#[derive(Debug, Clone)]
pub struct ThreatNetworkClient {
    http: reqwest::Client,
    endpoint: Url,
    pepper: SecretString,
}

impl ThreatNetworkClient {
    /// Build a new client.
    ///
    /// # Errors
    /// Returns [`AutonomyError::InsecureEndpoint`] when `endpoint` is
    /// not an `https://` URL.
    pub fn new(
        http: reqwest::Client,
        endpoint: Url,
        pepper: SecretString,
    ) -> Result<Self, AutonomyError> {
        if endpoint.scheme() != "https" {
            return Err(AutonomyError::InsecureEndpoint);
        }
        Ok(Self {
            http,
            endpoint,
            pepper,
        })
    }

    /// Submit an anonymised batch of observations to the threat network.
    ///
    /// # Errors
    /// - [`AutonomyError::MissingConsent`] when the supplied consent
    ///   does not authorise vulnerability-frequency submissions;
    /// - [`AutonomyError::InvalidInput`] when `observations` is empty;
    /// - [`AutonomyError::Serialization`] when the body cannot be
    ///   encoded;
    /// - [`AutonomyError::NetworkTransport`] on transport-level errors;
    /// - [`AutonomyError::NetworkSubmissionFailed`] on non-2xx responses.
    // Linear orchestration with redaction + transport + classification;
    // cognitive complexity reflects discrete error branches, not nesting.
    #[allow(clippy::cognitive_complexity)]
    pub async fn submit(
        &self,
        consent: TenantConsent,
        observations: Vec<ThreatObservation>,
    ) -> Result<(), AutonomyError> {
        if !consent.authorises_vulnerability_frequency() {
            return Err(AutonomyError::MissingConsent(
                "scope does not authorise vulnerability-frequency sharing".to_owned(),
            ));
        }
        if observations.is_empty() {
            return Err(AutonomyError::invalid_input(
                "observations must be non-empty",
            ));
        }

        let bundle = self.anonymise(&consent, observations);
        let body =
            serde_json::to_vec(&bundle).map_err(|e| AutonomyError::Serialization(e.to_string()))?;

        debug!(
            endpoint = %self.endpoint,
            observation_count = bundle.observations.len(),
            "posting anonymised threat-share bundle"
        );

        let resp = self
            .http
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| AutonomyError::NetworkTransport(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            warn!(
                status = status.as_u16(),
                "threat-network rejected submission"
            );
            return Err(AutonomyError::NetworkSubmissionFailed {
                status: status.as_u16(),
            });
        }
        info!(
            status = status.as_u16(),
            "threat-network submission accepted"
        );
        Ok(())
    }

    /// Hash `value` with the per-platform pepper. Wire format uses the
    /// full lowercase hex SHA-256 digest of `value || pepper`.
    fn hash(&self, value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hasher.update(self.pepper.expose_secret().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Build the wire-format bundle from raw observations.
    fn anonymise(
        &self,
        consent: &TenantConsent,
        observations: Vec<ThreatObservation>,
    ) -> ThreatShareBundle {
        let tenant_hash = self.hash(&consent.tenant_id.to_string());
        let anonymised = observations
            .into_iter()
            .map(|o| AnonymisedObservation {
                cve_id: o.cve_id.to_string(),
                asset_kind_hash: self.hash(&o.asset_kind),
                count: o.count,
            })
            .collect();
        ThreatShareBundle {
            shared_at: OffsetDateTime::now_utc(),
            tenant_hash,
            observations: anonymised,
        }
    }
}

#[cfg(test)]
impl ThreatNetworkClient {
    /// Test-only constructor that skips the HTTPS scheme check.
    ///
    /// Used by `threat_network_surfaces_5xx_as_error`, which needs to
    /// drive a `wiremock` mock server that only speaks plain HTTP.
    pub(crate) const fn new_for_test(
        http: reqwest::Client,
        endpoint: Url,
        pepper: SecretString,
    ) -> Self {
        Self {
            http,
            endpoint,
            pepper,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::consent::SharingScope;
    use sx_core::value_object::ids::{CveId, TenantId};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn pepper() -> SecretString {
        SecretString::new("test-pepper".to_owned().into_boxed_str())
    }

    fn consent_with_scope(scope: SharingScope) -> TenantConsent {
        TenantConsent::new(TenantId::new(), OffsetDateTime::now_utc(), scope)
    }

    #[test]
    fn threat_network_rejects_http_endpoint() {
        let http = reqwest::Client::new();
        let url = Url::parse("http://example.invalid/ingest").unwrap();
        let err = ThreatNetworkClient::new(http, url, pepper()).unwrap_err();
        assert!(matches!(err, AutonomyError::InsecureEndpoint));
    }

    #[tokio::test]
    async fn threat_network_rejects_when_consent_missing_scope() {
        let client = ThreatNetworkClient::new(
            reqwest::Client::new(),
            Url::parse("https://example.invalid/ingest").unwrap(),
            pepper(),
        )
        .unwrap();
        let consent = consent_with_scope(SharingScope::None);
        let obs = vec![ThreatObservation::new(
            CveId::new("CVE-2024-12345").unwrap(),
            "web-server",
            1,
        )];
        let err = client.submit(consent, obs).await.unwrap_err();
        assert!(matches!(err, AutonomyError::MissingConsent(_)));
    }

    #[test]
    fn threat_network_anonymises_tenant_id() {
        let client = ThreatNetworkClient::new(
            reqwest::Client::new(),
            Url::parse("https://example.invalid/ingest").unwrap(),
            pepper(),
        )
        .unwrap();
        let consent = consent_with_scope(SharingScope::VulnerabilityFrequency);
        let bundle = client.anonymise(&consent, vec![]);
        // Raw tenant uuid MUST NOT appear in the hash output.
        let raw_id = consent.tenant_id.to_string();
        assert_ne!(bundle.tenant_hash, raw_id);
        assert!(!bundle.tenant_hash.contains(&raw_id));
        // SHA-256 is 64 hex chars.
        assert_eq!(bundle.tenant_hash.len(), 64);
        assert!(bundle.tenant_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn threat_network_anonymises_asset_identifiers() {
        let client = ThreatNetworkClient::new(
            reqwest::Client::new(),
            Url::parse("https://example.invalid/ingest").unwrap(),
            pepper(),
        )
        .unwrap();
        let consent = consent_with_scope(SharingScope::VulnerabilityFrequency);
        let obs = vec![ThreatObservation::new(
            CveId::new("CVE-2024-12345").unwrap(),
            "linux-kernel-host",
            3,
        )];
        let bundle = client.anonymise(&consent, obs);
        assert_eq!(bundle.observations.len(), 1);
        let wire = bundle.observations.first().expect("one observation");
        // Raw asset_kind text MUST NOT appear on the wire.
        let serialised = serde_json::to_string(&bundle).unwrap();
        assert!(!serialised.contains("linux-kernel-host"));
        assert_eq!(wire.cve_id, "CVE-2024-12345");
        assert_eq!(wire.count, 3);
        assert_eq!(wire.asset_kind_hash.len(), 64);
    }

    #[tokio::test]
    async fn threat_network_surfaces_5xx_as_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ingest"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        // `wiremock` binds plain HTTP, but the production constructor
        // refuses non-HTTPS endpoints by design. Use the test-only
        // constructor that mirrors `new` minus the scheme guard.
        let endpoint = Url::parse(&format!("{}/ingest", server.uri())).unwrap();
        let client = ThreatNetworkClient::new_for_test(reqwest::Client::new(), endpoint, pepper());
        let consent = consent_with_scope(SharingScope::VulnerabilityFrequency);
        let obs = vec![ThreatObservation::new(
            CveId::new("CVE-2024-12345").unwrap(),
            "x",
            1,
        )];
        let err = client.submit(consent, obs).await.unwrap_err();
        assert!(matches!(
            err,
            AutonomyError::NetworkSubmissionFailed { status: 503 }
        ));
    }
}
