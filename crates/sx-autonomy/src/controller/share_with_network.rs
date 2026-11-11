//! Use case: share anonymised observations with the threat network.
//!
//! Thin wrapper around
//! [`crate::service::threat_network::ThreatNetworkClient`].

use std::sync::Arc;

use crate::error::AutonomyError;
use crate::model::consent::TenantConsent;
use crate::model::threat_share::ThreatObservation;
use crate::service::threat_network::ThreatNetworkClient;

/// Application-layer entry point for threat-network submission.
#[derive(Debug, Clone)]
pub struct ShareWithNetworkUseCase {
    client: Arc<ThreatNetworkClient>,
}

impl ShareWithNetworkUseCase {
    /// Build a new use case around the supplied client.
    #[must_use]
    pub const fn new(client: Arc<ThreatNetworkClient>) -> Self {
        Self { client }
    }

    /// Forward the submission to the underlying client.
    ///
    /// # Errors
    /// Surfaces any error returned by [`ThreatNetworkClient::submit`].
    pub async fn execute(
        &self,
        consent: TenantConsent,
        observations: Vec<ThreatObservation>,
    ) -> Result<(), AutonomyError> {
        self.client.submit(consent, observations).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::consent::SharingScope;
    use sx_core::value_object::ids::{CveId, TenantId};
    use time::OffsetDateTime;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn share_with_network_use_case_forwards_to_client() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ingest"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;
        let endpoint = Url::parse(&format!("{}/ingest", server.uri())).unwrap();
        let client = Arc::new(ThreatNetworkClient::new_for_test(
            reqwest::Client::new(),
            endpoint,
            secrecy::SecretString::new("pepper".to_owned().into_boxed_str()),
        ));
        let use_case = ShareWithNetworkUseCase::new(client);
        let consent = TenantConsent::new(
            TenantId::new(),
            OffsetDateTime::now_utc(),
            SharingScope::VulnerabilityFrequency,
        );
        let obs = vec![ThreatObservation::new(
            CveId::new("CVE-2024-99999").unwrap(),
            "web-server",
            1,
        )];
        use_case.execute(consent, obs).await.unwrap();
    }
}
