//! HTTPS collector client.
//!
//! `CollectorClient` is the single network egress for the agent. It owns a
//! reusable `reqwest::Client` (so connection pooling / keep-alive happens),
//! the collector endpoint URL, and the HMAC signer used to authenticate
//! every POST. The constructor enforces transport security: plain `http://`
//! is only ever allowed against a loopback host when the operator explicitly
//! opts in with `allow_insecure`.
//!
//! mTLS is optional. When a `(cert_path, key_path)` pair is supplied the
//! PEM bytes are concatenated into a single blob — `reqwest::Identity::from_pem`
//! accepts the combined form when built against `rustls-tls`.

use std::path::PathBuf;

use serde::Deserialize;

use crate::error::AgentError;
use crate::inventory::Inventory;
use crate::reporter::signer::HmacSigner;

/// HTTP header used to carry the hex-encoded HMAC-SHA256 of the request body.
pub const SIGNATURE_HEADER: &str = "X-SX-Signature";

/// Collector reply shape. The collector may withhold `kill`, in which case
/// the agent assumes `false` (no kill switch active).
#[derive(Debug, Clone, Deserialize)]
pub struct CollectorReply {
    pub accepted: bool,
    #[serde(default)]
    pub kill: bool,
}

/// Reusable HTTPS client that signs every request to the `SentinelX` collector.
pub struct CollectorClient {
    http: reqwest::Client,
    endpoint: url::Url,
    signer: HmacSigner,
}

impl std::fmt::Debug for CollectorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectorClient")
            .field("endpoint", &self.endpoint.as_str())
            .finish_non_exhaustive()
    }
}

impl CollectorClient {
    /// Build a client. Enforces transport security:
    ///
    /// * `https` is always allowed.
    /// * `http` is allowed **only** when `allow_insecure` is true and the host
    ///   is a loopback literal (`127.0.0.1`, `localhost`, `[::1]`).
    /// * Any other `http` URL returns [`AgentError::Config`].
    ///
    /// When `mtls` is supplied, the cert + key PEM blobs are loaded and
    /// installed as a client identity.
    pub fn new(
        endpoint: url::Url,
        signer: HmacSigner,
        mtls: Option<(PathBuf, PathBuf)>,
        allow_insecure: bool,
    ) -> Result<Self, AgentError> {
        validate_endpoint(&endpoint, allow_insecure)?;

        let mut builder = reqwest::Client::builder()
            .user_agent(concat!("sx-agent/", env!("CARGO_PKG_VERSION")))
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(30));

        if let Some((cert_path, key_path)) = mtls {
            let identity = load_identity(&cert_path, &key_path)?;
            builder = builder.identity(identity);
        }

        let http = builder
            .build()
            .map_err(|err| AgentError::Tls(format!("could not build http client: {err}")))?;

        Ok(Self {
            http,
            endpoint,
            signer,
        })
    }

    /// Submit one inventory snapshot. Returns the parsed reply on 2xx, a
    /// [`AgentError::CollectorRejected`] on 4xx, or an IO/transport error
    /// otherwise.
    pub async fn submit(&self, inventory: &Inventory) -> Result<CollectorReply, AgentError> {
        let body = serde_json::to_vec(inventory)?;
        let signature = self.signer.sign(&body);

        let response = self
            .http
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(SIGNATURE_HEADER, signature)
            .body(body)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            let bytes = response.bytes().await?;
            let reply: CollectorReply = serde_json::from_slice(&bytes)?;
            return Ok(reply);
        }

        let code = status.as_u16();
        if status.is_client_error() {
            return Err(AgentError::CollectorRejected { status: code });
        }

        Err(AgentError::GenericIo(std::io::Error::other(format!(
            "collector returned status {code}"
        ))))
    }
}

/// Returns `true` when the URL host is a loopback literal.
fn is_loopback_host(url: &url::Url) -> bool {
    url.host_str()
        .is_some_and(|h| matches!(h, "127.0.0.1" | "localhost" | "::1" | "[::1]"))
}

fn validate_endpoint(endpoint: &url::Url, allow_insecure: bool) -> Result<(), AgentError> {
    match endpoint.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure && is_loopback_host(endpoint) => Ok(()),
        "http" => Err(AgentError::Config("collector must use https".to_owned())),
        other => Err(AgentError::Config(format!(
            "unsupported collector url scheme: {other}"
        ))),
    }
}

fn load_identity(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Result<reqwest::Identity, AgentError> {
    let cert_bytes = std::fs::read(cert).map_err(|source| AgentError::Io {
        path: cert.to_path_buf(),
        source,
    })?;
    let key_bytes = std::fs::read(key).map_err(|source| AgentError::Io {
        path: key.to_path_buf(),
        source,
    })?;

    let mut combined = Vec::with_capacity(cert_bytes.len() + key_bytes.len() + 1);
    combined.extend_from_slice(&cert_bytes);
    if !cert_bytes.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(&key_bytes);

    reqwest::Identity::from_pem(&combined)
        .map_err(|err| AgentError::Tls(format!("invalid mTLS material: {err}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::inventory::{Inventory, SCHEMA_VERSION};
    use secrecy::SecretString;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn test_signer() -> HmacSigner {
        HmacSigner::new(SecretString::from("a".repeat(32))).unwrap()
    }

    fn test_inventory() -> Inventory {
        Inventory {
            schema_version: SCHEMA_VERSION,
            collected_at: time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            host_fingerprint: "deadbeef".to_owned(),
            os: None,
            kernel: None,
            mounts: vec![],
            listening_sockets: vec![],
            containers: vec![],
        }
    }

    #[test]
    fn collector_client_rejects_http_without_allow_insecure() {
        let endpoint = url::Url::parse("http://collector.example.invalid/v1/inventory").unwrap();
        let err = CollectorClient::new(endpoint, test_signer(), None, false).unwrap_err();
        match err {
            AgentError::Config(msg) => assert!(msg.contains("https"), "msg was {msg}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn collector_client_rejects_http_localhost_without_allow_insecure() {
        let endpoint = url::Url::parse("http://127.0.0.1:8443/v1/inventory").unwrap();
        let err = CollectorClient::new(endpoint, test_signer(), None, false).unwrap_err();
        assert!(matches!(err, AgentError::Config(_)));
    }

    #[test]
    fn collector_client_accepts_http_localhost_with_allow_insecure() {
        for host in ["127.0.0.1", "localhost", "[::1]"] {
            let endpoint = url::Url::parse(&format!("http://{host}:8443/v1/inventory")).unwrap();
            CollectorClient::new(endpoint, test_signer(), None, true)
                .unwrap_or_else(|e| panic!("expected ok for {host}, got {e:?}"));
        }
    }

    #[test]
    fn collector_client_accepts_https() {
        let endpoint = url::Url::parse("https://collector.example.invalid/v1/inventory").unwrap();
        CollectorClient::new(endpoint, test_signer(), None, false).unwrap();
    }

    #[tokio::test]
    async fn collector_client_signs_request_with_hmac_header() {
        let server = MockServer::start().await;
        let signer = test_signer();
        let inv = test_inventory();
        let body_bytes = serde_json::to_vec(&inv).unwrap();
        let expected_sig = signer.sign(&body_bytes);

        Mock::given(method("POST"))
            .and(path("/v1/inventory"))
            .and(header("content-type", "application/json"))
            .and(header(SIGNATURE_HEADER, expected_sig.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accepted": true,
                "kill": false
            })))
            .expect(1)
            .mount(&server)
            .await;

        let endpoint = url::Url::parse(&format!("{}/v1/inventory", server.uri())).unwrap();
        let client = CollectorClient::new(endpoint, signer, None, true).unwrap();
        let reply = client.submit(&inv).await.unwrap();
        assert!(reply.accepted);
        assert!(!reply.kill);

        // Cross-check: independently compute HMAC over the body the server saw
        // and ensure it matches what we sent.
        let recorded: Vec<Request> = server.received_requests().await.unwrap();
        assert_eq!(recorded.len(), 1);
        let req = &recorded[0];
        let signer2 = test_signer();
        let sig = signer2.sign(&req.body);
        let header_value = req
            .headers
            .get(SIGNATURE_HEADER)
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        assert_eq!(sig, header_value);
    }

    #[tokio::test]
    async fn collector_client_returns_kill_true_when_collector_replies_kill() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accepted": true,
                "kill": true
            })))
            .mount(&server)
            .await;

        let endpoint = url::Url::parse(&format!("{}/v1/inventory", server.uri())).unwrap();
        let client = CollectorClient::new(endpoint, test_signer(), None, true).unwrap();
        let reply = client.submit(&test_inventory()).await.unwrap();
        assert!(reply.kill);
    }

    #[tokio::test]
    async fn collector_client_maps_4xx_to_collector_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(418))
            .mount(&server)
            .await;
        let endpoint = url::Url::parse(&format!("{}/v1/inventory", server.uri())).unwrap();
        let client = CollectorClient::new(endpoint, test_signer(), None, true).unwrap();
        let err = client.submit(&test_inventory()).await.unwrap_err();
        match err {
            AgentError::CollectorRejected { status } => assert_eq!(status, 418),
            other => panic!("expected CollectorRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn collector_client_maps_5xx_to_io_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let endpoint = url::Url::parse(&format!("{}/v1/inventory", server.uri())).unwrap();
        let client = CollectorClient::new(endpoint, test_signer(), None, true).unwrap();
        let err = client.submit(&test_inventory()).await.unwrap_err();
        assert!(
            matches!(err, AgentError::GenericIo(_)),
            "expected GenericIo, got {err:?}"
        );
    }
}
