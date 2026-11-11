//! `HashiCorp` Vault KV v2 implementation of [`crate::SecretsProvider`].
//!
//! ## Endpoints
//!
//! | Op    | Method | Path                              |
//! |-------|--------|-----------------------------------|
//! | `get` | `GET`  | `/v1/{mount}/data/{path}`         |
//! | `put` | `POST` | `/v1/{mount}/data/{path}`         |
//!
//! ## Wire format
//!
//! KV v2 wraps the user payload twice: the outer envelope has a `data`
//! field whose value is `{ "data": <user_payload>, "metadata": {…} }`.
//! For the simple "single value per path" model we encode the secret as
//! `{ "value": "<the secret>" }`.
//!
//! ## Auth
//!
//! Bearer token is wrapped in [`secrecy::SecretString`], forwarded as the
//! `X-Vault-Token` header on every request, and never logged. The custom
//! [`std::fmt::Debug`] impl redacts the token field.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::error::SecretsError;
use crate::provider::SecretsProvider;

/// Default mount path for Vault's KV v2 secrets engine.
pub const DEFAULT_MOUNT: &str = "secret";

/// Vault KV v2 client implementing [`SecretsProvider`].
///
/// Cheap to clone: internally just holds a `reqwest::Client`, the base
/// URL, the mount path, and an [`Arc`] of the bearer token. Construct
/// once per `(base_url, token, mount)` triplet and share across tasks.
#[derive(Clone)]
pub struct VaultProvider {
    client: Client,
    base_url: String,
    token: Arc<SecretString>,
    mount: String,
}

impl VaultProvider {
    /// Construct a new Vault provider.
    ///
    /// * `base_url` — e.g. `"https://vault.example.com"`. Trailing `/`
    ///   is stripped.
    /// * `token` — the Vault token used to authenticate.
    /// * `mount` — the KV v2 mount, typically `"secret"`.
    pub fn new(
        client: Client,
        base_url: impl Into<String>,
        token: SecretString,
        mount: impl Into<String>,
    ) -> Self {
        let base = base_url.into();
        let trimmed = base.trim_end_matches('/').to_owned();
        Self {
            client,
            base_url: trimmed,
            token: Arc::new(token),
            mount: mount.into(),
        }
    }

    /// Convenience constructor using [`DEFAULT_MOUNT`].
    pub fn with_default_mount(
        client: Client,
        base_url: impl Into<String>,
        token: SecretString,
    ) -> Self {
        Self::new(client, base_url, token, DEFAULT_MOUNT)
    }

    /// The configured base URL (sans trailing slash).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The configured KV v2 mount path.
    #[must_use]
    pub fn mount(&self) -> &str {
        &self.mount
    }

    fn endpoint(&self, path: &str) -> String {
        let trimmed = path.trim_start_matches('/');
        format!("{}/v1/{}/data/{}", self.base_url, self.mount, trimmed)
    }

    fn headers(&self) -> Result<HeaderMap, SecretsError> {
        let mut headers = HeaderMap::new();
        let name = HeaderName::from_static("x-vault-token");
        let mut value = HeaderValue::from_str(self.token.expose_secret())
            .map_err(|e| SecretsError::transport(format!("invalid token header: {e}")))?;
        value.set_sensitive(true);
        headers.insert(name, value);
        Ok(headers)
    }
}

impl fmt::Debug for VaultProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultProvider")
            .field("base_url", &self.base_url)
            .field("mount", &self.mount)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SecretsProvider for VaultProvider {
    async fn get(&self, path: &str) -> Result<SecretString, SecretsError> {
        let url = self.endpoint(path);
        let started = Instant::now();
        let headers = self.headers()?;

        let response = self
            .client
            .request(Method::GET, &url)
            .headers(headers)
            .send()
            .await?;

        let status = response.status();
        match status {
            s if s.is_success() => {}
            StatusCode::NOT_FOUND => {
                warn!(target: "sx_secrets::vault", %path, status = %status, "vault get not found");
                return Err(SecretsError::NotFound(path.to_owned()));
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                warn!(target: "sx_secrets::vault", %path, status = %status, "vault get unauthorized");
                return Err(SecretsError::Unauthorized);
            }
            other => {
                warn!(target: "sx_secrets::vault", %path, status = %other, "vault get unexpected status");
                return Err(SecretsError::transport(format!(
                    "unexpected status {other} from vault"
                )));
            }
        }

        // Read bytes then parse with serde_json so a malformed payload
        // surfaces as `Format` rather than `Transport` (the latter is what
        // `reqwest::Response::json` returns for parse failures).
        let bytes = response.bytes().await?;
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|e| SecretsError::format(format!("malformed json: {e}")))?;
        let value = extract_value(&body).ok_or_else(|| {
            SecretsError::format("vault response missing `.data.data.value`".to_owned())
        })?;

        let elapsed_ms = started.elapsed().as_millis();
        debug!(target: "sx_secrets::vault", %path, outcome = "ok", duration_ms = elapsed_ms, "vault get");

        Ok(SecretString::new(value.into_boxed_str()))
    }

    async fn put(&self, path: &str, value: SecretString) -> Result<(), SecretsError> {
        let url = self.endpoint(path);
        let started = Instant::now();
        let headers = self.headers()?;
        let body = json!({ "data": { "value": value.expose_secret() } });

        let response = self
            .client
            .request(Method::POST, &url)
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        match status {
            s if s.is_success() => {
                let elapsed_ms = started.elapsed().as_millis();
                debug!(target: "sx_secrets::vault", %path, outcome = "ok", duration_ms = elapsed_ms, "vault put");
                Ok(())
            }
            StatusCode::NOT_FOUND => {
                warn!(target: "sx_secrets::vault", %path, status = %status, "vault put not found");
                Err(SecretsError::NotFound(path.to_owned()))
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                warn!(target: "sx_secrets::vault", %path, status = %status, "vault put unauthorized");
                Err(SecretsError::Unauthorized)
            }
            other => {
                warn!(target: "sx_secrets::vault", %path, status = %other, "vault put unexpected status");
                Err(SecretsError::transport(format!(
                    "unexpected status {other} from vault"
                )))
            }
        }
    }
}

/// Extract the `.data.data.value` string from a KV v2 response body.
fn extract_value(body: &Value) -> Option<String> {
    body.get("data")
        .and_then(|d| d.get("data"))
        .and_then(|d| d.get("value"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn token() -> SecretString {
        SecretString::new("vault-root-token".to_owned().into_boxed_str())
    }

    fn provider_for(server: &MockServer) -> VaultProvider {
        VaultProvider::with_default_mount(Client::new(), server.uri(), token())
    }

    #[tokio::test]
    async fn get_success_returns_decoded_value() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/prod/db"))
            .and(header("x-vault-token", "vault-root-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": { "value": "hunter2" },
                    "metadata": { "version": 1 }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let got = provider.get("prod/db").await.unwrap();
        assert_eq!(got.expose_secret(), "hunter2");
    }

    #[tokio::test]
    async fn get_404_maps_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"errors": []})))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider.get("missing").await.unwrap_err();
        assert!(matches!(err, SecretsError::NotFound(p) if p == "missing"));
    }

    #[tokio::test]
    async fn get_403_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/forbidden"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({"errors": ["denied"]})))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider.get("forbidden").await.unwrap_err();
        assert!(matches!(err, SecretsError::Unauthorized));
    }

    #[tokio::test]
    async fn get_401_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/forbidden"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let provider = provider_for(&server);
        let err = provider.get("forbidden").await.unwrap_err();
        assert!(matches!(err, SecretsError::Unauthorized));
    }

    #[tokio::test]
    async fn put_success_returns_ok() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/prod/api"))
            .and(header("x-vault-token", "vault-root-token"))
            .and(body_partial_json(json!({
                "data": { "value": "rotated-key" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "version": 2 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        provider
            .put(
                "prod/api",
                SecretString::new("rotated-key".to_owned().into_boxed_str()),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn put_204_no_content_is_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/prod/api"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        provider
            .put(
                "prod/api",
                SecretString::new("v".to_owned().into_boxed_str()),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn malformed_json_get_maps_to_format() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/broken"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(b"{not-json".to_vec(), "application/json"),
            )
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider.get("broken").await.unwrap_err();
        assert!(matches!(err, SecretsError::Format(_)));
    }

    #[tokio::test]
    async fn missing_value_field_maps_to_format() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/shapeless"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": { "other_field": "x" },
                    "metadata": {}
                }
            })))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider.get("shapeless").await.unwrap_err();
        assert!(matches!(err, SecretsError::Format(_)));
    }

    #[test]
    fn debug_impl_redacts_token() {
        let provider = VaultProvider::with_default_mount(
            Client::new(),
            "https://vault.example",
            SecretString::new("super-secret-token-xyz".to_owned().into_boxed_str()),
        );
        let rendered = format!("{provider:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret-token-xyz"));
        assert!(rendered.contains("https://vault.example"));
        assert!(rendered.contains("secret"));
    }

    #[test]
    fn endpoint_strips_leading_slash() {
        let provider = VaultProvider::with_default_mount(
            Client::new(),
            "https://vault.example/",
            SecretString::new("t".to_owned().into_boxed_str()),
        );
        assert_eq!(
            provider.endpoint("/foo/bar"),
            "https://vault.example/v1/secret/data/foo/bar"
        );
        assert_eq!(
            provider.endpoint("foo/bar"),
            "https://vault.example/v1/secret/data/foo/bar"
        );
    }
}
