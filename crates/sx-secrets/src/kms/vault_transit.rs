//! Vault Transit secret-engine implementation of [`KmsKeyProvider`].
//!
//! ## Endpoint mapping
//!
//! | Operation         | Method | Path                                          |
//! |-------------------|--------|-----------------------------------------------|
//! | `encrypt`         | `POST` | `/v1/{mount}/encrypt/{name}`                  |
//! | `decrypt`         | `POST` | `/v1/{mount}/decrypt/{name}`                  |
//! | `generate_dek`    | `POST` | `/v1/{mount}/datakey/plaintext/{name}`        |
//! | `rotate`          | `POST` | `/v1/{mount}/keys/{name}/rotate`              |
//!
//! Default `mount` is `transit`. The auth model matches
//! [`crate::vault::VaultProvider`] — bearer token is supplied via
//! `X-Vault-Token` and held in [`SecretString`].
//!
//! ## Wire shapes
//!
//! * encrypt request: `{ "plaintext": "<base64>" }`
//! * encrypt response: `{ "data": { "ciphertext": "vault:v1:…" } }`
//! * decrypt request: `{ "ciphertext": "vault:v1:…" }`
//! * decrypt response: `{ "data": { "plaintext": "<base64>" } }`
//! * datakey response: `{ "data": { "plaintext": "<b64>", "ciphertext": "vault:v1:…", "key_version": 1 } }`
//! * rotate response: `{ "data": { "latest_version": 2 } }`

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::error::SecretsError;
use crate::kms::provider::{Ciphertext, KeyVersion, KmsKeyProvider, WrappedDek};

/// Default mount path for Vault's Transit secrets engine.
pub const DEFAULT_TRANSIT_MOUNT: &str = "transit";

/// HTTP client for Vault Transit.
///
/// Cheap to clone: internally just holds a `reqwest::Client`, the base
/// URL, the mount, and an [`Arc`] of the bearer token.
#[derive(Clone)]
pub struct VaultTransitKms {
    client: Client,
    base_url: String,
    token: Arc<SecretString>,
    mount: String,
}

impl VaultTransitKms {
    /// Construct a new Vault Transit KMS client.
    ///
    /// * `base_url` — e.g. `"https://vault.example.com"`. Trailing `/`
    ///   is stripped.
    /// * `token` — Vault token; never logged.
    /// * `mount` — Transit engine mount path. Defaults to `"transit"`.
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

    /// Convenience constructor using [`DEFAULT_TRANSIT_MOUNT`].
    pub fn with_default_mount(
        client: Client,
        base_url: impl Into<String>,
        token: SecretString,
    ) -> Self {
        Self::new(client, base_url, token, DEFAULT_TRANSIT_MOUNT)
    }

    /// The configured base URL (sans trailing slash).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The configured Transit mount path.
    #[must_use]
    pub fn mount(&self) -> &str {
        &self.mount
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}/v1/{}/{}", self.base_url, self.mount, suffix)
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

    #[allow(clippy::cognitive_complexity)] // linear: build req → send → status branch → parse → trace
    async fn post_json(
        &self,
        url: &str,
        body: &Value,
        operation: &'static str,
        key_id: &str,
    ) -> Result<Value, SecretsError> {
        let started = Instant::now();
        let headers = self.headers()?;
        let response = self
            .client
            .request(Method::POST, url)
            .headers(headers)
            .json(body)
            .send()
            .await?;

        let status = response.status();
        match status {
            s if s.is_success() => {}
            StatusCode::NOT_FOUND => {
                warn!(
                    target: "sx_secrets::kms::vault_transit",
                    %operation, %key_id, status = %status, "transit not found"
                );
                return Err(SecretsError::NotFound(key_id.to_owned()));
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                warn!(
                    target: "sx_secrets::kms::vault_transit",
                    %operation, %key_id, status = %status, "transit unauthorized"
                );
                return Err(SecretsError::Unauthorized);
            }
            other => {
                warn!(
                    target: "sx_secrets::kms::vault_transit",
                    %operation, %key_id, status = %other, "transit unexpected status"
                );
                return Err(SecretsError::transport(format!(
                    "unexpected status {other} from vault transit"
                )));
            }
        }

        let bytes = response.bytes().await?;
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|e| SecretsError::format(format!("malformed json: {e}")))?;
        let elapsed_ms = started.elapsed().as_millis();
        debug!(
            target: "sx_secrets::kms::vault_transit",
            %operation, %key_id, outcome = "ok", duration_ms = elapsed_ms, "transit call"
        );
        Ok(body)
    }
}

impl fmt::Debug for VaultTransitKms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultTransitKms")
            .field("base_url", &self.base_url)
            .field("mount", &self.mount)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl KmsKeyProvider for VaultTransitKms {
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &SecretString,
    ) -> Result<Ciphertext, SecretsError> {
        let url = self.url(&format!("encrypt/{key_id}"));
        let encoded = B64.encode(plaintext.expose_secret().as_bytes());
        let body = json!({ "plaintext": encoded });
        let response = self.post_json(&url, &body, "encrypt", key_id).await?;
        let ct = response
            .get("data")
            .and_then(|d| d.get("ciphertext"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SecretsError::format("transit encrypt response missing `.data.ciphertext`")
            })?;
        Ok(Ciphertext::new(ct.to_owned()))
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &Ciphertext,
    ) -> Result<SecretString, SecretsError> {
        let url = self.url(&format!("decrypt/{key_id}"));
        let body = json!({ "ciphertext": ciphertext.as_str() });
        let response = self.post_json(&url, &body, "decrypt", key_id).await?;
        let pt_b64 = response
            .get("data")
            .and_then(|d| d.get("plaintext"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SecretsError::format("transit decrypt response missing `.data.plaintext`")
            })?;
        let bytes = B64.decode(pt_b64).map_err(|e| {
            SecretsError::format(format!("transit decrypt plaintext not valid base64: {e}"))
        })?;
        let s = String::from_utf8(bytes).map_err(|e| {
            SecretsError::format(format!("transit decrypt plaintext not utf8: {e}"))
        })?;
        Ok(SecretString::new(s.into_boxed_str()))
    }

    async fn generate_dek(&self, key_id: &str) -> Result<WrappedDek, SecretsError> {
        let url = self.url(&format!("datakey/plaintext/{key_id}"));
        let body = json!({});
        let response = self.post_json(&url, &body, "generate_dek", key_id).await?;
        let data = response
            .get("data")
            .ok_or_else(|| SecretsError::format("transit datakey response missing `.data`"))?;
        let pt = data
            .get("plaintext")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SecretsError::format("transit datakey response missing `.data.plaintext`")
            })?;
        let ct = data
            .get("ciphertext")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SecretsError::format("transit datakey response missing `.data.ciphertext`")
            })?;
        // key_version is optional in Vault's response; default to 1 if absent.
        let version = data
            .get("key_version")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .try_into()
            .unwrap_or(u32::MAX);

        Ok(WrappedDek::new(
            key_id,
            version,
            SecretString::new(pt.to_owned().into_boxed_str()),
            Ciphertext::new(ct.to_owned()),
        ))
    }

    async fn rotate(&self, key_id: &str) -> Result<KeyVersion, SecretsError> {
        let url = self.url(&format!("keys/{key_id}/rotate"));
        let body = json!({});
        let response = self.post_json(&url, &body, "rotate", key_id).await?;
        // Vault returns latest_version inside .data on rotate, but some
        // versions return an empty body and require a follow-up GET. We
        // accept either: missing version → assume 1 + previous (unknown),
        // so we read what's there and surface a Format error if neither
        // is present.
        let version = response
            .get("data")
            .and_then(|d| d.get("latest_version"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                SecretsError::format("transit rotate response missing `.data.latest_version`")
            })?
            .try_into()
            .unwrap_or(u32::MAX);
        Ok(KeyVersion::now(version))
    }
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

    fn kms_for(server: &MockServer) -> VaultTransitKms {
        VaultTransitKms::with_default_mount(Client::new(), server.uri(), token())
    }

    #[tokio::test]
    async fn encrypt_round_trip_returns_ciphertext() {
        let server = MockServer::start().await;
        let plaintext_bytes = B64.encode(b"hello-dek");
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/tenant-a"))
            .and(header("x-vault-token", "vault-root-token"))
            .and(body_partial_json(json!({ "plaintext": plaintext_bytes })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "ciphertext": "vault:v1:CIPHER==" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let kms = kms_for(&server);
        let pt = SecretString::new("hello-dek".to_owned().into_boxed_str());
        let ct = kms.encrypt("tenant-a", &pt).await.unwrap();
        assert_eq!(ct.as_str(), "vault:v1:CIPHER==");
    }

    #[tokio::test]
    async fn decrypt_round_trip_returns_plaintext() {
        let server = MockServer::start().await;
        let pt_b64 = B64.encode(b"original-plaintext");
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/tenant-a"))
            .and(body_partial_json(
                json!({ "ciphertext": "vault:v1:CIPHER==" }),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "plaintext": pt_b64 } })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let kms = kms_for(&server);
        let ct = Ciphertext::new("vault:v1:CIPHER==");
        let pt = kms.decrypt("tenant-a", &ct).await.unwrap();
        assert_eq!(pt.expose_secret(), "original-plaintext");
    }

    #[tokio::test]
    async fn generate_dek_returns_plaintext_and_wrapped() {
        let server = MockServer::start().await;
        let pt_b64 = B64.encode(b"32-byte-dek-bytes-encoded--here!");
        Mock::given(method("POST"))
            .and(path("/v1/transit/datakey/plaintext/tenant-a"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "plaintext": pt_b64,
                    "ciphertext": "vault:v1:WRAPPED",
                    "key_version": 3
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let kms = kms_for(&server);
        let dek = kms.generate_dek("tenant-a").await.unwrap();
        assert_eq!(dek.key_id, "tenant-a");
        assert_eq!(dek.version, 3);
        assert_eq!(dek.wrapped.as_str(), "vault:v1:WRAPPED");
        assert!(!dek.plaintext.expose_secret().is_empty());
    }

    #[tokio::test]
    async fn rotate_returns_incremented_version() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/keys/tenant-a/rotate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "latest_version": 7 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let kms = kms_for(&server);
        let kv = kms.rotate("tenant-a").await.unwrap();
        assert_eq!(kv.version, 7);
    }

    #[tokio::test]
    async fn encrypt_403_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/blocked"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let kms = kms_for(&server);
        let pt = SecretString::new("x".to_owned().into_boxed_str());
        let err = kms.encrypt("blocked", &pt).await.unwrap_err();
        assert!(matches!(err, SecretsError::Unauthorized));
    }

    #[tokio::test]
    async fn decrypt_after_key_deletion_404_maps_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/shredded"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let kms = kms_for(&server);
        let ct = Ciphertext::new("vault:v1:STALE");
        let err = kms.decrypt("shredded", &ct).await.unwrap_err();
        assert!(matches!(err, SecretsError::NotFound(_)));
    }

    #[test]
    fn debug_impl_redacts_token() {
        let kms = VaultTransitKms::with_default_mount(
            Client::new(),
            "https://vault.example",
            SecretString::new("super-secret-token-xyz".to_owned().into_boxed_str()),
        );
        let rendered = format!("{kms:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret-token-xyz"));
        assert!(rendered.contains("https://vault.example"));
        assert!(rendered.contains("transit"));
    }
}
