//! GCP Cloud KMS implementation of [`KekProvider`].

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};

use super::{EncryptionContext, KekError, KekProvider, NewKeyVersion, SecretVec};

const PROVIDER_ID: &str = "gcp_kms";

/// Bearer-token minter — exchanged from a service-account JSON or static.
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Return a fresh bearer token; implementations typically cache + refresh.
    async fn fetch_token(&self) -> Result<SecretString, KekError>;
}

/// Static-token authenticator. Useful for tests + dev.
#[derive(Debug)]
pub struct StaticToken(pub SecretString);

#[async_trait]
impl Authenticator for StaticToken {
    async fn fetch_token(&self) -> Result<SecretString, KekError> {
        Ok(SecretString::new(self.0.expose_secret().into()))
    }
}

/// GCP Cloud KMS KEK provider.
pub struct GcpKmsKekProvider {
    http: Client,
    endpoint: String,
    auth: Arc<dyn Authenticator>,
}

impl std::fmt::Debug for GcpKmsKekProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsKekProvider")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl GcpKmsKekProvider {
    /// Build a provider for the public Cloud KMS endpoint.
    pub fn new(http: Client, auth: Arc<dyn Authenticator>) -> Self {
        Self {
            http,
            endpoint: "https://cloudkms.googleapis.com".to_owned(),
            auth,
        }
    }

    /// Build a provider with an explicit endpoint (used by tests).
    pub fn with_endpoint(http: Client, auth: Arc<dyn Authenticator>, endpoint: String) -> Self {
        Self {
            http,
            endpoint,
            auth,
        }
    }

    fn url(&self, key_id: &str, op: &str) -> String {
        format!("{}/v1/{}:{}", self.endpoint, key_id, op)
    }

    async fn post_json(&self, url: &str, body: &Value) -> Result<Value, KekError> {
        let tok = self.auth.fetch_token().await?;
        let res = self
            .http
            .post(url)
            .header("authorization", format!("Bearer {}", tok.expose_secret()))
            .header("content-type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| KekError::provider(PROVIDER_ID, e))?;
        let status = res.status();
        let text = res
            .text()
            .await
            .map_err(|e| KekError::provider(PROVIDER_ID, e))?;
        if !status.is_success() {
            return Err(KekError::format(format!("gcp kms {url} {status}: {text}")));
        }
        serde_json::from_str(&text)
            .map_err(|e| KekError::format(format!("gcp kms response not json: {e}")))
    }
}

/// Validate a Cloud KMS `CryptoKey` resource path of the form
/// `projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}`.
#[must_use]
pub fn is_valid_resource_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        ["projects", proj, "locations", loc, "keyRings", ring, "cryptoKeys", key] => {
            !proj.is_empty() && !loc.is_empty() && !ring.is_empty() && !key.is_empty()
        }
        _ => false,
    }
}

#[async_trait]
impl KekProvider for GcpKmsKekProvider {
    fn provider_id(&self) -> &'static str {
        PROVIDER_ID
    }

    async fn wrap(
        &self,
        plaintext: &[u8],
        key_id: &str,
        context: &EncryptionContext,
    ) -> Result<Vec<u8>, KekError> {
        if !is_valid_resource_path(key_id) {
            return Err(KekError::format(format!(
                "gcp kms invalid resource path: {key_id}"
            )));
        }
        let url = self.url(key_id, "encrypt");
        let aad = serde_json::to_vec(&context.to_map())
            .map_err(|e| KekError::format(format!("aad serialise: {e}")))?;
        let body = json!({
            "plaintext": B64.encode(plaintext),
            "additionalAuthenticatedData": B64.encode(&aad),
        });
        let resp = self.post_json(&url, &body).await?;
        let ct = resp
            .get("ciphertext")
            .and_then(Value::as_str)
            .ok_or_else(|| KekError::format("gcp kms encrypt missing `.ciphertext`"))?;
        B64.decode(ct)
            .map_err(|e| KekError::format(format!("gcp kms ciphertext not base64: {e}")))
    }

    async fn unwrap(
        &self,
        ciphertext: &[u8],
        key_id: &str,
        context: &EncryptionContext,
    ) -> Result<SecretVec, KekError> {
        if !is_valid_resource_path(key_id) {
            return Err(KekError::format(format!(
                "gcp kms invalid resource path: {key_id}"
            )));
        }
        let url = self.url(key_id, "decrypt");
        let aad = serde_json::to_vec(&context.to_map())
            .map_err(|e| KekError::format(format!("aad serialise: {e}")))?;
        let body = json!({
            "ciphertext": B64.encode(ciphertext),
            "additionalAuthenticatedData": B64.encode(&aad),
        });
        let resp = self.post_json(&url, &body).await?;
        let pt = resp
            .get("plaintext")
            .and_then(Value::as_str)
            .ok_or_else(|| KekError::format("gcp kms decrypt missing `.plaintext`"))?;
        let bytes = B64
            .decode(pt)
            .map_err(|e| KekError::format(format!("gcp kms plaintext not base64: {e}")))?;
        Ok(SecretVec::new(bytes))
    }

    async fn rotate(&self, key_id: &str) -> Result<NewKeyVersion, KekError> {
        if !is_valid_resource_path(key_id) {
            return Err(KekError::format(format!(
                "gcp kms invalid resource path: {key_id}"
            )));
        }
        let url = format!("{}/v1/{}/cryptoKeyVersions", self.endpoint, key_id);
        let resp = self.post_json(&url, &json!({})).await?;
        let name = resp
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| KekError::format("gcp kms rotate missing `.name`"))?;
        let version = name
            .rsplit('/')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| {
                KekError::format(format!("gcp kms rotate `name` lacks N suffix: {name}"))
            })?;
        Ok(NewKeyVersion::now(key_id, version))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dek::TenantId;

    fn ctx() -> EncryptionContext {
        EncryptionContext::new(TenantId::new(uuid::Uuid::new_v4()), 1)
    }

    #[test]
    fn resource_path_validator_accepts_canonical_form() {
        assert!(is_valid_resource_path(
            "projects/p/locations/l/keyRings/r/cryptoKeys/k"
        ));
    }

    #[test]
    fn resource_path_validator_rejects_truncated() {
        assert!(!is_valid_resource_path("projects/p/locations/l/keyRings"));
    }

    #[test]
    fn resource_path_validator_rejects_empty_segment() {
        assert!(!is_valid_resource_path(
            "projects//locations/l/keyRings/r/cryptoKeys/k"
        ));
    }

    #[tokio::test]
    async fn wrap_with_invalid_path_returns_format_error() {
        let provider = GcpKmsKekProvider::new(
            Client::new(),
            Arc::new(StaticToken(SecretString::from("t"))),
        );
        let err = provider
            .wrap(b"pt", "bad/path", &ctx())
            .await
            .expect_err("expected error");
        assert!(matches!(err, KekError::Format(_)));
    }

    #[test]
    fn provider_id_is_gcp_kms() {
        let p = GcpKmsKekProvider::new(
            Client::new(),
            Arc::new(StaticToken(SecretString::from("t"))),
        );
        assert_eq!(p.provider_id(), "gcp_kms");
    }
}
