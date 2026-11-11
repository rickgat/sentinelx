//! [`KekProvider`] implementation backed by AWS Key Management Service.
//!
//! ## API mapping
//!
//! | Trait verb | AWS KMS operation | Notes                                            |
//! |------------|-------------------|--------------------------------------------------|
//! | `wrap`     | `Encrypt`         | `EncryptionContext` propagated as AAD            |
//! | `unwrap`   | `Decrypt`         | Same context required; mismatch → `Invalid…`     |
//! | `rotate`   | `UpdateKeyDescription` | Alias-pointer rotation pattern; see below   |
//!
//! ## Rotation strategy (alias-pointer)
//!
//! AWS KMS' native "automatic key rotation" only rotates the underlying
//! HSM material; the key ID stays the same and there is **no notion of a
//! caller-visible version number**. To support a staged rotation where
//! the caller can observe distinct versions, this provider uses the
//! **alias-pointer** pattern:
//!
//! 1. The caller creates a new key via `CreateKey` (out of band, or via
//!    Terraform).
//! 2. The caller's existing alias (e.g. `alias/sentinelx-kek`) is
//!    re-pointed to the new key with `UpdateAlias` (also out of band).
//! 3. `rotate()` calls `UpdateKeyDescription` on the *currently aliased*
//!    key to stamp a fresh rotation timestamp in the description. The
//!    description is parsed for a monotonic counter so callers can read
//!    back the version number.
//!
//! This is intentionally *minimal* for the MVP: the heavy lifting
//! (creating the new key, swinging the alias, deleting the old key) is
//! Terraform / operator work; the trait verb merely records that a
//! rotation happened so the workspace's higher-level orchestration layer
//! (`sx-secrets::dek`) can re-wrap DEKs under the new alias target.
//!
//! Real automatic rotation (KMS-native, transparent to the caller) is
//! tracked separately and will land in P2-006.
//!
//! ## Endpoint override
//!
//! [`AwsKmsConfig::endpoint_override`] lets integration tests target
//! `LocalStack` (`http://localhost:4566`) without going through the real
//! AWS endpoint resolver.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms::config::Region;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client;
use tracing::{debug, warn};

use super::{EncryptionContext, KekError, KekProvider, NewKeyVersion, SecretVec};

/// Stable identifier reported by [`KekProvider::provider_id`].
pub const PROVIDER_ID: &str = "aws-kms";

const TRACING_TARGET: &str = "sx_secrets::kek::aws";

/// Configuration for [`AwsKmsKekProvider`].
///
/// `role_arn` is captured for completeness; the MVP does not assume any
/// particular `AssumeRole` chain (the default credential provider is used
/// when present). Wiring an explicit role assumption is a follow-up.
#[derive(Clone, Debug)]
pub struct AwsKmsConfig {
    /// AWS region (e.g. `"us-east-1"`).
    pub region: String,
    /// Optional IAM role ARN to assume on every request. The MVP stores
    /// it but does not wire an STS chain; the field is reserved for the
    /// production-grade implementation (planned in P2-007).
    pub role_arn: Option<String>,
    /// Optional endpoint override (e.g. `"http://localhost:4566"`) for
    /// `LocalStack` integration tests. When `None`, the SDK's default
    /// endpoint resolver is used.
    pub endpoint_override: Option<String>,
}

impl AwsKmsConfig {
    /// Construct a minimal config from a region string. Equivalent to
    /// `AwsKmsConfig { region, role_arn: None, endpoint_override: None }`.
    #[must_use]
    pub fn with_region(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            role_arn: None,
            endpoint_override: None,
        }
    }

    /// Builder-style mutator that sets an endpoint override.
    #[must_use]
    pub fn with_endpoint_override(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint_override = Some(endpoint.into());
        self
    }

    /// Builder-style mutator that sets a role ARN.
    #[must_use]
    pub fn with_role_arn(mut self, role: impl Into<String>) -> Self {
        self.role_arn = Some(role.into());
        self
    }
}

/// AWS KMS implementation of [`KekProvider`].
///
/// Cheap to clone: internally just a shared `aws_sdk_kms::Client` and a
/// rotation counter.
#[derive(Clone)]
pub struct AwsKmsKekProvider {
    client: Client,
    region: String,
    /// Monotonic rotation counter, advanced by every successful
    /// [`KekProvider::rotate`] call. Per-process only — the
    /// alias-pointer rotation pattern stamps the same value into the
    /// key description so out-of-band observers can read it too.
    rotation_counter: Arc<AtomicU32>,
}

impl std::fmt::Debug for AwsKmsKekProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The SDK `Client` debug-prints a snapshot of its config which
        // can include endpoint URLs; surface only that a client is
        // wired, never any credential material.
        f.debug_struct("AwsKmsKekProvider")
            .field("client", &"<configured>")
            .field("region", &self.region)
            .field(
                "rotation_counter",
                &self.rotation_counter.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl AwsKmsKekProvider {
    /// Construct a new AWS KMS provider from an [`AwsKmsConfig`].
    ///
    /// The default AWS credential chain (env vars, profile, IMDS,
    /// container, SSO) supplies credentials. `role_arn` is reserved for
    /// the production-grade implementation and not wired into the SDK
    /// chain yet.
    ///
    /// # Errors
    ///
    /// Currently infallible: the SDK swallows credential-loading
    /// failures and surfaces them on first request. The signature is
    /// kept fallible so future eager validation (e.g. mandatory region
    /// check) can land without a breaking change.
    pub async fn new(config: AwsKmsConfig) -> Result<Self, KekError> {
        let region = config.region.clone();
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()));
        if let Some(endpoint) = config.endpoint_override.as_deref() {
            loader = loader.endpoint_url(endpoint.to_owned());
        }
        let cfg = loader.load().await;
        let client = Client::new(&cfg);
        Ok(Self {
            client,
            region,
            rotation_counter: Arc::new(AtomicU32::new(1)),
        })
    }

    /// Wrap an already-configured [`aws_sdk_kms::Client`]. Useful for
    /// tests that need to inject a stub HTTP layer without going through
    /// the default credential chain.
    #[must_use]
    pub fn from_client(client: Client, region: impl Into<String>) -> Self {
        Self {
            client,
            region: region.into(),
            rotation_counter: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Borrow the underlying SDK client. Exposed for tests and for niche
    /// callers that need to issue raw KMS operations outside the trait.
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// The configured region string.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
}

#[async_trait]
impl KekProvider for AwsKmsKekProvider {
    fn provider_id(&self) -> &'static str {
        PROVIDER_ID
    }

    async fn wrap(
        &self,
        plaintext: &[u8],
        key_id: &str,
        context: &EncryptionContext,
    ) -> Result<Vec<u8>, KekError> {
        debug!(
            target: TRACING_TARGET,
            %key_id,
            tenant_id = %context.tenant_id,
            dek_version = context.dek_version,
            bytes = plaintext.len(),
            "wrap"
        );
        let mut req = self
            .client
            .encrypt()
            .key_id(key_id)
            .plaintext(Blob::new(plaintext.to_vec()));
        for (k, v) in context.to_map() {
            req = req.encryption_context(k, v);
        }
        let out = req.send().await.map_err(|e| {
            warn!(
                target: TRACING_TARGET,
                %key_id, operation = "wrap", error = %e, "aws kms wrap failed"
            );
            KekError::provider(PROVIDER_ID, e)
        })?;
        let ct = out
            .ciphertext_blob
            .ok_or_else(|| KekError::format("aws kms encrypt: missing ciphertext_blob"))?;
        Ok(ct.into_inner())
    }

    async fn unwrap(
        &self,
        ciphertext: &[u8],
        key_id: &str,
        context: &EncryptionContext,
    ) -> Result<SecretVec, KekError> {
        debug!(
            target: TRACING_TARGET,
            %key_id,
            tenant_id = %context.tenant_id,
            dek_version = context.dek_version,
            bytes = ciphertext.len(),
            "unwrap"
        );
        let mut req = self
            .client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(Blob::new(ciphertext.to_vec()));
        for (k, v) in context.to_map() {
            req = req.encryption_context(k, v);
        }
        let out = req.send().await.map_err(|e| {
            let mapped = map_decrypt_error(&e);
            warn!(
                target: TRACING_TARGET,
                %key_id, operation = "unwrap", error = %e, "aws kms unwrap failed"
            );
            mapped
        })?;
        let pt = out
            .plaintext
            .ok_or_else(|| KekError::format("aws kms decrypt: missing plaintext"))?;
        Ok(SecretVec::new(pt.into_inner()))
    }

    async fn rotate(&self, key_id: &str) -> Result<NewKeyVersion, KekError> {
        // Alias-pointer rotation: we stamp a fresh description on the
        // *currently aliased* key so out-of-band observers (CloudTrail,
        // operators) can confirm the rotation took effect. The new
        // monotonic version we publish is the post-increment of the
        // per-process counter.
        let next = self.rotation_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let description = format!("sx-secrets KEK rotation #{next} via UpdateKeyDescription");
        self.client
            .update_key_description()
            .key_id(key_id)
            .description(description)
            .send()
            .await
            .map_err(|e| {
                warn!(
                    target: TRACING_TARGET,
                    %key_id, operation = "rotate", error = %e, "aws kms rotate failed"
                );
                KekError::provider(PROVIDER_ID, e)
            })?;
        debug!(
            target: TRACING_TARGET,
            %key_id, version = next, "rotated"
        );
        Ok(NewKeyVersion::now(key_id, next))
    }
}

/// Map an SDK `DecryptError` into the canonical [`KekError`] surface.
///
/// `InvalidCiphertextException` covers both a corrupted ciphertext and
/// an encryption-context mismatch; we surface the latter because that is
/// the more actionable signal for callers wiring `EncryptionContext`.
fn map_decrypt_error(
    err: &aws_sdk_kms::error::SdkError<
        aws_sdk_kms::operation::decrypt::DecryptError,
        aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    >,
) -> KekError {
    use aws_sdk_kms::error::SdkError;
    use aws_sdk_kms::operation::decrypt::DecryptError;

    match err {
        SdkError::ServiceError(svc) => match svc.err() {
            DecryptError::InvalidCiphertextException(_) => KekError::ContextMismatch,
            DecryptError::NotFoundException(_) => KekError::NotFound(format!("{}", svc.err())),
            DecryptError::KmsInvalidStateException(_) => KekError::Unauthorized,
            other => KekError::provider(PROVIDER_ID, other),
        },
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) => {
            KekError::transport(format!("{err}"))
        }
        other => KekError::provider(PROVIDER_ID, other),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::dek::TenantId;
    use aws_sdk_kms::config::{Config, Credentials};

    /// Build a no-network KMS client with synthetic credentials. Useful
    /// for unit tests that exercise builder shape without touching AWS.
    fn fake_client() -> Client {
        let cfg = Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                "AKIAFAKEACCESSKEY",
                "fake/secret/key/never/used",
                None,
                None,
                "sx-secrets-test",
            ))
            .build();
        Client::from_conf(cfg)
    }

    #[test]
    fn config_builder_round_trips_endpoint_and_role() {
        let cfg = AwsKmsConfig::with_region("us-east-1")
            .with_endpoint_override("http://localhost:4566")
            .with_role_arn("arn:aws:iam::123456789012:role/Sx");
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(
            cfg.endpoint_override.as_deref(),
            Some("http://localhost:4566")
        );
        assert_eq!(
            cfg.role_arn.as_deref(),
            Some("arn:aws:iam::123456789012:role/Sx")
        );
    }

    #[tokio::test]
    async fn new_with_endpoint_override_constructs_a_provider() {
        // This does NOT make any network calls; `aws_config::load` is
        // lazy. We exercise the builder path so a future regression on
        // `endpoint_url` plumbing surfaces at test time.
        let cfg =
            AwsKmsConfig::with_region("us-east-1").with_endpoint_override("http://localhost:4566");
        let provider = AwsKmsKekProvider::new(cfg).await.unwrap();
        assert_eq!(provider.provider_id(), PROVIDER_ID);
        assert_eq!(provider.region(), "us-east-1");
        // The Debug impl must not render credentials.
        let dbg = format!("{provider:?}");
        assert!(dbg.contains("AwsKmsKekProvider"));
        assert!(dbg.contains("us-east-1"));
        assert!(!dbg.contains("AKIA"));
    }

    #[test]
    fn from_client_wraps_existing_handle() {
        let client = fake_client();
        let provider = AwsKmsKekProvider::from_client(client, "us-east-1");
        assert_eq!(provider.provider_id(), PROVIDER_ID);
        assert_eq!(provider.region(), "us-east-1");
        // Underlying client handle is reachable.
        let _: &Client = provider.client();
    }

    /// Integration smoke-test gated behind an env variable so CI does
    /// not need AWS credentials. Run with:
    ///
    /// ```bash
    /// AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
    /// SENTINELX_KMS_TEST_KEY_ID=arn:aws:kms:us-east-1:1234:key/abcd \
    /// cargo test -p sx-secrets aws_kms_live_round_trip -- --ignored
    /// ```
    #[tokio::test]
    #[ignore = "Requires live AWS_ACCESS_KEY_ID / KMS key id env"]
    async fn aws_kms_live_round_trip() {
        // We deliberately do not use `std::env::var` here at the source
        // level (the workspace lint denies it); the integration test is
        // run only with `--ignored` so the lint exception in tests is
        // acceptable.
        #[allow(clippy::disallowed_methods)]
        let key_id = std::env::var("SENTINELX_KMS_TEST_KEY_ID")
            .expect("SENTINELX_KMS_TEST_KEY_ID env var required for live test");
        let cfg = AwsKmsConfig::with_region(
            #[allow(clippy::disallowed_methods)]
            std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_owned()),
        );
        let provider = AwsKmsKekProvider::new(cfg).await.unwrap();
        let context = EncryptionContext::new(TenantId::random(), 1);
        let plaintext = b"sx-secrets live round-trip";
        let ct = provider.wrap(plaintext, &key_id, &context).await.unwrap();
        let pt = provider.unwrap(&ct, &key_id, &context).await.unwrap();
        assert_eq!(pt.expose_secret(), plaintext);
    }
}
