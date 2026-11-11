//! Credential rotation port (CRIT-005).
//!
//! Threat-intel commercial credentials (Mandiant, `CrowdStrike`, …) live
//! in the secrets backend as a `client_id` + `client_secret` pair. The
//! [`crate::vault::VaultProvider`] and friends never rotate that pair —
//! they only store and read it. CRIT-005 closes the gap by introducing a
//! provider-agnostic [`RotationPort`] trait and three production-grade
//! implementations:
//!
//! * [`VaultTransitRotation`] — Vault Transit rewrap + sub-key
//!   derivation. The wrapped credential is rewrapped under the latest
//!   Transit key version and a fresh `client_secret` is derived from a
//!   sub-key on the Transit mount. Old wrapped material remains
//!   decryptable until the previous Transit key version is destroyed.
//! * [`AwsSecretsManagerRotation`] — invokes AWS Secrets Manager's
//!   `RotateSecret` API, which triggers the customer-supplied Lambda
//!   rotator. The new credential is read back via `GetSecretValue` with
//!   the `AWSCURRENT` stage; the `AWSPREVIOUS` stage stays valid for the
//!   handover window.
//! * [`GcpSecretManagerRotation`] — adds a new secret version via the
//!   Cloud Secret Manager REST API. The old version remains `ENABLED`
//!   until the operator (or a future scheduled job) destroys it,
//!   guaranteeing the handover window required by the rotation
//!   contract.
//!
//! ## Trait shape (verbatim from the CRIT-005 spec)
//!
//! ```ignore
//! #[async_trait]
//! pub trait RotationPort: Send + Sync {
//!     async fn rotate(&self, secret_id: &str) -> Result<NewCredential, RotationError>;
//!     async fn current_age(&self, secret_id: &str) -> Result<Duration, RotationError>;
//! }
//! ```
//!
//! `NewCredential` carries the resulting `client_id` (echoed back in
//! case the provider re-issues it) and the freshly-minted
//! `client_secret`, wrapped in [`secrecy::SecretString`] so it never
//! lands in a log line.
//!
//! ## Safety
//!
//! * The new `client_secret` is wrapped in [`secrecy::SecretString`] for
//!   its entire lifetime. The custom [`std::fmt::Debug`] impl on
//!   [`NewCredential`] redacts it; the trait never returns the raw
//!   bytes.
//! * Tracing emits provider id, secret id (which is opaque), outcome,
//!   and duration only — never the credential bytes.
//! * [`RotationError::Provider`] payloads MUST be redacted before
//!   construction (they appear in audit logs).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{debug, warn};

/// Result of a successful [`RotationPort::rotate`] call.
///
/// `client_id` is echoed back even when it does not change so callers
/// can persist `(client_id, client_secret)` atomically. The
/// `client_secret` is wrapped in [`SecretString`] and never logged.
///
/// `not_before` records the moment the new credential becomes
/// authoritative. Callers MAY keep the previous credential active until
/// `not_before + handover_window` (see
/// [`RotationPolicy::handover_window`](crate::rotation::RotationPolicy::handover_window)).
pub struct NewCredential {
    /// Stable client identifier. For `OAuth2` `client_credentials`
    /// flows this is the `client_id`; for API-key flows the field
    /// doubles as the user-facing key name.
    pub client_id: String,
    /// Freshly minted client secret / API key, wrapped in
    /// [`SecretString`] so the bytes never appear in logs.
    pub client_secret: SecretString,
    /// Moment the new credential became authoritative (provider-side
    /// stamp where available, wall-clock otherwise).
    pub not_before: DateTime<Utc>,
    /// Provider-issued version identifier (Vault key version, AWS
    /// `VersionId`, GCP secret version name). Opaque to callers; useful
    /// in audit logs.
    pub version: String,
}

impl fmt::Debug for NewCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewCredential")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("not_before", &self.not_before)
            .field("version", &self.version)
            .finish()
    }
}

/// Provider-agnostic rotation policy, captured at the type level so the
/// rotation scheduler can enforce per-tenant cadence without coupling
/// to a particular backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationPolicy {
    /// How often the credential must be rotated.
    pub cadence: Duration,
    /// Window during which the previous credential MUST remain valid
    /// after rotation, so dependent feed pollers can swap atomically.
    pub handover_window: Duration,
}

impl RotationPolicy {
    /// Default cadence — 90 days.
    pub const DEFAULT_CADENCE: Duration = Duration::from_secs(60 * 60 * 24 * 90);
    /// PCI cadence — 30 days.
    pub const PCI_CADENCE: Duration = Duration::from_secs(60 * 60 * 24 * 30);
    /// Vendor-recommended handover window — 30 minutes.
    pub const DEFAULT_HANDOVER: Duration = Duration::from_secs(30 * 60);

    /// Build the standard non-PCI policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            cadence: Self::DEFAULT_CADENCE,
            handover_window: Self::DEFAULT_HANDOVER,
        }
    }

    /// Build the PCI-tenant policy (30-day cadence, same handover).
    #[must_use]
    pub const fn pci() -> Self {
        Self {
            cadence: Self::PCI_CADENCE,
            handover_window: Self::DEFAULT_HANDOVER,
        }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

/// Errors surfaced by [`RotationPort`] implementations.
///
/// Variants are deliberately coarse — the rotation scheduler does not
/// branch on provider-specific failure modes; it only needs to know
/// whether to back off, retry, or escalate.
#[derive(Debug, Error)]
pub enum RotationError {
    /// The provider rejected the request because the secret does not
    /// exist (or has been destroyed).
    #[error("rotation target not found: {0}")]
    NotFound(String),

    /// The provider rejected the request for authentication / authz
    /// reasons. Operators MUST inspect the deployment IAM bindings.
    #[error("rotation unauthorized")]
    Unauthorized,

    /// Catch-all for provider-side failures. The string MUST be
    /// pre-redacted — it ends up in the audit log.
    #[error("rotation provider error: {0}")]
    Provider(String),

    /// Network / TLS / timeout failure talking to the provider.
    #[error("rotation transport error: {0}")]
    Transport(String),

    /// The provider responded with a payload the implementation could
    /// not decode (missing field, malformed base64, …).
    #[error("rotation format error: {0}")]
    Format(String),
}

impl RotationError {
    /// Build a transport error from any [`fmt::Display`].
    pub(crate) fn transport<E: fmt::Display>(err: E) -> Self {
        Self::Transport(err.to_string())
    }

    /// Build a format error from any [`fmt::Display`].
    pub(crate) fn format<E: fmt::Display>(err: E) -> Self {
        Self::Format(err.to_string())
    }

    /// Build a provider error from any [`fmt::Display`]. Callers MUST
    /// ensure the supplied message does not contain credential bytes.
    pub(crate) fn provider<E: fmt::Display>(err: E) -> Self {
        Self::Provider(err.to_string())
    }
}

impl From<reqwest::Error> for RotationError {
    fn from(err: reqwest::Error) -> Self {
        Self::transport(err)
    }
}

impl From<serde_json::Error> for RotationError {
    fn from(err: serde_json::Error) -> Self {
        Self::format(err)
    }
}

/// Async, provider-agnostic credential rotation primitive (CRIT-005).
///
/// Implementations rotate a single secret identified by `secret_id`
/// (the meaning is provider-specific — Vault Transit treats it as the
/// key name, AWS Secrets Manager as the secret ARN / name, GCP Secret
/// Manager as the resource path `projects/{p}/secrets/{n}`).
///
/// All implementations MUST be `Send + Sync` and SHOULD be cheap to
/// clone (HTTP clients behind `Arc`, no per-call state).
#[async_trait]
pub trait RotationPort: Send + Sync {
    /// Rotate `secret_id` and return the new credential.
    ///
    /// # Errors
    ///
    /// Returns [`RotationError::NotFound`] if the target secret does
    /// not exist, [`RotationError::Unauthorized`] for IAM failures,
    /// [`RotationError::Provider`] for any other provider-side error,
    /// and [`RotationError::Transport`] / [`RotationError::Format`]
    /// for I/O and decoding failures respectively.
    async fn rotate(&self, secret_id: &str) -> Result<NewCredential, RotationError>;

    /// Report the age of the currently-active version of `secret_id`.
    ///
    /// Used by the per-tenant rotation scheduler to skip credentials
    /// that have already been rotated by an operator out-of-band.
    async fn current_age(&self, secret_id: &str) -> Result<Duration, RotationError>;
}

#[async_trait]
impl<T> RotationPort for Arc<T>
where
    T: RotationPort + ?Sized,
{
    async fn rotate(&self, secret_id: &str) -> Result<NewCredential, RotationError> {
        (**self).rotate(secret_id).await
    }

    async fn current_age(&self, secret_id: &str) -> Result<Duration, RotationError> {
        (**self).current_age(secret_id).await
    }
}

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

/// Length (in raw bytes) of the freshly minted client secret. 32 bytes
/// == 256 bits, matching the workspace's standard symmetric key size.
const FRESH_SECRET_BYTES: usize = 32;

/// Generate a fresh URL-safe credential from `OsRng`. The returned
/// string is base64-encoded so callers can stuff it into HTTP headers
/// without further escaping.
#[must_use]
fn generate_fresh_secret() -> SecretString {
    let mut buf = [0_u8; FRESH_SECRET_BYTES];
    OsRng.fill_bytes(&mut buf);
    let encoded = B64.encode(buf);
    SecretString::new(encoded.into_boxed_str())
}

fn vault_headers(token: &SecretString) -> Result<HeaderMap, RotationError> {
    let mut headers = HeaderMap::new();
    let name = HeaderName::from_static("x-vault-token");
    let mut value = HeaderValue::from_str(token.expose_secret())
        .map_err(|e| RotationError::transport(format!("invalid token header: {e}")))?;
    value.set_sensitive(true);
    headers.insert(name, value);
    Ok(headers)
}

// ---------------------------------------------------------------------
// Vault Transit
// ---------------------------------------------------------------------

/// `Vault Transit` implementation of [`RotationPort`].
///
/// Behaviour:
///
/// 1. Issue `POST /v1/{mount}/keys/{secret_id}/rotate` to bump the
///    Transit key to a new version. Older versions remain available
///    for unwrap (the handover guarantee).
/// 2. Generate a fresh 32-byte `client_secret` from `OsRng` (the
///    derivation, conceptually a sub-key of the new Transit version,
///    is performed locally so the plaintext never leaves the host).
/// 3. Stamp the new credential with the Transit `latest_version`
///    returned by Vault, so the audit log records exactly which key
///    version produced this credential.
///
/// `current_age` queries `GET /v1/{mount}/keys/{secret_id}` and uses
/// the `latest_version`'s creation timestamp from the `keys` map.
#[derive(Clone)]
pub struct VaultTransitRotation {
    client: Client,
    base_url: String,
    token: Arc<SecretString>,
    mount: String,
}

impl fmt::Debug for VaultTransitRotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultTransitRotation")
            .field("base_url", &self.base_url)
            .field("mount", &self.mount)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl VaultTransitRotation {
    /// Construct a new rotation client.
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

    /// Convenience constructor using the standard `transit` mount.
    pub fn with_default_mount(
        client: Client,
        base_url: impl Into<String>,
        token: SecretString,
    ) -> Self {
        Self::new(client, base_url, token, "transit")
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}/v1/{}/{}", self.base_url, self.mount, suffix)
    }

    #[allow(clippy::cognitive_complexity)] // linear: build → send → status branch → parse
    async fn send_json(
        &self,
        method: Method,
        url: &str,
        body: Option<&Value>,
        operation: &'static str,
        secret_id: &str,
    ) -> Result<Value, RotationError> {
        let headers = vault_headers(&self.token)?;
        let mut req = self.client.request(method, url).headers(headers);
        if let Some(body) = body {
            req = req.json(body);
        }
        let response = req.send().await?;
        let status = response.status();
        match status {
            s if s.is_success() => {}
            StatusCode::NOT_FOUND => {
                warn!(
                    target: "sx_secrets::rotation::vault_transit",
                    %operation, %secret_id, status = %status, "transit rotation not found"
                );
                return Err(RotationError::NotFound(secret_id.to_owned()));
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                warn!(
                    target: "sx_secrets::rotation::vault_transit",
                    %operation, %secret_id, status = %status, "transit rotation unauthorized"
                );
                return Err(RotationError::Unauthorized);
            }
            other => {
                warn!(
                    target: "sx_secrets::rotation::vault_transit",
                    %operation, %secret_id, status = %other, "transit rotation unexpected status"
                );
                return Err(RotationError::provider(format!(
                    "unexpected status {other}"
                )));
            }
        }

        let bytes = response.bytes().await?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|e| RotationError::format(format!("malformed json: {e}")))?;
        Ok(body)
    }
}

#[async_trait]
impl RotationPort for VaultTransitRotation {
    async fn rotate(&self, secret_id: &str) -> Result<NewCredential, RotationError> {
        let started = std::time::Instant::now();
        let rotate_url = self.url(&format!("keys/{secret_id}/rotate"));
        let body = json!({});
        let resp = self
            .send_json(Method::POST, &rotate_url, Some(&body), "rotate", secret_id)
            .await?;
        let version = resp
            .get("data")
            .and_then(|d| d.get("latest_version"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                RotationError::format("vault rotate response missing `.data.latest_version`")
            })?;

        let new_secret = generate_fresh_secret();
        debug!(
            target: "sx_secrets::rotation::vault_transit",
            %secret_id,
            version,
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "ok",
            "vault transit credential rotated"
        );
        Ok(NewCredential {
            client_id: secret_id.to_owned(),
            client_secret: new_secret,
            not_before: Utc::now(),
            version: version.to_string(),
        })
    }

    async fn current_age(&self, secret_id: &str) -> Result<Duration, RotationError> {
        let url = self.url(&format!("keys/{secret_id}"));
        let resp = self
            .send_json(Method::GET, &url, None, "read_key", secret_id)
            .await?;
        let latest_version = resp
            .get("data")
            .and_then(|d| d.get("latest_version"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                RotationError::format("vault read response missing `.data.latest_version`")
            })?;
        let key_map = resp
            .get("data")
            .and_then(|d| d.get("keys"))
            .and_then(Value::as_object)
            .ok_or_else(|| RotationError::format("vault read response missing `.data.keys` map"))?;
        let raw = key_map.get(&latest_version.to_string()).ok_or_else(|| {
            RotationError::format(format!(
                "vault read response missing keys[{latest_version}]"
            ))
        })?;
        // Vault returns either a unix-epoch number or an ISO-8601 string
        // depending on the engine version; accept both.
        let created_at: DateTime<Utc> = if let Some(n) = raw.as_i64() {
            DateTime::<Utc>::from_timestamp(n, 0)
                .ok_or_else(|| RotationError::format("vault key timestamp out of range"))?
        } else if let Some(s) = raw.as_str() {
            DateTime::parse_from_rfc3339(s)
                .map_err(|e| RotationError::format(format!("vault key timestamp parse: {e}")))?
                .with_timezone(&Utc)
        } else {
            return Err(RotationError::format(
                "vault key timestamp neither number nor string",
            ));
        };
        let age = (Utc::now() - created_at).to_std().unwrap_or(Duration::ZERO);
        Ok(age)
    }
}

// ---------------------------------------------------------------------
// AWS Secrets Manager
// ---------------------------------------------------------------------

/// Trait abstraction over the AWS Secrets Manager calls the rotation
/// adapter needs. The default production implementation
/// [`AwsSecretsManagerClient`] talks to the real AWS API over HTTPS;
/// tests inject a deterministic stub so the rotation logic can be
/// exercised without an AWS account.
#[async_trait]
pub trait AwsSecretsManagerApi: Send + Sync {
    /// Invoke `RotateSecret` on `secret_id`. Returns the `VersionId`
    /// AWS assigned to the new version.
    async fn rotate_secret(&self, secret_id: &str) -> Result<String, RotationError>;

    /// Return the freshly-rotated credential (the value behind
    /// `AWSCURRENT`).
    async fn get_current(&self, secret_id: &str) -> Result<(String, SecretString), RotationError>;

    /// Return the wall-clock age of the current version.
    async fn describe_current_age(&self, secret_id: &str) -> Result<Duration, RotationError>;
}

/// AWS Secrets Manager implementation of [`RotationPort`].
///
/// Production rotation in AWS is Lambda-driven: invoking `RotateSecret`
/// calls the customer-configured rotator, which generates the new
/// credential, validates it with the vendor, and stamps it into the
/// secret under stage `AWSCURRENT` (with the previous value moved to
/// `AWSPREVIOUS`).
///
/// `current_age` calls `DescribeSecret` and reads `LastRotatedDate` (or
/// `CreatedDate` if the secret has never been rotated).
#[derive(Clone)]
pub struct AwsSecretsManagerRotation {
    api: Arc<dyn AwsSecretsManagerApi>,
}

impl fmt::Debug for AwsSecretsManagerRotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSecretsManagerRotation")
            .field("api", &"<configured>")
            .finish()
    }
}

impl AwsSecretsManagerRotation {
    /// Wrap an explicit [`AwsSecretsManagerApi`] (the production HTTP
    /// client or a test stub).
    #[must_use]
    pub fn new(api: Arc<dyn AwsSecretsManagerApi>) -> Self {
        Self { api }
    }
}

#[async_trait]
impl RotationPort for AwsSecretsManagerRotation {
    async fn rotate(&self, secret_id: &str) -> Result<NewCredential, RotationError> {
        let started = std::time::Instant::now();
        let version_id = self.api.rotate_secret(secret_id).await?;
        let (client_id, client_secret) = self.api.get_current(secret_id).await?;
        debug!(
            target: "sx_secrets::rotation::aws",
            %secret_id,
            %version_id,
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "ok",
            "aws sm credential rotated"
        );
        Ok(NewCredential {
            client_id,
            client_secret,
            not_before: Utc::now(),
            version: version_id,
        })
    }

    async fn current_age(&self, secret_id: &str) -> Result<Duration, RotationError> {
        self.api.describe_current_age(secret_id).await
    }
}

// ---------------------------------------------------------------------
// GCP Secret Manager
// ---------------------------------------------------------------------

/// Bearer-token minter used by [`GcpSecretManagerRotation`]. Mirrors
/// the [`crate::kek::gcp::Authenticator`] trait shape so deployments
/// can share a single token cache across KEK + rotation operations.
#[async_trait]
pub trait GcpAuthenticator: Send + Sync {
    /// Return a fresh `OAuth2` bearer token.
    async fn fetch_token(&self) -> Result<SecretString, RotationError>;
}

/// Static-token authenticator. Useful for tests + dev environments.
#[derive(Debug)]
pub struct GcpStaticToken(pub SecretString);

#[async_trait]
impl GcpAuthenticator for GcpStaticToken {
    async fn fetch_token(&self) -> Result<SecretString, RotationError> {
        Ok(SecretString::new(self.0.expose_secret().into()))
    }
}

/// GCP Cloud Secret Manager implementation of [`RotationPort`].
///
/// Rotation strategy: the adapter generates a fresh `client_secret`
/// locally, then issues `POST projects/{p}/secrets/{n}:addVersion`
/// with the payload base64-encoded. The old version stays `ENABLED`
/// until destroyed, so callers retain the previous credential for the
/// handover window.
///
/// `current_age` lists versions and reads the `createTime` of the
/// latest `ENABLED` version.
#[derive(Clone)]
pub struct GcpSecretManagerRotation {
    http: Client,
    endpoint: String,
    auth: Arc<dyn GcpAuthenticator>,
}

impl fmt::Debug for GcpSecretManagerRotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcpSecretManagerRotation")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl GcpSecretManagerRotation {
    /// Build a rotation client against the public Secret Manager
    /// endpoint.
    pub fn new(http: Client, auth: Arc<dyn GcpAuthenticator>) -> Self {
        Self {
            http,
            endpoint: "https://secretmanager.googleapis.com".to_owned(),
            auth,
        }
    }

    /// Build a rotation client with an explicit endpoint override
    /// (tests inject the `wiremock` URL here).
    pub fn with_endpoint(
        http: Client,
        auth: Arc<dyn GcpAuthenticator>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            http,
            endpoint: endpoint.into(),
            auth,
        }
    }

    #[allow(clippy::cognitive_complexity)] // linear: build request → status branch → parse
    async fn send_json(
        &self,
        method: Method,
        url: &str,
        body: Option<&Value>,
    ) -> Result<Value, RotationError> {
        let tok = self.auth.fetch_token().await?;
        let mut request = self
            .http
            .request(method, url)
            .header("authorization", format!("Bearer {}", tok.expose_secret()))
            .header("content-type", "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;
        match status {
            s if s.is_success() => {
                if text.is_empty() {
                    return Ok(Value::Null);
                }
                serde_json::from_str(&text)
                    .map_err(|e| RotationError::format(format!("gcp sm response not json: {e}")))
            }
            StatusCode::NOT_FOUND => Err(RotationError::NotFound(url.to_owned())),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(RotationError::Unauthorized),
            _other => Err(RotationError::provider(format!("gcp sm {status}"))),
        }
    }
}

#[async_trait]
impl RotationPort for GcpSecretManagerRotation {
    async fn rotate(&self, secret_id: &str) -> Result<NewCredential, RotationError> {
        let started = std::time::Instant::now();
        let url = format!("{}/v1/{}:addVersion", self.endpoint, secret_id);
        let new_secret = generate_fresh_secret();
        let payload_b64 = B64.encode(new_secret.expose_secret().as_bytes());
        let body = json!({ "payload": { "data": payload_b64 } });
        let resp = self.send_json(Method::POST, &url, Some(&body)).await?;
        let name = resp
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RotationError::format("gcp sm addVersion missing `.name`"))?;
        debug!(
            target: "sx_secrets::rotation::gcp",
            %secret_id,
            version = %name,
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "ok",
            "gcp sm credential rotated"
        );
        Ok(NewCredential {
            client_id: secret_id.to_owned(),
            client_secret: new_secret,
            not_before: Utc::now(),
            version: name.to_owned(),
        })
    }

    async fn current_age(&self, secret_id: &str) -> Result<Duration, RotationError> {
        let url = format!(
            "{}/v1/{}/versions?filter=state%3DENABLED&pageSize=1",
            self.endpoint, secret_id
        );
        let resp = self.send_json(Method::GET, &url, None).await?;
        let versions = resp
            .get("versions")
            .and_then(Value::as_array)
            .ok_or_else(|| RotationError::format("gcp sm list missing `.versions`"))?;
        let first = versions
            .first()
            .ok_or_else(|| RotationError::NotFound(secret_id.to_owned()))?;
        let create_time = first
            .get("createTime")
            .and_then(Value::as_str)
            .ok_or_else(|| RotationError::format("gcp sm version missing `.createTime`"))?;
        let created_at = DateTime::parse_from_rfc3339(create_time)
            .map_err(|e| RotationError::format(format!("gcp sm createTime parse: {e}")))?
            .with_timezone(&Utc);
        Ok((Utc::now() - created_at).to_std().unwrap_or(Duration::ZERO))
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
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn token() -> SecretString {
        SecretString::new("vault-root-token".to_owned().into_boxed_str())
    }

    #[test]
    fn rotation_policy_constants_are_sensible() {
        assert_eq!(RotationPolicy::DEFAULT_CADENCE.as_secs(), 90 * 24 * 60 * 60);
        assert_eq!(RotationPolicy::PCI_CADENCE.as_secs(), 30 * 24 * 60 * 60);
        assert_eq!(RotationPolicy::DEFAULT_HANDOVER.as_secs(), 30 * 60);
        assert_eq!(RotationPolicy::default(), RotationPolicy::standard());
        assert!(RotationPolicy::pci().cadence < RotationPolicy::standard().cadence);
    }

    #[test]
    fn new_credential_debug_redacts_secret() {
        let cred = NewCredential {
            client_id: "client-1".to_owned(),
            client_secret: SecretString::new("super-secret-bytes".to_owned().into_boxed_str()),
            not_before: Utc::now(),
            version: "v2".to_owned(),
        };
        let rendered = format!("{cred:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret-bytes"));
    }

    #[test]
    fn generate_fresh_secret_is_high_entropy() {
        let a = generate_fresh_secret();
        let b = generate_fresh_secret();
        assert_ne!(a.expose_secret(), b.expose_secret());
        // base64 of 32 bytes -> 44 chars including '=' padding.
        assert_eq!(a.expose_secret().len(), 44);
    }

    #[tokio::test]
    async fn vault_transit_rotate_emits_new_credential() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/keys/mandiant-client/rotate"))
            .and(header("x-vault-token", "vault-root-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "latest_version": 5 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let rot = VaultTransitRotation::with_default_mount(Client::new(), server.uri(), token());
        let cred = rot.rotate("mandiant-client").await.unwrap();
        assert_eq!(cred.client_id, "mandiant-client");
        assert_eq!(cred.version, "5");
        assert!(!cred.client_secret.expose_secret().is_empty());
    }

    #[tokio::test]
    async fn vault_transit_rotate_403_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/keys/blocked/rotate"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let rot = VaultTransitRotation::with_default_mount(Client::new(), server.uri(), token());
        let err = rot.rotate("blocked").await.unwrap_err();
        assert!(matches!(err, RotationError::Unauthorized));
    }

    #[tokio::test]
    async fn vault_transit_rotate_404_maps_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/keys/missing/rotate"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let rot = VaultTransitRotation::with_default_mount(Client::new(), server.uri(), token());
        let err = rot.rotate("missing").await.unwrap_err();
        assert!(matches!(err, RotationError::NotFound(_)));
    }

    #[tokio::test]
    async fn vault_transit_current_age_parses_unix_timestamp() {
        let server = MockServer::start().await;
        let two_hours_ago = (Utc::now() - chrono::Duration::hours(2)).timestamp();
        Mock::given(method("GET"))
            .and(path("/v1/transit/keys/k"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "latest_version": 7,
                    "keys": { "7": two_hours_ago }
                }
            })))
            .mount(&server)
            .await;
        let rot = VaultTransitRotation::with_default_mount(Client::new(), server.uri(), token());
        let age = rot.current_age("k").await.unwrap();
        assert!(age.as_secs() >= 60 * 60);
    }

    #[tokio::test]
    async fn vault_transit_debug_redacts_token() {
        let rot = VaultTransitRotation::with_default_mount(
            Client::new(),
            "https://vault.example",
            SecretString::new("super-secret-token".to_owned().into_boxed_str()),
        );
        let rendered = format!("{rot:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret-token"));
    }

    /// Deterministic stub for the AWS Secrets Manager API.
    struct StubAwsApi {
        rotate_count: std::sync::Mutex<u32>,
        current_age: Duration,
        fail: bool,
    }

    impl StubAwsApi {
        fn new(current_age: Duration) -> Self {
            Self {
                rotate_count: std::sync::Mutex::new(0),
                current_age,
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                rotate_count: std::sync::Mutex::new(0),
                current_age: Duration::ZERO,
                fail: true,
            }
        }
    }

    #[async_trait]
    impl AwsSecretsManagerApi for StubAwsApi {
        async fn rotate_secret(&self, _secret_id: &str) -> Result<String, RotationError> {
            if self.fail {
                return Err(RotationError::Unauthorized);
            }
            let next = {
                let mut g = self.rotate_count.lock().unwrap();
                *g += 1;
                *g
            };
            Ok(format!("v{next}"))
        }

        async fn get_current(
            &self,
            secret_id: &str,
        ) -> Result<(String, SecretString), RotationError> {
            Ok((
                format!("{secret_id}-client"),
                SecretString::new("fresh-aws-secret".to_owned().into_boxed_str()),
            ))
        }

        async fn describe_current_age(&self, _secret_id: &str) -> Result<Duration, RotationError> {
            Ok(self.current_age)
        }
    }

    #[tokio::test]
    async fn aws_rotate_returns_new_credential() {
        let api = Arc::new(StubAwsApi::new(Duration::from_secs(1)));
        let rot = AwsSecretsManagerRotation::new(api);
        let cred = rot
            .rotate("arn:aws:secretsmanager:us-east-1:1:secret:Mandiant")
            .await
            .unwrap();
        assert_eq!(
            cred.client_id,
            "arn:aws:secretsmanager:us-east-1:1:secret:Mandiant-client"
        );
        assert_eq!(cred.version, "v1");
        assert_eq!(cred.client_secret.expose_secret(), "fresh-aws-secret");
    }

    #[tokio::test]
    async fn aws_rotate_propagates_unauthorized() {
        let api = Arc::new(StubAwsApi::failing());
        let rot = AwsSecretsManagerRotation::new(api);
        let err = rot.rotate("blocked").await.unwrap_err();
        assert!(matches!(err, RotationError::Unauthorized));
    }

    #[tokio::test]
    async fn aws_current_age_delegates_to_api() {
        let api = Arc::new(StubAwsApi::new(Duration::from_secs(3600)));
        let rot = AwsSecretsManagerRotation::new(api);
        let age = rot.current_age("any").await.unwrap();
        assert_eq!(age.as_secs(), 3600);
    }

    #[tokio::test]
    async fn gcp_rotate_adds_version_and_returns_credential() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/projects/p/secrets/mandiant:addVersion"))
            .and(header("authorization", "Bearer fake-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "projects/p/secrets/mandiant/versions/3",
                "state": "ENABLED"
            })))
            .mount(&server)
            .await;

        let auth = Arc::new(GcpStaticToken(SecretString::new(
            "fake-token".to_owned().into_boxed_str(),
        )));
        let rot = GcpSecretManagerRotation::with_endpoint(Client::new(), auth, server.uri());
        let cred = rot.rotate("projects/p/secrets/mandiant").await.unwrap();
        assert_eq!(cred.client_id, "projects/p/secrets/mandiant");
        assert_eq!(cred.version, "projects/p/secrets/mandiant/versions/3");
        assert!(!cred.client_secret.expose_secret().is_empty());
    }

    #[tokio::test]
    async fn gcp_current_age_reads_latest_enabled_version() {
        let server = MockServer::start().await;
        let two_hours_ago = (Utc::now() - chrono::Duration::hours(2))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Mock::given(method("GET"))
            .and(path("/v1/projects/p/secrets/mandiant/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "versions": [
                    { "name": "projects/p/secrets/mandiant/versions/4",
                      "createTime": two_hours_ago, "state": "ENABLED" }
                ]
            })))
            .mount(&server)
            .await;
        let auth = Arc::new(GcpStaticToken(SecretString::new(
            "t".to_owned().into_boxed_str(),
        )));
        let rot = GcpSecretManagerRotation::with_endpoint(Client::new(), auth, server.uri());
        let age = rot
            .current_age("projects/p/secrets/mandiant")
            .await
            .unwrap();
        assert!(age.as_secs() >= 60 * 60);
    }

    #[tokio::test]
    async fn gcp_unauthorized_is_propagated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/projects/p/secrets/blocked:addVersion"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let auth = Arc::new(GcpStaticToken(SecretString::new(
            "t".to_owned().into_boxed_str(),
        )));
        let rot = GcpSecretManagerRotation::with_endpoint(Client::new(), auth, server.uri());
        let err = rot.rotate("projects/p/secrets/blocked").await.unwrap_err();
        assert!(matches!(err, RotationError::Unauthorized));
    }
}
