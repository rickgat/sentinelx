//! Per-tenant push credential resolution.
//!
//! Credential material (APNs PKCS#8 EC private key, FCM service-account
//! RSA private key) is owned outside this crate — typically encrypted
//! at rest via `sx-secrets` and unsealed only when the dispatcher
//! needs to mint a fresh provider JWT. Plumbing crates implement
//! [`TenantPushCredentials`] over their own secret-storage backend.
//!
//! This module also ships [`InMemoryTenantPushCredentials`] for tests
//! and single-tenant dev rigs. All key material is wrapped in
//! [`secrecy::SecretString`]; the [`std::fmt::Debug`] impls redact it.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Mutex;

use crate::push::error::PushError;

/// APNs credentials minted by Apple for a particular team and key.
///
/// `private_key_pem` carries a PKCS#8-encoded EC private key (curve
/// P-256). The key is wrapped in [`SecretString`] and never logged.
pub struct ApnsCredentials {
    /// 10-character Apple Team ID (the JWT `iss` claim).
    pub team_id: String,
    /// 10-character Apple Key ID (the JWT `kid` header parameter).
    pub key_id: String,
    /// Bundle id of the iOS app that owns these credentials (the
    /// `apns-topic` HTTP/2 header).
    pub bundle_id: String,
    /// PKCS#8-encoded EC P-256 private key as PEM text. Never logged.
    pub private_key_pem: SecretString,
}

impl ApnsCredentials {
    /// Clone the credentials while keeping the key material wrapped.
    #[must_use]
    pub fn clone_safe(&self) -> Self {
        Self {
            team_id: self.team_id.clone(),
            key_id: self.key_id.clone(),
            bundle_id: self.bundle_id.clone(),
            private_key_pem: SecretString::from(self.private_key_pem.expose_secret().to_owned()),
        }
    }
}

impl std::fmt::Debug for ApnsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApnsCredentials")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field("bundle_id", &self.bundle_id)
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

/// FCM service-account credentials (a minimised projection of the JSON
/// blob Google issues).
///
/// `private_key_pem` is the RSA private key from the service-account
/// JSON; never logged.
pub struct FcmCredentials {
    /// Google project id the messages will be sent against.
    pub project_id: String,
    /// Service-account email (the JWT `iss` claim).
    pub client_email: String,
    /// RSA private key as PEM text. Never logged.
    pub private_key_pem: SecretString,
    /// Optional override of the `OAuth2` token endpoint (defaults to
    /// `https://oauth2.googleapis.com/token`). Tests override this to
    /// point at a wiremock server.
    pub token_uri: Option<String>,
    /// Optional override of the FCM HTTP endpoint base. Defaults to
    /// `https://fcm.googleapis.com`. Tests override this to point at a
    /// wiremock server.
    pub fcm_base_url: Option<String>,
}

impl FcmCredentials {
    /// Clone the credentials while keeping the key material wrapped.
    #[must_use]
    pub fn clone_safe(&self) -> Self {
        Self {
            project_id: self.project_id.clone(),
            client_email: self.client_email.clone(),
            private_key_pem: SecretString::from(self.private_key_pem.expose_secret().to_owned()),
            token_uri: self.token_uri.clone(),
            fcm_base_url: self.fcm_base_url.clone(),
        }
    }
}

impl std::fmt::Debug for FcmCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FcmCredentials")
            .field("project_id", &self.project_id)
            .field("client_email", &self.client_email)
            .field("private_key_pem", &"<redacted>")
            .field("token_uri", &self.token_uri)
            .field("fcm_base_url", &self.fcm_base_url)
            .finish()
    }
}

/// Tenant-scoped credential lookup used by the dispatcher.
#[async_trait]
pub trait TenantPushCredentials: Send + Sync {
    /// Resolve APNs credentials for a tenant. `Ok(None)` means the
    /// tenant has no iOS channel configured (devices for that platform
    /// are skipped, not errored).
    async fn apns_for(&self, tenant_id: &str) -> Result<Option<ApnsCredentials>, PushError>;

    /// Resolve FCM credentials for a tenant. `Ok(None)` means the
    /// tenant has no Android channel configured.
    async fn fcm_for(&self, tenant_id: &str) -> Result<Option<FcmCredentials>, PushError>;

    /// Escalation contacts (user ids) for a tenant. The dispatcher
    /// fans CRITICAL findings out to *every* device registered for
    /// each of these users.
    async fn escalation_contacts(&self, tenant_id: &str) -> Result<Vec<String>, PushError>;
}

/// In-memory credential store. The dispatcher tests use this; the
/// production composition root will replace it with a `sx-secrets`-
/// backed implementation that unseals KMS-wrapped material per call.
#[derive(Default)]
pub struct InMemoryTenantPushCredentials {
    apns: Mutex<HashMap<String, ApnsCredentials>>,
    fcm: Mutex<HashMap<String, FcmCredentials>>,
    contacts: Mutex<HashMap<String, Vec<String>>>,
}

impl std::fmt::Debug for InMemoryTenantPushCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryTenantPushCredentials")
            .finish_non_exhaustive()
    }
}

impl InMemoryTenantPushCredentials {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap in an `Arc` for sharing across handler state.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Install or replace APNs credentials for a tenant.
    pub async fn set_apns(&self, tenant_id: &str, creds: ApnsCredentials) {
        self.apns.lock().await.insert(tenant_id.to_owned(), creds);
    }

    /// Install or replace FCM credentials for a tenant.
    pub async fn set_fcm(&self, tenant_id: &str, creds: FcmCredentials) {
        self.fcm.lock().await.insert(tenant_id.to_owned(), creds);
    }

    /// Replace the escalation-contact list for a tenant.
    pub async fn set_contacts(&self, tenant_id: &str, contacts: Vec<String>) {
        self.contacts
            .lock()
            .await
            .insert(tenant_id.to_owned(), contacts);
    }
}

#[async_trait]
impl TenantPushCredentials for InMemoryTenantPushCredentials {
    async fn apns_for(&self, tenant_id: &str) -> Result<Option<ApnsCredentials>, PushError> {
        Ok(self
            .apns
            .lock()
            .await
            .get(tenant_id)
            .map(ApnsCredentials::clone_safe))
    }

    async fn fcm_for(&self, tenant_id: &str) -> Result<Option<FcmCredentials>, PushError> {
        Ok(self
            .fcm
            .lock()
            .await
            .get(tenant_id)
            .map(FcmCredentials::clone_safe))
    }

    async fn escalation_contacts(&self, tenant_id: &str) -> Result<Vec<String>, PushError> {
        Ok(self
            .contacts
            .lock()
            .await
            .get(tenant_id)
            .cloned()
            .unwrap_or_default())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_apns_private_key() {
        let creds = ApnsCredentials {
            team_id: "TEAM123456".into(),
            key_id: "KEY0987654".into(),
            bundle_id: "com.example.app".into(),
            private_key_pem: SecretString::from("-----BEGIN PRIVATE KEY-----xxx".to_owned()),
        };
        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("BEGIN PRIVATE KEY"));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn debug_redacts_fcm_private_key() {
        let creds = FcmCredentials {
            project_id: "p".into(),
            client_email: "svc@p.iam.gserviceaccount.com".into(),
            private_key_pem: SecretString::from("-----BEGIN RSA PRIVATE KEY-----yyy".to_owned()),
            token_uri: None,
            fcm_base_url: None,
        };
        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("BEGIN RSA PRIVATE KEY"));
        assert!(dbg.contains("<redacted>"));
    }
}
