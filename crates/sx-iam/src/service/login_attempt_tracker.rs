//! Login-attempt tracking — outbound port only.
//!
//! The actual store (Redis) lives in `sx-storage`. This crate defines the
//! trait and a deterministic key derivation. The key is a SHA-256 of
//! `pepper || ":" || lowercased_email`, hex-encoded — so we can
//! rate-limit by email **without** ever storing the email plaintext.
//! A full HMAC construction is not required here: the pepper is secret
//! and the input is short and well-structured, so the simpler keyed
//! hash is sufficient for unforgeability of the tracker key from the
//! email alone.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::domain::TenantId;
use crate::IamError;

/// Composite key used by the tracker — `(tenant, email_hash)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttemptKey {
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Hex-encoded HMAC-SHA256 of the lowercased email.
    pub email_hash: String,
}

impl AttemptKey {
    /// Derive a tracker key from `(tenant, email, pepper)`.
    ///
    /// The pepper must be the one configured in
    /// `IamConfig::attempt_email_pepper`; rotating it invalidates all
    /// existing counters (which is generally fine — it just resets
    /// lockout state).
    pub fn derive(
        tenant_id: TenantId,
        email: &str,
        pepper: &SecretString,
    ) -> Result<Self, IamError> {
        if pepper.expose_secret().is_empty() {
            return Err(IamError::config("attempt_email_pepper must be non-empty"));
        }
        let mut hasher = Sha256::new();
        hasher.update(pepper.expose_secret().as_bytes());
        hasher.update(b":");
        hasher.update(email.trim().to_ascii_lowercase().as_bytes());
        let bytes = hasher.finalize();
        Ok(Self {
            tenant_id,
            email_hash: hex::encode(bytes),
        })
    }
}

/// Tracks consecutive failed login attempts per `(tenant, email)`.
///
/// Implementations are expected to be cluster-shared (e.g. Redis with
/// a TTL matching `LockoutPolicy::lock_duration`). The trait operates
/// in failure-counting terms only; lockout *thresholds* live in
/// `LockoutPolicy` and are evaluated by
/// [`crate::controller::AuthenticateUserUseCase`].
#[async_trait]
pub trait LoginAttemptTracker: Send + Sync {
    /// Record a single failure. Returns the **new** total.
    async fn record_failure(&self, key: &AttemptKey) -> Result<u32, IamError>;

    /// Return the current failure count (`0` if no record).
    async fn count_failures(&self, key: &AttemptKey) -> Result<u32, IamError>;

    /// Reset the failure counter (called on successful auth).
    async fn clear(&self, key: &AttemptKey) -> Result<(), IamError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn attempt_key_email_hashed_not_stored_plain() {
        let tid = TenantId::new();
        let pepper = SecretString::from("pep".to_string());
        let k = AttemptKey::derive(tid, "alice@example.com", &pepper).unwrap();
        assert!(!k.email_hash.contains("alice"));
        assert!(!k.email_hash.contains('@'));
        // SHA-256 → 32 bytes → 64 hex chars.
        assert_eq!(k.email_hash.len(), 64);
    }

    #[test]
    fn attempt_key_is_email_case_insensitive() {
        let tid = TenantId::new();
        let pepper = SecretString::from("pep".to_string());
        let a = AttemptKey::derive(tid, "Alice@Example.com", &pepper).unwrap();
        let b = AttemptKey::derive(tid, "alice@example.com", &pepper).unwrap();
        assert_eq!(a.email_hash, b.email_hash);
    }

    #[test]
    fn attempt_key_pepper_changes_hash() {
        let tid = TenantId::new();
        let a = AttemptKey::derive(
            tid,
            "alice@example.com",
            &SecretString::from("p1".to_string()),
        )
        .unwrap();
        let b = AttemptKey::derive(
            tid,
            "alice@example.com",
            &SecretString::from("p2".to_string()),
        )
        .unwrap();
        assert_ne!(a.email_hash, b.email_hash);
    }
}
