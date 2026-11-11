//! [`SigningKey`] + [`Kid`] — opaque envelopes around the per-tenant
//! HMAC secret and its short, header-safe identifier.
//!
//! The secret bytes live in [`secrecy::SecretString`] so neither `Debug`
//! nor accidental logging exposes them. The `kid` is a stable opaque
//! string (default `kid_<8 hex>`) we put on the wire as
//! `X-SentinelX-Kid` next to the HMAC.

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Header name carrying the active key id on every signed outbound
/// payload.
pub const KID_HEADER: &str = "X-SentinelX-Kid";

/// Header name carrying the HMAC-SHA256 signature (hex) on every
/// signed outbound payload.
pub const SIGNATURE_HEADER: &str = "X-SentinelX-Signature";

/// Opaque key id (short hex with a `kid_` prefix). Always safe for
/// HTTP headers and audit-log emission.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Kid(String);

impl Kid {
    /// Wrap an existing string. The caller is responsible for the
    /// invariants `length(s) >= 4` and `s` is header-safe ASCII.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Mint a fresh kid: `kid_<8 hex>` (32 bits of entropy is plenty —
    /// kids are non-secret identifiers; collisions across a single
    /// tenant are checked by the unique PK on the store).
    #[must_use]
    pub fn mint() -> Self {
        let mut buf = [0_u8; 4];
        OsRng.fill_bytes(&mut buf);
        Self(format!("kid_{}", hex::encode(buf)))
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the inner string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Convenience newtype for the `(tenant_id, kid)` row key — useful
/// across logs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SigningKeyId {
    /// Tenant the row belongs to.
    pub tenant_id: String,
    /// The key id.
    pub kid: Kid,
}

/// One per-tenant HMAC signing key.
///
/// `secret` is wrapped in [`SecretString`] so the bytes never appear in
/// logs (the custom `Debug` impl below redacts the field).
///
/// `activated_at` is when the verifier started accepting the key;
/// `retired_at` is the moment the verifier stopped accepting it (NULL
/// while the key is live).
#[derive(Clone)]
pub struct SigningKey {
    /// Tenant the key belongs to.
    pub tenant_id: String,
    /// Key id (rendered into headers + the audit log).
    pub kid: Kid,
    /// Raw HMAC secret bytes wrapped in [`SecretString`]. Plaintext;
    /// the store keeps a ciphertext copy and decrypts at read time.
    pub secret: SecretString,
    /// Wall-clock time the key was minted.
    pub created_at: DateTime<Utc>,
    /// Wall-clock time the key first became a signing candidate.
    pub activated_at: DateTime<Utc>,
    /// Wall-clock time the key stopped being accepted. `None` while
    /// the key is live.
    pub retired_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("tenant_id", &self.tenant_id)
            .field("kid", &self.kid)
            .field("secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("activated_at", &self.activated_at)
            .field("retired_at", &self.retired_at)
            .finish()
    }
}

impl SigningKey {
    /// Mint a fresh signing key for `tenant_id` with a brand-new kid
    /// and 32-byte random secret. Activates immediately.
    #[must_use]
    pub fn mint(tenant_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            tenant_id: tenant_id.into(),
            kid: Kid::mint(),
            secret: random_secret(),
            created_at: now,
            activated_at: now,
            retired_at: None,
        }
    }

    /// Borrow as a `SigningKeyId`.
    #[must_use]
    pub fn id(&self) -> SigningKeyId {
        SigningKeyId {
            tenant_id: self.tenant_id.clone(),
            kid: self.kid.clone(),
        }
    }

    /// Return `true` if the key is currently a valid signing /
    /// verifying candidate at `now`.
    #[must_use]
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        if self.activated_at > now {
            return false;
        }
        self.retired_at.is_none_or(|r| r > now)
    }
}

/// Generate a fresh 32-byte (256-bit) HMAC secret encoded
/// URL-safe-base64-no-pad. Plaintext lives only inside
/// [`SecretString`].
#[must_use]
pub(crate) fn random_secret() -> SecretString {
    let mut buf = [0_u8; 32];
    OsRng.fill_bytes(&mut buf);
    let encoded = B64URL.encode(buf);
    SecretString::new(encoded.into_boxed_str())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn kid_mint_is_header_safe_and_prefixed() {
        let k = Kid::mint();
        let s = k.as_str();
        assert!(s.starts_with("kid_"));
        // Header-safe: ASCII alnum + underscore.
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        // Two mints differ with overwhelming probability.
        assert_ne!(Kid::mint(), Kid::mint());
    }

    #[test]
    fn signing_key_secret_is_redacted_in_debug() {
        let key = SigningKey::mint("tenant-1");
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(key.secret.expose_secret()));
    }

    #[test]
    fn is_active_at_respects_activation_and_retirement() {
        let mut key = SigningKey::mint("tenant-1");
        let now = key.activated_at;
        assert!(key.is_active_at(now));
        // Retired in the past — no longer active.
        key.retired_at = Some(now - chrono::Duration::seconds(1));
        assert!(!key.is_active_at(now));
        // Retire in the future — still active right now.
        key.retired_at = Some(now + chrono::Duration::seconds(1));
        assert!(key.is_active_at(now));
        // Activation in the future — not yet active.
        key.activated_at = now + chrono::Duration::seconds(1);
        assert!(!key.is_active_at(now));
    }

    #[test]
    fn random_secret_is_high_entropy() {
        let a = random_secret();
        let b = random_secret();
        assert_ne!(a.expose_secret(), b.expose_secret());
        // 32 bytes -> 43 chars base64-url-no-pad.
        assert_eq!(a.expose_secret().len(), 43);
    }
}
