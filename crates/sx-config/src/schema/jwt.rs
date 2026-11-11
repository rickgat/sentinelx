//! JWT signing / verification configuration.

use std::time::Duration;

use secrecy::SecretString;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use validator::Validate;

use crate::secret;

/// Supported JWT signing algorithms.
///
/// Mirrors `jsonwebtoken::Algorithm` but only the subset `SentinelX` is
/// willing to vouch for.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum JwtAlgorithm {
    /// HMAC with SHA-256 (symmetric).
    Hs256,
    /// RSA-PKCS1 v1.5 with SHA-256 (asymmetric).
    Rs256,
    /// Edwards-curve DSA, Ed25519.
    EdDsa,
}

impl JwtAlgorithm {
    /// Minimum key length, in bytes, required to be considered safe for the
    /// chosen algorithm.
    pub(crate) const fn min_signing_key_bytes(self) -> usize {
        match self {
            // 256-bit recommendation for HMAC-SHA256.
            Self::Hs256 => 32,
            // For RS256 / EdDSA we cannot validate the key length without
            // parsing PEM — just require *something*.
            Self::Rs256 | Self::EdDsa => 1,
        }
    }
}

/// JWT issuer, audience, key, and TTL configuration.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    /// `iss` claim emitted on issued tokens.
    #[validate(length(min = 1))]
    pub issuer: String,

    /// `aud` claim emitted on issued tokens.
    #[validate(length(min = 1))]
    pub audience: String,

    /// Signing key. For HS256 this is the raw HMAC secret; for RS256 /
    /// `EdDSA` it is the PEM-encoded private key.
    pub signing_key: SecretString,

    /// `kid` header used in issued tokens, allowing key rotation.
    #[validate(length(min = 1))]
    pub key_id: String,

    /// Lifetime of issued access tokens.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub access_ttl: Duration,

    /// Lifetime of issued refresh tokens.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub refresh_ttl: Duration,

    /// Algorithm used for signing.
    pub algorithm: JwtAlgorithm,

    /// Optional verifying key. Required for asymmetric algorithms
    /// (`RS256`, `EdDSA`) and must be the PEM-encoded public key. For
    /// `HS256`, leave `None`; the symmetric `signing_key` is reused.
    #[serde(default)]
    pub verifying_key: Option<SecretString>,

    /// Clock-skew tolerance on `exp` / `nbf` / `iat`, in seconds.
    pub leeway_seconds: u64,
}

impl JwtConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if secret::is_empty(&self.signing_key) {
            return Err(crate::ConfigError::missing("jwt.signing_key"));
        }
        let min = self.algorithm.min_signing_key_bytes();
        if secret::len(&self.signing_key) < min {
            return Err(crate::ConfigError::invalid(
                "jwt.signing_key",
                format!("must be at least {min} bytes for the selected algorithm"),
            ));
        }
        if self.access_ttl.is_zero() {
            return Err(crate::ConfigError::invalid(
                "jwt.access_ttl",
                "must be greater than zero",
            ));
        }
        if self.refresh_ttl.is_zero() {
            return Err(crate::ConfigError::invalid(
                "jwt.refresh_ttl",
                "must be greater than zero",
            ));
        }
        match self.algorithm {
            JwtAlgorithm::Rs256 | JwtAlgorithm::EdDsa => {
                let Some(vk) = self.verifying_key.as_ref() else {
                    return Err(crate::ConfigError::missing("jwt.verifying_key"));
                };
                if secret::is_empty(vk) {
                    return Err(crate::ConfigError::missing("jwt.verifying_key"));
                }
            }
            JwtAlgorithm::Hs256 => {}
        }
        if self.refresh_ttl < self.access_ttl {
            return Err(crate::ConfigError::invalid(
                "jwt.refresh_ttl",
                "must be >= access_ttl",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{JwtAlgorithm, JwtConfig};
    use crate::secret;
    use std::time::Duration;

    /// Baseline HS256 configuration with all invariants satisfied. Tests
    /// flip individual fields to probe `check_invariants`.
    fn hs256_baseline() -> JwtConfig {
        JwtConfig {
            issuer: "https://sentinelx.example.invalid".to_string(),
            audience: "sentinelx-api".to_string(),
            // 64-byte secret, well above HS256's 32-byte minimum.
            signing_key: secret::wrap(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            key_id: "kid-test".to_string(),
            access_ttl: Duration::from_secs(900),
            refresh_ttl: Duration::from_secs(604_800),
            algorithm: JwtAlgorithm::Hs256,
            verifying_key: None,
            leeway_seconds: 30,
        }
    }

    fn rs256_baseline() -> JwtConfig {
        JwtConfig {
            algorithm: JwtAlgorithm::Rs256,
            // For RS256 the signing_key is a PEM private key; any non-empty
            // value satisfies the byte-length floor (`min_signing_key_bytes`
            // returns 1 for asymmetric algorithms).
            signing_key: secret::wrap(
                "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
            ),
            verifying_key: Some(secret::wrap(
                "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
            )),
            ..hs256_baseline()
        }
    }

    fn eddsa_baseline() -> JwtConfig {
        JwtConfig {
            algorithm: JwtAlgorithm::EdDsa,
            signing_key: secret::wrap(
                "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
            ),
            verifying_key: Some(secret::wrap(
                "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
            )),
            ..hs256_baseline()
        }
    }

    #[test]
    fn hs256_without_verifying_key_passes() {
        // HS256 reuses the symmetric signing_key; verifying_key must be
        // None/empty without triggering a validation error.
        hs256_baseline()
            .check_invariants()
            .expect("HS256 with no verifying_key must pass invariants");
    }

    #[test]
    fn hs256_short_signing_key_returns_invalid() {
        let mut cfg = hs256_baseline();
        cfg.signing_key = secret::wrap("too-short");
        let err = cfg
            .check_invariants()
            .expect_err("HS256 < 32 byte key must surface");
        match err {
            crate::ConfigError::InvalidValue { key, .. } => {
                assert_eq!(key, "jwt.signing_key");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn rs256_without_verifying_key_returns_missing() {
        let mut cfg = rs256_baseline();
        cfg.verifying_key = None;
        let err = cfg
            .check_invariants()
            .expect_err("RS256 without verifying_key must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "jwt.verifying_key");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn rs256_with_empty_verifying_key_returns_missing() {
        let mut cfg = rs256_baseline();
        cfg.verifying_key = Some(secret::wrap(""));
        let err = cfg
            .check_invariants()
            .expect_err("RS256 with empty verifying_key must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "jwt.verifying_key");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn rs256_with_valid_verifying_key_passes() {
        rs256_baseline()
            .check_invariants()
            .expect("RS256 with PEM verifying_key must pass invariants");
    }

    #[test]
    fn eddsa_without_verifying_key_returns_missing() {
        let mut cfg = eddsa_baseline();
        cfg.verifying_key = None;
        let err = cfg
            .check_invariants()
            .expect_err("EdDSA without verifying_key must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "jwt.verifying_key");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn eddsa_with_empty_verifying_key_returns_missing() {
        let mut cfg = eddsa_baseline();
        cfg.verifying_key = Some(secret::wrap(""));
        let err = cfg
            .check_invariants()
            .expect_err("EdDSA with empty verifying_key must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "jwt.verifying_key");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn eddsa_with_valid_verifying_key_passes() {
        eddsa_baseline()
            .check_invariants()
            .expect("EdDSA with PEM verifying_key must pass invariants");
    }

    #[test]
    fn empty_signing_key_returns_missing() {
        let mut cfg = hs256_baseline();
        cfg.signing_key = secret::wrap("");
        let err = cfg
            .check_invariants()
            .expect_err("empty signing_key must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "jwt.signing_key");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn refresh_ttl_below_access_ttl_returns_invalid() {
        let mut cfg = hs256_baseline();
        cfg.access_ttl = Duration::from_secs(3600);
        cfg.refresh_ttl = Duration::from_secs(60);
        let err = cfg
            .check_invariants()
            .expect_err("refresh_ttl < access_ttl must surface");
        match err {
            crate::ConfigError::InvalidValue { key, .. } => {
                assert_eq!(key, "jwt.refresh_ttl");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_verifying_key() {
        let cfg = rs256_baseline();
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("BEGIN PUBLIC KEY"),
            "verifying_key leaked in Debug: {dbg}"
        );
        assert!(
            !dbg.contains("BEGIN RSA PRIVATE KEY"),
            "signing_key leaked in Debug: {dbg}"
        );
    }
}
