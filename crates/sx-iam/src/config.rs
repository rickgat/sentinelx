//! Configuration types consumed by the use cases and services.
//!
//! Mirrors `sx_config::schema::iam::IamConfig` and
//! `sx_config::schema::jwt::JwtConfig`. These local stubs allow sx-iam to
//! build before the sibling crate has been wired up; once it has, swap the
//! `pub use` lines in `crate::config` over to re-export the canonical types.

use std::time::Duration;

use secrecy::SecretString;

use crate::IamError;

/// Algorithm to use when signing and verifying JWTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlgorithm {
    /// HMAC-SHA256, symmetric (`signing_key` is the shared secret).
    Hs256,
    /// RSASSA-PKCS1-v1_5 with SHA-256, asymmetric (PEM keys).
    Rs256,
    /// Edwards-curve DSA, Ed25519 (PEM keys).
    EdDsa,
}

impl JwtAlgorithm {
    /// Map onto the value expected by the `jsonwebtoken` crate.
    #[must_use]
    pub const fn to_jwt(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::Hs256 => jsonwebtoken::Algorithm::HS256,
            Self::Rs256 => jsonwebtoken::Algorithm::RS256,
            Self::EdDsa => jsonwebtoken::Algorithm::EdDSA,
        }
    }
}

/// JWT issuer / validator configuration.
///
/// Mirrors `sx_config::schema::jwt::JwtConfig`.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// `iss` claim emitted on issued tokens and required at validation.
    pub issuer: String,
    /// `aud` claim emitted on issued tokens and required at validation.
    pub audience: String,
    /// Signing key. HS256: shared secret. RS256/EdDSA: PEM private key.
    pub signing_key: SecretString,
    /// Verification key. HS256: same as `signing_key`. RS256/EdDSA: PEM public key.
    pub verifying_key: SecretString,
    /// `kid` header used in issued tokens (and required on incoming tokens).
    pub key_id: String,
    /// Lifetime of issued access tokens.
    pub access_ttl: Duration,
    /// Lifetime of issued refresh tokens.
    pub refresh_ttl: Duration,
    /// Algorithm selector.
    pub algorithm: JwtAlgorithm,
    /// Clock-skew allowance, in seconds, on `exp` / `nbf` / `iat`.
    pub leeway_seconds: u64,
}

/// Argon2id password-hasher parameters.
///
/// Mirrors the `password` sub-block of `sx_config::schema::iam::IamConfig`.
#[derive(Debug, Clone, Copy)]
pub struct PasswordConfig {
    /// Memory cost in KiB. OWASP-aligned default: 19456 (≈ 19 MiB).
    pub m_cost_kib: u32,
    /// Time cost (iterations). OWASP-aligned default: 2.
    pub t_cost: u32,
    /// Parallelism cost (lanes). OWASP-aligned default: 1.
    pub p_cost: u32,
    /// Length of the produced raw hash in bytes. Common default: 32.
    pub output_len: usize,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            output_len: 32,
        }
    }
}

/// Login-attempt lockout policy.
///
/// Mirrors the `lockout` sub-block of `sx_config::schema::iam::IamConfig`.
#[derive(Debug, Clone, Copy)]
pub struct LockoutPolicy {
    /// Number of consecutive failures that triggers a lock.
    pub max_failures: u32,
    /// How long the account remains locked once tripped.
    pub lock_duration: Duration,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_failures: 5,
            lock_duration: Duration::from_secs(15 * 60),
        }
    }
}

/// `WebAuthn` / FIDO2 configuration sub-block (HIGH-002).
///
/// Mirrors the `webauthn` sub-block of `sx_config::schema::iam::IamConfig`.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct WebauthnConfig {
    /// MDS3 metadata refresh cadence in seconds. Default: `604_800`
    /// (seven days). Mapped from `iam.webauthn.mds_refresh_secs`.
    pub mds_refresh_secs: u64,
    /// Past this age the registration path refuses to accept
    /// authenticators whose attestation could not be cross-checked
    /// against a fresher MDS table. Default: `604_800` (seven days).
    pub mds_staleness_tolerance_secs: u64,
    /// Strict mode: reject any authenticator whose AAGUID is not
    /// present in the local MDS3 cache. Default: false (soft-warn).
    pub mds_strict_unknown_aaguid: bool,
}

impl Default for WebauthnConfig {
    fn default() -> Self {
        Self {
            mds_refresh_secs: 7 * 24 * 60 * 60,
            mds_staleness_tolerance_secs: 7 * 24 * 60 * 60,
            mds_strict_unknown_aaguid: false,
        }
    }
}

/// Top-level IAM configuration.
#[derive(Debug, Clone)]
pub struct IamConfig {
    /// Password-hasher parameters.
    pub password: PasswordConfig,
    /// Lockout policy.
    pub lockout: LockoutPolicy,
    /// HMAC-SHA256 pepper for email hashing in the attempt tracker key.
    pub attempt_email_pepper: SecretString,
    /// JWT configuration (issuer/audience/keys/TTLs).
    pub jwt: JwtConfig,
    /// HIGH-002 — `WebAuthn` / FIDO MDS3 knobs.
    pub webauthn: WebauthnConfig,
}

impl IamConfig {
    /// Validate basic invariants. Adapter crates should call this in their
    /// own loader, but the function is exposed here for downstream tests.
    pub fn validate(&self) -> Result<(), IamError> {
        if self.password.output_len < 16 {
            return Err(IamError::config("password.output_len must be >= 16"));
        }
        if self.lockout.max_failures == 0 {
            return Err(IamError::config("lockout.max_failures must be > 0"));
        }
        if self.jwt.access_ttl.is_zero() || self.jwt.refresh_ttl.is_zero() {
            return Err(IamError::config("jwt ttls must be > 0"));
        }
        if self.jwt.refresh_ttl < self.jwt.access_ttl {
            return Err(IamError::config("jwt.refresh_ttl must be >= access_ttl"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn cfg() -> IamConfig {
        IamConfig {
            password: PasswordConfig::default(),
            lockout: LockoutPolicy::default(),
            attempt_email_pepper: SecretString::from("pepper".to_string()),
            webauthn: WebauthnConfig::default(),
            jwt: JwtConfig {
                issuer: "sx".into(),
                audience: "sx-clients".into(),
                signing_key: SecretString::from("0123456789abcdef0123456789abcdef".to_string()),
                verifying_key: SecretString::from("0123456789abcdef0123456789abcdef".to_string()),
                key_id: "k1".into(),
                access_ttl: Duration::from_secs(900),
                refresh_ttl: Duration::from_secs(86_400),
                algorithm: JwtAlgorithm::Hs256,
                leeway_seconds: 30,
            },
        }
    }

    #[test]
    fn valid_config_passes() {
        cfg().validate().unwrap();
    }

    #[test]
    fn refresh_shorter_than_access_rejected() {
        let mut c = cfg();
        c.jwt.refresh_ttl = Duration::from_secs(60);
        assert!(c.validate().is_err());
    }

    #[test]
    fn jwt_algorithm_map() {
        assert_eq!(JwtAlgorithm::Hs256.to_jwt(), jsonwebtoken::Algorithm::HS256);
        assert_eq!(JwtAlgorithm::Rs256.to_jwt(), jsonwebtoken::Algorithm::RS256);
        assert_eq!(JwtAlgorithm::EdDsa.to_jwt(), jsonwebtoken::Algorithm::EdDSA);
    }
}
