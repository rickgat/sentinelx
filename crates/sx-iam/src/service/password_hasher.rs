//! Password hashing — Argon2id only.
//!
//! Parameters (memory / time / parallelism / output length) come from
//! [`PasswordConfig`]. The hasher never panics: parameter construction
//! errors map to [`IamError::Config`] and library failures to
//! [`IamError::Internal`].

use argon2::password_hash::{PasswordHasher as Argon2Hasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHash, Version};
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretString};

use crate::config::PasswordConfig;
use crate::IamError;

/// Hashes and verifies passwords.
///
/// Implementations MUST be constant-time on verify and never reveal
/// timing information about plaintext length. The Argon2 verifier
/// already satisfies that property.
pub trait PasswordHasher: Send + Sync {
    /// Produce a PHC-formatted hash of `plaintext`.
    fn hash(&self, plaintext: &SecretString) -> Result<String, IamError>;

    /// Verify `plaintext` against `phc`. Returns `Ok(())` on match,
    /// `Err(IamError::InvalidCredentials)` on mismatch.
    fn verify(&self, plaintext: &SecretString, phc: &str) -> Result<(), IamError>;
}

/// Argon2id hasher driven by [`PasswordConfig`].
///
/// Construct once per process and share via `Arc`.
#[derive(Debug)]
pub struct Argon2idHasher {
    params: Params,
}

impl Argon2idHasher {
    /// Build an [`Argon2idHasher`] from configuration.
    pub fn from_config(cfg: &PasswordConfig) -> Result<Self, IamError> {
        let params = Params::new(cfg.m_cost_kib, cfg.t_cost, cfg.p_cost, Some(cfg.output_len))
            .map_err(|e| IamError::config(format!("argon2 params: {e}")))?;
        Ok(Self { params })
    }

    fn engine(&self) -> Argon2<'_> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
    }
}

impl PasswordHasher for Argon2idHasher {
    fn hash(&self, plaintext: &SecretString) -> Result<String, IamError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon = self.engine();
        let phc = argon
            .hash_password(plaintext.expose_secret().as_bytes(), &salt)
            .map_err(|e| IamError::internal(format!("argon2 hash: {e}")))?;
        Ok(phc.to_string())
    }

    fn verify(&self, plaintext: &SecretString, phc: &str) -> Result<(), IamError> {
        let parsed = PasswordHash::new(phc).map_err(|_| IamError::InvalidCredentials)?;
        let argon = self.engine();
        argon
            .verify_password(plaintext.expose_secret().as_bytes(), &parsed)
            .map_err(|_| IamError::InvalidCredentials)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    /// Cheap params keep the test suite fast (~ms instead of ~hundred ms
    /// per hash). Production loads OWASP-strength params from config.
    fn fast_params() -> PasswordConfig {
        PasswordConfig {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        }
    }

    #[test]
    fn argon2id_hash_and_verify() {
        let h = Argon2idHasher::from_config(&fast_params()).unwrap();
        let pw = SecretString::from("correct horse battery staple".to_string());
        let phc = h.hash(&pw).unwrap();
        assert!(phc.starts_with("$argon2id$"));
        h.verify(&pw, &phc).unwrap();
    }

    #[test]
    fn argon2id_verify_rejects_wrong_password() {
        let h = Argon2idHasher::from_config(&fast_params()).unwrap();
        let pw = SecretString::from("right".to_string());
        let phc = h.hash(&pw).unwrap();
        let bad = SecretString::from("wrong".to_string());
        let err = h.verify(&bad, &phc).unwrap_err();
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[test]
    fn argon2id_verify_rejects_garbage_phc() {
        let h = Argon2idHasher::from_config(&fast_params()).unwrap();
        let pw = SecretString::from("x".to_string());
        let err = h.verify(&pw, "not-a-phc-string").unwrap_err();
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[test]
    fn verify_uses_phc_params_not_config_params() {
        // A PHC produced with low params (what `sx hash-password` emits:
        // m=8) must still verify under a server configured with OWASP
        // params (m=19456). If this fails, the bootstrap-admin workflow
        // (CLI-generated PHC -> ADMIN_PASSWORD_PHC -> login) is broken.
        let low = Argon2idHasher::from_config(&PasswordConfig {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        })
        .unwrap();
        let pw = SecretString::from("bootstrap-pw".to_string());
        let phc = low.hash(&pw).unwrap();

        let owasp = Argon2idHasher::from_config(&PasswordConfig {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            output_len: 32,
        })
        .unwrap();
        owasp
            .verify(&pw, &phc)
            .expect("OWASP-configured verifier must accept a low-param PHC");
    }

    #[test]
    fn argon2id_unique_salt_per_hash() {
        let h = Argon2idHasher::from_config(&fast_params()).unwrap();
        let pw = SecretString::from("same".to_string());
        let a = h.hash(&pw).unwrap();
        let b = h.hash(&pw).unwrap();
        assert_ne!(a, b, "hashes of same plaintext must differ — unique salts");
    }
}
