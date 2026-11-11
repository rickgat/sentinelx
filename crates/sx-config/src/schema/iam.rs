//! Identity & access management configuration.

use std::time::Duration;

use secrecy::SecretString;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use validator::Validate;

use crate::secret;

/// Argon2id parameters. Defaults are intentionally **not** provided — the
/// values must be set per-environment based on the host's capacity.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Argon2Params {
    /// Memory cost in KiB. OWASP recommends ≥ 19456 (19 MiB).
    #[validate(range(min = 8))]
    pub m_cost: u32,

    /// Time cost (iterations). OWASP recommends ≥ 2.
    #[validate(range(min = 1))]
    pub t_cost: u32,

    /// Parallelism (lanes).
    #[validate(range(min = 1))]
    pub p_cost: u32,

    /// Output hash length in bytes.
    #[validate(range(min = 16))]
    pub output_len: u32,

    /// Salt length in bytes.
    #[validate(range(min = 8))]
    pub salt_len: u32,
}

/// Account-lockout policy.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct LockoutPolicy {
    /// Number of consecutive failed logins that triggers a lockout.
    #[validate(range(min = 1))]
    pub threshold: u32,

    /// Window over which failed attempts are counted.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub window: Duration,

    /// How long an account remains locked after threshold is reached.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub duration: Duration,
}

/// IAM configuration: password hashing, sessions, lockout, MFA.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct IamConfig {
    /// Argon2id parameters used by the password hasher.
    #[validate(nested)]
    pub password: Argon2Params,

    /// Idle timeout for interactive sessions.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub session_inactivity_timeout: Duration,

    /// Whether multi-factor authentication is mandatory for all users.
    pub mfa_required: bool,

    /// Account-lockout policy.
    #[validate(nested)]
    pub lockout: LockoutPolicy,

    /// Secret pepper used to key-hash emails before they are written to the
    /// login-attempt tracker. Rotating it resets all in-flight counters.
    pub attempt_email_pepper: SecretString,
}

impl IamConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.session_inactivity_timeout.is_zero() {
            return Err(crate::ConfigError::invalid(
                "iam.session_inactivity_timeout",
                "must be greater than zero",
            ));
        }
        if secret::is_empty(&self.attempt_email_pepper) {
            return Err(crate::ConfigError::missing("iam.attempt_email_pepper"));
        }
        if secret::len(&self.attempt_email_pepper) < 16 {
            return Err(crate::ConfigError::invalid(
                "iam.attempt_email_pepper",
                "must be at least 16 bytes",
            ));
        }
        if self.lockout.window.is_zero() {
            return Err(crate::ConfigError::invalid(
                "iam.lockout.window",
                "must be greater than zero",
            ));
        }
        if self.lockout.duration.is_zero() {
            return Err(crate::ConfigError::invalid(
                "iam.lockout.duration",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}
