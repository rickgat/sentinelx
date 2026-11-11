//! GitHub credentials for the autonomy auto-remediation PR generator.
//!
//! Ships disabled by default. When an operator flips `enabled: true`, the
//! monolith constructs an `octocrab`-backed [`sx_autonomy`] `GithubClient`
//! adapter and wires it into the propose-PR pipeline.
//!
//! Two authentication modes are supported:
//!
//! 1. **GitHub App installation token** (preferred): supply `app_id` +
//!    `installation_id` + the App's RSA `private_key` (PEM-encoded). The
//!    monolith's adapter feeds the PEM into octocrab's
//!    [`jsonwebtoken::EncodingKey::from_rsa_pem`] and exchanges it for a
//!    short-lived installation access token.
//! 2. **Personal access token** (fallback): supply `personal_access_token`.
//!    Only used when no App credentials are configured.
//!
//! When enabled, at least one complete credential set must be supplied.
//! Neither mode being filled in is a [`crate::ConfigError::MissingValue`].
//!
//! All credential fields are wrapped in [`secrecy::SecretString`] so they
//! never appear in `Debug` output and the backing memory is zeroed on drop.

use secrecy::SecretString;
use serde::Deserialize;
use validator::Validate;

/// GitHub credential configuration for the autonomy adapter.
///
/// Disabled by default; flip `enabled: true` and supply either an App
/// credential triple or a personal access token to activate the
/// `octocrab`-backed auto-remediation PR adapter.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    /// Whether the `octocrab`-backed GitHub client should be constructed.
    ///
    /// When `false`, the monolith falls back to the no-op stub and any
    /// attempt to propose a PR returns a deterministic dependency error.
    pub enabled: bool,

    /// GitHub App id (numeric). Mandatory iff `enabled` and configured
    /// alongside `installation_id` + `private_key`.
    #[serde(default)]
    pub app_id: Option<u64>,

    /// GitHub App installation id (numeric). Mandatory iff `enabled` and
    /// configured alongside `app_id` + `private_key`.
    #[serde(default)]
    pub installation_id: Option<u64>,

    /// GitHub App private key, PEM-encoded. Mandatory iff `enabled` and
    /// configured alongside `app_id` + `installation_id`.
    ///
    /// Wrapped in [`SecretString`] so the PEM body never appears in
    /// `Debug` output and is zeroed on drop.
    #[serde(default)]
    pub private_key: SecretString,

    /// Personal access token. Fallback credential when no App triple is
    /// configured. Mandatory iff `enabled` and the App triple is empty.
    #[serde(default)]
    pub personal_access_token: SecretString,
}

impl GithubConfig {
    /// Cross-field invariants. Disabled configs never fail; enabled
    /// configs must supply exactly one of:
    ///
    /// * a complete App credential triple (`app_id` + `installation_id` +
    ///   `private_key`), OR
    /// * a non-empty `personal_access_token`.
    ///
    /// Partial App credentials (e.g. `app_id` set but no `private_key`)
    /// surface a [`crate::ConfigError::MissingValue`] pointing at the
    /// first missing key.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        let has_app_id = self.app_id.is_some();
        let has_installation_id = self.installation_id.is_some();
        let has_private_key = !crate::secret::is_empty(&self.private_key);
        let has_pat = !crate::secret::is_empty(&self.personal_access_token);

        let any_app_field = has_app_id || has_installation_id || has_private_key;
        let app_complete = has_app_id && has_installation_id && has_private_key;

        if any_app_field && !app_complete {
            if !has_app_id {
                return Err(crate::ConfigError::missing("github.app_id"));
            }
            if !has_installation_id {
                return Err(crate::ConfigError::missing("github.installation_id"));
            }
            if !has_private_key {
                return Err(crate::ConfigError::missing("github.private_key"));
            }
        }

        if !app_complete && !has_pat {
            return Err(crate::ConfigError::missing("github.personal_access_token"));
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::GithubConfig;
    use crate::secret;

    fn disabled() -> GithubConfig {
        GithubConfig {
            enabled: false,
            app_id: None,
            installation_id: None,
            private_key: secret::wrap(""),
            personal_access_token: secret::wrap(""),
        }
    }

    #[test]
    fn enabled_without_creds_returns_missing() {
        let mut cfg = disabled();
        cfg.enabled = true;
        let err = cfg
            .check_invariants()
            .expect_err("enabled config without credentials must surface MissingValue");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "github.personal_access_token");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn pat_alone_passes() {
        let mut cfg = disabled();
        cfg.enabled = true;
        cfg.personal_access_token = secret::wrap("ghp_exampletokenvalue");
        cfg.check_invariants()
            .expect("PAT-only enabled config must pass");
    }

    #[test]
    fn app_creds_alone_pass() {
        let mut cfg = disabled();
        cfg.enabled = true;
        cfg.app_id = Some(12345);
        cfg.installation_id = Some(67890);
        cfg.private_key = secret::wrap(
            "-----BEGIN RSA PRIVATE KEY-----\nfakekeymaterial\n-----END RSA PRIVATE KEY-----\n",
        );
        cfg.check_invariants()
            .expect("complete App triple must pass");
    }

    #[test]
    fn enabled_false_skips_validation() {
        // Even with nothing configured, disabled MUST pass.
        let cfg = disabled();
        cfg.check_invariants()
            .expect("disabled config must always pass invariants");
    }

    #[test]
    fn partial_app_creds_missing_installation_returns_missing() {
        let mut cfg = disabled();
        cfg.enabled = true;
        cfg.app_id = Some(1);
        cfg.private_key = secret::wrap("pem");
        let err = cfg
            .check_invariants()
            .expect_err("missing installation_id must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "github.installation_id");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn partial_app_creds_missing_private_key_returns_missing() {
        let mut cfg = disabled();
        cfg.enabled = true;
        cfg.app_id = Some(1);
        cfg.installation_id = Some(2);
        let err = cfg
            .check_invariants()
            .expect_err("missing private_key must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "github.private_key");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn partial_app_creds_missing_app_id_returns_missing() {
        let mut cfg = disabled();
        cfg.enabled = true;
        cfg.installation_id = Some(2);
        cfg.private_key = secret::wrap("pem");
        let err = cfg
            .check_invariants()
            .expect_err("missing app_id must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "github.app_id");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_pat() {
        let mut cfg = disabled();
        cfg.personal_access_token = secret::wrap("ghp_topsecret");
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("ghp_topsecret"), "PAT leaked in Debug: {dbg}");
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let mut cfg = disabled();
        cfg.private_key = secret::wrap("-----BEGIN RSA PRIVATE KEY-----\nLEAK\n");
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("LEAK"), "private key leaked in Debug: {dbg}");
    }
}
