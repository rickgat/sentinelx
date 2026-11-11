//! Mutual TLS (mTLS) configuration.
//!
//! When `enabled: true` the host service uses the configured PEM-encoded
//! certificate, private key and (optionally) client CA bundle to enforce
//! mTLS on its inter-service listeners. The [`sx-mtls`] crate consumes
//! this struct and produces a `rustls::ServerConfig` plus a hot-reloading
//! background watcher.
//!
//! Ships **disabled** by default so a freshly cloned checkout boots
//! without on-disk certificate material. Flipping `enabled: true` makes
//! the cert / key paths mandatory; requiring client certificates makes
//! `client_ca_path` mandatory on top.
//!
//! Paths are plain strings (not [`std::path::PathBuf`]) so they survive
//! the figment `Env` provider's string-only payload. The `sx-mtls` crate
//! normalises them to `PathBuf` at load time.

use serde::Deserialize;
use validator::Validate;

/// Default reload interval (60 seconds) when none is supplied.
const fn default_reload_interval_secs() -> u64 {
    60
}

/// Mutual TLS configuration for inter-service listeners.
///
/// Disabled by default. When `enabled` is `true`:
///   * `cert_path` and `key_path` MUST be non-empty.
///   * If `require_client_cert` is `true`, `client_ca_path` MUST also be
///     non-empty (the verifier needs an anchor bundle to validate peer
///     certificates).
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct MtlsConfig {
    /// Whether mTLS enforcement is wired into the host service.
    ///
    /// When `false`, every other field is ignored and the [`sx-mtls`] crate
    /// refuses to build a `rustls::ServerConfig`.
    pub enabled: bool,

    /// Filesystem path to the server certificate chain (PEM-encoded).
    /// Mandatory iff `enabled`.
    #[serde(default)]
    pub cert_path: String,

    /// Filesystem path to the server private key (PEM-encoded, PKCS#8 or
    /// SEC1). Mandatory iff `enabled`. The key bytes are NEVER logged —
    /// only the certificate fingerprint + expiry surface in tracing.
    #[serde(default)]
    pub key_path: String,

    /// Filesystem path to a PEM bundle of trusted client CAs. Mandatory iff
    /// `enabled` AND `require_client_cert` is `true`.
    #[serde(default)]
    pub client_ca_path: String,

    /// When `true`, the listener rejects connections that do not present a
    /// certificate signed by `client_ca_path`. When `false`, client
    /// certificates are accepted but optional.
    #[serde(default)]
    pub require_client_cert: bool,

    /// How often the hot-reloader re-checks the certificate file on disk
    /// even in the absence of a filesystem-watch event (defence in depth
    /// against missed `notify` events on network mounts). Seconds.
    #[serde(default = "default_reload_interval_secs")]
    pub reload_interval_secs: u64,
}

impl Default for MtlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
            client_ca_path: String::new(),
            require_client_cert: false,
            reload_interval_secs: default_reload_interval_secs(),
        }
    }
}

impl MtlsConfig {
    /// Cross-field invariants checked by the loader.
    ///
    /// Disabled configs always pass. Enabled configs enforce:
    ///   1. `cert_path` non-empty,
    ///   2. `key_path` non-empty,
    ///   3. `client_ca_path` non-empty when `require_client_cert` is `true`,
    ///   4. `reload_interval_secs` non-zero (a zero interval would spin
    ///      the reloader thread).
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.cert_path.trim().is_empty() {
            return Err(crate::ConfigError::missing("mtls.cert_path"));
        }
        if self.key_path.trim().is_empty() {
            return Err(crate::ConfigError::missing("mtls.key_path"));
        }
        if self.require_client_cert && self.client_ca_path.trim().is_empty() {
            return Err(crate::ConfigError::missing("mtls.client_ca_path"));
        }
        if self.reload_interval_secs == 0 {
            return Err(crate::ConfigError::invalid(
                "mtls.reload_interval_secs",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::MtlsConfig;

    fn enabled() -> MtlsConfig {
        MtlsConfig {
            enabled: true,
            cert_path: "/etc/sentinelx/server.crt".into(),
            key_path: "/etc/sentinelx/server.key".into(),
            client_ca_path: "/etc/sentinelx/clients.pem".into(),
            require_client_cert: false,
            reload_interval_secs: 60,
        }
    }

    #[test]
    fn disabled_passes_with_no_fields() {
        MtlsConfig::default()
            .check_invariants()
            .expect("disabled config must always pass");
    }

    #[test]
    fn enabled_requires_cert_path() {
        let mut cfg = enabled();
        cfg.cert_path = String::new();
        let err = cfg.check_invariants().expect_err("missing cert_path");
        assert!(
            matches!(err, crate::ConfigError::MissingValue { ref key } if key == "mtls.cert_path"),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_requires_key_path() {
        let mut cfg = enabled();
        cfg.key_path = String::new();
        let err = cfg.check_invariants().expect_err("missing key_path");
        assert!(
            matches!(err, crate::ConfigError::MissingValue { ref key } if key == "mtls.key_path"),
            "got {err:?}"
        );
    }

    #[test]
    fn require_client_cert_requires_client_ca() {
        let mut cfg = enabled();
        cfg.require_client_cert = true;
        cfg.client_ca_path = String::new();
        let err = cfg
            .check_invariants()
            .expect_err("missing client_ca_path when require_client_cert=true");
        assert!(
            matches!(err, crate::ConfigError::MissingValue { ref key } if key == "mtls.client_ca_path"),
            "got {err:?}"
        );
    }

    #[test]
    fn zero_reload_interval_is_rejected() {
        let mut cfg = enabled();
        cfg.reload_interval_secs = 0;
        let err = cfg.check_invariants().expect_err("zero reload interval");
        assert!(
            matches!(
                err,
                crate::ConfigError::InvalidValue { ref key, .. } if key == "mtls.reload_interval_secs"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn require_client_cert_false_does_not_require_ca() {
        let mut cfg = enabled();
        cfg.require_client_cert = false;
        cfg.client_ca_path = String::new();
        cfg.check_invariants()
            .expect("optional client auth should not require CA");
    }
}
