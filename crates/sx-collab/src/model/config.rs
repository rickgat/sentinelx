//! Configuration for the OOB Collaborator.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use time::Duration;

use crate::error::CollabError;

/// Default capture cap for HTTP request bodies (1 KiB).
pub const DEFAULT_HTTP_BODY_CAPTURE_BYTES: usize = 1024;

/// Default capture cap for SMTP DATA payloads (16 KiB).
pub const DEFAULT_SMTP_MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Default TTL for recorded callbacks — 72 hours.
pub const DEFAULT_CALLBACK_TTL_HOURS: i64 = 72;

/// Default cadence of the background purge task — 5 minutes.
pub const DEFAULT_PURGE_INTERVAL_SECS: u64 = 300;

/// Default redaction list: header names whose values must never be stored
/// verbatim.
pub fn default_redaction_headers() -> Vec<String> {
    vec![
        "set-cookie".to_string(),
        "cookie".to_string(),
        "authorization".to_string(),
        "x-api-key".to_string(),
    ]
}

/// Static configuration handed to [`crate::controller::StartCollaboratorUseCase`].
///
/// Bind addresses are full [`SocketAddr`]s so the operator can choose a
/// non-privileged port in tests (e.g. `127.0.0.1:0` to let the OS pick).
/// Production deployments will bind privileged ports (53 / 80 / 25) via a
/// process supervisor with `CAP_NET_BIND_SERVICE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollabConfig {
    /// Domain anchor.  All tokens are minted under
    /// `<token>.oob.<base_domain>` and the DNS authority refuses anything
    /// outside this scope.
    pub base_domain: String,

    /// Bind address for the DNS receiver (UDP).
    pub dns_bind: SocketAddr,

    /// Bind address for the HTTP receiver.
    pub http_bind: SocketAddr,

    /// Bind address for the SMTP receiver.
    pub smtp_bind: SocketAddr,

    /// IPv4 address that the DNS authority answers with for every recognised
    /// token.  Operators point this at a stable advertising IP that is logged
    /// outside this process.
    pub answer_ipv4: Ipv4Addr,

    /// Maximum HTTP body bytes captured.
    pub http_body_capture_bytes: usize,

    /// Maximum SMTP DATA bytes captured.  Larger payloads are rejected.
    pub smtp_max_message_bytes: usize,

    /// How long recorded callbacks stay queryable before the background
    /// purge task removes them.
    pub callback_ttl: Duration,

    /// Cadence of the background purge task.
    pub purge_interval: std::time::Duration,

    /// Header names whose values must never be stored verbatim.  Matched
    /// case-insensitively against `ascii_lowercase(name)`.
    pub redaction_headers: Vec<String>,
}

impl CollabConfig {
    /// Build a `CollabConfig` validating the obvious invariants.
    pub fn new(
        base_domain: impl Into<String>,
        dns_bind: SocketAddr,
        http_bind: SocketAddr,
        smtp_bind: SocketAddr,
        answer_ipv4: Ipv4Addr,
    ) -> Result<Self, CollabError> {
        let base_domain = base_domain.into();
        if base_domain.is_empty() {
            return Err(CollabError::config("base_domain must not be empty"));
        }
        if !base_domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(CollabError::config(format!(
                "base_domain has invalid characters: {base_domain}"
            )));
        }
        Ok(Self {
            base_domain,
            dns_bind,
            http_bind,
            smtp_bind,
            answer_ipv4,
            http_body_capture_bytes: DEFAULT_HTTP_BODY_CAPTURE_BYTES,
            smtp_max_message_bytes: DEFAULT_SMTP_MAX_MESSAGE_BYTES,
            callback_ttl: Duration::hours(DEFAULT_CALLBACK_TTL_HOURS),
            purge_interval: std::time::Duration::from_secs(DEFAULT_PURGE_INTERVAL_SECS),
            redaction_headers: default_redaction_headers(),
        })
    }

    /// A loopback-only config useful for tests: `dns_bind` UDP/0,
    /// `http_bind` TCP/0, `smtp_bind` TCP/0.
    ///
    /// The OS-assigned ports are read back from the bound sockets at start
    /// time.
    #[must_use]
    pub fn loopback_for_tests(base_domain: impl Into<String>) -> Self {
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        Self {
            base_domain: base_domain.into(),
            dns_bind: SocketAddr::new(lo, 0),
            http_bind: SocketAddr::new(lo, 0),
            smtp_bind: SocketAddr::new(lo, 0),
            answer_ipv4: Ipv4Addr::LOCALHOST,
            http_body_capture_bytes: DEFAULT_HTTP_BODY_CAPTURE_BYTES,
            smtp_max_message_bytes: DEFAULT_SMTP_MAX_MESSAGE_BYTES,
            callback_ttl: Duration::hours(DEFAULT_CALLBACK_TTL_HOURS),
            purge_interval: std::time::Duration::from_secs(DEFAULT_PURGE_INTERVAL_SECS),
            redaction_headers: default_redaction_headers(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::CollabConfig;
    use std::net::{Ipv4Addr, SocketAddr};

    fn addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn config_new_accepts_valid_domain() {
        let cfg =
            CollabConfig::new("oob.example", addr(), addr(), addr(), Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(cfg.base_domain, "oob.example");
        assert_eq!(cfg.http_body_capture_bytes, 1024);
    }

    #[test]
    fn config_new_rejects_empty_domain() {
        let e = CollabConfig::new("", addr(), addr(), addr(), Ipv4Addr::LOCALHOST)
            .expect_err("empty domain must fail");
        assert!(e.to_string().contains("base_domain"));
    }

    #[test]
    fn config_new_rejects_bad_chars() {
        let e = CollabConfig::new("oo b.example", addr(), addr(), addr(), Ipv4Addr::LOCALHOST)
            .expect_err("space must fail");
        assert!(e.to_string().contains("invalid characters"));
    }

    #[test]
    fn loopback_for_tests_uses_localhost() {
        let cfg = CollabConfig::loopback_for_tests("oob.example");
        assert_eq!(cfg.dns_bind.ip().to_string(), "127.0.0.1");
        assert_eq!(cfg.smtp_bind.port(), 0);
    }
}
