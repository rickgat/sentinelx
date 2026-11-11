//! Collaborator (OOB receiver) configuration.
//!
//! The OOB collaborator hosts a DNS authority, an HTTP receiver, and a
//! background TTL purge task. All three are spawned by the monolith at
//! startup when [`CollabConfig::enabled`] is `true`. The configuration is
//! deliberately opt-in: dev environments default to `enabled = false` so
//! they do not attempt to bind privileged or shared ports.
//!
//! Production deployments override [`CollabConfig::dns_bind`] /
//! [`CollabConfig::http_bind`] via the `SENTINELX__COLLAB__DNS_BIND` /
//! `SENTINELX__COLLAB__HTTP_BIND` environment variables (or the equivalent
//! YAML keys).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use validator::Validate;

/// Collaborator receiver configuration.
///
/// Mirrors the field set exposed by `sx_collab::model::CollabConfig`. The
/// translation between the two lives at the monolith adapter boundary so
/// the sibling crate keeps owning its own validated, in-memory shape while
/// `sx-config` continues to be the single source of truth for everything
/// the operator can tune.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct CollabConfig {
    /// Whether to spawn the DNS / HTTP / purge tasks at startup. Defaults
    /// to `false` in shipped fixtures so a freshly-cloned checkout does
    /// not try to bind 5353 / 9080 on a developer's laptop.
    pub enabled: bool,

    /// FQDN-style base domain (e.g. `oob.sentinelx.invalid`). Tokens are
    /// prepended as the leftmost label, and queries outside this scope are
    /// refused by the DNS authority.
    #[validate(length(min = 1, max = 253))]
    pub base_domain: String,

    /// DNS authority bind address. Default off-loop port (5353) so the
    /// process need not be privileged. Operators wanting to serve real DNS
    /// can bind port 53 under a supervisor that grants
    /// `CAP_NET_BIND_SERVICE`.
    pub dns_bind: SocketAddr,

    /// HTTP receiver bind address.
    pub http_bind: SocketAddr,

    /// IPv4 returned for any in-scope DNS A query. Operators point this at
    /// a stable advertising IP logged outside this process.
    pub answer_ipv4: Ipv4Addr,

    /// Callback record TTL — how long a recorded DNS / HTTP / SMTP
    /// callback stays queryable before the background purge task removes
    /// it.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub callback_ttl: Duration,

    /// Maximum number of body bytes captured by the HTTP receiver. Larger
    /// requests are truncated at this boundary.
    #[validate(range(min = 64, max = 65_536))]
    pub http_body_capture_bytes: u32,

    /// Maximum DATA payload accepted by the SMTP receiver. The SMTP
    /// receiver itself is not yet auto-spawned (Phase-3.5+2); the cap is
    /// parsed for forward compatibility so the operator surface does not
    /// change once the receiver lands.
    #[validate(range(min = 1_024, max = 1_048_576))]
    pub smtp_max_message_bytes: u32,
}

impl CollabConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.callback_ttl.is_zero() {
            return Err(crate::ConfigError::invalid(
                "collab.callback_ttl",
                "must be > 0",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::CollabConfig;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use validator::Validate;

    fn baseline() -> CollabConfig {
        CollabConfig {
            enabled: false,
            base_domain: "oob.sentinelx.invalid".into(),
            dns_bind: "127.0.0.1:5353".parse::<SocketAddr>().unwrap(),
            http_bind: "127.0.0.1:9080".parse::<SocketAddr>().unwrap(),
            answer_ipv4: Ipv4Addr::LOCALHOST,
            callback_ttl: Duration::from_secs(259_200),
            http_body_capture_bytes: 4096,
            smtp_max_message_bytes: 65_536,
        }
    }

    #[test]
    fn rejects_zero_ttl() {
        let mut cfg = baseline();
        cfg.callback_ttl = Duration::from_secs(0);
        let err = cfg
            .check_invariants()
            .expect_err("zero ttl must be rejected");
        match err {
            crate::ConfigError::InvalidValue { key, reason } => {
                assert_eq!(key, "collab.callback_ttl");
                assert!(reason.contains("> 0"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn rejects_body_cap_outside_range() {
        // Below the minimum (64).
        let mut cfg = baseline();
        cfg.http_body_capture_bytes = 32;
        assert!(
            cfg.validate().is_err(),
            "body cap below 64 must fail validator",
        );
        // Above the maximum (65_536).
        let mut cfg = baseline();
        cfg.http_body_capture_bytes = 100_000;
        assert!(
            cfg.validate().is_err(),
            "body cap above 65_536 must fail validator",
        );
    }

    #[test]
    fn baseline_is_valid() {
        let cfg = baseline();
        cfg.validate().expect("baseline must pass validation");
        cfg.check_invariants()
            .expect("baseline must pass invariant check");
    }
}
