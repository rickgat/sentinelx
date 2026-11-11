//! Discovery / probing configuration.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use validator::Validate;

/// Discovery configuration: DNS, HTTP probes, port scans.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryConfig {
    /// Recursive DNS resolvers used during discovery. Must be non-empty.
    #[validate(length(min = 1))]
    pub dns_resolvers: Vec<SocketAddr>,

    /// Cap on the total number of in-flight active probes.
    #[validate(range(min = 1))]
    pub max_concurrent_probes: u32,

    /// Maximum requests-per-second per target, enforced by the probe rate
    /// limiter.
    #[validate(range(min = 1))]
    pub per_target_rps_limit: u32,

    /// User-Agent header sent on every HTTP probe.
    #[validate(length(min = 1))]
    pub http_user_agent: String,

    /// Per-request HTTP timeout.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub http_timeout: Duration,

    /// Upper bound on the number of ports probed per target during port
    /// scans. 65 535 is the protocol max.
    #[validate(range(min = 1, max = 65535))]
    pub port_scan_max_ports: u32,
}

impl DiscoveryConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.http_timeout.is_zero() {
            return Err(crate::ConfigError::invalid(
                "discovery.http_timeout",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}
