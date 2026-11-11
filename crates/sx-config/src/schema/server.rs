//! HTTP server configuration.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use validator::Validate;

/// Per-tenant / per-IP rate-limiting policy applied at the HTTP edge.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Sustained request budget per minute, per identity key.
    #[validate(range(min = 1))]
    pub limit_per_minute: u32,

    /// Maximum burst above the sustained rate.
    #[validate(range(min = 1))]
    pub burst: u32,

    /// Whether the limiter is engaged. Set to `false` for local dev only.
    pub enabled: bool,
}

/// Configuration for the public-facing HTTP server.
///
/// All fields are required. `bind_addr` is parsed as a [`SocketAddr`] so an
/// invalid host:port is rejected at load time, not at first request.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket address to bind, e.g. `0.0.0.0:8080`.
    pub bind_addr: SocketAddr,

    /// Maximum time to wait for in-flight requests during graceful shutdown.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub shutdown_timeout: Duration,

    /// Per-request total timeout.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub request_timeout: Duration,

    /// Maximum body size in bytes. Must be greater than zero.
    #[validate(range(min = 1))]
    pub max_body_bytes: u64,

    /// Rate-limiter policy.
    #[validate(nested)]
    pub rate_limit: RateLimitConfig,
}

impl ServerConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.shutdown_timeout.is_zero() {
            return Err(crate::ConfigError::invalid(
                "server.shutdown_timeout",
                "must be greater than zero",
            ));
        }
        if self.request_timeout.is_zero() {
            return Err(crate::ConfigError::invalid(
                "server.request_timeout",
                "must be greater than zero",
            ));
        }
        if self.rate_limit.burst > self.rate_limit.limit_per_minute {
            return Err(crate::ConfigError::invalid(
                "server.rate_limit.burst",
                "must be <= limit_per_minute",
            ));
        }
        Ok(())
    }
}
