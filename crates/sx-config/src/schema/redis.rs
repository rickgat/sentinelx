//! Redis (cache / kill-switch channel) configuration.

use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use url::Url;
use validator::Validate;

/// Redis connection configuration.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct RedisConfig {
    /// Full Redis URL (e.g. `redis://:pw@host:6379/0`).
    pub url: SecretString,

    /// Maximum size of the connection pool.
    #[validate(range(min = 1))]
    pub pool_size: u32,

    /// Per-command timeout.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub command_timeout: Duration,

    /// Whether the monolith should connect to Redis. When `false`, the
    /// in-memory `KillSwitch` and login-attempt tracker are used instead.
    pub enabled: bool,
}

impl RedisConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        let raw = self.url.expose_secret();
        if raw.is_empty() {
            return Err(crate::ConfigError::missing("redis.url"));
        }
        let parsed = Url::parse(raw)
            .map_err(|_| crate::ConfigError::invalid("redis.url", "not a valid URL"))?;
        let scheme = parsed.scheme();
        if scheme != "redis" && scheme != "rediss" {
            return Err(crate::ConfigError::invalid(
                "redis.url",
                "scheme must be redis or rediss",
            ));
        }
        if self.command_timeout.is_zero() {
            return Err(crate::ConfigError::invalid(
                "redis.command_timeout",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}
