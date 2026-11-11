//! Engagement (scan job) configuration.

use std::time::Duration;

use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use validator::Validate;

/// Intensity setting controlling how aggressively `SentinelX` probes targets.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Intensity {
    /// Passive only — no active probes.
    Passive,
    /// Light active probing (low RPS).
    Light,
    /// Default active probing.
    Normal,
    /// Aggressive active probing (subject to operator approval).
    Aggressive,
}

/// What kind of entry sits in the global denylist.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DenylistKind {
    /// CIDR block (IPv4 or IPv6).
    Cidr,
    /// Fully-qualified domain name.
    Domain,
    /// Regex pattern (matched against target host).
    Regex,
}

/// A single denylist entry. `SentinelX` will refuse to probe any target that
/// matches an entry, regardless of the engagement's own scope.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct DenylistEntry {
    /// What `value` represents.
    pub kind: DenylistKind,

    /// The CIDR / domain / regex literal.
    #[validate(length(min = 1))]
    pub value: String,

    /// Human-readable justification, surfaced in audit logs.
    #[validate(length(min = 1))]
    pub reason: String,
}

impl DenylistEntry {
    /// Validates `value` for the chosen [`DenylistKind`].
    pub(crate) fn check_invariants(&self, index: usize) -> Result<(), crate::ConfigError> {
        match self.kind {
            DenylistKind::Cidr => {
                self.value.parse::<IpNet>().map_err(|_| {
                    crate::ConfigError::invalid(
                        format!("engagement.global_denylist[{index}].value"),
                        "not a valid CIDR block",
                    )
                })?;
            }
            DenylistKind::Domain => {
                if self.value.contains(char::is_whitespace) || !self.value.contains('.') {
                    return Err(crate::ConfigError::invalid(
                        format!("engagement.global_denylist[{index}].value"),
                        "not a valid domain",
                    ));
                }
            }
            DenylistKind::Regex => {
                Regex::new(&self.value).map_err(|e| {
                    crate::ConfigError::invalid(
                        format!("engagement.global_denylist[{index}].value"),
                        format!("invalid regex: {e}"),
                    )
                })?;
            }
        }
        Ok(())
    }
}

/// Engagement / scan-job configuration.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct EngagementConfig {
    /// Maximum number of engagements running at once.
    #[validate(range(min = 1))]
    pub max_concurrent: u32,

    /// Default intensity applied when an engagement does not specify one.
    pub default_intensity: Intensity,

    /// Redis pub/sub channel listened to for the kill-switch signal.
    #[validate(length(min = 1))]
    pub kill_switch_channel: String,

    /// Interval at which the kill-switch watchdog polls Redis.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub killswitch_watchdog_interval: Duration,

    /// Targets that `SentinelX` must never probe, regardless of scope.
    pub global_denylist: Vec<DenylistEntry>,
}

impl EngagementConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.killswitch_watchdog_interval.is_zero() {
            return Err(crate::ConfigError::invalid(
                "engagement.killswitch_watchdog_interval",
                "must be greater than zero",
            ));
        }
        for (idx, entry) in self.global_denylist.iter().enumerate() {
            entry.check_invariants(idx)?;
        }
        Ok(())
    }
}
