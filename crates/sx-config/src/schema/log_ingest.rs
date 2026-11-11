//! Log-ingest rate-limit configuration (MED-001).
//!
//! Per-tier token-bucket rates used by
//! [`sx_log_ingest::rate_limit::RateLimiter`]. The runtime limiter is
//! seeded from this struct at composition-root time so operators can
//! tune the steady-state and burst budgets without recompiling.
//!
//! ## Defaults (`SentinelX` canonical)
//!
//! | Tier | per-second | burst |
//! |---|---|---|
//! | `free` | 100 | 200 |
//! | `pro` | 1 000 | 2 000 |
//! | `enterprise` | 10 000 | 20 000 |
//!
//! Burst defaults to `2 *` the steady-state so a spiky integration has
//! one second of headroom before the bucket starves. Operators may
//! override either field per tier.
//!
//! ## Default tier
//!
//! `default_tier` controls which tier a tenant lands on before an admin
//! issues an override via
//! `PUT /v1/admin/log-ingest/tiers/{tenant_id}`. Defaults to `free` so
//! a misconfigured tenant cannot DOS the ingest path.

use serde::Deserialize;
use validator::Validate;

/// Default free-tier steady-state (events/sec).
const fn default_free_per_sec() -> u32 {
    100
}

/// Default free-tier burst.
const fn default_free_burst() -> u32 {
    200
}

/// Default pro-tier steady-state.
const fn default_pro_per_sec() -> u32 {
    1_000
}

/// Default pro-tier burst.
const fn default_pro_burst() -> u32 {
    2_000
}

/// Default enterprise-tier steady-state.
const fn default_enterprise_per_sec() -> u32 {
    10_000
}

/// Default enterprise-tier burst.
const fn default_enterprise_burst() -> u32 {
    20_000
}

/// Default tier string. Lower-cased snake-case matches
/// [`sx_log_ingest::Tier::as_str`].
fn default_default_tier() -> String {
    "free".to_owned()
}

/// One tier's token-bucket parameters.
#[derive(Debug, Clone, Copy, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct TierRateConfig {
    /// Steady-state events per second. Must be strictly positive — a
    /// zero rate would lock the tier out entirely.
    #[validate(range(min = 1))]
    pub per_sec_rate: u32,
    /// Maximum token count (burst ceiling). Must be `>= per_sec_rate`
    /// — a burst below the steady-state rate cannot accumulate
    /// headroom and would silently behave like `per_sec_rate`.
    #[validate(range(min = 1))]
    pub burst: u32,
}

impl TierRateConfig {
    /// Per-field invariant check called by the parent.
    fn check_invariants(self, key_prefix: &str) -> Result<(), crate::ConfigError> {
        if self.per_sec_rate == 0 {
            return Err(crate::ConfigError::invalid(
                format!("{key_prefix}.per_sec_rate"),
                "must be greater than zero",
            ));
        }
        if self.burst < self.per_sec_rate {
            return Err(crate::ConfigError::invalid(
                format!("{key_prefix}.burst"),
                "must be >= per_sec_rate",
            ));
        }
        Ok(())
    }
}

/// Per-tenant log-ingest rate limiter configuration.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct LogIngestRateLimitConfig {
    /// Free-tier rates.
    #[validate(nested)]
    #[serde(default = "default_free")]
    pub free: TierRateConfig,

    /// Pro-tier rates.
    #[validate(nested)]
    #[serde(default = "default_pro")]
    pub pro: TierRateConfig,

    /// Enterprise-tier rates.
    #[validate(nested)]
    #[serde(default = "default_enterprise")]
    pub enterprise: TierRateConfig,

    /// Tier new tenants land on before any admin override.
    #[serde(default = "default_default_tier")]
    pub default_tier: String,
}

const fn default_free() -> TierRateConfig {
    TierRateConfig {
        per_sec_rate: default_free_per_sec(),
        burst: default_free_burst(),
    }
}

const fn default_pro() -> TierRateConfig {
    TierRateConfig {
        per_sec_rate: default_pro_per_sec(),
        burst: default_pro_burst(),
    }
}

const fn default_enterprise() -> TierRateConfig {
    TierRateConfig {
        per_sec_rate: default_enterprise_per_sec(),
        burst: default_enterprise_burst(),
    }
}

impl Default for LogIngestRateLimitConfig {
    fn default() -> Self {
        Self {
            free: default_free(),
            pro: default_pro(),
            enterprise: default_enterprise(),
            default_tier: default_default_tier(),
        }
    }
}

impl LogIngestRateLimitConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        self.free.check_invariants("log_ingest_rate_limit.free")?;
        self.pro.check_invariants("log_ingest_rate_limit.pro")?;
        self.enterprise
            .check_invariants("log_ingest_rate_limit.enterprise")?;
        if !matches!(self.default_tier.as_str(), "free" | "pro" | "enterprise") {
            return Err(crate::ConfigError::invalid(
                "log_ingest_rate_limit.default_tier",
                "must be one of: free, pro, enterprise",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_sentinelx_canonical() {
        let cfg = LogIngestRateLimitConfig::default();
        assert_eq!(cfg.free.per_sec_rate, 100);
        assert_eq!(cfg.free.burst, 200);
        assert_eq!(cfg.pro.per_sec_rate, 1_000);
        assert_eq!(cfg.pro.burst, 2_000);
        assert_eq!(cfg.enterprise.per_sec_rate, 10_000);
        assert_eq!(cfg.enterprise.burst, 20_000);
        assert_eq!(cfg.default_tier, "free");
        cfg.check_invariants().expect("defaults must validate");
    }

    #[test]
    fn rejects_zero_per_sec_rate() {
        let cfg = LogIngestRateLimitConfig {
            free: TierRateConfig {
                per_sec_rate: 0,
                burst: 1,
            },
            ..Default::default()
        };
        let err = cfg.check_invariants().expect_err("zero rate rejected");
        assert!(matches!(
            err,
            crate::ConfigError::InvalidValue { ref key, .. }
                if key == "log_ingest_rate_limit.free.per_sec_rate"
        ));
    }

    #[test]
    fn rejects_burst_below_steady_state() {
        let cfg = LogIngestRateLimitConfig {
            pro: TierRateConfig {
                per_sec_rate: 100,
                burst: 50,
            },
            ..Default::default()
        };
        let err = cfg
            .check_invariants()
            .expect_err("burst < per_sec_rate rejected");
        assert!(matches!(
            err,
            crate::ConfigError::InvalidValue { ref key, .. }
                if key == "log_ingest_rate_limit.pro.burst"
        ));
    }

    #[test]
    fn rejects_unknown_default_tier() {
        let cfg = LogIngestRateLimitConfig {
            default_tier: "ultra".into(),
            ..Default::default()
        };
        let err = cfg.check_invariants().expect_err("unknown tier rejected");
        assert!(matches!(
            err,
            crate::ConfigError::InvalidValue { ref key, .. }
                if key == "log_ingest_rate_limit.default_tier"
        ));
    }
}
