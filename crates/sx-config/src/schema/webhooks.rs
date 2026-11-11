//! Per-tenant outbound webhook signing-key rotation configuration (MED-003).
//!
//! Backs the [`sx_webhooks`] background rotator and the
//! `POST /v1/admin/webhooks/keys/rotate` admin endpoint. Operators tune
//! the cadence (default: 90 days) and grace window (default: 7 days)
//! per deployment; per-tenant overrides live in `sx-config` so the same
//! schema can carry both the platform default and an optional list of
//! per-tenant exceptions.
//!
//! ## Defaults
//!
//! | Field | Default |
//! |---|---|
//! | `enabled` | `true` |
//! | `cadence_days` | `90` |
//! | `grace_days` | `7` |
//! | `tick_seconds` | `3 600` (1 h) |
//!
//! `enabled=true` (MED-003 default): the background rotator is spawned and
//! the force-rotate admin route is live. The composition root wires the
//! Postgres-backed signing-key store when the DB is enabled (keys survive
//! restart) and the in-memory store otherwise; the HMAC secret rides the
//! `SecretCipher` seam (KMS-backed cipher when configured).

use std::collections::BTreeMap;

use serde::Deserialize;
use validator::Validate;

/// Default cadence — 90 days.
const fn default_cadence_days() -> u32 {
    90
}

/// Default grace window — 7 days.
const fn default_grace_days() -> u32 {
    7
}

/// Default background-tick interval — 1 hour.
const fn default_tick_seconds() -> u64 {
    3_600
}

/// Per-tenant override pair (cadence + grace).
#[derive(Debug, Clone, Copy, Deserialize, Validate, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantWebhookRotationOverride {
    /// Cadence override in days; defaults to the platform `cadence_days`.
    #[validate(range(min = 1, max = 3650))]
    #[serde(default = "default_cadence_days")]
    pub cadence_days: u32,
    /// Grace window override in days; defaults to the platform
    /// `grace_days`.
    #[validate(range(min = 0, max = 365))]
    #[serde(default = "default_grace_days")]
    pub grace_days: u32,
}

impl Default for TenantWebhookRotationOverride {
    fn default() -> Self {
        Self {
            cadence_days: default_cadence_days(),
            grace_days: default_grace_days(),
        }
    }
}

/// Outbound webhook signing-key rotation configuration (MED-003).
#[derive(Debug, Clone, Deserialize, Validate, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebhookSigningRotationConfig {
    /// Master switch — when `false` the background rotator is not
    /// spawned. Defaults to `true` (MED-003 rotation is on by default);
    /// admin-triggered force-rotation works regardless via the API
    /// surface for whichever store is wired.
    #[serde(default = "default_rotation_enabled")]
    pub enabled: bool,

    /// Default rotation cadence in days. Per-tenant overrides may push
    /// shorter or longer cadences. Range 1..=3650 (10 years).
    #[validate(range(min = 1, max = 3650))]
    #[serde(default = "default_cadence_days")]
    pub cadence_days: u32,

    /// Default grace window (in days) during which BOTH the old and
    /// new key are accepted by the verifier endpoint AND remain valid
    /// signing keys (the newer one is the primary; the older is kept
    /// for asymmetric subscriber handover). Range 0..=365.
    #[validate(range(min = 0, max = 365))]
    #[serde(default = "default_grace_days")]
    pub grace_days: u32,

    /// Background-tick interval. The rotator wakes up this often and
    /// scans for keys aging past cadence. Defaults to 1 h.
    #[validate(range(min = 60, max = 86_400))]
    #[serde(default = "default_tick_seconds")]
    pub tick_seconds: u64,

    /// Per-tenant overrides. Map key is the tenant UUID; absent keys
    /// fall through to the platform defaults above.
    #[serde(default)]
    pub tenant_overrides: BTreeMap<String, TenantWebhookRotationOverride>,
}

/// Serde default for [`WebhookSigningRotationConfig::enabled`] — rotation
/// is on by default (MED-003 "build + enable").
const fn default_rotation_enabled() -> bool {
    true
}

impl Default for WebhookSigningRotationConfig {
    fn default() -> Self {
        Self {
            enabled: default_rotation_enabled(),
            cadence_days: default_cadence_days(),
            grace_days: default_grace_days(),
            tick_seconds: default_tick_seconds(),
            tenant_overrides: BTreeMap::new(),
        }
    }
}

impl WebhookSigningRotationConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.cadence_days == 0 {
            return Err(crate::ConfigError::invalid(
                "webhook_signing_rotation.cadence_days",
                "must be greater than zero",
            ));
        }
        if u64::from(self.grace_days) > u64::from(self.cadence_days) {
            return Err(crate::ConfigError::invalid(
                "webhook_signing_rotation.grace_days",
                "must be <= cadence_days",
            ));
        }
        for (tenant, ovr) in &self.tenant_overrides {
            if ovr.cadence_days == 0 {
                return Err(crate::ConfigError::invalid(
                    format!("webhook_signing_rotation.tenant_overrides.{tenant}.cadence_days"),
                    "must be greater than zero",
                ));
            }
            if u64::from(ovr.grace_days) > u64::from(ovr.cadence_days) {
                return Err(crate::ConfigError::invalid(
                    format!("webhook_signing_rotation.tenant_overrides.{tenant}.grace_days"),
                    "must be <= cadence_days",
                ));
            }
        }
        Ok(())
    }

    /// Resolve the cadence + grace for a particular tenant. Falls back
    /// to platform defaults when no override row exists.
    #[must_use]
    pub fn for_tenant(&self, tenant_id: &str) -> (u32, u32) {
        self.tenant_overrides
            .get(tenant_id)
            .map_or((self.cadence_days, self.grace_days), |ovr| {
                (ovr.cadence_days, ovr.grace_days)
            })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let cfg = WebhookSigningRotationConfig::default();
        assert!(cfg.enabled, "rotation is on by default (MED-003)");
        assert_eq!(cfg.cadence_days, 90);
        assert_eq!(cfg.grace_days, 7);
        assert_eq!(cfg.tick_seconds, 3_600);
        cfg.check_invariants().expect("defaults must validate");
    }

    #[test]
    fn rejects_zero_cadence() {
        let cfg = WebhookSigningRotationConfig {
            cadence_days: 0,
            ..Default::default()
        };
        let err = cfg.check_invariants().expect_err("zero cadence rejected");
        assert!(matches!(
            err,
            crate::ConfigError::InvalidValue { ref key, .. }
                if key == "webhook_signing_rotation.cadence_days"
        ));
    }

    #[test]
    fn rejects_grace_greater_than_cadence() {
        let cfg = WebhookSigningRotationConfig {
            cadence_days: 7,
            grace_days: 10,
            ..Default::default()
        };
        let err = cfg
            .check_invariants()
            .expect_err("grace > cadence rejected");
        assert!(matches!(
            err,
            crate::ConfigError::InvalidValue { ref key, .. }
                if key == "webhook_signing_rotation.grace_days"
        ));
    }

    #[test]
    fn per_tenant_overrides_take_precedence() {
        let mut tenant_overrides = BTreeMap::new();
        tenant_overrides.insert(
            "tenant-a".to_owned(),
            TenantWebhookRotationOverride {
                cadence_days: 30,
                grace_days: 1,
            },
        );
        let cfg = WebhookSigningRotationConfig {
            tenant_overrides,
            ..Default::default()
        };
        cfg.check_invariants().unwrap();
        assert_eq!(cfg.for_tenant("tenant-a"), (30, 1));
        assert_eq!(cfg.for_tenant("tenant-b"), (90, 7));
    }
}
