//! Audit-pipeline configuration.
//!
//! Holds the small set of operator-facing knobs needed by the audit
//! subsystem outside the `audit.chain_verifier.*` cadence (which is
//! sourced from a dedicated env var so a malformed YAML cannot silence
//! the CRIT-002 background verifier).
//!
//! ## Current fields
//!
//! - [`AuditConfig::system_engagement_id`] — UUID of the
//!   "system-internal" engagement under which synthetic platform
//!   findings (TOP5-#3-P2-007 audit-chain break, TOP5-#3-P2-008
//!   rate-limit, etc.) are persisted. When `None` the at-boundary
//!   observer falls back to a deterministic derived UUID per the
//!   contract in
//!   `services/sx-monolith/src/adapters/audit_break_observer.rs`.
//!
//! ## Why this lives in its own section
//!
//! The `audit.chain_verifier.interval_secs` knob is read out-of-band via
//! `AUDIT_CHAIN_VERIFIER_INTERVAL_SECS` (see
//! `services/sx-monolith/src/adapters/chain_verifier.rs`) so a busted
//! YAML cannot silence the verifier. This struct holds the *finding-side*
//! settings — they are safe to surface through the regular layered
//! loader because a misconfigured value falls back to the
//! deterministic derived UUID rather than disabling the emission path.

use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

/// Audit-pipeline operator settings.
///
/// Fields are intentionally all-optional with serde defaults so omitting
/// the section keeps backwards compatibility with on-disk configs from
/// before TOP5-#3-P2-007 landed. The loader installs an empty
/// [`AuditConfig`] when the section is absent.
#[derive(Debug, Clone, Default, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Optional UUID of the "system-internal" engagement under which
    /// the platform's synthetic findings (TOP5-#3-P2-007 audit-chain
    /// break, TOP5-#3-P2-008 rate-limiter, …) are persisted.
    ///
    /// When `None` the at-boundary observer derives a deterministic UUID
    /// per tenant from the tenant id so re-fires stay idempotent without
    /// requiring an operator-supplied row in `engagements`. Deployments
    /// running against the production Postgres adapter SHOULD set this
    /// to the real `engagements.id` of a long-lived "Platform Internal"
    /// engagement so the `findings.engagement_id` FK resolves.
    #[serde(default)]
    pub system_engagement_id: Option<Uuid>,
}

impl AuditConfig {
    /// Cross-field invariants. No-op today — every field is independent.
    /// Kept as a method so the loader call site mirrors the rest of the
    /// schema sub-configs.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn
    )]
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_has_no_system_engagement_id() {
        let c = AuditConfig::default();
        assert!(c.system_engagement_id.is_none());
        assert!(c.check_invariants().is_ok());
    }

    #[test]
    fn parses_uuid_when_provided() {
        let json = r#"{"system_engagement_id":"00000000-0000-7000-8000-000000000001"}"#;
        let c: AuditConfig = serde_json::from_str(json).expect("must parse");
        assert!(c.system_engagement_id.is_some());
    }

    #[test]
    fn omitting_field_keeps_none() {
        let json = "{}";
        let c: AuditConfig = serde_json::from_str(json).expect("must parse");
        assert!(c.system_engagement_id.is_none());
    }

    #[test]
    fn unknown_field_is_rejected() {
        let json = r#"{"system_engagement_id":"00000000-0000-7000-8000-000000000001","stray":1}"#;
        assert!(serde_json::from_str::<AuditConfig>(json).is_err());
    }
}
