//! Risk-Based Authentication (RBA) global configuration block
//! (TOP5-#3-P2-005).
//!
//! Today this block exists solely to wire the synthetic-finding emission
//! introduced by TOP5-#3-P2-005. The RBA engine itself (per-tenant scorer
//! weights, thresholds, feature flags) is configured via the in-process
//! `sx_rba::RbaConfig` and the `POST /v1/rba/config/{tenant}` admin
//! endpoint — not this file. Both stay disjoint by design:
//!
//! * `RbaConfig` (per-tenant, hot-reloadable) → scoring thresholds.
//! * `RbaSettings` (platform-wide, file-only) → emitter wiring + SOC
//!   visibility knobs.
//!
//! The whole block is optional and defaults to a back-compatible off
//! state, so a freshly cloned checkout does not mint any synthetic
//! findings until an operator opts in.

use serde::Deserialize;
use validator::Validate;

/// Default emission threshold — at-or-above 75/100 maps to "Block + real
/// signal" per the Wave B audit. Tunable per deployment.
const fn default_block_threshold_score() -> u8 {
    75
}

/// Default system engagement id used when an operator has not pinned one
/// of their own. The all-zero UUID is the conventional "system-internal"
/// sentinel across the codebase — when the operator runs the platform
/// against the in-memory finding adapter this id is harmless; against
/// the Postgres adapter it MUST be overridden because `findings.engagement_id`
/// carries a foreign key. The composition root logs a warning when
/// emission is enabled with the default engagement id.
const SYSTEM_ENGAGEMENT_ID_DEFAULT: &str = "00000000-0000-0000-0000-000000000000";

/// Default system asset id used when an operator has not pinned one of
/// their own. See [`SYSTEM_ENGAGEMENT_ID_DEFAULT`] for the rationale.
const SYSTEM_ASSET_ID_DEFAULT: &str = "00000000-0000-0000-0000-000000000000";

fn default_system_engagement_id() -> String {
    SYSTEM_ENGAGEMENT_ID_DEFAULT.to_owned()
}

fn default_system_asset_id() -> String {
    SYSTEM_ASSET_ID_DEFAULT.to_owned()
}

/// `rba.finding_emission` sub-block.
///
/// Controls whether high-risk RBA `Block` decisions are surfaced to the
/// SOC as synthetic `Finding` rows (TOP5-#3-P2-005, PO decision Option
/// (b) on the Wave B audit). Allow / `StepUpMfa` decisions are NEVER
/// surfaced — they remain decision-only.
///
/// ## Defaults
///
/// | Field | Default |
/// |---|---|
/// | `enabled` | `false` |
/// | `block_threshold_score` | `75` |
/// | `system_engagement_id` | all-zero UUID |
/// | `system_asset_id` | all-zero UUID |
#[derive(Debug, Clone, Deserialize, Validate, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RbaFindingEmissionConfig {
    /// Master switch. When `false`, no synthetic findings are emitted
    /// regardless of decision score. Back-compat default for fresh
    /// checkouts.
    #[serde(default)]
    pub enabled: bool,

    /// Minimum composite score a `Block` decision MUST exceed (inclusive)
    /// to be surfaced as a synthetic Finding. Range 0..=100 mirroring
    /// the RBA composite score scale.
    #[validate(range(min = 0, max = 100))]
    #[serde(default = "default_block_threshold_score")]
    pub block_threshold_score: u8,

    /// System-internal engagement id every synthetic Finding is bound
    /// to. Operators wiring against Postgres MUST override this with a
    /// real engagement row id because `findings.engagement_id` carries a
    /// foreign key. The default (all-zero UUID) is the platform
    /// convention for "system-internal" and is silently accepted by the
    /// in-memory finding adapter used in dev/tests.
    #[serde(default = "default_system_engagement_id")]
    pub system_engagement_id: String,

    /// System-internal asset id every synthetic Finding is bound to.
    /// Same caveat as [`Self::system_engagement_id`] when wiring against
    /// Postgres.
    #[serde(default = "default_system_asset_id")]
    pub system_asset_id: String,
}

impl Default for RbaFindingEmissionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            block_threshold_score: default_block_threshold_score(),
            system_engagement_id: default_system_engagement_id(),
            system_asset_id: default_system_asset_id(),
        }
    }
}

impl RbaFindingEmissionConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.block_threshold_score > 100 {
            return Err(crate::ConfigError::invalid(
                "rba.finding_emission.block_threshold_score",
                "must be in 0..=100",
            ));
        }
        if uuid::Uuid::parse_str(&self.system_engagement_id).is_err() {
            return Err(crate::ConfigError::invalid(
                "rba.finding_emission.system_engagement_id",
                "must be a UUID",
            ));
        }
        if uuid::Uuid::parse_str(&self.system_asset_id).is_err() {
            return Err(crate::ConfigError::invalid(
                "rba.finding_emission.system_asset_id",
                "must be a UUID",
            ));
        }
        Ok(())
    }
}

/// `rba` top-level config block.
///
/// Currently only carries [`Self::finding_emission`]; future global RBA
/// knobs (e.g. cross-tenant kill-switch, observation-mode override)
/// land here without growing the [`crate::Settings`] root.
#[derive(Debug, Clone, Deserialize, Validate, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RbaSettings {
    /// Synthetic-finding emission for high-risk Block decisions
    /// (TOP5-#3-P2-005).
    #[serde(default)]
    #[validate(nested)]
    pub finding_emission: RbaFindingEmissionConfig,
}

impl RbaSettings {
    /// Cross-field invariants delegated to each sub-block.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        self.finding_emission.check_invariants()?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let cfg = RbaFindingEmissionConfig::default();
        assert!(!cfg.enabled, "fresh checkouts must NOT emit findings");
        assert_eq!(cfg.block_threshold_score, 75);
        assert_eq!(
            cfg.system_engagement_id,
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(cfg.system_asset_id, "00000000-0000-0000-0000-000000000000");
        cfg.check_invariants().expect("defaults must validate");
    }

    #[test]
    fn rejects_non_uuid_engagement_id() {
        let cfg = RbaFindingEmissionConfig {
            system_engagement_id: "not-a-uuid".to_owned(),
            ..Default::default()
        };
        let err = cfg
            .check_invariants()
            .expect_err("non-uuid engagement id rejected");
        assert!(matches!(
            err,
            crate::ConfigError::InvalidValue { ref key, .. }
                if key == "rba.finding_emission.system_engagement_id"
        ));
    }

    #[test]
    fn rejects_non_uuid_asset_id() {
        let cfg = RbaFindingEmissionConfig {
            system_asset_id: "not-a-uuid".to_owned(),
            ..Default::default()
        };
        let err = cfg
            .check_invariants()
            .expect_err("non-uuid asset id rejected");
        assert!(matches!(
            err,
            crate::ConfigError::InvalidValue { ref key, .. }
                if key == "rba.finding_emission.system_asset_id"
        ));
    }

    #[test]
    fn rba_settings_default_passes_invariants() {
        let cfg = RbaSettings::default();
        cfg.check_invariants().expect("RbaSettings defaults valid");
        assert!(!cfg.finding_emission.enabled);
    }

    #[test]
    fn validate_attribute_rejects_score_out_of_range() {
        let cfg = RbaFindingEmissionConfig {
            block_threshold_score: 200,
            ..Default::default()
        };
        // Field-level validator catches the range violation before
        // check_invariants runs.
        assert!(cfg.validate().is_err());
    }
}
