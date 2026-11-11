//! TSA fallback configuration (CRIT-006).
//!
//! Defines the operator-facing knobs for the multi-TSA pipeline shipped
//! by `sx-audit::tsa_fallback`. Mirrors the in-crate
//! [`MultiTsaConfig`](sx_audit::tsa_fallback::MultiTsaConfig) shape one-
//! for-one so the composition root can translate without surprises.
//!
//! The section ships **enabled by default with dev-fixture defaults**:
//! `FreeTSA`, `Sectigo`, `DigiCert`, `GlobalSign`. The CA PEMs are placeholders
//! — production deployments MUST replace them with the real per-issuer
//! pinned CA before any live anchor. The verifier refuses the
//! placeholder so a misconfigured drop surfaces immediately.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// One TSA endpoint inside a [`TsaFallbackConfig`].
#[derive(Debug, Clone, Deserialize, Serialize, Validate, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TsaEndpointConfig {
    /// TSA URL (must start with `http://` or `https://`).
    #[validate(length(min = 1, max = 1024))]
    pub url: String,
    /// PEM-encoded RSA SPKI public key of the operator-pinned CA that
    /// the TSA's signing cert chains to.
    #[validate(length(min = 1, max = 16384))]
    pub ca_pem: String,
    /// Optional human-readable label (defaults to URL host).
    #[serde(default)]
    pub label: Option<String>,
    /// Per-request timeout in milliseconds. Default 30 000 (spec).
    #[serde(default = "default_timeout_ms")]
    #[validate(range(min = 100, max = 600_000))]
    pub timeout_ms: u32,
}

const fn default_timeout_ms() -> u32 {
    30_000
}

/// Per-tenant TSA fallback configuration block.
///
/// `tenant_id` is the UUID of the tenant the row scopes to. Carries
/// exactly one primary endpoint and zero-or-more backups.
#[derive(Debug, Clone, Deserialize, Serialize, Validate, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantTsaConfig {
    /// Tenant UUID. Stored as a string to avoid a hard dep on `uuid`
    /// from the config crate; downstream callers parse to UUID.
    #[validate(length(equal = 36))]
    pub tenant_id: String,
    /// Primary endpoint (highest priority).
    #[validate(nested)]
    pub primary: TsaEndpointConfig,
    /// Ordered backup list — capped at 8 entries (the migration matches
    /// this cap).
    #[serde(default)]
    #[validate(length(max = 8))]
    pub backups: Vec<TsaEndpointConfig>,
}

/// Top-level TSA fallback config — sits as `tsa` on
/// [`crate::schema::Settings`].
///
/// When `enabled = false` the composition root skips the multi-TSA
/// wiring entirely and the legacy single-TSA path stays in place. When
/// `enabled = true` but no `tenants` are listed, the composition root
/// applies the [`default_endpoints`] dev-fixture list to every tenant
/// (with the placeholder CA, which is by design).
///
/// # Quorum (MED-002)
///
/// Anchor records are produced via an n-of-m quorum across the
/// configured endpoints. `quorum_required` is the minimum number of
/// TSAs that must successfully sign the same Merkle root before the
/// run is accepted; `quorum_total` is the target fan-out. Defaults are
/// `2` and `3` respectively — operators can shrink to `1` of `1` for
/// the legacy single-TSA pipeline (the behaviour before MED-002).
#[derive(Debug, Clone, Deserialize, Serialize, Validate, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TsaFallbackConfig {
    /// Whether the multi-TSA pipeline is active.
    #[serde(default)]
    pub enabled: bool,
    /// Per-tenant TSA configurations. May be empty when `enabled =
    /// false` or when the operator wants the default dev fixtures
    /// for every tenant.
    #[serde(default)]
    #[validate(nested)]
    pub tenants: Vec<TenantTsaConfig>,
    /// Minimum TSAs that must successfully sign before an anchor run
    /// is accepted. Defaults to `2` (the spec). Setting `1` collapses
    /// to the pre-MED-002 first-wins behaviour.
    #[serde(default = "default_quorum_required")]
    #[validate(range(min = 1, max = 16))]
    pub quorum_required: u32,
    /// Target fan-out — number of TSAs the orchestrator will attempt
    /// to collect signatures from. Must be `>= quorum_required`.
    /// Defaults to `3`.
    #[serde(default = "default_quorum_total")]
    #[validate(range(min = 1, max = 16))]
    pub quorum_total: u32,
}

impl Default for TsaFallbackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tenants: Vec::new(),
            quorum_required: default_quorum_required(),
            quorum_total: default_quorum_total(),
        }
    }
}

const fn default_quorum_required() -> u32 {
    2
}

const fn default_quorum_total() -> u32 {
    3
}

impl TsaFallbackConfig {
    /// Cross-field invariants. Disabled configs always pass; enabled
    /// configs require every tenant block to be self-consistent (the
    /// `Validate` impl already covers per-field shape).
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        // Quorum invariants apply whether or not the pipeline is
        // enabled — a misconfigured ratio is a deployment bug we want
        // to surface at boot, not silently roll back to 1-of-1.
        if self.quorum_required > self.quorum_total {
            return Err(crate::ConfigError::missing(format!(
                "tsa.quorum_required ({}) cannot exceed tsa.quorum_total ({})",
                self.quorum_required, self.quorum_total,
            )));
        }
        if !self.enabled {
            return Ok(());
        }
        // When enabled, each listed tenant must have a non-empty primary
        // URL — the `Validate` impl already enforces it, but re-checking
        // here lets us surface a clear `MissingValue` key.
        for (idx, t) in self.tenants.iter().enumerate() {
            if t.primary.url.trim().is_empty() {
                return Err(crate::ConfigError::missing(format!(
                    "tsa.tenants[{idx}].primary.url"
                )));
            }
            if t.primary.ca_pem.trim().is_empty() {
                return Err(crate::ConfigError::missing(format!(
                    "tsa.tenants[{idx}].primary.ca_pem"
                )));
            }
            for (b_idx, b) in t.backups.iter().enumerate() {
                if b.url.trim().is_empty() {
                    return Err(crate::ConfigError::missing(format!(
                        "tsa.tenants[{idx}].backups[{b_idx}].url"
                    )));
                }
                if b.ca_pem.trim().is_empty() {
                    return Err(crate::ConfigError::missing(format!(
                        "tsa.tenants[{idx}].backups[{b_idx}].ca_pem"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Dev-fixture default TSA list shipped per CRIT-006 spec.
///
/// All entries use a placeholder CA PEM that the verifier will refuse;
/// production deployments MUST replace each `ca_pem` with the real
/// per-issuer pinned CA before any live anchor.
#[must_use]
pub fn default_endpoints() -> Vec<TsaEndpointConfig> {
    vec![
        TsaEndpointConfig {
            url: "https://freetsa.org/tsr".to_owned(),
            ca_pem: DEV_PLACEHOLDER_CA_PEM.to_owned(),
            label: Some("freetsa".to_owned()),
            timeout_ms: 30_000,
        },
        TsaEndpointConfig {
            url: "http://timestamp.sectigo.com".to_owned(),
            ca_pem: DEV_PLACEHOLDER_CA_PEM.to_owned(),
            label: Some("sectigo".to_owned()),
            timeout_ms: 30_000,
        },
        TsaEndpointConfig {
            url: "http://timestamp.digicert.com".to_owned(),
            ca_pem: DEV_PLACEHOLDER_CA_PEM.to_owned(),
            label: Some("digicert".to_owned()),
            timeout_ms: 30_000,
        },
        TsaEndpointConfig {
            url: "http://rfc3161timestamp.globalsign.com/standard".to_owned(),
            ca_pem: DEV_PLACEHOLDER_CA_PEM.to_owned(),
            label: Some("globalsign".to_owned()),
            timeout_ms: 30_000,
        },
    ]
}

/// Placeholder CA PEM marker used by the dev fixtures.
pub const DEV_PLACEHOLDER_CA_PEM: &str =
    "-----BEGIN PUBLIC KEY-----\nDEV_PLACEHOLDER_REPLACE_ME\n-----END PUBLIC KEY-----\n";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn disabled_default_passes() {
        let cfg = TsaFallbackConfig::default();
        cfg.check_invariants().expect("disabled default must pass");
        // MED-002: defaults are 2-of-3.
        assert_eq!(cfg.quorum_required, 2);
        assert_eq!(cfg.quorum_total, 3);
    }

    #[test]
    fn quorum_required_cannot_exceed_total() {
        let cfg = TsaFallbackConfig {
            enabled: false,
            tenants: vec![],
            quorum_required: 4,
            quorum_total: 3,
        };
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert!(key.contains("quorum_required"));
                assert!(key.contains("quorum_total"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quorum_one_of_one_is_legacy_compat() {
        let cfg = TsaFallbackConfig {
            enabled: false,
            tenants: vec![],
            quorum_required: 1,
            quorum_total: 1,
        };
        cfg.check_invariants()
            .expect("1-of-1 must pass (legacy compat)");
    }

    #[test]
    fn default_endpoints_lists_four_spec_providers() {
        let eps = default_endpoints();
        let labels: Vec<_> = eps
            .iter()
            .map(|e| e.label.clone().unwrap_or_default())
            .collect();
        assert_eq!(labels, vec!["freetsa", "sectigo", "digicert", "globalsign"]);
        assert!(
            eps.iter().all(|e| e.ca_pem.contains("DEV_PLACEHOLDER")),
            "every default endpoint must use the placeholder CA",
        );
        assert!(eps.iter().all(|e| e.timeout_ms == 30_000));
    }

    #[test]
    fn enabled_without_url_returns_missing() {
        let cfg = TsaFallbackConfig {
            enabled: true,
            tenants: vec![TenantTsaConfig {
                tenant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                primary: TsaEndpointConfig {
                    url: "   ".to_owned(),
                    ca_pem: "x".to_owned(),
                    label: None,
                    timeout_ms: 30_000,
                },
                backups: vec![],
            }],
            quorum_required: 1,
            quorum_total: 1,
        };
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "tsa.tenants[0].primary.url");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn enabled_baseline_passes() {
        let cfg = TsaFallbackConfig {
            enabled: true,
            tenants: vec![TenantTsaConfig {
                tenant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                primary: TsaEndpointConfig {
                    url: "https://freetsa.org/tsr".to_owned(),
                    ca_pem: "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n".to_owned(),
                    label: Some("primary".to_owned()),
                    timeout_ms: 30_000,
                },
                backups: vec![],
            }],
            quorum_required: 2,
            quorum_total: 3,
        };
        cfg.check_invariants().expect("baseline must pass");
    }
}
