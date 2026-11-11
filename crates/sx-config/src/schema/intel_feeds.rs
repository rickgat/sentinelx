//! Threat-intelligence feed (TAXII) ingestion configuration.
//!
//! Configures the optional STIX/TAXII 2.x poller that the monolith spawns
//! as a background tokio task. Ships **disabled** by default — a freshly
//! cloned checkout never reaches any external TAXII server. When an
//! operator flips `enabled: true`, the loader requires every connection
//! parameter (endpoint URL, bearer token, collection id) to be non-empty
//! so the poller can authenticate against the configured server.
//!
//! The `taxii_bearer` is wrapped in [`secrecy::SecretString`] so it never
//! appears in `Debug` output, panic messages, or `tracing` records. The
//! poller adapter only exposes the secret at the moment it writes the
//! `Authorization: Bearer ...` header into a `reqwest` request — and even
//! then, the tracing event for the poll cycle carries only the endpoint
//! and collection id, never the bearer.

use secrecy::SecretString;
use serde::Deserialize;
use validator::Validate;

/// Default poll interval (3600 seconds / 1 hour) when none is supplied.
const fn default_poll_interval_secs() -> u64 {
    3600
}

/// Default minimum number of *independent* (distinct trust-family)
/// feeds that must corroborate an IOC before the matcher emits a
/// finding. Mirrors
/// [`sx_intel_feeds::DEFAULT_MIN_INDEPENDENT_SOURCES`] (HIGH-011).
///
/// `2` reflects the standard threat-intel best practice: never act on
/// a singleton report; require independent corroboration from a
/// second trust family (e.g. one commercial + one OSS, or one ISAC +
/// one commercial).
const fn default_min_independent_sources() -> u8 {
    2
}

/// Threat-intelligence feed (TAXII) configuration.
///
/// Disabled by default. When `enabled` is `true`:
///   * `taxii_endpoint` MUST be non-empty,
///   * `taxii_bearer` MUST be non-empty,
///   * `collection_id` MUST be non-empty,
///   * `poll_interval_secs` MUST be non-zero (a zero interval would spin
///     the background task into a tight loop).
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct IntelFeedsConfig {
    /// Whether the TAXII poller should be spawned at boot.
    ///
    /// When `false`, every other field is ignored and the monolith's
    /// `intel_feeds_job::spawn` returns `None`.
    pub enabled: bool,

    /// TAXII 2.x server discovery / collection root URL. Mandatory iff
    /// `enabled`.
    #[serde(default)]
    pub taxii_endpoint: String,

    /// Bearer token presented in the `Authorization` header on every
    /// TAXII poll. Mandatory iff `enabled`.
    ///
    /// Wrapped in [`SecretString`] so the value never appears in `Debug`
    /// output, panic messages, or `tracing` records. The poller adapter
    /// only exposes it inside a `reqwest` `Authorization` header at the
    /// moment the request is sent.
    #[serde(default)]
    pub taxii_bearer: SecretString,

    /// TAXII collection identifier to poll. Mandatory iff `enabled`.
    #[serde(default)]
    pub collection_id: String,

    /// Poll interval in seconds. Defaults to `3600` (1 hour). MUST be
    /// non-zero when the poller is enabled.
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,

    /// Minimum number of independent feed families that must
    /// corroborate an IOC before the matcher emits a finding
    /// (HIGH-011). Defaults to `2`. `0` is rejected at validation
    /// time as a configuration error — a threshold of `0` would
    /// degenerate to "always emit on a single feed", which defeats
    /// the entire diversity check. Set to `1` if you genuinely want
    /// to allow single-source findings (high-noise stance).
    #[serde(default = "default_min_independent_sources")]
    pub min_independent_sources: u8,
}

impl Default for IntelFeedsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            taxii_endpoint: String::new(),
            taxii_bearer: SecretString::from(String::new()),
            collection_id: String::new(),
            poll_interval_secs: default_poll_interval_secs(),
            min_independent_sources: default_min_independent_sources(),
        }
    }
}

impl IntelFeedsConfig {
    /// Cross-field invariants. Disabled configs always pass; enabled
    /// configs must supply a non-empty endpoint + bearer + collection id,
    /// and a non-zero poll interval.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.taxii_endpoint.trim().is_empty() {
            return Err(crate::ConfigError::missing("intel_feeds.taxii_endpoint"));
        }
        if self.collection_id.trim().is_empty() {
            return Err(crate::ConfigError::missing("intel_feeds.collection_id"));
        }
        if crate::secret::is_empty(&self.taxii_bearer) {
            return Err(crate::ConfigError::missing("intel_feeds.taxii_bearer"));
        }
        if self.poll_interval_secs == 0 {
            return Err(crate::ConfigError::invalid(
                "intel_feeds.poll_interval_secs",
                "must be greater than zero",
            ));
        }
        if self.min_independent_sources == 0 {
            return Err(crate::ConfigError::invalid(
                "intel_feeds.min_independent_sources",
                "must be at least 1 — zero would emit findings on \
                 every single-feed match and defeat the diversity gate",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::IntelFeedsConfig;
    use crate::secret;

    fn enabled_baseline() -> IntelFeedsConfig {
        IntelFeedsConfig {
            enabled: true,
            taxii_endpoint: "https://taxii.example.com/api/v21/".to_string(),
            taxii_bearer: secret::wrap("taxii-bearer-token"),
            collection_id: "00000000-0000-0000-0000-000000000001".to_string(),
            poll_interval_secs: 3600,
            min_independent_sources: 2,
        }
    }

    #[test]
    fn disabled_default_passes() {
        let cfg = IntelFeedsConfig::default();
        cfg.check_invariants()
            .expect("disabled default config must pass invariants");
    }

    #[test]
    fn enabled_baseline_passes() {
        enabled_baseline()
            .check_invariants()
            .expect("complete enabled baseline must pass");
    }

    #[test]
    fn enabled_without_endpoint_returns_missing() {
        let mut cfg = enabled_baseline();
        cfg.taxii_endpoint = String::new();
        let err = cfg
            .check_invariants()
            .expect_err("missing endpoint must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "intel_feeds.taxii_endpoint");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_without_collection_id_returns_missing() {
        let mut cfg = enabled_baseline();
        cfg.collection_id = "   ".to_string();
        let err = cfg
            .check_invariants()
            .expect_err("missing collection_id must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "intel_feeds.collection_id");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_without_bearer_returns_missing() {
        let mut cfg = enabled_baseline();
        cfg.taxii_bearer = secret::wrap("");
        let err = cfg
            .check_invariants()
            .expect_err("missing bearer must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "intel_feeds.taxii_bearer");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_with_zero_poll_interval_returns_invalid() {
        let mut cfg = enabled_baseline();
        cfg.poll_interval_secs = 0;
        let err = cfg
            .check_invariants()
            .expect_err("zero poll_interval must surface");
        match err {
            crate::ConfigError::InvalidValue { key, .. } => {
                assert_eq!(key, "intel_feeds.poll_interval_secs");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_bearer() {
        let cfg = enabled_baseline();
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("taxii-bearer-token"),
            "bearer leaked in Debug: {dbg}"
        );
    }

    #[test]
    fn defaults_match_documented_values() {
        let cfg = IntelFeedsConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.poll_interval_secs, 3600);
        assert!(cfg.taxii_endpoint.is_empty());
        assert!(cfg.collection_id.is_empty());
        assert_eq!(cfg.min_independent_sources, 2);
    }

    #[test]
    fn enabled_with_zero_min_independent_sources_returns_invalid() {
        let mut cfg = enabled_baseline();
        cfg.min_independent_sources = 0;
        let err = cfg
            .check_invariants()
            .expect_err("zero min_independent_sources must surface");
        match err {
            crate::ConfigError::InvalidValue { key, .. } => {
                assert_eq!(key, "intel_feeds.min_independent_sources");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
