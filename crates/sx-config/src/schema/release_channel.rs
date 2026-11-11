//! Release-channel / SARIF `tool.driver` metadata configuration
//! (TOP5-#3 Phase 3).
//!
//! Holds the two operator-facing knobs that populate SARIF
//! `runs[].tool.driver.organization` (§3.19.16) and
//! `runs[].tool.driver.downloadUri` (§3.19.18) when the SARIF export
//! endpoint (`GET /v1/scans/{id}.sarif`) renders a stored scan record.
//!
//! ## Fields
//!
//! - [`ReleaseChannelConfig::organization`] — human-readable organisation
//!   name emitted onto every SARIF envelope. Defaults to `"SentinelX"` so
//!   fresh checkouts render a compliant driver block without operator
//!   opt-in. Set it to the deployment's brand / tenant name in
//!   white-labelled installs.
//! - [`ReleaseChannelConfig::download_uri`] — optional stable release URL.
//!   `None` by default (Phase 3 dispatch: "must be a stable URL") — a
//!   half-baked staging URL emitted on every SARIF is worse than nothing
//!   because SOC pipelines dedupe by (organization, downloadUri).
//!
//! ## Why this lives in its own section
//!
//! Both fields belong on the SARIF envelope, not on the `SentinelX`
//! run-time; keeping them separate from `server` / `telemetry` avoids
//! accidental blast-radius when an operator flips the release-channel
//! metadata.

use serde::Deserialize;
use validator::Validate;

/// Default organisation emitted onto SARIF envelopes.
///
/// Kept as an associated constant so downstream tests can assert the
/// exact string without depending on the serde default handler.
pub const DEFAULT_ORGANIZATION: &str = "SentinelX";

/// Release-channel / SARIF `tool.driver` metadata.
///
/// Both fields are optional and default to a safe posture (fresh
/// checkouts render `organization: "SentinelX"` and omit `downloadUri`).
/// Omitting the section is equivalent to `release_channel:
/// {organization: "SentinelX", download_uri: null}`.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct ReleaseChannelConfig {
    /// Organisation name emitted onto `runs[].tool.driver.organization`.
    /// Non-empty per SARIF §3.19.16 (the schema does not allow an empty
    /// string).
    #[serde(default = "default_organization")]
    #[validate(length(min = 1))]
    pub organization: String,

    /// Optional stable download URL emitted onto
    /// `runs[].tool.driver.downloadUri`. `None` until a release channel
    /// is wired — SARIF consumers dedupe by (organization, downloadUri)
    /// so shipping a staging URL is worse than omitting the key.
    #[serde(default)]
    pub download_uri: Option<String>,
}

impl Default for ReleaseChannelConfig {
    fn default() -> Self {
        Self {
            organization: default_organization(),
            download_uri: None,
        }
    }
}

fn default_organization() -> String {
    DEFAULT_ORGANIZATION.to_owned()
}

impl ReleaseChannelConfig {
    /// Cross-field invariants. Rejects an all-whitespace `download_uri`
    /// (serde already rejects empty via `Option<String>` shape when the
    /// caller passes `""`, but a stray `"   "` slips through).
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.organization.trim().is_empty() {
            return Err(crate::ConfigError::invalid(
                "release_channel.organization",
                "must be non-empty",
            ));
        }
        if let Some(u) = &self.download_uri {
            if u.trim().is_empty() {
                return Err(crate::ConfigError::invalid(
                    "release_channel.download_uri",
                    "must be a non-empty stable URL when set (omit the key instead)",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_organization_is_sentinelx() {
        let c = ReleaseChannelConfig::default();
        assert_eq!(c.organization, "SentinelX");
        assert!(c.download_uri.is_none());
        assert!(c.check_invariants().is_ok());
    }

    #[test]
    fn empty_object_yaml_uses_default_organization() {
        let json = "{}";
        let c: ReleaseChannelConfig = serde_json::from_str(json).expect("must parse");
        assert_eq!(c.organization, "SentinelX");
        assert!(c.download_uri.is_none());
    }

    #[test]
    fn organization_override_round_trips() {
        let json = r#"{"organization":"Acme Corp"}"#;
        let c: ReleaseChannelConfig = serde_json::from_str(json).expect("must parse");
        assert_eq!(c.organization, "Acme Corp");
    }

    #[test]
    fn download_uri_round_trips() {
        let json = r#"{"download_uri":"https://releases.example.com/latest.zip"}"#;
        let c: ReleaseChannelConfig = serde_json::from_str(json).expect("must parse");
        assert_eq!(
            c.download_uri.as_deref(),
            Some("https://releases.example.com/latest.zip"),
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let json = r#"{"organization":"Acme","stray":1}"#;
        assert!(serde_json::from_str::<ReleaseChannelConfig>(json).is_err());
    }

    #[test]
    fn whitespace_download_uri_is_rejected() {
        let c = ReleaseChannelConfig {
            organization: "SentinelX".into(),
            download_uri: Some("   ".into()),
        };
        assert!(c.check_invariants().is_err());
    }

    #[test]
    fn whitespace_organization_is_rejected() {
        let c = ReleaseChannelConfig {
            organization: "   ".into(),
            download_uri: None,
        };
        assert!(c.check_invariants().is_err());
    }
}
