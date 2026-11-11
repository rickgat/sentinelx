//! `BugBountyConnector` trait + shared DTOs.
//!
//! Two outbound surfaces are implemented today: HackerOne and Bugcrowd.
//! Both expose the same shape:
//!
//! * Push a triaged `SentinelX` finding (severity ≥ `High`) as a
//!   **draft, internal program note** — never as a public report. The
//!   distinction matters: posting a researcher-visible draft would leak
//!   internal telemetry to the public bug-bounty pipeline.
//!
//! Inbound (researcher reports) goes through
//! [`super::webhook`] and is connector-agnostic: every platform delivers
//! a JSON envelope, we just verify the signature and map to a canonical
//! [`super::webhook::CanonicalFinding`].

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::siem::Severity;

/// The bug-bounty platform a connector talks to.
///
/// Serialised as a lowercase wire string by [`Self::as_wire`] and the
/// inverse parser [`Self::from_wire`]. The wire representation is the
/// stable identifier the `bug_bounty_connections` table persists, the
/// inbound webhook path segment uses, and the `Finding::source` prefix
/// embeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BugBountyKind {
    /// HackerOne — <https://api.hackerone.com/v1>
    HackerOne,
    /// Bugcrowd — <https://api.bugcrowd.com/v2>
    Bugcrowd,
}

impl BugBountyKind {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::HackerOne => "hackerone",
            Self::Bugcrowd => "bugcrowd",
        }
    }

    /// Parse the wire string. Returns `None` for unknown identifiers.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hackerone" | "h1" | "hacker_one" | "hacker-one" => Some(Self::HackerOne),
            "bugcrowd" | "bc" => Some(Self::Bugcrowd),
            _ => None,
        }
    }
}

impl std::fmt::Display for BugBountyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// HackerOne credentials — API username + API token (basic auth).
///
/// Production deployments mint the token from the HackerOne organisation
/// settings and persist it inside the tenant's `bug_bounty_connections`
/// row (encrypted at rest with the tenant DEK via `sx-secrets`).
#[derive(Clone)]
pub struct HackerOneCredentials {
    /// API username (identifier of the API user inside the program).
    pub api_username: String,
    /// API token, wrapped so the [`Debug`] impl can redact it.
    pub api_token: SecretString,
}

impl std::fmt::Debug for HackerOneCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HackerOneCredentials")
            .field("api_username", &self.api_username)
            .field("api_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Bugcrowd credentials — a single bearer API token.
#[derive(Clone)]
pub struct BugcrowdCredentials {
    /// Bearer API token, wrapped so the [`Debug`] impl can redact it.
    pub api_token: SecretString,
}

impl std::fmt::Debug for BugcrowdCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BugcrowdCredentials")
            .field("api_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A triaged `SentinelX` finding being pushed to a bug-bounty program as
/// an internal draft note.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriagedFinding {
    /// SentinelX finding uuid.
    pub id: String,
    /// Tenant uuid the finding belongs to.
    pub tenant_id: String,
    /// Bug-bounty program handle the note attaches to. HackerOne uses a
    /// `program.handle`, Bugcrowd uses an `engagement_brief.uuid`.
    pub program_handle: String,
    /// Severity (must be `High` or `Critical` for the push to be
    /// accepted — the dispatcher enforces this).
    pub severity: Severity,
    /// Short title.
    pub title: String,
    /// Long-form description (markdown).
    pub description: String,
}

/// Outcome reported by a successful push.
///
/// Both fields are optional so a connector that does not surface them
/// remains compliant. HackerOne returns a numeric note id; Bugcrowd
/// returns a uuid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// Upstream identifier the bug-bounty platform persisted under.
    pub upstream_id: Option<String>,
    /// Canonical URL of the upserted note resource.
    pub url: Option<String>,
}

impl PushOutcome {
    /// Empty outcome — used by stubs that have no upstream context.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            upstream_id: None,
            url: None,
        }
    }
}

/// Errors surfaced by bug-bounty connectors.
#[derive(Debug, Error)]
pub enum ConnectorError {
    /// Underlying HTTP transport / TLS / timeout failure.
    #[error("connector transport error: {0}")]
    Transport(String),

    /// The remote response (or local payload) could not be
    /// parsed/serialised into the expected shape.
    #[error("connector format error: {0}")]
    Format(String),

    /// The remote rejected the request on authn/authz grounds.
    #[error("connector unauthorized")]
    Unauthorized,

    /// The remote returned `429 Too Many Requests`. `retry_after_secs`
    /// echoes the `Retry-After` header when present and parsable.
    #[error("connector rate limited (retry after {retry_after_secs:?}s)")]
    RateLimited {
        /// Parsed value of the `Retry-After` header.
        retry_after_secs: Option<u64>,
    },

    /// The caller attempted to push a finding below the severity floor
    /// (HIGH). Caught locally so it never hits the upstream API.
    #[error("finding severity {0:?} below HIGH floor; not pushed")]
    BelowSeverityFloor(Severity),
}

impl ConnectorError {
    /// Convenience constructor for transport errors.
    #[must_use]
    pub fn transport<E: std::fmt::Display>(err: E) -> Self {
        Self::Transport(err.to_string())
    }

    /// Convenience constructor for format errors.
    #[must_use]
    pub fn format<E: std::fmt::Display>(err: E) -> Self {
        Self::Format(err.to_string())
    }
}

impl From<reqwest::Error> for ConnectorError {
    fn from(err: reqwest::Error) -> Self {
        Self::transport(err)
    }
}

impl From<serde_json::Error> for ConnectorError {
    fn from(err: serde_json::Error) -> Self {
        Self::format(err)
    }
}

/// Bug-bounty connector surface — implemented per vendor.
#[async_trait]
pub trait BugBountyConnector: Send + Sync {
    /// Identify which platform this connector talks to.
    fn kind(&self) -> BugBountyKind;

    /// Push a triaged finding to the program as an internal draft note.
    /// The implementation **must not** post anything researcher-visible.
    async fn push_internal_note(
        &self,
        finding: &TriagedFinding,
    ) -> Result<PushOutcome, ConnectorError>;
}

/// Minimum severity that may be pushed to a bug-bounty program. Findings
/// below this floor are rejected locally with
/// [`ConnectorError::BelowSeverityFloor`].
pub const MIN_PUSH_SEVERITY: Severity = Severity::High;

/// Returns `true` when `sev` is at or above the [`MIN_PUSH_SEVERITY`]
/// floor.
#[must_use]
pub const fn is_pushable(sev: Severity) -> bool {
    matches!(sev, Severity::High | Severity::Critical)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bug_bounty_kind_wire_round_trip() {
        for k in [BugBountyKind::HackerOne, BugBountyKind::Bugcrowd] {
            assert_eq!(BugBountyKind::from_wire(k.as_wire()), Some(k));
        }
    }

    #[test]
    fn bug_bounty_kind_aliases_parse() {
        assert_eq!(
            BugBountyKind::from_wire("H1"),
            Some(BugBountyKind::HackerOne)
        );
        assert_eq!(
            BugBountyKind::from_wire("hacker_one"),
            Some(BugBountyKind::HackerOne)
        );
        assert_eq!(
            BugBountyKind::from_wire("hacker-one"),
            Some(BugBountyKind::HackerOne)
        );
        assert_eq!(
            BugBountyKind::from_wire("BC"),
            Some(BugBountyKind::Bugcrowd)
        );
        assert_eq!(
            BugBountyKind::from_wire("BUGCROWD"),
            Some(BugBountyKind::Bugcrowd)
        );
    }

    #[test]
    fn bug_bounty_kind_rejects_unknown() {
        assert_eq!(BugBountyKind::from_wire("yeswehack"), None);
        assert_eq!(BugBountyKind::from_wire(""), None);
    }

    #[test]
    fn hackerone_credentials_debug_redacts() {
        let creds = HackerOneCredentials {
            api_username: "ops-api".into(),
            api_token: SecretString::from("h1-token-shh".to_owned()),
        };
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("ops-api"));
        assert!(!dbg.contains("h1-token-shh"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn bugcrowd_credentials_debug_redacts() {
        let creds = BugcrowdCredentials {
            api_token: SecretString::from("bc-token-shh".to_owned()),
        };
        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("bc-token-shh"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn is_pushable_enforces_high_floor() {
        assert!(!is_pushable(Severity::Info));
        assert!(!is_pushable(Severity::Low));
        assert!(!is_pushable(Severity::Medium));
        assert!(is_pushable(Severity::High));
        assert!(is_pushable(Severity::Critical));
    }

    #[test]
    fn kind_display_is_wire() {
        assert_eq!(BugBountyKind::HackerOne.to_string(), "hackerone");
        assert_eq!(BugBountyKind::Bugcrowd.to_string(), "bugcrowd");
    }

    #[test]
    fn connector_error_constructors() {
        let e = ConnectorError::transport("boom");
        assert!(matches!(e, ConnectorError::Transport(_)));
        let e = ConnectorError::format("nope");
        assert!(matches!(e, ConnectorError::Format(_)));
    }
}
