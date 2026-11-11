//! `GrcConnector` trait + shared evidence / finding-state DTOs.
//!
//! The connector surface intentionally stays minimal: every concrete
//! connector exposes two upserts —
//!
//! * [`GrcConnector::push_evidence`] — ship a compliance evidence record
//!   so the GRC platform can attach it to the relevant control.
//! * [`GrcConnector::push_finding`] — ship the lifecycle state of a
//!   finding (open / triaged / accepted / closed) so the GRC platform
//!   can correlate it to a risk register or open incident.
//!
//! Both methods are idempotent on the upstream side — they always
//! upsert keyed by `(connector_kind, tenant_id, source_ref)`.
//!
//! ## Identity
//!
//! [`GrcKind`] tags the concrete connector implementation. Today the
//! enum carries three variants: [`Vanta`](GrcKind::Vanta),
//! [`Drata`](GrcKind::Drata), and [`ServiceNow`](GrcKind::ServiceNow).
//! Adding a new connector is a single variant + a wire string in
//! [`GrcKind::as_wire`].

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The kind of GRC platform a connector talks to.
///
/// Serialised as a lowercase wire string by [`Self::as_wire`] and the
/// inverse parser [`Self::from_wire`]. The wire representation is the
/// stable identifier the `grc_connections` table persists and the HTTP
/// surface accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrcKind {
    /// Vanta — <https://vanta.com>
    Vanta,
    /// Drata — <https://drata.com>
    Drata,
    /// `ServiceNow` — <https://servicenow.com>
    #[serde(rename = "servicenow")]
    ServiceNow,
}

impl GrcKind {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Vanta => "vanta",
            Self::Drata => "drata",
            Self::ServiceNow => "servicenow",
        }
    }

    /// Parse the wire string. Returns `None` for unknown identifiers.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "vanta" => Some(Self::Vanta),
            "drata" => Some(Self::Drata),
            "servicenow" | "service_now" | "service-now" => Some(Self::ServiceNow),
            _ => None,
        }
    }
}

impl std::fmt::Display for GrcKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// Vanta credentials — a bearer API key.
///
/// Production deployments mint the API key from the Vanta admin console
/// and persist it inside the tenant's `grc_connections` row (encrypted at
/// rest with the tenant DEK).
#[derive(Clone)]
pub struct VantaCredentials {
    /// Bearer API key, wrapped so the [`Debug`] impl can redact it.
    pub api_key: SecretString,
}

impl std::fmt::Debug for VantaCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VantaCredentials")
            .field("api_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// `ServiceNow` credentials — instance URL + basic-auth username/password.
#[derive(Clone)]
pub struct ServiceNowCredentials {
    /// Instance URL, e.g. `https://acme.service-now.com`.
    pub instance_url: String,
    /// Basic-auth username.
    pub user: String,
    /// Basic-auth password, wrapped so the [`Debug`] impl can redact it.
    pub password: SecretString,
}

impl std::fmt::Debug for ServiceNowCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceNowCredentials")
            .field("instance_url", &self.instance_url)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A compliance evidence record headed to a GRC platform.
///
/// Shaped so the projection is identical regardless of the underlying
/// compliance framework — the connector adapter is responsible for
/// translating the homogeneous shape into the vendor's wire payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceEvidence {
    /// Stable id minted by the platform; used by the connector as the
    /// upstream upsert key.
    pub id: String,
    /// Tenant uuid the evidence belongs to.
    pub tenant_id: String,
    /// Framework identifier — e.g. `soc2`, `iso27001`.
    pub framework: String,
    /// Control identifier inside the framework.
    pub control_id: String,
    /// Free-form reference to the originating finding (uuid).
    pub finding_ref: String,
    /// Free-form reference to the observation that produced the
    /// finding (scan id, log doc id, …).
    pub observation_ref: String,
    /// RFC 3339 timestamp the evidence was collected (UTC).
    pub collected_at: String,
}

/// The lifecycle state of a finding being shipped to a GRC platform.
///
/// We intentionally project a thin slice of the full finding so the
/// connector adapter never sees fields it does not need (e.g. CVSS,
/// CVE id, raw description).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingState {
    /// Finding uuid; used by the connector as the upstream upsert key.
    pub id: String,
    /// Tenant uuid the finding belongs to.
    pub tenant_id: String,
    /// Severity (`info`, `low`, `medium`, `high`, `critical`).
    pub severity: String,
    /// Lifecycle status (`open`, `triaged`, `accepted`, `closed`).
    pub status: String,
    /// Short title.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// RFC 3339 first-seen timestamp.
    pub first_seen: String,
    /// RFC 3339 last-seen timestamp.
    pub last_seen: String,
}

/// Outcome reported by a successful push.
///
/// Concrete connectors return the upstream identifier they minted /
/// upserted against, plus the canonical URL when the vendor returns one.
/// Both fields are optional so a connector that does not surface them
/// remains compliant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// Upstream identifier the GRC platform persisted under.
    pub upstream_id: Option<String>,
    /// Canonical URL of the upserted resource.
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

/// Errors surfaced by GRC connectors.
///
/// `Unimplemented` is the placeholder variant returned by stub
/// implementations (Drata today, future connectors before they ship).
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

    /// The connector is a stub / placeholder and has no implementation
    /// for the requested operation yet.
    #[error("connector not implemented")]
    Unimplemented,
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

/// GRC connector surface — implemented per vendor.
#[async_trait]
pub trait GrcConnector: Send + Sync {
    /// Identify which kind of GRC platform this connector talks to.
    fn kind(&self) -> GrcKind;

    /// Push (upsert) a compliance evidence record to the GRC platform.
    async fn push_evidence(
        &self,
        evidence: &ComplianceEvidence,
    ) -> Result<PushOutcome, ConnectorError>;

    /// Push (upsert) a finding lifecycle update to the GRC platform.
    async fn push_finding(&self, finding: &FindingState) -> Result<PushOutcome, ConnectorError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn grc_kind_wire_round_trip() {
        for k in [GrcKind::Vanta, GrcKind::Drata, GrcKind::ServiceNow] {
            assert_eq!(GrcKind::from_wire(k.as_wire()), Some(k));
        }
    }

    #[test]
    fn grc_kind_alt_aliases_parse() {
        assert_eq!(GrcKind::from_wire("ServiceNow"), Some(GrcKind::ServiceNow));
        assert_eq!(GrcKind::from_wire("service_now"), Some(GrcKind::ServiceNow));
        assert_eq!(GrcKind::from_wire("service-now"), Some(GrcKind::ServiceNow));
        assert_eq!(GrcKind::from_wire("VANTA"), Some(GrcKind::Vanta));
    }

    #[test]
    fn grc_kind_rejects_unknown() {
        assert_eq!(GrcKind::from_wire("openpages"), None);
        assert_eq!(GrcKind::from_wire(""), None);
    }

    #[test]
    fn vanta_credentials_debug_redacts() {
        let creds = VantaCredentials {
            api_key: SecretString::from("vanta-key-shh".to_owned()),
        };
        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("vanta-key-shh"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn servicenow_credentials_debug_redacts() {
        let creds = ServiceNowCredentials {
            instance_url: "https://acme.service-now.com".to_owned(),
            user: "ops".to_owned(),
            password: SecretString::from("password-shh".to_owned()),
        };
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("acme.service-now.com"));
        assert!(dbg.contains("ops"));
        assert!(!dbg.contains("password-shh"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn grc_kind_display_is_wire() {
        assert_eq!(GrcKind::Vanta.to_string(), "vanta");
        assert_eq!(GrcKind::ServiceNow.to_string(), "servicenow");
    }

    #[test]
    fn connector_error_constructors() {
        let e = ConnectorError::transport("boom");
        assert!(matches!(e, ConnectorError::Transport(_)));
        let e = ConnectorError::format("nope");
        assert!(matches!(e, ConnectorError::Format(_)));
    }
}
