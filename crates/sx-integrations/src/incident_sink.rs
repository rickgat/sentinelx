//! Incident-sink port and shared types (TOP5-#5).
//!
//! The framework piece of the ticketing + alerting MVP. Three reference
//! adapters land alongside it:
//!
//! * [`crate::jira_incident`] — Jira Cloud REST API v3 (`POST
//!   /rest/api/3/issue`).
//! * [`crate::pagerduty`] — PagerDuty Events API v2 (`POST
//!   /v2/enqueue`).
//! * [`crate::linear`] — Linear GraphQL (`POST
//!   https://api.linear.app/graphql`, `IssueCreate` mutation, TOP5-#5-FU2).
//!
//! Two additional vendors are tracked as follow-ups in
//! `docs/SPRINT_HARDENING_HANDOFF.md` (`TOP5-#5-FU1` ServiceNow,
//! `TOP5-#5-FU3` Opsgenie) — each new adapter plugs into the same
//! [`IncidentSinkPort`] trait declared here.
//!
//! ## Why the port lives in `sx-integrations` (not `sx-api`)
//!
//! Every other vendor adapter in this crate already publishes its own
//! port (`ChatNotifier`, `GrcConnector`, …). The composition root in
//! `services/sx-monolith` wires the concrete sinks into the request
//! handlers / background tasks that need to fan an event out — sx-api
//! just consumes a trait object via `Arc<dyn IncidentSinkPort>`.
//!
//! Keeping the trait here means `sx-integrations` stays self-contained
//! and the sx-api crate does not need to take a transitive dependency
//! on any HTTP / vendor-specific code.
//!
//! ## The event shape
//!
//! [`IncidentEvent`] travels with the canonical enrichment envelope:
//! CVSS v3.1, CWE ids, MITRE ATT&CK techniques, and compliance tags. The
//! envelope mirrors what `sx-core::entity::finding::Finding` already
//! carries — adapters stamp the structured data into vendor-specific
//! custom fields without re-parsing the rendered description.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use sx_core::value_object::compliance::ComplianceTags;
use sx_core::value_object::cvss_v31::CvssV31;
use sx_core::value_object::cwe::CweId;
use sx_core::value_object::mitre_attack::MitreAttackTechnique;
use sx_core::value_object::severity::Severity;

/// Reason an [`IncidentEvent`] is being emitted.
///
/// Three trigger points are wired in the MVP:
///
/// * [`Self::FindingEmitted`] — a `Critical` finding landed in the
///   monolith (FOUND-001's repository `insert` path). The originating
///   finding's stable id and a `FindingDigest` ride alongside.
/// * [`Self::PlaybookTriggered`] — a SOC playbook fired. The originating
///   playbook identifier travels in [`IncidentEvent::title`] /
///   [`IncidentEvent::description`].
/// * [`Self::AuditChainBreak`] — the `sx-audit` chain verifier detected
///   a hash-chain discontinuity. The description carries the offending
///   sequence ids.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentKind {
    /// A `Critical` finding was just persisted.
    FindingEmitted,
    /// A SOC playbook fired (manual or auto).
    PlaybookTriggered,
    /// Audit hash-chain break detected by the verifier.
    AuditChainBreak,
}

/// Vendor-agnostic projection of a `FindingView` for use inside
/// [`IncidentEvent`].
///
/// We deliberately do **not** depend on `sx_api::view::finding_view`
/// from `sx-integrations` — the API view DTO is API-layer state, the
/// digest below is the minimum the vendor adapters need to mint a
/// useful ticket / incident.
///
/// Build this from a `FindingView` at the trigger site (the monolith
/// adapters layer); see
/// `services/sx-monolith/src/adapters/incident_sinks.rs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingDigest {
    /// Finding uuid (stable across re-emits).
    pub id: String,
    /// Asset uuid the finding is bound to.
    pub asset_id: String,
    /// Status snake-case identifier (`open`, `triaged`, ...).
    pub status: String,
    /// Optional CVE identifier (e.g. `CVE-2024-1234`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
}

/// One outbound incident event fanned to every configured sink.
///
/// `description` is the rendered, human-readable body. The structured
/// enrichment fields (`cvss`, `cwe`, `mitre_attack`, `compliance`) are
/// passed alongside so each adapter can stamp them into vendor-specific
/// custom fields (Jira custom fields, PagerDuty `custom_details`, …)
/// without re-parsing the description.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentEvent {
    /// Trigger reason — see [`IncidentKind`].
    pub kind: IncidentKind,
    /// SentinelX severity (drives vendor severity mapping).
    pub severity: Severity,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// Short title (≤ 255 chars).
    pub title: String,
    /// Long-form description (rendered Markdown / plain text).
    pub description: String,
    /// Originating finding digest, if any.
    ///
    /// Populated for [`IncidentKind::FindingEmitted`]; `None` for
    /// playbook + chain-break events. Adapters that file a vendor record
    /// per finding embed the digest as a structured custom-field /
    /// custom-details object on the vendor side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<FindingDigest>,
    /// CVSS v3.1 envelope when the originating finding has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<CvssV31>,
    /// CWE ids linked to the originating finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<CweId>,
    /// MITRE ATT&CK techniques tagged on the originating finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_attack: Vec<MitreAttackTechnique>,
    /// Compliance frameworks the originating finding maps to.
    #[serde(default)]
    pub compliance: ComplianceTags,
    /// Optional dashboard deep-link the vendor record should point at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
}

/// Receipt returned by an [`IncidentSinkPort::emit`] call on success.
///
/// `external_id` is the vendor-side primary identifier (Jira issue key
/// `SEC-1234`, PagerDuty incident `PXXX`). `external_url` is the
/// browser-navigable URL (Jira issue page, PagerDuty incident page) so
/// the dashboard can link straight back into the vendor system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmissionReceipt {
    /// Vendor-side primary identifier.
    pub external_id: String,
    /// Vendor-side browser URL.
    pub external_url: String,
}

/// Failure taxonomy returned by every [`IncidentSinkPort::emit`] call.
///
/// Each variant maps to one operator-actionable failure mode. The
/// monolith's fan-out logs each `IncidentSinkError` at `warn` with
/// structured fields and never lets a single sink failure block the
/// others.
#[derive(Debug, Error)]
pub enum IncidentSinkError {
    /// Vendor returned `429 Too Many Requests`. The optional duration is
    /// the parsed `Retry-After` header (delta-seconds) when present.
    #[error("rate limited (retry after {retry_after:?})")]
    RateLimited {
        /// Parsed `Retry-After`, when supplied by the vendor.
        retry_after: Option<Duration>,
    },
    /// Vendor returned `401`.
    #[error("unauthenticated: vendor rejected the credential")]
    Unauthenticated,
    /// Vendor returned `403`.
    #[error("unauthorised: vendor refused the action")]
    Unauthorised,
    /// Vendor returned a `>= 500` (or otherwise unrecoverable) status.
    /// Status + body for diagnostics.
    #[error("bad gateway: vendor returned {status}: {body}")]
    BadGateway {
        /// HTTP status code as a `u16`.
        status: u16,
        /// Vendor response body (truncated to a reasonable cap).
        body: String,
    },
    /// Underlying transport (TLS, DNS, timeout, connection refused).
    #[error("transient transport error: {0}")]
    Transient(String),
    /// Local payload or vendor response could not be serialised /
    /// parsed into the expected shape.
    #[error("schema: {0}")]
    Schema(String),
}

impl IncidentSinkError {
    /// Convenience: build a transient error from any `Display`.
    pub(crate) fn transient<E: std::fmt::Display>(err: E) -> Self {
        Self::Transient(err.to_string())
    }

    /// Convenience: build a schema error from any `Display`.
    pub(crate) fn schema<E: std::fmt::Display>(err: E) -> Self {
        Self::Schema(err.to_string())
    }
}

impl From<reqwest::Error> for IncidentSinkError {
    fn from(err: reqwest::Error) -> Self {
        Self::transient(err)
    }
}

impl From<serde_json::Error> for IncidentSinkError {
    fn from(err: serde_json::Error) -> Self {
        Self::schema(err)
    }
}

/// Sink for outbound incident events.
///
/// Each adapter ([`crate::jira_incident::JiraIncidentSink`],
/// [`crate::pagerduty::PagerDutyIncidentSink`], …) returns a vendor-side
/// [`EmissionReceipt`] on success and one of the variants in
/// [`IncidentSinkError`] on failure. The monolith's fan-out invokes
/// every enabled sink in parallel; a single sink's failure never blocks
/// the others.
///
/// Implementations MUST be `Send + Sync` because they are stored behind
/// `Arc<dyn IncidentSinkPort>` and shared across the request handlers /
/// background tasks that emit events.
#[async_trait]
pub trait IncidentSinkPort: Send + Sync {
    /// Emit a single incident event to the vendor. Returns the
    /// vendor-side identifier + URL on success.
    async fn emit(&self, event: &IncidentEvent) -> Result<EmissionReceipt, IncidentSinkError>;

    /// Stable adapter name for tracing / metrics labels (e.g. `"jira"`,
    /// `"pagerduty"`).
    fn name(&self) -> &'static str;
}

/// Parse the standard HTTP `Retry-After` header value (delta-seconds).
///
/// Returns `None` for absent, unparsable, or zero values — the caller
/// then falls back to a default vendor-specific backoff. RFC 9110 also
/// allows an HTTP-date form; we treat that as `None` rather than pull
/// `httpdate` into the dependency tree for the MVP. Both Jira and
/// PagerDuty consistently emit delta-seconds in practice.
#[must_use]
pub fn parse_retry_after_secs(raw: Option<&str>) -> Option<Duration> {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_parses_integer_seconds() {
        assert_eq!(
            parse_retry_after_secs(Some("17")),
            Some(Duration::from_secs(17))
        );
        assert_eq!(
            parse_retry_after_secs(Some("  3  ")),
            Some(Duration::from_secs(3))
        );
    }

    #[test]
    fn retry_after_rejects_zero_and_garbage() {
        assert_eq!(parse_retry_after_secs(Some("0")), None);
        assert_eq!(parse_retry_after_secs(Some("never")), None);
        assert_eq!(parse_retry_after_secs(Some("")), None);
        assert_eq!(parse_retry_after_secs(None), None);
    }

    #[test]
    fn incident_kind_round_trips_snake_case() {
        let json = serde_json::to_string(&IncidentKind::FindingEmitted).unwrap();
        assert_eq!(json, "\"finding_emitted\"");
        let back: IncidentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, IncidentKind::FindingEmitted);
    }

    #[test]
    fn emission_receipt_serializes_stable_shape() {
        let r = EmissionReceipt {
            external_id: "SEC-7".to_owned(),
            external_url: "https://acme.atlassian.net/browse/SEC-7".to_owned(),
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["external_id"], "SEC-7");
        assert_eq!(
            json["external_url"],
            "https://acme.atlassian.net/browse/SEC-7"
        );
    }
}
