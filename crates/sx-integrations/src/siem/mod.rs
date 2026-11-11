//! SIEM forwarders.
//!
//! Two transports are supported today:
//!
//! * [`splunk_hec`] — POSTs JSON event envelopes to Splunk's HTTP Event
//!   Collector with `Authorization: Splunk {token}`.
//! * [`syslog_cef`] — emits CEF-formatted records over a UDP socket,
//!   suitable for any RFC-5424-ish receiver (`ArcSight`, `QRadar`,
//!   Sentinel, ...).
//!
//! Both expose a small, common shape: build an [`AuditEvent`], hand it to
//! the forwarder, get back a [`Result<(), crate::IntegrationError>`].

pub mod splunk_hec;
pub mod syslog_cef;

use serde::{Deserialize, Serialize};

/// A unified, integration-facing view of a `SentinelX` audit event.
///
/// This is intentionally a small, hand-rolled shape rather than a re-use
/// of `sx_audit::AuditEvent` — the integrations crate is standalone and
/// must not depend on the monolith's internal types. Conversions live
/// at the call site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    /// Short, machine-readable action identifier (e.g. `"login.success"`).
    pub action: String,
    /// Human-readable title.
    pub title: String,
    /// Severity level, mapped consistently across both transports.
    pub severity: Severity,
    /// Optional acting principal (user/service id) — surfaced as CEF `act`.
    pub actor: Option<String>,
    /// Optional source IP / hostname — surfaced as CEF `src`.
    pub source: Option<String>,
    /// Optional free-form metadata. For Splunk this is merged into the
    /// `event` object; for CEF it is ignored.
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// Severity scale shared across SIEM forwarders.
///
/// CEF maps these onto integer scores 0-10; Splunk receives them as the
/// string label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational.
    Info,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

impl Severity {
    /// Map this severity onto the CEF severity scale 0-10.
    ///
    /// CEF defines severity as a 0-10 integer where 0-3 is low, 4-6
    /// medium, 7-8 high, and 9-10 very high. We pick canonical
    /// representatives for the `SentinelX` five-level scale:
    ///
    /// | Severity   | CEF score |
    /// |------------|-----------|
    /// | `Info`     | 0         |
    /// | `Low`      | 3         |
    /// | `Medium`   | 5         |
    /// | `High`     | 7         |
    /// | `Critical` | 10        |
    #[must_use]
    pub const fn cef_score(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 3,
            Self::Medium => 5,
            Self::High => 7,
            Self::Critical => 10,
        }
    }

    /// String label used in Splunk event envelopes and Jira labels.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}
