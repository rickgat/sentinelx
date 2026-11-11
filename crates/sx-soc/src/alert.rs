//! Alert and severity types.
//!
//! An [`Alert`] is the *output* of the [`crate::engine::RuleEngine`]: it
//! represents one rule firing against one event and is forwarded to every
//! configured [`crate::sink::AlertSink`].

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Severity of a fired alert.
///
/// The ordering is `Critical > High > Medium > Low > Info`, matching the
/// `SentinelX` risk taxonomy. The derived [`Ord`] follows the *declaration*
/// order, so we deliberately list the most severe variant first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Service-impacting, customer-visible, or active compromise.
    Critical,
    /// Strong indicator of compromise / policy violation.
    High,
    /// Notable but not immediately actionable.
    Medium,
    /// Hygiene-level finding.
    Low,
    /// Purely informational; included for audit completeness.
    Info,
}

impl Severity {
    /// Returns the canonical lowercase label used in logs and JSON sinks.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

/// A reference to a piece of evidence backing the alert.
///
/// `EvidenceRef` is a pointer (URI / id) plus a short label; the actual
/// blob lives in the audit / object store and is fetched lazily by the
/// UI or by downstream analysts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Short human-readable label, e.g. `"audit_entry"` or `"raw_event"`.
    pub label: String,
    /// Opaque locator — typically a UUID or `audit://...` URI.
    pub locator: String,
}

impl EvidenceRef {
    /// Construct an evidence reference from owned strings.
    #[must_use]
    pub fn new(label: impl Into<String>, locator: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            locator: locator.into(),
        }
    }
}

/// A fired alert.
///
/// Alerts are produced by [`crate::engine::RuleEngine::evaluate`] and consumed
/// by the [`crate::correlator::Correlator`], which may throttle duplicates
/// before forwarding to sinks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    /// Stable id for this alert instance (UUID v4 string).
    pub id: String,
    /// Severity bucket; see [`Severity`].
    pub severity: Severity,
    /// Coarse alert kind (e.g. `"auth.bruteforce"`, `"audit.tamper"`).
    /// Drives correlation grouping together with `rule_id` and `tenant_id`.
    pub kind: String,
    /// Short single-line title, suitable for a notification row.
    pub title: String,
    /// Multi-line human description; may include rule-rendered facts.
    pub description: String,
    /// Wall-clock time the alert was constructed.
    pub fired_at: OffsetDateTime,
    /// Pointers to backing evidence (audit entries, raw events, etc).
    pub evidence: Vec<EvidenceRef>,
    /// Tenant scope for multi-tenant deployments. `None` means "global".
    pub tenant_id: Option<String>,
}

impl Alert {
    /// Construct a new alert with a freshly minted UUID v4 id and `fired_at`
    /// set to [`OffsetDateTime::now_utc`].
    #[must_use]
    pub fn new(
        severity: Severity,
        kind: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        tenant_id: Option<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            severity,
            kind: kind.into(),
            title: title.into(),
            description: description.into(),
            fired_at: OffsetDateTime::now_utc(),
            evidence: Vec::new(),
            tenant_id,
        }
    }

    /// Append an evidence reference; returns `self` for chaining.
    #[must_use]
    pub fn with_evidence(mut self, evidence: EvidenceRef) -> Self {
        self.evidence.push(evidence);
        self
    }
}
