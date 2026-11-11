//! Tolerant Kubernetes `AdmissionReview` (v1) wire schema + analyzer DTOs.
//!
//! Only the fields the rule engine actually inspects are modelled; everything
//! else is captured into an `extra` `serde_json::Map` so the analyzer never
//! rejects a real-world payload over an unmodelled field. All structs default
//! to empty when missing so partial fixtures (used widely in tests) remain
//! ergonomic.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Top-level `AdmissionReview` wrapper.
///
/// Mirrors `admission.k8s.io/v1` `AdmissionReview`. The analyzer reads
/// `request.object` and synthesises a `response` carrying the `SentinelX`
/// advisory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdmissionReview {
    /// `apiVersion`/`kind`. Optional on input; populated on the response.
    #[serde(flatten, default)]
    pub type_meta: TypeMeta,
    /// The admission request — what the API server is asking us to vet.
    #[serde(default)]
    pub request: Option<AdmissionRequest>,
    /// The analyzer's reply. Populated on output only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<AdmissionResponse>,
}

/// `apiVersion`/`kind` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeMeta {
    /// `apiVersion`, e.g. `"admission.k8s.io/v1"`.
    #[serde(
        default,
        rename = "apiVersion",
        skip_serializing_if = "String::is_empty"
    )]
    pub api_version: String,
    /// `kind`, e.g. `"AdmissionReview"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
}

/// `request` sub-object on the `AdmissionReview`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdmissionRequest {
    /// Per-review uid assigned by the API server.
    #[serde(default)]
    pub uid: String,
    /// `kind` of the object being admitted.
    #[serde(default)]
    pub kind: GroupVersionKind,
    /// `resource` of the object being admitted.
    #[serde(default)]
    pub resource: GroupVersionResource,
    /// Caller info — surfaced into the audit record.
    #[serde(default, rename = "userInfo")]
    pub user_info: K8sUserInfo,
    /// The operation, e.g. `CREATE`, `UPDATE`.
    #[serde(default)]
    pub operation: String,
    /// Target namespace.
    #[serde(default)]
    pub namespace: String,
    /// Target resource name (may be empty for generateName-only requests).
    #[serde(default)]
    pub name: String,
    /// The object the API server is asking us to admit.
    #[serde(default)]
    pub object: Option<Value>,
    /// The previous object on UPDATE — not currently inspected but preserved
    /// for future rules.
    #[serde(default, rename = "oldObject", skip_serializing_if = "Option::is_none")]
    pub old_object: Option<Value>,
}

/// `kind` triple — `group`/`version`/`kind`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupVersionKind {
    /// API group, e.g. `""` for core, `"apps"` for Deployment.
    #[serde(default)]
    pub group: String,
    /// API version, e.g. `"v1"`.
    #[serde(default)]
    pub version: String,
    /// Kind, e.g. `"Pod"`, `"Deployment"`.
    #[serde(default)]
    pub kind: String,
}

/// `resource` triple.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupVersionResource {
    /// API group.
    #[serde(default)]
    pub group: String,
    /// API version.
    #[serde(default)]
    pub version: String,
    /// Resource (plural), e.g. `"pods"`, `"deployments"`.
    #[serde(default)]
    pub resource: String,
}

/// `userInfo` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sUserInfo {
    /// Username of the caller (often a serviceaccount).
    #[serde(default)]
    pub username: String,
    /// Uid of the caller.
    #[serde(default)]
    pub uid: String,
    /// Groups.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// The `SentinelX` advisory returned to the cluster (or to a user calling
/// the HTTP endpoint directly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionResponse {
    /// Echoes [`AdmissionRequest::uid`].
    pub uid: String,
    /// `true` when **no** `Critical`/`High` finding fired; informational only —
    /// this is an analyzer, not a blocking webhook in the MVP.
    pub allowed: bool,
    /// Human-readable status block — included even on allow so callers can
    /// surface low-severity findings as warnings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<AdmissionStatus>,
    /// Warnings — surfaced verbatim by `kubectl` and the API server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// All findings produced by the analyzer. Stable order: input rule order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<K8sAdmissionFinding>,
}

/// Status block on the [`AdmissionResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionStatus {
    /// HTTP-style status code (200 / 422). Informational.
    pub code: u16,
    /// Human-readable summary.
    pub message: String,
}

/// A single finding produced by the analyzer.
///
/// Findings are deterministic — re-running the analyzer on the same input
/// always produces the same finding set (modulo rule-set changes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K8sAdmissionFinding {
    /// Stable rule id, e.g. `"k8s.pod.privileged"`.
    pub rule_id: String,
    /// Severity bucket.
    pub severity: FindingSeverity,
    /// Short human-readable title.
    pub title: String,
    /// Free-form detail — typically names the offending container / field.
    pub detail: String,
    /// JSON Pointer-ish path to the offending field, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// External references (CIS K8s, NSA hardening, MITRE ATT&CK).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

/// Severity bucket assigned to each rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    /// Informational signal; surfaced but not counted toward deny.
    Info,
    /// Hardening recommendation.
    Low,
    /// Notable risk; should be remediated before production.
    Medium,
    /// Significant risk; likely a policy violation.
    High,
    /// Likely-exploitable misconfiguration; rule recommends deny.
    Critical,
}

impl FindingSeverity {
    /// `true` for severities that the analyzer recommends denying on.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }

    /// Stable lower-case string form for logs and audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Per-tenant cluster registry entry.
///
/// The HTTP layer resolves which cluster a review came from via this map so
/// findings can be attributed to a specific cluster on the dashboard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterRegistry {
    /// Map of cluster id to display name. Empty until the tenant onboards a
    /// cluster.
    #[serde(default)]
    pub clusters: BTreeMap<String, String>,
}

impl ClusterRegistry {
    /// Insert (or replace) a cluster entry.
    pub fn upsert(&mut self, id: impl Into<String>, name: impl Into<String>) {
        self.clusters.insert(id.into(), name.into());
    }

    /// `true` when the cluster id is registered.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.clusters.contains_key(id)
    }

    /// Look up the display name for a registered cluster.
    #[must_use]
    pub fn display_name(&self, id: &str) -> Option<&str> {
        self.clusters.get(id).map(String::as_str)
    }

    /// Iterate `(id, name)` pairs in sorted-id order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.clusters.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// A persisted audit record of one analyzer invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionAuditRecord {
    /// Tenant id (uuid string).
    pub tenant_id: String,
    /// Optional cluster id (when the caller identified the cluster).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    /// Echoes [`AdmissionRequest::uid`].
    pub review_uid: String,
    /// `kind` of the object reviewed.
    pub kind: String,
    /// `namespace` of the object reviewed.
    pub namespace: String,
    /// `name` of the object reviewed.
    pub name: String,
    /// Total finding count.
    pub finding_count: usize,
    /// Highest severity in the finding set, lower-case (`"none"` if empty).
    pub max_severity: String,
    /// Whether the analyzer recommended deny.
    pub recommended_deny: bool,
    /// Unix epoch seconds; injected by the service so tests are deterministic.
    pub at_unix: i64,
}
