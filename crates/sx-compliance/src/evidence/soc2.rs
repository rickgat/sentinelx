//! SOC 2 Trust Services Criteria evidence collectors.
//!
//! This module exposes five small, deterministic
//! [`EvidenceCollector`]s mapped to the AICPA Trust Services Criteria
//! (TSC). Each collector inspects the repository checkout (config
//! samples, runbooks, ADRs, etc.) and produces a JSON artifact with a
//! handful of data points sufficient to demonstrate the existence and
//! discoverability of the control without leaking secrets.
//!
//! ## Mapped controls
//!
//! | id     | TSC family                | what this collector samples                                  |
//! | ------ | ------------------------- | ------------------------------------------------------------ |
//! | CC1.1  | Control Environment       | presence + sha256 of the config sample; runbook count.       |
//! | CC6.1  | Logical & Physical Access | presence of security docs, JWT/IAM ADR digest.               |
//! | CC7.2  | System Operations         | operations runbook + ops doc presence, incident-response.    |
//! | CC8.1  | Change Management         | ADR directory file count, gitops doc presence.               |
//! | CC9.1  | Risk Mitigation           | DR + breach-notification runbook presence + supply-chain.    |
//!
//! Each collector degrades gracefully: a missing file is recorded as
//! `"unavailable": true` rather than producing an error. Errors are
//! reserved for hard I/O / serialisation failures.

// The `id` methods return string literals that, on paper, could be
// `&'static str`. The trait signature in `evidence/mod.rs` is
// `fn id(&self) -> &str`, so binding to `'static` would mean diverging
// from the trait. Silence the suggestion rather than churn the trait.
#![allow(clippy::unnecessary_literal_bound)]

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use super::{
    count_files_with_extension, path_exists, sha256_of_file, workspace_root, EvidenceArtifact,
    EvidenceCollector, EvidenceError,
};

/// Framework code embedded into every SOC 2 artifact.
pub const FRAMEWORK: &str = "soc2";

/// Read the `SENTINELX__ENVIRONMENT` env var without panicking, honouring
/// the workspace clippy `disallowed_methods` rule via an allow.
#[allow(clippy::disallowed_methods)]
fn env_environment() -> Option<String> {
    std::env::var("SENTINELX__ENVIRONMENT").ok()
}

/// Build the `evidence` payload describing a single file: `exists`,
/// optional `sha256`, and `path` (relative to the workspace root).
fn file_evidence(root: &Path, rel: &str) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("path".to_owned(), Value::String(rel.to_owned()));
    let full = root.join(rel);
    if !path_exists(&full) {
        obj.insert("exists".to_owned(), Value::Bool(false));
        obj.insert("unavailable".to_owned(), Value::Bool(true));
        return obj;
    }
    obj.insert("exists".to_owned(), Value::Bool(true));
    match sha256_of_file(&full) {
        Ok(Some(d)) => {
            obj.insert("sha256".to_owned(), Value::String(d));
        }
        Ok(None) | Err(_) => {
            obj.insert("unavailable".to_owned(), Value::Bool(true));
        }
    }
    obj
}

/// Build the `evidence` payload describing a directory: `exists` and an
/// extension-keyed file count map (e.g. `{"md": 4}`).
fn dir_evidence(root: &Path, rel: &str, exts: &[&str]) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("path".to_owned(), Value::String(rel.to_owned()));
    let full = root.join(rel);
    if !path_exists(&full) {
        obj.insert("exists".to_owned(), Value::Bool(false));
        obj.insert("unavailable".to_owned(), Value::Bool(true));
        return obj;
    }
    obj.insert("exists".to_owned(), Value::Bool(true));
    let mut counts = Map::new();
    for ext in exts {
        let n = count_files_with_extension(&full, ext).unwrap_or(0);
        counts.insert((*ext).to_owned(), Value::from(n));
    }
    obj.insert("file_counts".to_owned(), Value::Object(counts));
    obj
}

/// Construct the artifact, stamping the supplied timestamp.
fn artifact(
    control_id: &str,
    now: OffsetDateTime,
    body: Value,
) -> Result<EvidenceArtifact, EvidenceError> {
    EvidenceArtifact::new(control_id, FRAMEWORK, now, body)
}

// ---------------------------------------------------------------------
// CC1.1 — Control Environment
// ---------------------------------------------------------------------

/// CC1.1 — *Control Environment*.
///
/// Demonstrates that the codebase ships a documented baseline
/// configuration (the `config/sentinelx.example.yaml`) and a non-empty
/// runbook library. The configured environment label is recorded so
/// auditors can correlate the artifact with a deployment.
#[derive(Debug, Default, Clone, Copy)]
pub struct ControlEnvironmentCollector;

impl ControlEnvironmentCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for ControlEnvironmentCollector {
    fn id(&self) -> &str {
        "CC1.1"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "Control environment baseline: config sample + documented runbooks.",
            "config_sample": file_evidence(&root, "config/sentinelx.example.yaml"),
            "runbooks": dir_evidence(&root, "docs/runbooks", &["md"]),
            "operations_docs": dir_evidence(&root, "docs/operations", &["md"]),
            "environment_label": env_environment(),
        });
        artifact("CC1.1", OffsetDateTime::now_utc(), body)
    }
}

// ---------------------------------------------------------------------
// CC6.1 — Logical & Physical Access Controls
// ---------------------------------------------------------------------

/// CC6.1 — *Logical and Physical Access Controls*.
///
/// Evidences the presence of authentication / authorisation ADRs and
/// the security documentation that describes the access model.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogicalAccessCollector;

impl LogicalAccessCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for LogicalAccessCollector {
    fn id(&self) -> &str {
        "CC6.1"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "Logical access: JWT / OIDC ADR + supply-chain + threat-model docs.",
            "jwt_adr": file_evidence(&root, "docs/adr/0003-jwt-hs256-with-pluggable-oidc.md"),
            "supply_chain_doc": file_evidence(&root, "docs/security/supply-chain.md"),
            "threat_model_doc": file_evidence(&root, "docs/security/threat-model-stride.md"),
            "security_docs": dir_evidence(&root, "docs/security", &["md"]),
            "environment_label": env_environment(),
        });
        artifact("CC6.1", OffsetDateTime::now_utc(), body)
    }
}

// ---------------------------------------------------------------------
// CC7.2 — System Operations
// ---------------------------------------------------------------------

/// CC7.2 — *System Operations*: detection and monitoring of anomalies.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemOperationsCollector;

impl SystemOperationsCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for SystemOperationsCollector {
    fn id(&self) -> &str {
        "CC7.2"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "System operations: runbook + incident-response + runtime-security docs.",
            "incident_response": file_evidence(&root, "docs/runbooks/incident-response.md"),
            "runtime_security": file_evidence(&root, "docs/operations/runtime-security.md"),
            "ops_runbook": file_evidence(&root, "docs/operations/runbook.md"),
            "slo_doc": file_evidence(&root, "docs/slos.md"),
            "environment_label": env_environment(),
        });
        artifact("CC7.2", OffsetDateTime::now_utc(), body)
    }
}

// ---------------------------------------------------------------------
// CC8.1 — Change Management
// ---------------------------------------------------------------------

/// CC8.1 — *Change Management*: changes are authorised, documented,
/// tested, and approved.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChangeManagementCollector;

impl ChangeManagementCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for ChangeManagementCollector {
    fn id(&self) -> &str {
        "CC8.1"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "Change management: ADR catalog + gitops + architecture docs.",
            "adrs": dir_evidence(&root, "docs/adr", &["md"]),
            "gitops_doc": file_evidence(&root, "docs/operations/gitops.md"),
            "architecture_doc": file_evidence(&root, "docs/ARCHITECTURE.md"),
            "environment_label": env_environment(),
        });
        artifact("CC8.1", OffsetDateTime::now_utc(), body)
    }
}

// ---------------------------------------------------------------------
// CC9.1 — Risk Mitigation
// ---------------------------------------------------------------------

/// CC9.1 — *Risk Mitigation*: business continuity and risk transfer.
#[derive(Debug, Default, Clone, Copy)]
pub struct RiskMitigationCollector;

impl RiskMitigationCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for RiskMitigationCollector {
    fn id(&self) -> &str {
        "CC9.1"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "Risk mitigation: DR + breach-notification + finops runbooks.",
            "disaster_recovery": file_evidence(&root, "docs/runbooks/disaster-recovery.md"),
            "breach_notification": file_evidence(&root, "docs/runbooks/breach-notification.md"),
            "finops": file_evidence(&root, "docs/runbooks/finops.md"),
            "supply_chain_doc": file_evidence(&root, "docs/security/supply-chain.md"),
            "environment_label": env_environment(),
        });
        artifact("CC9.1", OffsetDateTime::now_utc(), body)
    }
}

/// Return the canonical, framework-ordered set of SOC 2 collectors.
#[must_use]
pub fn all_collectors() -> Vec<Box<dyn EvidenceCollector>> {
    vec![
        Box::new(ControlEnvironmentCollector::new()),
        Box::new(LogicalAccessCollector::new()),
        Box::new(SystemOperationsCollector::new()),
        Box::new(ChangeManagementCollector::new()),
        Box::new(RiskMitigationCollector::new()),
    ]
}

/// Return the SOC 2 control identifiers in catalog order.
#[must_use]
pub fn control_ids() -> Vec<&'static str> {
    vec!["CC1.1", "CC6.1", "CC7.2", "CC8.1", "CC9.1"]
}

/// Resolve the workspace root used by the collectors. Exposed so the
/// CLI can echo the path that was sampled into its operator output.
#[must_use]
pub fn root_for_evidence() -> PathBuf {
    workspace_root()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn control_ids_are_five_and_ordered() {
        let ids = control_ids();
        assert_eq!(ids.len(), 5);
        assert_eq!(ids.first().copied(), Some("CC1.1"));
        assert_eq!(ids.last().copied(), Some("CC9.1"));
    }

    #[test]
    fn all_collectors_return_five() {
        assert_eq!(all_collectors().len(), 5);
    }

    #[test]
    fn cc1_1_collector_produces_soc2_artifact() {
        let a = ControlEnvironmentCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "CC1.1");
        assert_eq!(a.framework, "soc2");
        assert!(a.evidence.is_object());
        assert!(!a.collected_at.is_empty());
    }

    #[test]
    fn cc6_1_collector_produces_soc2_artifact() {
        let a = LogicalAccessCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "CC6.1");
        assert_eq!(a.framework, "soc2");
        assert!(a.evidence.is_object());
    }

    #[test]
    fn cc7_2_collector_produces_soc2_artifact() {
        let a = SystemOperationsCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "CC7.2");
        assert_eq!(a.framework, "soc2");
    }

    #[test]
    fn cc8_1_collector_produces_soc2_artifact() {
        let a = ChangeManagementCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "CC8.1");
        assert_eq!(a.framework, "soc2");
    }

    #[test]
    fn cc9_1_collector_produces_soc2_artifact() {
        let a = RiskMitigationCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "CC9.1");
        assert_eq!(a.framework, "soc2");
    }

    #[test]
    fn missing_file_is_marked_unavailable() {
        let root = std::env::temp_dir().join("definitely-not-a-real-sx-root-xyz");
        let m = file_evidence(&root, "config/sentinelx.example.yaml");
        assert_eq!(m.get("exists"), Some(&Value::Bool(false)));
        assert_eq!(m.get("unavailable"), Some(&Value::Bool(true)));
    }

    #[test]
    fn missing_dir_is_marked_unavailable() {
        let root = std::env::temp_dir().join("definitely-not-a-real-sx-root-xyz");
        let m = dir_evidence(&root, "docs/runbooks", &["md"]);
        assert_eq!(m.get("exists"), Some(&Value::Bool(false)));
    }
}
