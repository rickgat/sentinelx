//! ISO/IEC 27001:2022 Annex A evidence collectors.
//!
//! Mirrors the SOC 2 collector layout: five small, deterministic
//! [`EvidenceCollector`]s that inspect the checkout and produce JSON
//! artifacts demonstrating the existence of the documented control.
//!
//! ## Mapped controls
//!
//! | id    | Annex A clause                  | what this collector samples                                 |
//! | ----- | ------------------------------- | ----------------------------------------------------------- |
//! | A.5.1 | Information security policies   | architecture + ADR digest, environment label.               |
//! | A.8.2 | Privileged access rights        | JWT/OIDC ADR + supply-chain + security docs.                |
//! | A.9.1 | Access control                  | runbook count + IAM-related ADR + threat model.             |
//! | A.12.6| Technical vulnerability mgmt    | runtime-security + supply-chain + red-team / bug-bounty.    |
//! | A.18.1| Compliance with legal reqs      | GDPR/PDP, PCI-DSS mapping, compliance evidence doc.         |
//!
//! Missing filesystem inputs degrade gracefully via the shared
//! `file_evidence` / `dir_evidence` helpers — they record
//! `"unavailable": true` instead of returning an error.

// See `evidence/soc2.rs` for rationale — the trait return type forces
// these implementations to use `&str` rather than `&'static str`.
#![allow(clippy::unnecessary_literal_bound)]

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use super::{
    count_files_with_extension, path_exists, sha256_of_file, workspace_root, EvidenceArtifact,
    EvidenceCollector, EvidenceError,
};

/// Framework code embedded into every ISO 27001 artifact.
pub const FRAMEWORK: &str = "iso27001";

#[allow(clippy::disallowed_methods)]
fn env_environment() -> Option<String> {
    std::env::var("SENTINELX__ENVIRONMENT").ok()
}

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

fn artifact(
    control_id: &str,
    now: OffsetDateTime,
    body: Value,
) -> Result<EvidenceArtifact, EvidenceError> {
    EvidenceArtifact::new(control_id, FRAMEWORK, now, body)
}

// ---------------------------------------------------------------------
// A.5.1 — Policies for information security
// ---------------------------------------------------------------------

/// A.5.1 — *Policies for information security*.
///
/// Records the presence of the top-level architecture document, the ADR
/// catalog, and the environment label so an auditor can confirm that
/// the deployment is mapped to a documented policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct PoliciesCollector;

impl PoliciesCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for PoliciesCollector {
    fn id(&self) -> &str {
        "A.5.1"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "Information-security policies: architecture doc + ADR catalog.",
            "architecture": file_evidence(&root, "docs/ARCHITECTURE.md"),
            "adrs": dir_evidence(&root, "docs/adr", &["md"]),
            "readme": file_evidence(&root, "README.md"),
            "environment_label": env_environment(),
        });
        artifact("A.5.1", OffsetDateTime::now_utc(), body)
    }
}

// ---------------------------------------------------------------------
// A.8.2 — Privileged access rights
// ---------------------------------------------------------------------

/// A.8.2 — *Privileged access rights*.
#[derive(Debug, Default, Clone, Copy)]
pub struct PrivilegedAccessCollector;

impl PrivilegedAccessCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for PrivilegedAccessCollector {
    fn id(&self) -> &str {
        "A.8.2"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "Privileged access controls: JWT/OIDC ADR + security docs.",
            "jwt_adr": file_evidence(&root, "docs/adr/0003-jwt-hs256-with-pluggable-oidc.md"),
            "audit_hmac_adr": file_evidence(&root, "docs/adr/0005-audit-log-hmac-chain-anchoring.md"),
            "supply_chain_doc": file_evidence(&root, "docs/security/supply-chain.md"),
            "environment_label": env_environment(),
        });
        artifact("A.8.2", OffsetDateTime::now_utc(), body)
    }
}

// ---------------------------------------------------------------------
// A.9.1 — Access control (business requirements)
// ---------------------------------------------------------------------

/// A.9.1 — *Business requirements of access control*.
#[derive(Debug, Default, Clone, Copy)]
pub struct AccessControlCollector;

impl AccessControlCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for AccessControlCollector {
    fn id(&self) -> &str {
        "A.9.1"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "Access control policy: runbook count + threat model + onboarding doc.",
            "runbooks": dir_evidence(&root, "docs/runbooks", &["md"]),
            "threat_model": file_evidence(&root, "docs/security/threat-model-stride.md"),
            "onboarding": file_evidence(&root, "docs/onboarding.md"),
            "config_sample": file_evidence(&root, "config/sentinelx.example.yaml"),
            "environment_label": env_environment(),
        });
        artifact("A.9.1", OffsetDateTime::now_utc(), body)
    }
}

// ---------------------------------------------------------------------
// A.12.6 — Technical vulnerability management
// ---------------------------------------------------------------------

/// A.12.6 — *Management of technical vulnerabilities*.
#[derive(Debug, Default, Clone, Copy)]
pub struct VulnerabilityMgmtCollector;

impl VulnerabilityMgmtCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for VulnerabilityMgmtCollector {
    fn id(&self) -> &str {
        "A.12.6"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "Technical vulnerability mgmt: runtime-security + bug-bounty + red-team docs.",
            "runtime_security": file_evidence(&root, "docs/operations/runtime-security.md"),
            "bug_bounty": file_evidence(&root, "docs/security/bug-bounty.md"),
            "internal_red_team": file_evidence(&root, "docs/security/internal-red-team.md"),
            "supply_chain_doc": file_evidence(&root, "docs/security/supply-chain.md"),
            "environment_label": env_environment(),
        });
        artifact("A.12.6", OffsetDateTime::now_utc(), body)
    }
}

// ---------------------------------------------------------------------
// A.18.1 — Compliance with legal & contractual requirements
// ---------------------------------------------------------------------

/// A.18.1 — *Compliance with legal and contractual requirements*.
#[derive(Debug, Default, Clone, Copy)]
pub struct LegalComplianceCollector;

impl LegalComplianceCollector {
    /// Construct a new collector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EvidenceCollector for LegalComplianceCollector {
    fn id(&self) -> &str {
        "A.18.1"
    }
    fn frame(&self) -> &str {
        FRAMEWORK
    }
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError> {
        let root = workspace_root();
        let body = json!({
            "summary": "Legal & contractual compliance: GDPR/PDP DPIA + PCI mapping + RoE.",
            "gdpr_pdp_dpia": file_evidence(&root, "docs/compliance/gdpr-pdp-dpia.md"),
            "pci_dss_mapping": file_evidence(&root, "docs/compliance/pci-dss-v4-mapping.md"),
            "engagement_roe": file_evidence(&root, "docs/compliance/engagement-roe-template.md"),
            "compliance_evidence_doc": file_evidence(&root, "docs/operations/compliance-evidence.md"),
            "compliance_docs": dir_evidence(&root, "docs/compliance", &["md"]),
            "environment_label": env_environment(),
        });
        artifact("A.18.1", OffsetDateTime::now_utc(), body)
    }
}

/// Return the canonical, framework-ordered set of ISO collectors.
#[must_use]
pub fn all_collectors() -> Vec<Box<dyn EvidenceCollector>> {
    vec![
        Box::new(PoliciesCollector::new()),
        Box::new(PrivilegedAccessCollector::new()),
        Box::new(AccessControlCollector::new()),
        Box::new(VulnerabilityMgmtCollector::new()),
        Box::new(LegalComplianceCollector::new()),
    ]
}

/// Return the ISO 27001 control identifiers in catalog order.
#[must_use]
pub fn control_ids() -> Vec<&'static str> {
    vec!["A.5.1", "A.8.2", "A.9.1", "A.12.6", "A.18.1"]
}

/// Resolve the workspace root used by the collectors.
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
        assert_eq!(ids.first().copied(), Some("A.5.1"));
        assert_eq!(ids.last().copied(), Some("A.18.1"));
    }

    #[test]
    fn all_collectors_return_five() {
        assert_eq!(all_collectors().len(), 5);
    }

    #[test]
    fn a_5_1_collector_produces_iso_artifact() {
        let a = PoliciesCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "A.5.1");
        assert_eq!(a.framework, "iso27001");
        assert!(a.evidence.is_object());
    }

    #[test]
    fn a_8_2_collector_produces_iso_artifact() {
        let a = PrivilegedAccessCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "A.8.2");
        assert_eq!(a.framework, "iso27001");
    }

    #[test]
    fn a_9_1_collector_produces_iso_artifact() {
        let a = AccessControlCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "A.9.1");
        assert_eq!(a.framework, "iso27001");
    }

    #[test]
    fn a_12_6_collector_produces_iso_artifact() {
        let a = VulnerabilityMgmtCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "A.12.6");
        assert_eq!(a.framework, "iso27001");
    }

    #[test]
    fn a_18_1_collector_produces_iso_artifact() {
        let a = LegalComplianceCollector::new().collect().unwrap();
        assert_eq!(a.control_id, "A.18.1");
        assert_eq!(a.framework, "iso27001");
    }

    #[test]
    fn missing_paths_are_marked_unavailable() {
        let root = std::env::temp_dir().join("definitely-not-a-real-sx-root-xyz-iso");
        let f = file_evidence(&root, "docs/ARCHITECTURE.md");
        let d = dir_evidence(&root, "docs/adr", &["md"]);
        assert_eq!(f.get("unavailable"), Some(&Value::Bool(true)));
        assert_eq!(d.get("unavailable"), Some(&Value::Bool(true)));
    }
}
