//! Finding entity — a security issue detected on an asset.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::entity::finding_status::FindingStatus;
use crate::error::DomainError;
use crate::value_object::compliance::ComplianceTags;
use crate::value_object::cvss_v31::CvssV31;
use crate::value_object::cwe::CweId;
use crate::value_object::ids::{AssetId, FindingId, TenantId};
use crate::value_object::mitre_attack::MitreAttackTechnique;
use crate::value_object::severity::Severity;

/// A pointer to evidence backing a finding (e.g. screenshot, raw scanner output).
///
/// The actual payload lives in object storage; this struct only carries
/// the URI and minimal metadata.
///
/// # Source-aware locations (TOP5-#3 Phase 3)
///
/// Emitters that read line-oriented source (DLP scanning a config file,
/// CI/config linters, YAML/TOML/JSON audits) can populate the optional
/// `line` / `column` fields. Both are 1-indexed per the OASIS SARIF
/// 2.1.0 §3.30.4 convention (`region.startLine` / `region.startColumn`).
/// Non-source scanners (network probes, CSPM, RBA) leave them `None`
/// and the SARIF emitter falls back to a bare `artifactLocation.uri`.
///
/// Both fields default to `None` and are `skip_serializing_if` gated so
/// existing wire payloads stay byte-identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Storage URI (e.g. `s3://bucket/key` or `local://...`).
    pub uri: String,
    /// MIME content-type, if known.
    pub content_type: Option<String>,
    /// SHA-256 of the bytes, hex-encoded, if known.
    pub sha256: Option<String>,
    /// 1-indexed source line, for line-oriented emitters (TOP5-#3 P3).
    /// See the type-level "Source-aware locations" section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// 1-indexed source column, for line-oriented emitters (TOP5-#3 P3).
    /// See the type-level "Source-aware locations" section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

impl EvidenceRef {
    /// Build an evidence ref, validating the URI is non-empty.
    pub fn new(
        uri: impl Into<String>,
        content_type: Option<String>,
        sha256: Option<String>,
    ) -> Result<Self, DomainError> {
        let uri = uri.into();
        if uri.is_empty() {
            return Err(DomainError::invalid("evidence uri cannot be empty"));
        }
        if let Some(h) = &sha256 {
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(DomainError::invalid("sha256 must be 64 hex chars"));
            }
        }
        Ok(Self {
            uri,
            content_type,
            sha256,
            line: None,
            column: None,
        })
    }

    /// Builder-style: attach a 1-indexed source `line` / `column` pair
    /// (TOP5-#3 Phase 3). Zero is rejected — SARIF 2.1.0 §3.30.4 pins
    /// both fields to the 1-indexed convention.
    pub fn with_region(mut self, line: u32, column: u32) -> Result<Self, DomainError> {
        if line == 0 {
            return Err(DomainError::invalid("evidence line must be >= 1"));
        }
        if column == 0 {
            return Err(DomainError::invalid("evidence column must be >= 1"));
        }
        self.line = Some(line);
        self.column = Some(column);
        Ok(self)
    }
}

/// A finding — one security issue observed on one asset.
///
/// # Enrichment fields (Phase 1, TOP5-#3)
///
/// The following optional fields enrich a finding with the metadata
/// enterprise procurement, SOC pipelines, and compliance auditors expect:
///
/// - [`Finding::cvss`] — CVSS v3.1 base score + vector + qualitative rating.
/// - [`Finding::cwe`] — zero-or-more CWE identifiers.
/// - [`Finding::mitre_attack`] — zero-or-more MITRE ATT&CK technique refs.
/// - [`Finding::compliance`] — control mappings per framework
///   (NIST 800-53, ISO 27001, PCI DSS, SOC 2, HIPAA).
/// - [`Finding::confidence`] — emitter-provided confidence in `0.0..=1.0`.
///
/// All five fields default to `None`/empty so emitters that have not yet
/// been migrated keep compiling unchanged and their JSON payload stays
/// backwards-compatible (omitted when empty). See
/// `docs/finding-enrichment.md` for the rollout plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Identifier.
    pub id: FindingId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Affected asset.
    pub asset_id: AssetId,
    /// Identifier of the rule / detector that produced this finding.
    pub rule_id: String,
    /// Short title, suitable for lists.
    pub title: String,
    /// Free-form Markdown description.
    pub description: String,
    /// Severity.
    pub severity: Severity,
    /// Lifecycle status.
    pub status: FindingStatus,
    /// Evidence pointers.
    pub evidence_refs: Vec<EvidenceRef>,
    /// Discovery timestamp.
    pub discovered_at: OffsetDateTime,
    /// Timestamp at which the finding was confirmed, if ever.
    pub confirmed_at: Option<OffsetDateTime>,
    /// Timestamp at which remediation was applied, if ever.
    pub remediated_at: Option<OffsetDateTime>,

    // ----- enrichment payload (TOP5-#3 Phase 1) ---------------------------
    /// CVSS v3.1 base metric payload, if the emitter computed/looked one up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<CvssV31>,
    /// CWE identifiers describing the underlying weakness class(es).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<CweId>,
    /// MITRE ATT&CK techniques/sub-techniques this finding maps to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_attack: Vec<MitreAttackTechnique>,
    /// Compliance-framework control mappings.
    #[serde(default, skip_serializing_if = "ComplianceTags::is_empty")]
    pub compliance: ComplianceTags,
    /// Emitter-provided confidence in `0.0..=1.0` (1.0 = certain).
    ///
    /// This generalises the per-emitter `confidence` field DLP introduced;
    /// future emitters should populate this rather than carrying a bespoke
    /// confidence field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

impl Finding {
    /// Build a new finding in the `Discovered` state.
    pub fn new(
        tenant_id: TenantId,
        asset_id: AssetId,
        rule_id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        discovered_at: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let rule_id = rule_id.into();
        let title = title.into();
        let description = description.into();
        validate_non_empty("rule_id", &rule_id)?;
        validate_non_empty("title", &title)?;
        if title.len() > 200 {
            return Err(DomainError::invalid("title exceeds 200 bytes"));
        }
        Ok(Self {
            id: FindingId::new(),
            tenant_id,
            asset_id,
            rule_id,
            title,
            description,
            severity,
            status: FindingStatus::Discovered,
            evidence_refs: Vec::new(),
            discovered_at,
            confirmed_at: None,
            remediated_at: None,
            cvss: None,
            cwe: Vec::new(),
            mitre_attack: Vec::new(),
            compliance: ComplianceTags::default(),
            confidence: None,
        })
    }

    /// Builder-style: attach a CVSS v3.1 score.
    #[must_use]
    pub fn with_cvss(mut self, cvss: CvssV31) -> Self {
        self.cvss = Some(cvss);
        self
    }

    /// Builder-style: attach CWE identifiers.
    #[must_use]
    pub fn with_cwe(mut self, cwe: Vec<CweId>) -> Self {
        self.cwe = cwe;
        self
    }

    /// Builder-style: attach MITRE ATT&CK techniques.
    #[must_use]
    pub fn with_mitre_attack(mut self, techniques: Vec<MitreAttackTechnique>) -> Self {
        self.mitre_attack = techniques;
        self
    }

    /// Builder-style: attach compliance-framework tags.
    #[must_use]
    pub fn with_compliance(mut self, compliance: ComplianceTags) -> Self {
        self.compliance = compliance;
        self
    }

    /// Builder-style: attach a confidence score in `0.0..=1.0`.
    ///
    /// Returns [`DomainError::InvalidValue`] if `score` is NaN or outside
    /// the allowed range.
    pub fn with_confidence(mut self, score: f64) -> Result<Self, DomainError> {
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(DomainError::invalid(format!(
                "confidence must be finite in 0.0..=1.0, got {score}",
            )));
        }
        self.confidence = Some(score);
        Ok(self)
    }

    /// Apply a status transition with timestamp bookkeeping.
    pub fn transition(&mut self, to: FindingStatus, at: OffsetDateTime) -> Result<(), DomainError> {
        let next = self.status.try_transition(to)?;
        self.status = next;
        match next {
            FindingStatus::Confirmed if self.confirmed_at.is_none() => {
                self.confirmed_at = Some(at);
            }
            FindingStatus::Remediated if self.remediated_at.is_none() => {
                self.remediated_at = Some(at);
            }
            _ => {}
        }
        Ok(())
    }

    /// Attach a new piece of evidence.
    pub fn add_evidence(&mut self, ev: EvidenceRef) {
        self.evidence_refs.push(ev);
    }
}

fn validate_non_empty(label: &str, s: &str) -> Result<(), DomainError> {
    if s.trim().is_empty() {
        return Err(DomainError::invalid(format!("{label} cannot be empty")));
    }
    Ok(())
}

/// Filter parameters for listing findings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FindingFilter {
    /// Restrict to a specific asset.
    pub asset_id: Option<AssetId>,
    /// Restrict to a set of severities.
    pub severities: Vec<Severity>,
    /// Restrict to a set of statuses.
    pub statuses: Vec<FindingStatus>,
    /// Restrict to a specific rule id.
    pub rule_id: Option<String>,
    /// Inclusive lower bound on `discovered_at`.
    pub discovered_from: Option<OffsetDateTime>,
    /// Inclusive upper bound on `discovered_at`.
    pub discovered_to: Option<OffsetDateTime>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn finding() -> Finding {
        Finding::new(
            TenantId::new(),
            AssetId::new(),
            "rule.cve.2024.12345",
            "OpenSSL RCE",
            "Long description",
            Severity::High,
            now(),
        )
        .unwrap()
    }

    #[test]
    fn new_starts_discovered() {
        assert_eq!(finding().status, FindingStatus::Discovered);
    }

    #[test]
    fn transition_sets_confirmed_at() {
        let mut f = finding();
        let later = now() + time::Duration::seconds(5);
        f.transition(FindingStatus::Triaged, later).unwrap();
        let later2 = later + time::Duration::seconds(5);
        f.transition(FindingStatus::Confirmed, later2).unwrap();
        assert_eq!(f.confirmed_at, Some(later2));
    }

    #[test]
    fn transition_rejects_invalid() {
        let mut f = finding();
        assert!(f.transition(FindingStatus::Closed, now()).is_err());
    }

    #[test]
    fn evidence_validation() {
        assert!(EvidenceRef::new("", None, None).is_err());
        assert!(EvidenceRef::new("s3://x/y", None, Some("zz".into())).is_err());
        assert!(EvidenceRef::new("s3://x/y", None, Some("a".repeat(64))).is_ok());
    }

    #[test]
    fn evidence_new_defaults_line_column_to_none() {
        let ev = EvidenceRef::new("s3://x/y", None, None).unwrap();
        assert!(ev.line.is_none());
        assert!(ev.column.is_none());
        // JSON payload omits the keys via `skip_serializing_if`.
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("\"line\""), "json = {json}");
        assert!(!json.contains("\"column\""), "json = {json}");
    }

    #[test]
    fn evidence_with_region_sets_line_column() {
        let ev = EvidenceRef::new("s3://x/y", None, None)
            .unwrap()
            .with_region(3, 12)
            .unwrap();
        assert_eq!(ev.line, Some(3));
        assert_eq!(ev.column, Some(12));
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"line\":3"), "json = {json}");
        assert!(json.contains("\"column\":12"), "json = {json}");
    }

    #[test]
    fn evidence_with_region_rejects_zero() {
        let ev = EvidenceRef::new("s3://x/y", None, None).unwrap();
        assert!(ev.clone().with_region(0, 1).is_err());
        assert!(ev.with_region(1, 0).is_err());
    }

    #[test]
    fn rejects_empty_title() {
        assert!(Finding::new(
            TenantId::new(),
            AssetId::new(),
            "r",
            "",
            "d",
            Severity::Low,
            now(),
        )
        .is_err());
    }

    // ----- enrichment field defaults --------------------------------------

    #[test]
    fn new_leaves_enrichment_empty() {
        let f = finding();
        assert!(f.cvss.is_none());
        assert!(f.cwe.is_empty());
        assert!(f.mitre_attack.is_empty());
        assert!(f.compliance.is_empty());
        assert!(f.confidence.is_none());
    }

    #[test]
    fn unenriched_finding_serialises_without_enrichment_keys() {
        // A finding with no enrichment must not leak empty enrichment
        // keys into the JSON payload — `skip_serializing_if` guards them.
        let f = finding();
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("\"cvss\""), "json = {json}");
        assert!(!json.contains("\"cwe\""), "json = {json}");
        assert!(!json.contains("\"mitre_attack\""), "json = {json}");
        assert!(!json.contains("\"compliance\""), "json = {json}");
        assert!(!json.contains("\"confidence\""), "json = {json}");
    }

    #[test]
    fn enriched_finding_round_trips_through_json() {
        use crate::value_object::compliance::{
            ComplianceTags, IsoControl, NistControl, PciRequirement,
        };
        use crate::value_object::cvss_v31::{CvssV31, CvssV31Rating};
        use crate::value_object::cwe::CweId;
        use crate::value_object::mitre_attack::MitreAttackTechnique;

        let f = finding()
            .with_cvss(
                CvssV31::new(
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    7.5,
                    CvssV31Rating::High,
                )
                .unwrap(),
            )
            .with_cwe(vec![CweId::new(319).unwrap()])
            .with_mitre_attack(vec![
                MitreAttackTechnique::new("TA0009", "T1040", None).unwrap()
            ])
            .with_compliance(ComplianceTags {
                nist_800_53: vec![NistControl::new("SC-8").unwrap()],
                iso_27001: vec![IsoControl::new("A.13.1.1").unwrap()],
                pci_dss: vec![PciRequirement::new("4.1").unwrap()],
                ..Default::default()
            })
            .with_confidence(0.95)
            .unwrap();

        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("CVSS:3.1/"), "json = {json}");
        assert!(json.contains("CWE-319"), "json = {json}");
        assert!(json.contains("T1040"), "json = {json}");
        assert!(json.contains("SC-8"), "json = {json}");

        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cvss, f.cvss);
        assert_eq!(back.cwe, f.cwe);
        assert_eq!(back.mitre_attack, f.mitre_attack);
        assert_eq!(back.compliance, f.compliance);
        assert_eq!(back.confidence, f.confidence);
    }

    #[test]
    fn with_confidence_rejects_out_of_range() {
        assert!(finding().with_confidence(-0.1).is_err());
        assert!(finding().with_confidence(1.1).is_err());
        assert!(finding().with_confidence(f64::NAN).is_err());
        assert!(finding().with_confidence(0.5).is_ok());
    }
}
