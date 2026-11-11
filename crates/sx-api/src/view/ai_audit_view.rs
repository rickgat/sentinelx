//! AI security audit (AI-SEC-001) view layer.
//!
//! Wire shapes returned by the `/v1/ai-audit/*` endpoints. The DTOs are
//! self-contained (they do **not** depend on the `sx-ai-audit` crate); the
//! composition-root adapter in `services/sx-monolith` projects the domain
//! types onto these.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Request body for `POST /v1/ai-audit/run-external` (AI-SEC-002): red-team a
/// config-registered external LLM target under a named engagement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunExternalAuditRequest {
    /// Engagement whose scope + kill-switch + RoE window authorize the run.
    pub engagement_id: String,
    /// Id of the `ai_copilot.external_targets` entry to probe.
    pub target_id: String,
}

/// One AI asset on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiAssetView {
    /// Stable asset id.
    pub id: String,
    /// Owning tenant. `None` means untenanted / global.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Asset kind code (`llm_api_endpoint` | `model_registry` | …).
    pub kind: String,
    /// Human-readable name.
    pub name: String,
    /// Provider / vendor.
    pub provider: String,
    /// Network endpoint when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// RFC 3339 discovery timestamp.
    pub discovered_at: String,
    /// Provenance metadata.
    pub metadata: BTreeMap<String, String>,
}

/// `GET /v1/ai-audit/assets` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiAssetListResponse {
    /// AI assets visible for the caller's tenant.
    pub assets: Vec<AiAssetView>,
}

/// One CycloneDX property on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiBomPropertyView {
    /// Property name.
    pub name: String,
    /// Property value.
    pub value: String,
}

/// One CycloneDX component on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiBomComponentView {
    /// CycloneDX `bom-ref`.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// CycloneDX component type.
    #[serde(rename = "type")]
    pub component_type: String,
    /// Component name.
    pub name: String,
    /// Publisher / provider.
    pub publisher: String,
    /// Provenance properties.
    pub properties: Vec<AiBomPropertyView>,
}

/// `GET /v1/ai-audit/aibom` response body (CycloneDX-ML-style AI-BOM).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiBomView {
    /// Always `"CycloneDX"`.
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    /// CycloneDX spec version.
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    /// Monotonic document version.
    pub version: u32,
    /// One component per AI asset.
    pub components: Vec<AiBomComponentView>,
}

/// One AI governance control on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiControlView {
    /// SentinelX-local control id (`"SX-AI-…"`).
    pub id: String,
    /// Auditor-readable title.
    pub title: String,
    /// Framework code (`nist_ai_rmf` | `iso_42001` | `eu_ai_act`).
    pub framework: String,
    /// Longer description.
    pub description: String,
}

/// `GET /v1/ai-audit/controls` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiControlListResponse {
    /// Built-in AI governance controls.
    pub controls: Vec<AiControlView>,
}

/// One probe outcome on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProbeOutcomeView {
    /// The probe id.
    pub probe_id: String,
    /// The probe category code.
    pub category: String,
    /// Whether the probe succeeded (a guardrail failure).
    pub success: bool,
    /// Heuristic confidence in `[0,1]`.
    pub confidence: f64,
    /// Whether the response contained an explicit refusal.
    pub refused: bool,
    /// Signals that drove the verdict.
    pub signals: Vec<String>,
    /// OWASP LLM Top-10 id.
    pub owasp_id: String,
    /// OWASP LLM Top-10 title.
    pub owasp_title: String,
    /// MITRE ATLAS technique id.
    pub atlas_id: String,
    /// MITRE ATLAS technique title.
    pub atlas_title: String,
}

/// One model-file finding on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelFileFindingView {
    /// Finding kind code.
    pub kind: String,
    /// Severity code.
    pub severity: String,
    /// Operator-readable detail.
    pub detail: String,
    /// Byte offset when meaningful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// OWASP LLM Top-10 id.
    pub owasp_id: String,
    /// MITRE ATLAS technique id.
    pub atlas_id: String,
}

/// One control evidence record on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiControlEvidenceView {
    /// Control id this evidence attests to.
    pub control_id: String,
    /// Status code (`pass` | `fail` | `not_applicable` | `manual`).
    pub status: String,
    /// Detail / citation.
    pub detail: String,
    /// RFC 3339 collection timestamp.
    pub collected_at: String,
}

/// `POST /v1/ai-audit/run` response body — the full audit report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiAuditReportView {
    /// AI assets in scope.
    pub assets: Vec<AiAssetView>,
    /// CycloneDX-ML-style AI-BOM.
    pub aibom: AiBomView,
    /// Probe outcomes (empty when no in-scope probe target was supplied).
    pub probe_results: Vec<ProbeOutcomeView>,
    /// Model-file supply-chain findings.
    pub modelfile_findings: Vec<ModelFileFindingView>,
    /// Governance control evidence.
    pub control_evidence: Vec<AiControlEvidenceView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn asset_view_omits_optional_when_absent() {
        let v = AiAssetView {
            id: "a".into(),
            tenant_id: None,
            kind: "model_registry".into(),
            name: "n".into(),
            provider: "p".into(),
            endpoint: None,
            discovered_at: "2026-10-31T00:00:00Z".into(),
            metadata: BTreeMap::new(),
        };
        let raw = serde_json::to_string(&v).unwrap();
        // The optional `tenant_id` and `endpoint` keys are omitted when None.
        assert!(!raw.contains("\"tenant_id\""));
        assert!(!raw.contains("\"endpoint\""));
    }

    #[test]
    fn aibom_view_uses_cyclonedx_keys() {
        let v = AiBomView {
            bom_format: "CycloneDX".into(),
            spec_version: "1.6".into(),
            version: 1,
            components: vec![AiBomComponentView {
                bom_ref: "r".into(),
                component_type: "machine-learning-model".into(),
                name: "n".into(),
                publisher: "p".into(),
                properties: vec![AiBomPropertyView {
                    name: "k".into(),
                    value: "v".into(),
                }],
            }],
        };
        let raw = serde_json::to_string(&v).unwrap();
        assert!(raw.contains("\"bomFormat\""));
        assert!(raw.contains("\"specVersion\""));
        assert!(raw.contains("\"bom-ref\""));
        let back: AiBomView = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn report_view_round_trips() {
        let v = AiAuditReportView {
            assets: Vec::new(),
            aibom: AiBomView {
                bom_format: "CycloneDX".into(),
                spec_version: "1.6".into(),
                version: 1,
                components: Vec::new(),
            },
            probe_results: vec![ProbeOutcomeView {
                probe_id: "PI-DIRECT-001".into(),
                category: "direct_injection".into(),
                success: false,
                confidence: 0.9,
                refused: true,
                signals: vec!["refused".into()],
                owasp_id: "LLM01".into(),
                owasp_title: "Prompt Injection".into(),
                atlas_id: "AML.T0051".into(),
                atlas_title: "LLM Prompt Injection".into(),
            }],
            modelfile_findings: Vec::new(),
            control_evidence: Vec::new(),
        };
        let raw = serde_json::to_string(&v).unwrap();
        let back: AiAuditReportView = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, v);
    }
}
