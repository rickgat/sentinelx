//! AI governance controls.
//!
//! Control definitions spanning NIST AI RMF (GOVERN/MAP/MEASURE/MANAGE),
//! ISO/IEC 42001, and the EU AI Act (risk tiers + key articles), plus an
//! evidence-record type. The shape mirrors
//! `sx-compliance::p1_004::control` so downstream dashboards can join
//! cleanly.

use serde::{Deserialize, Serialize};

/// The governance framework a control belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiControlFramework {
    /// NIST AI Risk Management Framework (AI RMF 1.0).
    NistAiRmf,
    /// ISO/IEC 42001 — AI management systems.
    Iso42001,
    /// EU AI Act (Regulation 2024/1689).
    EuAiAct,
}

impl AiControlFramework {
    /// Short, machine-readable code matching the serde tag.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NistAiRmf => "nist_ai_rmf",
            Self::Iso42001 => "iso_42001",
            Self::EuAiAct => "eu_ai_act",
        }
    }
}

/// The EU AI Act risk tier a system falls under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EuAiActRiskTier {
    /// Prohibited practice (Title II, Article 5).
    Unacceptable,
    /// High-risk system (Title III).
    High,
    /// Limited risk — transparency obligations (Article 50).
    Limited,
    /// Minimal risk — no mandatory obligations.
    Minimal,
}

impl EuAiActRiskTier {
    /// Short, machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unacceptable => "unacceptable",
            Self::High => "high",
            Self::Limited => "limited",
            Self::Minimal => "minimal",
        }
    }
}

/// A single AI governance control definition.
///
/// `Serialize` + `Deserialize`: the id is an owned `String` (namespaced
/// `"SX-AI-…"`), the title/description are `&'static str` so the built-in
/// registry lives in code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AiControl {
    /// SentinelX-local control id (`"SX-AI-…"`).
    pub id: String,
    /// One-line auditor-readable title.
    pub title: &'static str,
    /// The framework this control derives from.
    pub framework: AiControlFramework,
    /// Longer description, naming the framework function / article.
    pub description: &'static str,
}

/// Stable control-id constants committed to in evidence + audit records.
pub mod ids {
    /// NIST AI RMF GOVERN — AI governance structure established.
    pub const NIST_GOVERN: &str = "SX-AI-NIST-GOVERN-1";
    /// NIST AI RMF MAP — AI system context + risks mapped.
    pub const NIST_MAP: &str = "SX-AI-NIST-MAP-1";
    /// NIST AI RMF MEASURE — AI risks measured / probed.
    pub const NIST_MEASURE: &str = "SX-AI-NIST-MEASURE-1";
    /// NIST AI RMF MANAGE — AI risks prioritised + responded to.
    pub const NIST_MANAGE: &str = "SX-AI-NIST-MANAGE-1";
    /// ISO/IEC 42001 — AI management system in place.
    pub const ISO_42001_AIMS: &str = "SX-AI-ISO42001-AIMS";
    /// ISO/IEC 42001 — AI system impact assessment performed.
    pub const ISO_42001_IMPACT: &str = "SX-AI-ISO42001-IMPACT";
    /// EU AI Act — risk classification recorded (Art. 6).
    pub const EU_AI_ACT_RISK_CLASS: &str = "SX-AI-EUACT-RISK-CLASS";
    /// EU AI Act — transparency obligations met (Art. 50).
    pub const EU_AI_ACT_TRANSPARENCY: &str = "SX-AI-EUACT-TRANSPARENCY";
    /// EU AI Act — logging / record-keeping (Art. 12).
    pub const EU_AI_ACT_LOGGING: &str = "SX-AI-EUACT-LOGGING";
}

/// The closed set of built-in AI governance controls.
#[must_use]
pub fn builtin_ai_controls() -> Vec<AiControl> {
    vec![
        AiControl {
            id: ids::NIST_GOVERN.to_owned(),
            title: "AI governance structure, roles, and policies are established.",
            framework: AiControlFramework::NistAiRmf,
            description:
                "NIST AI RMF GOVERN function: accountability, policies, and oversight for AI systems are defined and operational.",
        },
        AiControl {
            id: ids::NIST_MAP.to_owned(),
            title: "AI system context and risks are mapped.",
            framework: AiControlFramework::NistAiRmf,
            description:
                "NIST AI RMF MAP function: intended use, assets (AI-BOM), and foreseeable risks of each AI system are catalogued.",
        },
        AiControl {
            id: ids::NIST_MEASURE.to_owned(),
            title: "AI risks are measured through testing and probing.",
            framework: AiControlFramework::NistAiRmf,
            description:
                "NIST AI RMF MEASURE function: adversarial probing (prompt injection/jailbreak) and supply-chain scans quantify AI risk.",
        },
        AiControl {
            id: ids::NIST_MANAGE.to_owned(),
            title: "AI risks are prioritised and responded to.",
            framework: AiControlFramework::NistAiRmf,
            description:
                "NIST AI RMF MANAGE function: findings are triaged, remediated, and residual risk is tracked over time.",
        },
        AiControl {
            id: ids::ISO_42001_AIMS.to_owned(),
            title: "An AI management system (AIMS) is implemented and maintained.",
            framework: AiControlFramework::Iso42001,
            description:
                "ISO/IEC 42001 Clause 4-10: a documented AI management system governs the lifecycle of AI systems.",
        },
        AiControl {
            id: ids::ISO_42001_IMPACT.to_owned(),
            title: "AI system impact assessments are performed.",
            framework: AiControlFramework::Iso42001,
            description:
                "ISO/IEC 42001 Annex: impact to individuals and society is assessed for each AI system before and during operation.",
        },
        AiControl {
            id: ids::EU_AI_ACT_RISK_CLASS.to_owned(),
            title: "Each AI system has a recorded EU AI Act risk classification.",
            framework: AiControlFramework::EuAiAct,
            description:
                "EU AI Act Art. 6 + Annex III: every AI system is classified (unacceptable/high/limited/minimal) and the rationale is retained.",
        },
        AiControl {
            id: ids::EU_AI_ACT_TRANSPARENCY.to_owned(),
            title: "Transparency obligations for AI interactions are met.",
            framework: AiControlFramework::EuAiAct,
            description:
                "EU AI Act Art. 50: users are informed when they interact with an AI system and AI-generated content is marked.",
        },
        AiControl {
            id: ids::EU_AI_ACT_LOGGING.to_owned(),
            title: "AI system events are logged for record-keeping.",
            framework: AiControlFramework::EuAiAct,
            description:
                "EU AI Act Art. 12: high-risk AI systems automatically record events (logs) over their lifetime for traceability.",
        },
    ]
}

/// The status of a collected piece of control evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// The control is satisfied by automatically-collected evidence.
    Pass,
    /// The control is not satisfied.
    Fail,
    /// The control does not apply to this tenant's AI estate.
    NotApplicable,
    /// The control requires manual attestation not yet provided.
    Manual,
}

impl EvidenceStatus {
    /// Short, machine-readable code matching the serde tag.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotApplicable => "not_applicable",
            Self::Manual => "manual",
        }
    }
}

/// An evidence record attesting to a control's status at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiControlEvidence {
    /// The control this evidence attests to.
    pub control_id: String,
    /// Evidence status.
    pub status: EvidenceStatus,
    /// Operator-readable detail / citation.
    pub detail: String,
    /// RFC 3339 collection timestamp.
    pub collected_at: String,
}

impl AiControlEvidence {
    /// Build an evidence record stamped with the current time.
    #[must_use]
    pub fn now(
        control_id: impl Into<String>,
        status: EvidenceStatus,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            control_id: control_id.into(),
            status,
            detail: detail.into(),
            collected_at: crate::now_rfc3339(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn registry_spans_all_three_frameworks() {
        let controls = builtin_ai_controls();
        let frameworks: std::collections::HashSet<&str> =
            controls.iter().map(|c| c.framework.code()).collect();
        assert!(frameworks.contains("nist_ai_rmf"));
        assert!(frameworks.contains("iso_42001"));
        assert!(frameworks.contains("eu_ai_act"));
    }

    #[test]
    fn all_control_ids_are_sx_ai_namespaced_and_unique() {
        let controls = builtin_ai_controls();
        assert!(controls.iter().all(|c| c.id.starts_with("SX-AI-")));
        let mut ids: Vec<&str> = controls.iter().map(|c| c.id.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len());
    }

    #[test]
    fn nist_rmf_has_all_four_functions() {
        let controls = builtin_ai_controls();
        for id in [
            ids::NIST_GOVERN,
            ids::NIST_MAP,
            ids::NIST_MEASURE,
            ids::NIST_MANAGE,
        ] {
            assert!(controls.iter().any(|c| c.id == id), "missing {id}");
        }
    }

    #[test]
    fn evidence_round_trips() {
        let e = AiControlEvidence::now(ids::NIST_MAP, EvidenceStatus::Pass, "AI-BOM built");
        let raw = serde_json::to_string(&e).unwrap();
        let back: AiControlEvidence = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, e);
        assert!(raw.contains("\"pass\""));
    }

    #[test]
    fn eu_risk_tier_codes() {
        assert_eq!(EuAiActRiskTier::High.code(), "high");
        assert_eq!(EuAiActRiskTier::Unacceptable.code(), "unacceptable");
    }
}
