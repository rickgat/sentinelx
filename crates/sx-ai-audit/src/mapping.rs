//! Framework mapping — OWASP LLM Top-10 + MITRE ATLAS.
//!
//! Probe-corpus entries and model-file findings reference these enums so a
//! single finding can be rendered with its canonical OWASP id/title and the
//! ATLAS technique it maps to. The enums are the source of truth; the HTTP
//! layer projects them onto flat string DTOs via [`FrameworkMapping`].

use serde::{Deserialize, Serialize};

/// Severity bucket attached to a finding. Ordered low → high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — no action required.
    Info,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical — immediate attention.
    Critical,
}

impl Severity {
    /// Short, machine-readable code matching the serde tag.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// The OWASP Top-10 for Large Language Model Applications (2025 list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwaspLlmTop10 {
    /// LLM01 — Prompt Injection.
    Llm01PromptInjection,
    /// LLM02 — Sensitive Information Disclosure.
    Llm02SensitiveInformationDisclosure,
    /// LLM03 — Supply Chain.
    Llm03SupplyChain,
    /// LLM04 — Data and Model Poisoning.
    Llm04DataAndModelPoisoning,
    /// LLM05 — Improper Output Handling.
    Llm05ImproperOutputHandling,
    /// LLM06 — Excessive Agency.
    Llm06ExcessiveAgency,
    /// LLM07 — System Prompt Leakage.
    Llm07SystemPromptLeakage,
    /// LLM08 — Vector and Embedding Weaknesses.
    Llm08VectorAndEmbeddingWeaknesses,
    /// LLM09 — Misinformation.
    Llm09Misinformation,
    /// LLM10 — Unbounded Consumption.
    Llm10UnboundedConsumption,
}

impl OwaspLlmTop10 {
    /// Canonical OWASP id (e.g. `"LLM01"`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Llm01PromptInjection => "LLM01",
            Self::Llm02SensitiveInformationDisclosure => "LLM02",
            Self::Llm03SupplyChain => "LLM03",
            Self::Llm04DataAndModelPoisoning => "LLM04",
            Self::Llm05ImproperOutputHandling => "LLM05",
            Self::Llm06ExcessiveAgency => "LLM06",
            Self::Llm07SystemPromptLeakage => "LLM07",
            Self::Llm08VectorAndEmbeddingWeaknesses => "LLM08",
            Self::Llm09Misinformation => "LLM09",
            Self::Llm10UnboundedConsumption => "LLM10",
        }
    }

    /// Human-readable OWASP title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Llm01PromptInjection => "Prompt Injection",
            Self::Llm02SensitiveInformationDisclosure => "Sensitive Information Disclosure",
            Self::Llm03SupplyChain => "Supply Chain",
            Self::Llm04DataAndModelPoisoning => "Data and Model Poisoning",
            Self::Llm05ImproperOutputHandling => "Improper Output Handling",
            Self::Llm06ExcessiveAgency => "Excessive Agency",
            Self::Llm07SystemPromptLeakage => "System Prompt Leakage",
            Self::Llm08VectorAndEmbeddingWeaknesses => "Vector and Embedding Weaknesses",
            Self::Llm09Misinformation => "Misinformation",
            Self::Llm10UnboundedConsumption => "Unbounded Consumption",
        }
    }
}

/// A curated subset of MITRE ATLAS techniques relevant to the probe corpus
/// and model-file scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AtlasTechnique {
    /// AML.T0051 — LLM Prompt Injection.
    T0051LlmPromptInjection,
    /// AML.T0054 — LLM Jailbreak.
    T0054LlmJailbreak,
    /// AML.T0056 — LLM Meta Prompt Extraction.
    T0056LlmMetaPromptExtraction,
    /// AML.T0057 — LLM Data Leakage.
    T0057LlmDataLeakage,
    /// AML.T0010 — ML Supply Chain Compromise.
    T0010MlSupplyChainCompromise,
    /// AML.T0018 — Backdoor ML Model.
    T0018BackdoorMlModel,
    /// AML.T0020 — Poison Training Data.
    T0020PoisonTrainingData,
    /// AML.T0048 — External Harms (downstream impact of model output, e.g.
    /// unsafe markup/commands or confidently-asserted misinformation).
    T0048ExternalHarms,
    /// AML.T0034 — Cost Harvesting (inducing unbounded / expensive
    /// generation to exhaust resources).
    T0034CostHarvesting,
}

impl AtlasTechnique {
    /// Canonical ATLAS technique id (e.g. `"AML.T0051"`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::T0051LlmPromptInjection => "AML.T0051",
            Self::T0054LlmJailbreak => "AML.T0054",
            Self::T0056LlmMetaPromptExtraction => "AML.T0056",
            Self::T0057LlmDataLeakage => "AML.T0057",
            Self::T0010MlSupplyChainCompromise => "AML.T0010",
            Self::T0018BackdoorMlModel => "AML.T0018",
            Self::T0020PoisonTrainingData => "AML.T0020",
            Self::T0048ExternalHarms => "AML.T0048",
            Self::T0034CostHarvesting => "AML.T0034",
        }
    }

    /// Human-readable ATLAS technique title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::T0051LlmPromptInjection => "LLM Prompt Injection",
            Self::T0054LlmJailbreak => "LLM Jailbreak",
            Self::T0056LlmMetaPromptExtraction => "LLM Meta Prompt Extraction",
            Self::T0057LlmDataLeakage => "LLM Data Leakage",
            Self::T0010MlSupplyChainCompromise => "ML Supply Chain Compromise",
            Self::T0018BackdoorMlModel => "Backdoor ML Model",
            Self::T0020PoisonTrainingData => "Poison Training Data",
            Self::T0048ExternalHarms => "External Harms",
            Self::T0034CostHarvesting => "Cost Harvesting",
        }
    }
}

/// Flat, serialisable projection of an OWASP + ATLAS pairing. This is the
/// shape the HTTP/dashboard layers consume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkMapping {
    /// OWASP LLM Top-10 id (e.g. `"LLM01"`).
    pub owasp_id: String,
    /// OWASP LLM Top-10 title.
    pub owasp_title: String,
    /// MITRE ATLAS technique id (e.g. `"AML.T0051"`).
    pub atlas_id: String,
    /// MITRE ATLAS technique title.
    pub atlas_title: String,
}

impl FrameworkMapping {
    /// Build a flat mapping from the two source enums.
    #[must_use]
    pub fn new(owasp: OwaspLlmTop10, atlas: AtlasTechnique) -> Self {
        Self {
            owasp_id: owasp.id().to_owned(),
            owasp_title: owasp.title().to_owned(),
            atlas_id: atlas.id().to_owned(),
            atlas_title: atlas.title().to_owned(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn owasp_ids_are_sequential() {
        let all = [
            OwaspLlmTop10::Llm01PromptInjection,
            OwaspLlmTop10::Llm02SensitiveInformationDisclosure,
            OwaspLlmTop10::Llm03SupplyChain,
            OwaspLlmTop10::Llm04DataAndModelPoisoning,
            OwaspLlmTop10::Llm05ImproperOutputHandling,
            OwaspLlmTop10::Llm06ExcessiveAgency,
            OwaspLlmTop10::Llm07SystemPromptLeakage,
            OwaspLlmTop10::Llm08VectorAndEmbeddingWeaknesses,
            OwaspLlmTop10::Llm09Misinformation,
            OwaspLlmTop10::Llm10UnboundedConsumption,
        ];
        for (i, v) in all.iter().enumerate() {
            assert_eq!(v.id(), format!("LLM{:02}", i + 1));
            assert!(!v.title().is_empty());
        }
    }

    #[test]
    fn atlas_ids_have_aml_prefix() {
        let t = AtlasTechnique::T0051LlmPromptInjection;
        assert_eq!(t.id(), "AML.T0051");
        assert_eq!(t.title(), "LLM Prompt Injection");
    }

    #[test]
    fn severity_orders_low_to_high() {
        assert!(Severity::Info < Severity::Critical);
        assert!(Severity::Medium < Severity::High);
        assert_eq!(Severity::High.code(), "high");
    }

    #[test]
    fn framework_mapping_flattens_both_enums() {
        let m = FrameworkMapping::new(
            OwaspLlmTop10::Llm01PromptInjection,
            AtlasTechnique::T0051LlmPromptInjection,
        );
        assert_eq!(m.owasp_id, "LLM01");
        assert_eq!(m.atlas_id, "AML.T0051");
    }
}
