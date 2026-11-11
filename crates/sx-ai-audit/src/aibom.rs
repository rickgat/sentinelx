//! AI Bill of Materials (AI-BOM) document builder.
//!
//! Produces a CycloneDX-ML-style JSON document from an [`AiAsset`] slice:
//! a top-level BOM envelope plus one component per asset, each carrying its
//! provenance (kind, provider, endpoint, discovery time, tenant) as
//! CycloneDX `properties`.
//!
//! The output is pure data — [`AiBomDocument`] is `Serialize`, and
//! [`AiBomDocument::to_value`] hands back a `serde_json::Value` for callers
//! that want to embed it.

use serde::{Deserialize, Serialize};

use crate::inventory::{AiAsset, AiAssetKind};

/// CycloneDX spec version this builder targets.
pub const SPEC_VERSION: &str = "1.6";

/// A single CycloneDX `properties` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiBomProperty {
    /// Property name (namespaced, e.g. `"sx:ai:kind"`).
    pub name: String,
    /// Property value.
    pub value: String,
}

impl AiBomProperty {
    fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// One CycloneDX component describing an AI asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiBomComponent {
    /// CycloneDX `bom-ref` — stable within the document.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// CycloneDX component type (e.g. `"machine-learning-model"`, `"data"`,
    /// `"application"`).
    #[serde(rename = "type")]
    pub component_type: String,
    /// Component name.
    pub name: String,
    /// Publisher / provider.
    pub publisher: String,
    /// Provenance properties.
    pub properties: Vec<AiBomProperty>,
}

/// A CycloneDX-ML-style AI-BOM document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiBomDocument {
    /// Always `"CycloneDX"`.
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    /// CycloneDX spec version (see [`SPEC_VERSION`]).
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    /// Monotonic document version.
    pub version: u32,
    /// One component per AI asset.
    pub components: Vec<AiBomComponent>,
}

impl AiBomDocument {
    /// Project this document into a `serde_json::Value`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::AiAuditError::Internal`] if serialisation
    /// fails (not expected for this all-owned, string-keyed shape).
    pub fn to_value(&self) -> Result<serde_json::Value, crate::error::AiAuditError> {
        serde_json::to_value(self).map_err(|e| crate::error::AiAuditError::Internal(e.to_string()))
    }
}

/// Map an [`AiAssetKind`] onto the closest CycloneDX component type.
const fn component_type_for(kind: AiAssetKind) -> &'static str {
    match kind {
        AiAssetKind::LlmApiEndpoint | AiAssetKind::ModelRegistry | AiAssetKind::ModelFile => {
            "machine-learning-model"
        }
        AiAssetKind::VectorStore => "data",
        AiAssetKind::AgentFramework | AiAssetKind::McpServer => "application",
    }
}

/// Build a CycloneDX-ML-style AI-BOM from a set of AI assets.
#[must_use]
pub fn build_aibom(assets: &[AiAsset]) -> AiBomDocument {
    let components = assets
        .iter()
        .map(|a| {
            let mut properties = vec![
                AiBomProperty::new("sx:ai:kind", a.kind.code()),
                AiBomProperty::new("sx:ai:tenant", a.tenant_id.clone()),
                AiBomProperty::new("sx:ai:discovered_at", a.discovered_at.clone()),
            ];
            if let Some(ep) = &a.endpoint {
                properties.push(AiBomProperty::new("sx:ai:endpoint", ep.clone()));
            }
            for (k, v) in &a.metadata {
                properties.push(AiBomProperty::new(format!("sx:ai:meta:{k}"), v.clone()));
            }
            AiBomComponent {
                bom_ref: a.id.clone(),
                component_type: component_type_for(a.kind).to_owned(),
                name: a.name.clone(),
                publisher: a.provider.clone(),
                properties,
            }
        })
        .collect();

    AiBomDocument {
        bom_format: "CycloneDX".to_owned(),
        spec_version: SPEC_VERSION.to_owned(),
        version: 1,
        components,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample() -> Vec<AiAsset> {
        vec![
            AiAsset::new(
                "llm-1",
                "t",
                AiAssetKind::LlmApiEndpoint,
                "Copilot",
                "anthropic",
            )
            .with_endpoint("https://api.anthropic.com")
            .with_metadata("model_id", "claude"),
            AiAsset::new(
                "vec-1",
                "t",
                AiAssetKind::VectorStore,
                "Store",
                "self-hosted",
            ),
        ]
    }

    #[test]
    fn builds_one_component_per_asset() {
        let bom = build_aibom(&sample());
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, SPEC_VERSION);
        assert_eq!(bom.components.len(), 2);
    }

    #[test]
    fn endpoint_and_metadata_become_properties() {
        let bom = build_aibom(&sample());
        let llm = bom
            .components
            .iter()
            .find(|c| c.bom_ref == "llm-1")
            .unwrap();
        assert_eq!(llm.component_type, "machine-learning-model");
        assert!(llm
            .properties
            .iter()
            .any(|p| p.name == "sx:ai:endpoint" && p.value.contains("anthropic")));
        assert!(llm
            .properties
            .iter()
            .any(|p| p.name == "sx:ai:meta:model_id" && p.value == "claude"));
    }

    #[test]
    fn serialises_with_cyclonedx_keys() {
        let bom = build_aibom(&sample());
        let raw = serde_json::to_string(&bom).unwrap();
        assert!(raw.contains("\"bomFormat\":\"CycloneDX\""));
        assert!(raw.contains("\"specVersion\""));
        assert!(raw.contains("\"bom-ref\""));
        // to_value must round-trip too.
        let v = bom.to_value().unwrap();
        assert_eq!(v["bomFormat"], "CycloneDX");
    }
}
