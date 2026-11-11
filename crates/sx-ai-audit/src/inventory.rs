//! AI asset inventory.
//!
//! The [`AiAssetSource`] trait abstracts over *how* AI assets are
//! discovered (a cloud scan, a registry crawl, an operator-supplied
//! manifest). The default [`InMemoryAiAssetSource`] holds a static set and
//! is the MVP source the composition root installs.
//!
//! No source in this module performs any network I/O — discovery that
//! reaches out to a live provider lands behind a dedicated, scope-gated
//! source in a later phase.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::AiAuditError;

/// The kind of AI asset a record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAssetKind {
    /// A hosted large-language-model inference endpoint.
    LlmApiEndpoint,
    /// A model registry (e.g. an internal MLflow / Hugging Face mirror).
    ModelRegistry,
    /// A vector store / embedding database.
    VectorStore,
    /// A serialised model artifact on disk / in object storage.
    ModelFile,
    /// An agent-orchestration framework deployment.
    AgentFramework,
    /// A Model Context Protocol (MCP) server.
    McpServer,
}

impl AiAssetKind {
    /// Short, machine-readable code matching the serde tag.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LlmApiEndpoint => "llm_api_endpoint",
            Self::ModelRegistry => "model_registry",
            Self::VectorStore => "vector_store",
            Self::ModelFile => "model_file",
            Self::AgentFramework => "agent_framework",
            Self::McpServer => "mcp_server",
        }
    }
}

/// One discovered AI asset belonging to a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiAsset {
    /// Stable, source-assigned identifier.
    pub id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// What kind of asset this is.
    pub kind: AiAssetKind,
    /// Human-readable name.
    pub name: String,
    /// Provider / vendor (e.g. `"anthropic"`, `"self-hosted"`).
    pub provider: String,
    /// Network endpoint when applicable (URL, host:port). `None` for
    /// file-backed assets.
    pub endpoint: Option<String>,
    /// RFC 3339 timestamp the asset was discovered.
    pub discovered_at: String,
    /// Free-form provenance / configuration metadata.
    pub metadata: BTreeMap<String, String>,
}

impl AiAsset {
    /// Construct a minimal asset with no endpoint and empty metadata.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        tenant_id: impl Into<String>,
        kind: AiAssetKind,
        name: impl Into<String>,
        provider: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            tenant_id: tenant_id.into(),
            kind,
            name: name.into(),
            provider: provider.into(),
            endpoint: None,
            discovered_at: crate::now_rfc3339(),
            metadata: BTreeMap::new(),
        }
    }

    /// Builder: set the network endpoint.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Builder: insert a metadata key/value pair.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let _ = self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A source of AI assets for a tenant.
///
/// Implementations must be `Send + Sync` so the composition root can share
/// them behind an `Arc` across the async runtime.
#[async_trait]
pub trait AiAssetSource: Send + Sync + std::fmt::Debug {
    /// Enumerate every AI asset visible for `tenant_id`.
    async fn enumerate(&self, tenant_id: &str) -> Result<Vec<AiAsset>, AiAuditError>;
}

/// An in-memory [`AiAssetSource`]. Holds a static set and filters by
/// tenant on `enumerate`. Pure (no I/O).
#[derive(Debug, Clone, Default)]
pub struct InMemoryAiAssetSource {
    assets: Vec<AiAsset>,
}

impl InMemoryAiAssetSource {
    /// Build a source from an explicit asset list.
    #[must_use]
    pub fn new(assets: Vec<AiAsset>) -> Self {
        Self { assets }
    }

    /// Builder: append one asset.
    #[must_use]
    pub fn with_asset(mut self, asset: AiAsset) -> Self {
        self.assets.push(asset);
        self
    }

    /// A small, realistic demo inventory for `tenant_id`, used by the
    /// MVP composition root so the dashboard has something to render.
    #[must_use]
    pub fn seeded_demo(tenant_id: &str) -> Self {
        let assets = vec![
            AiAsset::new(
                "ai-asset-llm-01",
                tenant_id,
                AiAssetKind::LlmApiEndpoint,
                "Remediation Copilot (Claude)",
                "anthropic",
            )
            .with_endpoint("https://api.anthropic.com/v1/messages")
            .with_metadata("model_id", "claude-opus-4")
            .with_metadata("purpose", "sx-remediation copilot"),
            AiAsset::new(
                "ai-asset-registry-01",
                tenant_id,
                AiAssetKind::ModelRegistry,
                "Internal Model Registry",
                "self-hosted",
            )
            .with_endpoint("https://registry.internal.example/models")
            .with_metadata("backend", "mlflow"),
            AiAsset::new(
                "ai-asset-vector-01",
                tenant_id,
                AiAssetKind::VectorStore,
                "Finding Embeddings Store",
                "self-hosted",
            )
            .with_endpoint("https://vectors.internal.example")
            .with_metadata("engine", "qdrant"),
            AiAsset::new(
                "ai-asset-mcp-01",
                tenant_id,
                AiAssetKind::McpServer,
                "Threat-Intel MCP Server",
                "self-hosted",
            )
            .with_endpoint("stdio://threat-intel-mcp")
            .with_metadata("tools", "lookup_ioc,enrich_cve"),
        ];
        Self { assets }
    }
}

#[async_trait]
impl AiAssetSource for InMemoryAiAssetSource {
    async fn enumerate(&self, tenant_id: &str) -> Result<Vec<AiAsset>, AiAuditError> {
        if tenant_id.is_empty() {
            return Err(AiAuditError::Invalid("tenant_id is empty".to_owned()));
        }
        Ok(self
            .assets
            .iter()
            .filter(|a| a.tenant_id == tenant_id)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enumerate_filters_by_tenant() {
        let src = InMemoryAiAssetSource::new(vec![
            AiAsset::new("a", "t-a", AiAssetKind::LlmApiEndpoint, "A", "p"),
            AiAsset::new("b", "t-b", AiAssetKind::VectorStore, "B", "p"),
        ]);
        let only_a = src.enumerate("t-a").await.unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].id, "a");
    }

    #[tokio::test]
    async fn empty_tenant_is_rejected() {
        let src = InMemoryAiAssetSource::default();
        let err = src.enumerate("").await.unwrap_err();
        assert!(matches!(err, AiAuditError::Invalid(_)));
    }

    #[tokio::test]
    async fn seeded_demo_is_tenant_scoped() {
        let src = InMemoryAiAssetSource::seeded_demo("t-demo");
        let rows = src.enumerate("t-demo").await.unwrap();
        assert!(rows.len() >= 4);
        assert!(rows.iter().all(|a| a.tenant_id == "t-demo"));
        // Another tenant sees nothing from the demo source.
        assert!(src.enumerate("t-other").await.unwrap().is_empty());
    }

    #[test]
    fn asset_round_trips_through_serde() {
        let a = AiAsset::new("id", "t", AiAssetKind::McpServer, "n", "self-hosted")
            .with_endpoint("stdio://x")
            .with_metadata("k", "v");
        let raw = serde_json::to_string(&a).unwrap();
        let back: AiAsset = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, a);
        assert!(raw.contains("mcp_server"));
    }
}
