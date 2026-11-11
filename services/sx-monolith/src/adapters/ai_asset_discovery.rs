//! AI asset discovery from the dependency SBOM (#5).
//!
//! Makes the AI-audit inventory *real* instead of demo-seeded: scans the
//! checked-in SBOM (syft / CycloneDX / grype JSON) for signatures of AI
//! dependencies — LLM SDKs, vector databases, model registries, agent
//! frameworks, MCP servers, ML runtimes — and materialises each as an
//! [`AiAsset`]. Substring matching over the SBOM text keeps the detector
//! robust against SBOM schema differences and cheap (no full JSON parse).
//!
//! The detected assets are tenant-scoped to the supplied tenant and merged
//! with the demo inventory by the composition root, so `/v1/ai-audit/assets`
//! reflects the platform's actual AI dependency surface.

use std::path::Path;

use sx_ai_audit::inventory::{AiAsset, AiAssetKind};

/// One AI dependency signature: a lowercase package marker mapped to the
/// asset it implies.
struct Signature {
    /// Substring to look for in the SBOM (lowercased).
    marker: &'static str,
    kind: AiAssetKind,
    provider: &'static str,
    name: &'static str,
}

/// Curated AI dependency signatures. Ordered so the most specific win; the
/// detector de-duplicates on `(kind, provider)`.
const SIGNATURES: &[Signature] = &[
    Signature {
        marker: "openai",
        kind: AiAssetKind::LlmApiEndpoint,
        provider: "OpenAI",
        name: "OpenAI API client",
    },
    Signature {
        marker: "anthropic",
        kind: AiAssetKind::LlmApiEndpoint,
        provider: "Anthropic",
        name: "Anthropic Claude API client",
    },
    Signature {
        marker: "cohere",
        kind: AiAssetKind::LlmApiEndpoint,
        provider: "Cohere",
        name: "Cohere API client",
    },
    Signature {
        marker: "ollama",
        kind: AiAssetKind::LlmApiEndpoint,
        provider: "Ollama",
        name: "Ollama local LLM runtime",
    },
    Signature {
        marker: "mistralai",
        kind: AiAssetKind::LlmApiEndpoint,
        provider: "Mistral",
        name: "Mistral API client",
    },
    Signature {
        marker: "google-generativeai",
        kind: AiAssetKind::LlmApiEndpoint,
        provider: "Google",
        name: "Google Generative AI client",
    },
    Signature {
        marker: "langchain",
        kind: AiAssetKind::AgentFramework,
        provider: "LangChain",
        name: "LangChain agent framework",
    },
    Signature {
        marker: "llama-index",
        kind: AiAssetKind::AgentFramework,
        provider: "LlamaIndex",
        name: "LlamaIndex framework",
    },
    Signature {
        marker: "llama_index",
        kind: AiAssetKind::AgentFramework,
        provider: "LlamaIndex",
        name: "LlamaIndex framework",
    },
    Signature {
        marker: "autogen",
        kind: AiAssetKind::AgentFramework,
        provider: "AutoGen",
        name: "AutoGen multi-agent framework",
    },
    Signature {
        marker: "huggingface",
        kind: AiAssetKind::ModelRegistry,
        provider: "Hugging Face",
        name: "Hugging Face Hub",
    },
    Signature {
        marker: "transformers",
        kind: AiAssetKind::ModelFile,
        provider: "Hugging Face",
        name: "Transformers model runtime",
    },
    Signature {
        marker: "onnxruntime",
        kind: AiAssetKind::ModelFile,
        provider: "ONNX",
        name: "ONNX Runtime",
    },
    Signature {
        marker: "tensorflow",
        kind: AiAssetKind::ModelFile,
        provider: "TensorFlow",
        name: "TensorFlow runtime",
    },
    Signature {
        marker: "pytorch",
        kind: AiAssetKind::ModelFile,
        provider: "PyTorch",
        name: "PyTorch runtime",
    },
    Signature {
        marker: "safetensors",
        kind: AiAssetKind::ModelFile,
        provider: "Hugging Face",
        name: "safetensors model weights",
    },
    Signature {
        marker: "pinecone",
        kind: AiAssetKind::VectorStore,
        provider: "Pinecone",
        name: "Pinecone vector DB",
    },
    Signature {
        marker: "chromadb",
        kind: AiAssetKind::VectorStore,
        provider: "Chroma",
        name: "Chroma vector DB",
    },
    Signature {
        marker: "weaviate",
        kind: AiAssetKind::VectorStore,
        provider: "Weaviate",
        name: "Weaviate vector DB",
    },
    Signature {
        marker: "qdrant",
        kind: AiAssetKind::VectorStore,
        provider: "Qdrant",
        name: "Qdrant vector DB",
    },
    Signature {
        marker: "milvus",
        kind: AiAssetKind::VectorStore,
        provider: "Milvus",
        name: "Milvus vector DB",
    },
    Signature {
        marker: "pgvector",
        kind: AiAssetKind::VectorStore,
        provider: "pgvector",
        name: "pgvector (Postgres) store",
    },
    Signature {
        marker: "modelcontextprotocol",
        kind: AiAssetKind::McpServer,
        provider: "MCP",
        name: "Model Context Protocol server",
    },
    Signature {
        marker: "\"mcp\"",
        kind: AiAssetKind::McpServer,
        provider: "MCP",
        name: "Model Context Protocol server",
    },
];

/// Detect AI assets by scanning `sbom_text` for dependency signatures.
#[must_use]
pub(crate) fn detect_from_text(sbom_text: &str, tenant_id: &str) -> Vec<AiAsset> {
    let haystack = sbom_text.to_ascii_lowercase();
    let mut seen: Vec<(AiAssetKind, &'static str)> = Vec::new();
    let mut assets = Vec::new();
    for sig in SIGNATURES {
        if !haystack.contains(sig.marker) {
            continue;
        }
        if seen.contains(&(sig.kind, sig.provider)) {
            continue;
        }
        seen.push((sig.kind, sig.provider));
        let id = format!(
            "ai-dep:{}:{}",
            sig.kind.code(),
            sig.provider.to_ascii_lowercase()
        );
        assets.push(
            AiAsset::new(id, tenant_id, sig.kind, sig.name, sig.provider)
                .with_metadata("source", "sbom-dependency-scan")
                .with_metadata("marker", sig.marker),
        );
    }
    assets
}

/// Detect AI assets from an on-disk SBOM file. Returns an empty vec when the
/// file is absent or unreadable (the caller falls back to the demo inventory).
#[must_use]
pub(crate) fn detect_from_file(path: &Path, tenant_id: &str) -> Vec<AiAsset> {
    match std::fs::read_to_string(path) {
        Ok(text) => detect_from_text(&text, tenant_id),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_llm_vector_and_framework() {
        let sbom = r#"{"artifacts":[{"name":"openai"},{"name":"langchain"},{"name":"pinecone-client"},{"name":"transformers"}]}"#;
        let assets = detect_from_text(sbom, "t-1");
        let kinds: Vec<&str> = assets.iter().map(|a| a.kind.code()).collect();
        assert!(kinds.contains(&"llm_api_endpoint"));
        assert!(kinds.contains(&"agent_framework"));
        assert!(kinds.contains(&"vector_store"));
        assert!(kinds.contains(&"model_file"));
        assert!(assets.iter().all(|a| a.tenant_id == "t-1"));
    }

    #[test]
    fn dedupes_same_kind_provider() {
        // Two Hugging Face markers (huggingface + transformers map to HF) —
        // transformers is ModelFile, huggingface is ModelRegistry → distinct.
        let sbom = "openai openai openai";
        let assets = detect_from_text(sbom, "t");
        assert_eq!(
            assets.len(),
            1,
            "duplicate OpenAI markers collapse to one asset"
        );
    }

    #[test]
    fn empty_sbom_yields_nothing() {
        assert!(detect_from_text("{\"artifacts\":[]}", "t").is_empty());
    }
}
