//! Domain services: vendor sources, sanitiser, LLM client, registry.

pub mod cisco;
pub mod claude_client;
pub mod explain;
pub mod llm_client;
pub mod msrc;
pub mod outcomes;
pub mod redhat;
pub mod registry;
pub mod sanitiser;
pub mod source;
pub mod ubuntu;

/// User-Agent string emitted on every outbound HTTP request originating
/// from this crate.
pub(crate) const USER_AGENT: &str =
    "SentinelX-Remediation/0.1 (+https://sentinelx.example.invalid)";

/// Default per-request timeout for vendor advisory sources.
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 10;
