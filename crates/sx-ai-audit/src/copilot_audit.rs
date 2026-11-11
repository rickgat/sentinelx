//! Copilot decision audit.
//!
//! Satisfies ADR-0004 §Decision item 7 ("Audit logging"): every copilot
//! invocation writes a record capturing the **hashed** redacted prompt, the
//! **hashed** response, the model id, and the user id. Plaintext never
//! enters this record — only SHA-256 digests — so the audit trail is safe to
//! persist and replay.
//!
//! The [`CopilotAuditSink`] trait is the append-only write seam; the
//! composition root installs an [`InMemoryCopilotAuditSink`] for the MVP (or
//! a [`NullCopilotAuditSink`] to disable it).

use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AiAuditError;

/// Hash an input with SHA-256 and return lowercase hex.
#[must_use]
pub fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex::encode(digest)
}

/// An append-only copilot-decision audit record.
///
/// Prompt and response are stored **only** as SHA-256 hex digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopilotDecisionAudit {
    /// SHA-256 hex of the (already redacted) prompt.
    pub prompt_hash: String,
    /// SHA-256 hex of the response.
    pub response_hash: String,
    /// Model of record (e.g. `"claude-opus-4"`).
    pub model_id: String,
    /// Acting user id.
    pub user_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// The decision / action taken (e.g. `"remediation_draft"`,
    /// `"ai_audit_run"`).
    pub action: String,
    /// RFC 3339 timestamp the decision was made.
    pub decided_at: String,
}

impl CopilotDecisionAudit {
    /// Build a record, hashing `prompt` and `response` with SHA-256 and
    /// stamping the current time.
    #[must_use]
    pub fn new(
        tenant_id: impl Into<String>,
        user_id: impl Into<String>,
        model_id: impl Into<String>,
        action: impl Into<String>,
        prompt: &str,
        response: &str,
    ) -> Self {
        Self {
            prompt_hash: sha256_hex(prompt.as_bytes()),
            response_hash: sha256_hex(response.as_bytes()),
            model_id: model_id.into(),
            user_id: user_id.into(),
            tenant_id: tenant_id.into(),
            action: action.into(),
            decided_at: crate::now_rfc3339(),
        }
    }
}

/// An append-only sink for copilot-decision audit records.
#[async_trait]
pub trait CopilotAuditSink: Send + Sync + std::fmt::Debug {
    /// Append one decision record.
    ///
    /// # Errors
    ///
    /// Returns [`AiAuditError::Sink`] if the backing store rejects the write.
    async fn record(&self, entry: CopilotDecisionAudit) -> Result<(), AiAuditError>;

    /// Snapshot every record written so far (newest last). Used by tests and
    /// by read-side inspection in the composition root.
    async fn all(&self, tenant_id: &str) -> Result<Vec<CopilotDecisionAudit>, AiAuditError>;
}

/// An in-memory [`CopilotAuditSink`] backed by a `Mutex<Vec<_>>`.
#[derive(Debug, Default)]
pub struct InMemoryCopilotAuditSink {
    records: Mutex<Vec<CopilotDecisionAudit>>,
}

impl InMemoryCopilotAuditSink {
    /// A fresh, empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current record count across all tenants (test introspection).
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Whether the sink is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl CopilotAuditSink for InMemoryCopilotAuditSink {
    async fn record(&self, entry: CopilotDecisionAudit) -> Result<(), AiAuditError> {
        let mut guard = self
            .records
            .lock()
            .map_err(|_| AiAuditError::Sink("audit sink lock poisoned".to_owned()))?;
        guard.push(entry);
        drop(guard);
        Ok(())
    }

    async fn all(&self, tenant_id: &str) -> Result<Vec<CopilotDecisionAudit>, AiAuditError> {
        let guard = self
            .records
            .lock()
            .map_err(|_| AiAuditError::Sink("audit sink lock poisoned".to_owned()))?;
        let out = guard
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        drop(guard);
        Ok(out)
    }
}

/// A no-op [`CopilotAuditSink`] that discards every record. Use to disable
/// copilot audit without changing call sites.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullCopilotAuditSink;

#[async_trait]
impl CopilotAuditSink for NullCopilotAuditSink {
    async fn record(&self, _entry: CopilotDecisionAudit) -> Result<(), AiAuditError> {
        Ok(())
    }

    async fn all(&self, _tenant_id: &str) -> Result<Vec<CopilotDecisionAudit>, AiAuditError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn record_hashes_prompt_and_response() {
        let r = CopilotDecisionAudit::new(
            "t",
            "u",
            "claude-opus-4",
            "ai_audit_run",
            "secret prompt",
            "the response",
        );
        // 64 hex chars for SHA-256.
        assert_eq!(r.prompt_hash.len(), 64);
        assert_eq!(r.response_hash.len(), 64);
        // Plaintext never appears.
        assert_ne!(r.prompt_hash, "secret prompt");
        assert_eq!(r.prompt_hash, sha256_hex(b"secret prompt"));
    }

    #[tokio::test]
    async fn in_memory_sink_appends_and_isolates_by_tenant() {
        let sink = InMemoryCopilotAuditSink::new();
        assert!(sink.is_empty());
        sink.record(CopilotDecisionAudit::new("t-a", "u", "m", "a", "p", "r"))
            .await
            .unwrap();
        sink.record(CopilotDecisionAudit::new("t-b", "u", "m", "a", "p", "r"))
            .await
            .unwrap();
        assert_eq!(sink.len(), 2);
        assert_eq!(sink.all("t-a").await.unwrap().len(), 1);
        assert_eq!(sink.all("t-b").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn null_sink_discards() {
        let sink = NullCopilotAuditSink;
        sink.record(CopilotDecisionAudit::new("t", "u", "m", "a", "p", "r"))
            .await
            .unwrap();
        assert!(sink.all("t").await.unwrap().is_empty());
    }
}
