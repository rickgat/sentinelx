//! Crate-level error type returned by every fallible SOAR API.

use thiserror::Error;

/// Errors surfaced by SOAR workflow definition, persistence, and execution.
#[derive(Debug, Clone, Error)]
pub enum SoarError {
    /// Workflow definition failed semantic validation (e.g. zero nodes,
    /// cycle, dangling edge, malformed action payload).
    #[error("invalid workflow: {0}")]
    InvalidDefinition(String),

    /// Lookup or update against a workflow id that does not exist for the
    /// tenant.
    #[error("workflow not found")]
    NotFound,

    /// Backing store rejected the write (uniqueness violation, RLS guard,
    /// etc.). The message is opaque enough to be safe to surface upward.
    #[error("storage error: {0}")]
    Storage(String),

    /// A downstream action port returned a failure during execution.
    /// Carries the offending node id and the renderable reason so the
    /// operator can locate the failing step in the run log.
    #[error("node {node_id} failed: {reason}")]
    ActionFailed {
        /// Identifier of the failing node in the workflow graph.
        node_id: String,
        /// Human-readable reason — never echoes secret material.
        reason: String,
    },

    /// Internal programmer error / poisoned mutex / etc. Should never be
    /// reachable through the public surface in steady state.
    #[error("internal: {0}")]
    Internal(String),
}

impl SoarError {
    /// Convenience constructor for invalid-definition errors.
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::InvalidDefinition(reason.into())
    }

    /// Convenience constructor for storage errors.
    pub fn storage(reason: impl Into<String>) -> Self {
        Self::Storage(reason.into())
    }

    /// Convenience constructor for internal errors.
    pub fn internal(reason: impl Into<String>) -> Self {
        Self::Internal(reason.into())
    }
}
