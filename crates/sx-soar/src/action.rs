//! Action enum + `ActionExecutor` registry the SOAR DAG executor invokes.
//!
//! Each [`Action`] variant maps onto exactly one downstream
//! [`ActionExecutor`] implementation registered in the
//! [`ActionRegistry`]. The DAG executor dispatches by variant name —
//! variants and their executor wiring are decoupled so embedders can swap
//! the HTTP / remediation / webhook adapters without touching the engine.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::SoarError;

/// One executable action variant.
///
/// The JSON DSL serialises each variant under a `kind` discriminator so a
/// dashboard editor can render variant-specific fields with no schema
/// coupling.
///
/// The MVP ships four action kinds covering the three port-backed
/// integrations called out in P3-005 (HTTP, remediation, webhook) plus a
/// pure-data variant used by tests + dry-runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// Issue an outbound HTTP request. The DAG executor pipes the trigger
    /// payload as the JSON body and forwards arbitrary headers.
    HttpRequest {
        /// HTTP method (`GET`, `POST`, `PUT`, `DELETE`, ...).
        method: String,
        /// Fully-qualified target URL.
        url: String,
        /// Header bag forwarded to the downstream port verbatim.
        #[serde(default)]
        headers: HashMap<String, String>,
        /// Optional request body. When `None`, the executor forwards the
        /// trigger payload as JSON.
        #[serde(default)]
        body: Option<serde_json::Value>,
    },
    /// Invoke an `sx-remediation` play. The play id is statically pinned
    /// in the workflow so the operator's intent is auditable.
    RunRemediationPlay {
        /// Play identifier (matches `sx_remediation::PlayId`).
        play_id: String,
        /// Free-form play parameters forwarded to the play runner.
        #[serde(default)]
        params: serde_json::Value,
    },
    /// Emit an outbound webhook via `sx-webhooks`.
    EmitWebhook {
        /// Logical webhook topic (e.g. `"finding.created"`).
        topic: String,
        /// JSON payload forwarded to subscribers. Falls back to the
        /// trigger payload when omitted.
        #[serde(default)]
        payload: Option<serde_json::Value>,
    },
    /// No-op action useful for tests + dashboard dry-runs. Returns its
    /// `tag` as detail so the run log can echo it.
    Noop {
        /// Free-form tag echoed in the run log.
        tag: String,
    },
}

impl Action {
    /// Stable lowercase action-kind label used by the executor's run log
    /// and the dashboard. Mirrors the serde tag.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::HttpRequest { .. } => "http_request",
            Self::RunRemediationPlay { .. } => "run_remediation_play",
            Self::EmitWebhook { .. } => "emit_webhook",
            Self::Noop { .. } => "noop",
        }
    }
}

/// Per-action execution outcome captured in the run log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResult {
    /// Identifier of the node whose action produced this result.
    pub node_id: String,
    /// Action kind label (mirrors [`Action::kind`]).
    pub kind: String,
    /// Final status of the action.
    pub status: ActionStatus,
    /// Free-form opaque detail rendered for the operator (e.g. HTTP
    /// response excerpt, webhook id). Never contains secret material.
    pub detail: serde_json::Value,
}

/// Terminal status of an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionStatus {
    /// Action completed cleanly.
    Ok,
    /// Action returned a domain failure.
    Failed,
}

// ---------------------------------------------------------------------------
// ActionExecutor trait + registry
// ---------------------------------------------------------------------------

/// Single downstream port the DAG executor calls per action node.
///
/// One implementation per action `kind` is registered in the
/// [`ActionRegistry`]. The trait is intentionally minimal — the executor
/// passes the *full* parsed [`Action`] plus the immutable trigger payload
/// snapshot so the executor never needs to know which fields a given
/// adapter consumes.
#[async_trait]
pub trait ActionExecutor: Send + Sync {
    /// Execute `action` against `trigger_payload` and return free-form
    /// detail (e.g. HTTP status, webhook id). Errors propagate as
    /// [`SoarError::ActionFailed`] in the executor frame.
    async fn execute(
        &self,
        action: &Action,
        trigger_payload: &serde_json::Value,
    ) -> Result<serde_json::Value, SoarError>;
}

/// Composition-root container for one [`ActionExecutor`] per
/// [`Action::kind`].
///
/// Built once at startup; cheap to clone (every entry is an `Arc`).
#[derive(Clone, Default)]
pub struct ActionRegistry {
    inner: HashMap<&'static str, Arc<dyn ActionExecutor>>,
}

impl std::fmt::Debug for ActionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionRegistry")
            .field("kinds", &self.inner.keys().copied().collect::<Vec<_>>())
            .finish()
    }
}

impl ActionRegistry {
    /// Build an empty registry. Use [`register`](Self::register) to add
    /// adapters before passing to [`crate::executor::DagExecutor`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `executor` for action `kind`. Replaces any prior entry
    /// for the same kind — tests rely on this to swap stubs.
    #[must_use]
    pub fn register(mut self, kind: &'static str, executor: Arc<dyn ActionExecutor>) -> Self {
        self.inner.insert(kind, executor);
        self
    }

    /// Look up the executor registered for `kind`. Returns `None` when
    /// no adapter has been wired — the DAG executor surfaces this as
    /// [`SoarError::Internal`].
    #[must_use]
    pub fn get(&self, kind: &str) -> Option<Arc<dyn ActionExecutor>> {
        self.inner.get(kind).cloned()
    }

    /// Stable iterator over registered action kinds.
    pub fn kinds(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.inner.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;
    #[async_trait]
    impl ActionExecutor for Echo {
        async fn execute(
            &self,
            action: &Action,
            _payload: &serde_json::Value,
        ) -> Result<serde_json::Value, SoarError> {
            Ok(serde_json::json!({ "kind": action.kind() }))
        }
    }

    #[test]
    fn action_kind_labels_match_serde_tags() {
        let a = Action::HttpRequest {
            method: "POST".into(),
            url: "https://example.com".into(),
            headers: HashMap::new(),
            body: None,
        };
        assert_eq!(a.kind(), "http_request");
        let a = Action::RunRemediationPlay {
            play_id: "rotate_secrets".into(),
            params: serde_json::Value::Null,
        };
        assert_eq!(a.kind(), "run_remediation_play");
        let a = Action::EmitWebhook {
            topic: "x".into(),
            payload: None,
        };
        assert_eq!(a.kind(), "emit_webhook");
        let a = Action::Noop { tag: "x".into() };
        assert_eq!(a.kind(), "noop");
    }

    #[test]
    fn registry_round_trips_by_kind() {
        let reg = ActionRegistry::new().register("noop", Arc::new(Echo));
        assert!(reg.get("noop").is_some());
        assert!(reg.get("missing").is_none());
        assert_eq!(reg.kinds(), vec!["noop"]);
    }

    #[test]
    fn action_serde_round_trip() {
        let a = Action::HttpRequest {
            method: "POST".into(),
            url: "https://hooks.example/relay".into(),
            headers: HashMap::new(),
            body: Some(serde_json::json!({ "k": "v" })),
        };
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("http_request"));
        let back: Action = serde_json::from_str(&s).unwrap();
        assert_eq!(back, a);
    }
}
