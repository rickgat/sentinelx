//! Prompt-injection / jailbreak probe harness.
//!
//! * [`corpus`] — the static probe corpus (OWASP/ATLAS-tagged).
//! * [`evaluator`] — the passive response scorer.
//! * This module — the [`LlmTarget`] trait (the thing under test), the
//!   engagement-scope gate ([`ProbeScope`]), the scope-gated runner
//!   ([`run_probes`]), and a [`RecordingLlmTarget`] test double.
//!
//! # Scope gating
//!
//! Probing is a live action. [`run_probes`] refuses to send anything unless
//! the caller presents a [`ProbeScope`] with `allowed == true`; otherwise it
//! returns [`AiAuditError::OutOfScope`] before the first byte is sent. This
//! is the enforcement point for the engagement-scope model — the HTTP /
//! service layers derive the scope from the authenticated engagement.

pub mod corpus;
pub mod evaluator;

use std::sync::Mutex;

use async_trait::async_trait;

pub use corpus::{Probe, ProbeCategory, BUILTIN_PROBES, INJECTION_CANARY};
pub use evaluator::{Evaluator, ProbeOutcome};

use crate::error::AiAuditError;

/// An authorization token for probing one target.
///
/// The HTTP / service layer constructs this *only after* confirming the
/// target falls inside an active, authorized engagement scope.
#[derive(Debug, Clone)]
pub struct ProbeScope {
    /// Whether probing this target is authorized.
    pub allowed: bool,
    /// A reference to the target this scope authorizes (asset id / URL),
    /// used in the out-of-scope error and audit trail.
    pub target_ref: String,
}

impl ProbeScope {
    /// An in-scope token for `target_ref`.
    #[must_use]
    pub fn allowed(target_ref: impl Into<String>) -> Self {
        Self {
            allowed: true,
            target_ref: target_ref.into(),
        }
    }

    /// An out-of-scope token for `target_ref` (probing will be refused).
    #[must_use]
    pub fn denied(target_ref: impl Into<String>) -> Self {
        Self {
            allowed: false,
            target_ref: target_ref.into(),
        }
    }
}

/// The LLM (or agentic) target under test.
///
/// Implementations wrap whatever transport reaches the real model. The
/// probe harness only ever calls [`LlmTarget::send`]; it never inspects the
/// transport, so a test double is a drop-in.
#[async_trait]
pub trait LlmTarget: Send + Sync {
    /// Send `prompt` to the target and return its textual response.
    ///
    /// # Errors
    ///
    /// Returns [`AiAuditError::TargetUnavailable`] when the target cannot be
    /// reached or returns a transport-level error.
    async fn send(&self, prompt: &str) -> Result<String, AiAuditError>;
}

/// Run the full built-in corpus against `target`, gated by `scope`.
///
/// # Errors
///
/// * [`AiAuditError::OutOfScope`] — `scope.allowed` is `false`; nothing is
///   sent.
/// * Any error [`LlmTarget::send`] returns is propagated.
pub async fn run_probes(
    target: &dyn LlmTarget,
    scope: &ProbeScope,
) -> Result<Vec<ProbeOutcome>, AiAuditError> {
    run_selected(target, scope, BUILTIN_PROBES).await
}

/// Run a caller-selected probe slice against `target`, gated by `scope`.
///
/// # Errors
///
/// See [`run_probes`].
pub async fn run_selected(
    target: &dyn LlmTarget,
    scope: &ProbeScope,
    probes: &[Probe],
) -> Result<Vec<ProbeOutcome>, AiAuditError> {
    if !scope.allowed {
        return Err(AiAuditError::OutOfScope(scope.target_ref.clone()));
    }
    let evaluator = Evaluator;
    let mut outcomes = Vec::with_capacity(probes.len());
    for probe in probes {
        let response = target.send(probe.prompt).await?;
        outcomes.push(evaluator.evaluate(probe, &response));
    }
    Ok(outcomes)
}

/// A test double that records every prompt it is sent and replies with a
/// canned response. Use it to exercise the harness and evaluator without a
/// live model.
#[derive(Debug, Default)]
pub struct RecordingLlmTarget {
    canned: String,
    sent: Mutex<Vec<String>>,
}

impl RecordingLlmTarget {
    /// A target that always replies with `canned`.
    #[must_use]
    pub fn new(canned: impl Into<String>) -> Self {
        Self {
            canned: canned.into(),
            sent: Mutex::new(Vec::new()),
        }
    }

    /// A well-guarded target that refuses every probe.
    #[must_use]
    pub fn refusing() -> Self {
        Self::new("I'm sorry, I can't help with that request.")
    }

    /// Snapshot the prompts received so far (test introspection).
    #[must_use]
    pub fn sent(&self) -> Vec<String> {
        self.sent.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl LlmTarget for RecordingLlmTarget {
    async fn send(&self, prompt: &str) -> Result<String, AiAuditError> {
        if let Ok(mut g) = self.sent.lock() {
            g.push(prompt.to_owned());
        }
        Ok(self.canned.clone())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn out_of_scope_sends_nothing() {
        let target = RecordingLlmTarget::refusing();
        let scope = ProbeScope::denied("https://api.example/llm");
        let err = run_probes(&target, &scope).await.unwrap_err();
        assert!(matches!(err, AiAuditError::OutOfScope(t) if t.contains("example")));
        // Crucially: not a single prompt was dispatched.
        assert!(target.sent().is_empty());
    }

    #[tokio::test]
    async fn in_scope_runs_the_full_corpus() {
        let target = RecordingLlmTarget::refusing();
        let scope = ProbeScope::allowed("asset-1");
        let outcomes = run_probes(&target, &scope).await.unwrap();
        assert_eq!(outcomes.len(), BUILTIN_PROBES.len());
        // A refusing target holds against every probe.
        assert!(outcomes.iter().all(|o| !o.success));
        assert_eq!(target.sent().len(), BUILTIN_PROBES.len());
    }

    #[tokio::test]
    async fn compromised_target_trips_injection_probes() {
        // A target that leaks the canary on every prompt.
        let target = RecordingLlmTarget::new(format!("ok {INJECTION_CANARY}"));
        let scope = ProbeScope::allowed("asset-1");
        let outcomes = run_probes(&target, &scope).await.unwrap();
        assert!(outcomes.iter().any(|o| o.success));
    }
}
