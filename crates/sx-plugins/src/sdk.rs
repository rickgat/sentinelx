//! Plugin SDK — the stable trait third-party authors implement.
//!
//! There are two ways to ship a plugin to `SentinelX`:
//!
//! 1. **External (default)** — run a standalone HTTP service that
//!    handles signed [`crate::PluginEnvelope`] POSTs from the host.
//!    The plugin verifies the signature with [`crate::verify_signature`]
//!    and replies 2xx. This module is irrelevant — the SDK contract
//!    is purely the envelope + HMAC + manifest JSON.
//!
//! 2. **In-process (advanced)** — implement the [`Plugin`] trait and
//!    register a `Box<dyn Plugin>` with the host loader (used by tests +
//!    by the dev "no-op" plugin shipped here). This path is intentionally
//!    capability-scoped: the host hands the plugin a [`HostContext`]
//!    whose surface is exactly the *required scopes* declared in the
//!    plugin's [`crate::PluginManifest`].
//!
//! ## Required scopes
//!
//! Every host function (`read_findings`, `write_annotation`,
//! `fetch_url`) is gated on a stable lowercase scope string:
//!
//! - `findings:read`        — list findings (tenant-scoped).
//! - `findings:annotate`    — append a free-form annotation to a finding.
//! - `http:fetch`           — outbound HTTP fetch, with the URL allow-list
//!   in [`HostFetchPolicy::allow_list`].
//!
//! Calls that touch a scope the plugin did not declare in its manifest
//! return [`HostError::ScopeDenied`] *without* invoking the inner
//! capability — that's the **capability-scoped host functions**
//! requirement of P3-007.

use std::collections::HashSet;
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::envelope::PluginEnvelope;

/// Stable scope identifier — lowercased `resource:action`, dot-free.
///
/// The wire form is intentionally a `String`, not a sealed enum, so the
/// host can extend the scope vocabulary in a backwards-compatible way
/// (older plugins simply do not request the new scope).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scope(pub String);

impl Scope {
    /// Stable scope: list findings for the tenant.
    pub const FINDINGS_READ: &'static str = "findings:read";
    /// Stable scope: append annotations to findings.
    pub const FINDINGS_ANNOTATE: &'static str = "findings:annotate";
    /// Stable scope: outbound HTTP fetch (host-mediated, allow-listed).
    pub const HTTP_FETCH: &'static str = "http:fetch";

    /// Build a scope from a string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow as `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Per-scope errors surfaced by host functions.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HostError {
    /// The plugin invoked a host function whose scope was not declared
    /// in its [`crate::PluginManifest`].
    #[error("scope denied: {0}")]
    ScopeDenied(String),
    /// The plugin tried to fetch a URL not on the host's allow-list.
    #[error("url not allow-listed: {0}")]
    UrlNotAllowed(String),
    /// Underlying dependency (storage, network) failed.
    #[error("dependency: {0}")]
    Dependency(String),
}

/// Compact finding projection surfaced to plugins via
/// [`HostContext::list_findings`]. Only the fields safe to expose
/// across a plugin trust boundary are included — no PII, no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginFindingView {
    /// Finding id (opaque to the plugin).
    pub id: String,
    /// Severity bucket (`critical|high|medium|low|info`).
    pub severity: String,
    /// Short title.
    pub title: String,
    /// Status (`open|triaged|fixed|wont_fix`).
    pub status: String,
}

/// Outbound-fetch policy enforced by the host.
#[derive(Debug, Clone, Default)]
pub struct HostFetchPolicy {
    /// Allow-listed hosts (`example.com`, `api.example.org`). Empty
    /// allow-list ⇒ every fetch is denied.
    pub allow_list: HashSet<String>,
}

impl HostFetchPolicy {
    /// Build a policy with the supplied allow-list.
    #[must_use]
    pub fn with_hosts<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allow_list: hosts.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns true when `host` is on the allow-list.
    #[must_use]
    pub fn is_allowed(&self, host: &str) -> bool {
        self.allow_list.contains(host)
    }
}

/// Capability handle handed to in-process plugins.
///
/// Each method first checks that the caller's `granted_scopes` contains
/// the relevant scope; this is the **capability-scoped host functions**
/// requirement of P3-007.
#[async_trait]
pub trait HostContext: Send + Sync + std::fmt::Debug {
    /// The tenant the plugin is scoped to. The plugin cannot widen its
    /// scope here — the host minted the context with this tenant id and
    /// every downstream call uses it.
    fn tenant_id(&self) -> &str;

    /// Scopes the manifest declared, projected from
    /// [`crate::PluginManifest::required_scopes`].
    fn granted_scopes(&self) -> &HashSet<String>;

    /// List findings for the plugin's tenant.
    ///
    /// # Errors
    ///
    /// * [`HostError::ScopeDenied`] when the plugin did not declare
    ///   `findings:read`.
    async fn list_findings(&self, limit: usize) -> Result<Vec<PluginFindingView>, HostError>;

    /// Annotate a finding for the plugin's tenant.
    ///
    /// # Errors
    ///
    /// * [`HostError::ScopeDenied`] when the plugin did not declare
    ///   `findings:annotate`.
    async fn annotate_finding(&self, finding_id: &str, note: &str) -> Result<(), HostError>;

    /// Outbound HTTP fetch, allow-listed by the host.
    ///
    /// # Errors
    ///
    /// * [`HostError::ScopeDenied`] when the plugin did not declare
    ///   `http:fetch`.
    /// * [`HostError::UrlNotAllowed`] when the URL's host is not on the
    ///   host's [`HostFetchPolicy`] allow-list.
    async fn fetch_url(&self, url: &str) -> Result<Vec<u8>, HostError>;
}

/// Stable plugin trait. In-process plugins implement this; the host
/// loader dispatches every [`PluginEnvelope`] through
/// [`Plugin::on_event`].
///
/// External (HTTP) plugins do *not* implement this trait — they ship
/// their own server-side handler. The envelope + signature contract is
/// the SDK surface for them.
#[async_trait]
pub trait Plugin: Send + Sync + std::fmt::Debug {
    /// Plugin name (stable string used by the marketplace UI).
    fn name(&self) -> &str;

    /// Handle a single inbound envelope.
    ///
    /// # Errors
    ///
    /// The plugin can return any [`HostError`] (typically scope or URL
    /// rejection) — the loader records the outcome alongside the
    /// dispatch history.
    async fn on_event(
        &self,
        ctx: &dyn HostContext,
        envelope: &PluginEnvelope,
    ) -> Result<(), HostError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// In-memory `HostContext` used by SDK tests + by the no-op test
    /// plugin shipped in the integration suite.
    #[derive(Debug)]
    struct StubHost {
        tenant_id: String,
        scopes: HashSet<String>,
        findings: Vec<PluginFindingView>,
        annotated: std::sync::Mutex<Vec<(String, String)>>,
        fetch_policy: HostFetchPolicy,
    }

    impl StubHost {
        fn new(
            tenant_id: &str,
            scopes: impl IntoIterator<Item = &'static str>,
            findings: Vec<PluginFindingView>,
            policy: HostFetchPolicy,
        ) -> Self {
            Self {
                tenant_id: tenant_id.to_owned(),
                scopes: scopes.into_iter().map(ToOwned::to_owned).collect(),
                findings,
                annotated: std::sync::Mutex::new(Vec::new()),
                fetch_policy: policy,
            }
        }
    }

    #[async_trait]
    impl HostContext for StubHost {
        fn tenant_id(&self) -> &str {
            &self.tenant_id
        }
        fn granted_scopes(&self) -> &HashSet<String> {
            &self.scopes
        }
        async fn list_findings(&self, limit: usize) -> Result<Vec<PluginFindingView>, HostError> {
            if !self.scopes.contains(Scope::FINDINGS_READ) {
                return Err(HostError::ScopeDenied(Scope::FINDINGS_READ.into()));
            }
            Ok(self.findings.iter().take(limit).cloned().collect())
        }
        async fn annotate_finding(&self, finding_id: &str, note: &str) -> Result<(), HostError> {
            if !self.scopes.contains(Scope::FINDINGS_ANNOTATE) {
                return Err(HostError::ScopeDenied(Scope::FINDINGS_ANNOTATE.into()));
            }
            {
                let mut g = self
                    .annotated
                    .lock()
                    .map_err(|_| HostError::Dependency("annotate mutex".into()))?;
                g.push((finding_id.to_owned(), note.to_owned()));
            }
            Ok(())
        }
        async fn fetch_url(&self, url: &str) -> Result<Vec<u8>, HostError> {
            if !self.scopes.contains(Scope::HTTP_FETCH) {
                return Err(HostError::ScopeDenied(Scope::HTTP_FETCH.into()));
            }
            let parsed = url::Url::parse(url)
                .map_err(|e| HostError::Dependency(format!("url parse: {e}")))?;
            let host = parsed.host_str().unwrap_or("");
            if !self.fetch_policy.is_allowed(host) {
                return Err(HostError::UrlNotAllowed(host.to_owned()));
            }
            Ok(b"ok".to_vec())
        }
    }

    #[derive(Debug)]
    struct NoopPlugin;

    #[async_trait]
    impl Plugin for NoopPlugin {
        #[allow(clippy::unnecessary_literal_bound)]
        fn name(&self) -> &str {
            "noop"
        }
        async fn on_event(
            &self,
            ctx: &dyn HostContext,
            _e: &PluginEnvelope,
        ) -> Result<(), HostError> {
            // Exercise the host capability — proves it round-trips.
            let _ = ctx.list_findings(1).await?;
            Ok(())
        }
    }

    fn finding() -> PluginFindingView {
        PluginFindingView {
            id: "f1".into(),
            severity: "high".into(),
            title: "demo".into(),
            status: "open".into(),
        }
    }

    #[tokio::test]
    async fn list_findings_requires_findings_read_scope() {
        let host = StubHost::new("t1", [], vec![finding()], HostFetchPolicy::default());
        let err = host.list_findings(10).await.expect_err("must deny");
        assert!(matches!(err, HostError::ScopeDenied(_)));
    }

    #[tokio::test]
    async fn list_findings_succeeds_with_scope() {
        let host = StubHost::new(
            "t1",
            [Scope::FINDINGS_READ],
            vec![finding()],
            HostFetchPolicy::default(),
        );
        let out = host.list_findings(10).await.expect("must succeed");
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn annotate_finding_requires_annotate_scope() {
        let host = StubHost::new(
            "t1",
            [Scope::FINDINGS_READ],
            vec![finding()],
            HostFetchPolicy::default(),
        );
        let err = host
            .annotate_finding("f1", "needs review")
            .await
            .expect_err("must deny");
        assert!(matches!(err, HostError::ScopeDenied(_)));
    }

    #[tokio::test]
    async fn fetch_url_enforces_allow_list() {
        let policy = HostFetchPolicy::with_hosts(["allowed.example"]);
        let host = StubHost::new("t1", [Scope::HTTP_FETCH], vec![], policy);
        let err = host
            .fetch_url("https://denied.example/x")
            .await
            .expect_err("must deny");
        assert!(matches!(err, HostError::UrlNotAllowed(_)));
        let ok = host
            .fetch_url("https://allowed.example/x")
            .await
            .expect("must succeed");
        assert_eq!(ok, b"ok");
    }

    #[tokio::test]
    async fn noop_plugin_round_trips_through_host_context() {
        let host = StubHost::new(
            "t1",
            [Scope::FINDINGS_READ],
            vec![finding()],
            HostFetchPolicy::default(),
        );
        let plugin = NoopPlugin;
        let env = PluginEnvelope::new(
            crate::envelope::EventKind::FindingCreated,
            "t1".into(),
            serde_json::json!({}),
        );
        plugin.on_event(&host, &env).await.expect("must succeed");
    }

    #[test]
    fn scope_constants_are_stable_strings() {
        assert_eq!(Scope::FINDINGS_READ, "findings:read");
        assert_eq!(Scope::FINDINGS_ANNOTATE, "findings:annotate");
        assert_eq!(Scope::HTTP_FETCH, "http:fetch");
    }
}
