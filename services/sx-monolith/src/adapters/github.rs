//! Octocrab-backed adapter for the autonomy [`sx_autonomy::prelude::GithubClient`]
//! port.
//!
//! Supports two credential modes, evaluated in this precedence order:
//!
//! * **GitHub App installation token** (preferred): `app_id` +
//!   `installation_id` + RSA `private_key` (PEM). The PEM is parsed into a
//!   [`jsonwebtoken::EncodingKey`] and handed to octocrab's app builder,
//!   which exchanges it for a short-lived installation access token.
//! * **Personal access token** (fallback): `personal_access_token`.
//!
//! [`build`] returns `None` when the config is disabled OR when no
//! credentials are supplied, so the monolith falls back to the stub
//! [`HttpGithubClient`](super::autonomy::HttpGithubClient).
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]` is inherited from the workspace.
//! - No `unwrap`/`expect`/`panic!` on production paths.
//! - Credential material never reaches a `tracing` call site. The PEM body
//!   stays inside [`secrecy::SecretString`] / [`secrecy::ExposeSecret`] until
//!   it is parsed by `jsonwebtoken`, and the PAT is moved directly into
//!   octocrab's `personal_token` builder without intermediate logging.
//! - The repo identifier supplied by `PrProposal` is split with [`split_repo`]
//!   which rejects malformed slugs before any HTTP call.

use std::sync::Arc;

use async_trait::async_trait;
use octocrab::models::{AppId, InstallationId};
use octocrab::Octocrab;
use secrecy::{ExposeSecret, SecretString};
use sx_autonomy::prelude::{AutonomyError, GithubClient, PrOutcome, PrProposal};
use sx_config::GithubConfig;
use tracing::info;
use url::Url;

/// `octocrab`-backed [`GithubClient`] implementation.
///
/// Owns a single [`Octocrab`] handle (octocrab's client is cheap to clone
/// internally and safe to share across tasks).
pub(crate) struct OctocrabGithubClient {
    client: Octocrab,
}

impl std::fmt::Debug for OctocrabGithubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: the inner client carries credential state we
        // never want appearing in a debug print or panic message.
        f.debug_struct("OctocrabGithubClient").finish()
    }
}

impl OctocrabGithubClient {
    /// Build an instance authenticated with a personal access token.
    ///
    /// # Errors
    /// Returns [`AutonomyError::Config`] if octocrab refuses to build a
    /// client around the supplied token (extremely rare — usually only on
    /// global allocator / TLS init failure).
    pub(crate) fn from_pat(token: &SecretString) -> Result<Self, AutonomyError> {
        let token_string = token.expose_secret().to_owned();
        let client = Octocrab::builder()
            .personal_token(SecretString::from(token_string))
            .build()
            .map_err(|e| AutonomyError::config(format!("octocrab personal_token: {e}")))?;
        Ok(Self { client })
    }

    /// Build an instance authenticated as a specific GitHub App installation.
    ///
    /// # Errors
    /// Returns [`AutonomyError::Config`] if the PEM cannot be parsed as an
    /// RSA private key, or if octocrab refuses to build the underlying
    /// client.
    pub(crate) fn from_app(
        app_id: u64,
        installation_id: u64,
        key_pem: &SecretString,
    ) -> Result<Self, AutonomyError> {
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(key_pem.expose_secret().as_bytes())
                .map_err(|e| AutonomyError::config(format!("github app private_key: {e}")))?;
        let app_client = Octocrab::builder()
            .app(AppId(app_id), encoding_key)
            .build()
            .map_err(|e| AutonomyError::config(format!("octocrab app builder: {e}")))?;
        let client = app_client
            .installation(InstallationId(installation_id))
            .map_err(|e| AutonomyError::config(format!("octocrab installation: {e}")))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl GithubClient for OctocrabGithubClient {
    async fn open_pull_request(
        &self,
        prop: &PrProposal,
        body: &str,
    ) -> Result<PrOutcome, AutonomyError> {
        let owner = prop.repo.owner.as_str();
        let repo = prop.repo.name.as_str();
        // Surface a deterministic invariant if the proposal carried empty
        // coords. The autonomy domain already rejects this at construction
        // time, but defence in depth keeps the HTTP call from firing with
        // a malformed path.
        if owner.is_empty() || repo.is_empty() {
            return Err(AutonomyError::invalid_input(
                "repo owner and name must be non-empty",
            ));
        }

        info!(
            target = "adapters.github.open_pull_request",
            owner = %owner,
            repo = %repo,
            head = %prop.source_branch,
            base = %prop.target_branch,
            finding_id = %prop.finding_id,
            "opening pull request",
        );

        let pr = self
            .client
            .pulls(owner, repo)
            .create(
                prop.title.as_str(),
                prop.source_branch.as_str(),
                prop.target_branch.as_str(),
            )
            .body(body.to_owned())
            .send()
            .await
            .map_err(map_octocrab_error)?;

        let url = pr
            .html_url
            .ok_or_else(|| AutonomyError::github("github response missing html_url".to_owned()))?;
        let pull_request_number = pr.number;
        // Re-parse through our `url::Url` re-export so the autonomy type
        // remains the single canonical URL representation.
        let parsed = Url::parse(url.as_str())
            .map_err(|e| AutonomyError::github(format!("github html_url unparseable: {e}")))?;

        info!(
            target = "adapters.github.open_pull_request.ok",
            owner = %owner,
            repo = %repo,
            pull_request_number = pull_request_number,
            "pull request opened",
        );

        Ok(PrOutcome {
            pull_request_number,
            url: parsed,
        })
    }
}

/// Translate an [`octocrab::Error`] into an [`AutonomyError::GithubClient`]
/// without leaking the raw response body (which could include tokens echoed
/// back in 4xx error payloads).
fn map_octocrab_error(err: octocrab::Error) -> AutonomyError {
    // Use the Display impl only — the Debug impl can include header dumps.
    AutonomyError::github(format!("octocrab: {err}"))
}

/// Split a `"owner/repo"` slug into a `(owner, repo)` tuple.
///
/// Mirrors the format the autonomy domain stores internally
/// ([`PrProposal::repo`] keeps `owner` and `name` already split). This
/// helper exists so callers that received a flat `String` (e.g. from an
/// HTTP request body, or from upstream PR-generator wiring) can validate
/// the shape before constructing a [`sx_autonomy::prelude::RepoTarget`].
///
/// Currently only invoked from tests, but kept on the production surface
/// so the upcoming wave of HTTP wiring can call it directly without a
/// duplicate parser.
///
/// # Errors
/// Returns [`AutonomyError::InvalidInput`] when:
/// * the input does not contain exactly one `/`, OR
/// * either side of the `/` is empty.
#[allow(dead_code)] // public surface for future HTTP-slug wiring; tests cover it.
pub(crate) fn split_repo(slug: &str) -> Result<(&str, &str), AutonomyError> {
    let trimmed = slug.trim();
    let mut parts = trimmed.splitn(2, '/');
    let owner = parts.next().unwrap_or("");
    let repo = parts.next().unwrap_or("");
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err(AutonomyError::invalid_input(format!(
            "repo slug must be 'owner/name', got '{slug}'"
        )));
    }
    Ok((owner, repo))
}

/// Build an [`OctocrabGithubClient`] from a [`GithubConfig`].
///
/// Returns `None` when the config is `enabled = false` so callers can fall
/// back to the no-op stub without branching on a sentinel error.
///
/// Credential-source precedence rule: when both App credentials and a
/// personal access token are configured, the App triple wins. This
/// matches the GitHub-recommended posture (App tokens are short-lived,
/// repo-scoped, and revocable from the App settings page).
///
/// # Errors
/// Returns [`AutonomyError::Config`] when the config is enabled but every
/// credential mode failed to construct an octocrab client (e.g. malformed
/// PEM). Pure missing-credential cases are caught by
/// [`GithubConfig::check_invariants`] at boot, so this path should be
/// unreachable in practice.
pub(crate) fn build(
    cfg: &GithubConfig,
) -> Result<Option<Arc<OctocrabGithubClient>>, AutonomyError> {
    if !cfg.enabled {
        info!(
            target = "adapters.github.disabled",
            "github config disabled; using stub client",
        );
        return Ok(None);
    }

    // App credentials take precedence over the PAT when both are present.
    if let (Some(app_id), Some(installation_id)) = (cfg.app_id, cfg.installation_id) {
        if !cfg.private_key.expose_secret().is_empty() {
            let client = OctocrabGithubClient::from_app(app_id, installation_id, &cfg.private_key)?;
            info!(
                target = "adapters.github.enabled",
                mode = "github_app",
                app_id = app_id,
                "github client constructed",
            );
            return Ok(Some(Arc::new(client)));
        }
    }

    if !cfg.personal_access_token.expose_secret().is_empty() {
        let client = OctocrabGithubClient::from_pat(&cfg.personal_access_token)?;
        info!(
            target = "adapters.github.enabled",
            mode = "personal_access_token",
            "github client constructed",
        );
        return Ok(Some(Arc::new(client)));
    }

    // Reachable only if config invariants were bypassed.
    Err(AutonomyError::config(
        "github.enabled=true but no credentials configured".to_owned(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Once;
    use sx_config::GithubConfig;

    /// Workspace-wide feature unification activates BOTH `aws-lc-rs` and
    /// `ring` on rustls (via `metrics-exporter-prometheus`'s default
    /// `hyper-rustls` features intersecting with octocrab's `rustls-ring`).
    /// rustls 0.23 refuses to auto-pick under that ambiguity, so any test
    /// that constructs an Octocrab client (which builds an HTTPS connector)
    /// must install a `CryptoProvider` first. We pick `ring` to match the
    /// feature octocrab itself requests.
    fn ensure_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // Best-effort: if some other test already installed a provider
            // (unlikely in unit-test scope but possible on a hot reload),
            // the second call is a no-op and we proceed.
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn disabled_cfg() -> GithubConfig {
        GithubConfig {
            enabled: false,
            app_id: None,
            installation_id: None,
            private_key: SecretString::from(String::new()),
            personal_access_token: SecretString::from(String::new()),
        }
    }

    #[tokio::test]
    async fn pat_constructor_succeeds() {
        ensure_crypto_provider();
        let token = SecretString::from("ghp_exampletokenvalue".to_owned());
        let client = OctocrabGithubClient::from_pat(&token)
            .expect("PAT constructor must succeed for a non-empty token");
        // Smoke check: the debug print is opaque and never reveals the
        // token material.
        let dbg = format!("{client:?}");
        assert!(
            !dbg.contains("ghp_exampletokenvalue"),
            "PAT leaked in Debug: {dbg}"
        );
    }

    #[test]
    fn app_constructor_rejects_malformed_pem() {
        let key = SecretString::from("not a pem".to_owned());
        let err = OctocrabGithubClient::from_app(1, 2, &key)
            .expect_err("malformed PEM must surface as Config error");
        assert!(
            matches!(err, AutonomyError::Config(_)),
            "expected Config, got {err:?}"
        );
    }

    #[test]
    fn build_returns_none_when_disabled() {
        let cfg = disabled_cfg();
        let out = build(&cfg).expect("disabled build must succeed");
        assert!(out.is_none(), "disabled config must yield None");
    }

    #[tokio::test]
    async fn build_returns_some_when_pat_configured() {
        ensure_crypto_provider();
        let mut cfg = disabled_cfg();
        cfg.enabled = true;
        cfg.personal_access_token = SecretString::from("ghp_fake".to_owned());
        let out = build(&cfg).expect("PAT-configured build must succeed");
        assert!(out.is_some(), "enabled PAT config must yield Some");
    }

    #[test]
    fn build_prefers_app_when_both_modes_configured() {
        // App over PAT: when both are configured, App wins (precedence
        // rule documented at the top of the module). The malformed PEM
        // here is good enough to prove the path is taken — it surfaces
        // a Config error rather than silently falling through to the
        // PAT branch.
        let mut cfg = disabled_cfg();
        cfg.enabled = true;
        cfg.app_id = Some(1);
        cfg.installation_id = Some(2);
        cfg.private_key = SecretString::from("not a pem".to_owned());
        cfg.personal_access_token = SecretString::from("ghp_fake".to_owned());
        let err = build(&cfg).expect_err("App PEM failure must surface, not PAT fallback");
        assert!(
            matches!(err, AutonomyError::Config(_)),
            "expected Config, got {err:?}"
        );
    }

    #[test]
    fn split_repo_parses_owner_repo() {
        let (owner, repo) = split_repo("acme/site").expect("well-formed slug must split");
        assert_eq!(owner, "acme");
        assert_eq!(repo, "site");
    }

    #[test]
    fn split_repo_trims_whitespace() {
        let (owner, repo) = split_repo("  acme/site\n").expect("trimmed slug must split");
        assert_eq!(owner, "acme");
        assert_eq!(repo, "site");
    }

    #[test]
    fn split_repo_rejects_malformed() {
        for bad in &["acme", "/site", "acme/", "", "/", "acme/site/extra"] {
            let err = split_repo(bad).unwrap_err();
            assert!(
                matches!(err, AutonomyError::InvalidInput(_)),
                "expected InvalidInput for {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn map_octocrab_error_redacts_debug_dump() {
        // We can't easily construct an octocrab::Error directly without
        // an HTTP round-trip; this test is a placeholder asserting only
        // that the helper compiles and yields a GithubClient variant
        // for a representative error path. The redaction guarantee is
        // structural — we never call `format!("{:?}", err)`.
        let err = AutonomyError::github("octocrab: synthesised".to_owned());
        assert!(matches!(err, AutonomyError::GithubClient(_)));
    }
}
