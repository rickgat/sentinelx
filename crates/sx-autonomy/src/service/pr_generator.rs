//! Auto-remediation pull-request generator.
//!
//! [`AutoRemediationPrGenerator`] turns a validated [`PrProposal`] into a
//! GitHub Pull Request — but only after every safety guard passes.
//!
//! # Safety pipeline
//!
//! 1. [`BranchProtectionGuard`] refuses pushes to `main`, `master`, or
//!    any branch matching one of the configured regexes (default
//!    includes `release/.*` and `prod/.*`).
//! 2. [`DiffSizeGuard`] refuses diffs above `max_diff_loc` lines
//!    (default `200`).
//! 3. The PR body is augmented with the finding id, any upstream
//!    references, and a mandatory `Signed-off-by` footer.
//! 4. The augmented body is then handed to a [`GithubClient`] adapter
//!    which performs the actual HTTP traffic; this crate has no
//!    knowledge of `octocrab` or other low-level details.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info};

use crate::error::AutonomyError;
use crate::model::pr_proposal::PrProposal;
use crate::service::pr_safety::{BranchProtectionGuard, DiffSizeGuard};

/// Configuration for [`AutoRemediationPrGenerator`].
///
/// The defaults are tuned for the safety contract documented in the
/// crate-level docs:
///
/// - `max_diff_loc = 200` — anything larger is escalated to a human
///   reviewer rather than auto-opened.
/// - `protected_branches = ["main", "master"]` — never PR against these.
/// - `protected_branch_regexes = ["release/.*", "prod/.*"]` — never PR
///   against release or prod-train branches.
/// - `signed_off_by = "SentinelX Autonomy <autonomy@sentinelx.invalid>"`
///   — a deterministic footer satisfies the `DCO` check on most repos
///   while keeping personal identities out of bot-generated PRs.
#[derive(Debug, Clone)]
pub struct PrGeneratorConfig {
    /// Maximum total line count across the proposed file changes.
    pub max_diff_loc: u32,
    /// Literal protected branches.
    pub protected_branches: Vec<String>,
    /// Regex patterns for protected branches (anchored end-to-end at
    /// construction time).
    pub protected_branch_regexes: Vec<String>,
    /// `Signed-off-by` footer appended to every generated PR body.
    pub signed_off_by: String,
}

impl Default for PrGeneratorConfig {
    fn default() -> Self {
        Self {
            max_diff_loc: 200,
            protected_branches: vec!["main".to_owned(), "master".to_owned()],
            protected_branch_regexes: vec!["release/.*".to_owned(), "prod/.*".to_owned()],
            signed_off_by: "SentinelX Autonomy <autonomy@sentinelx.invalid>".to_owned(),
        }
    }
}

/// Successful outcome of [`AutoRemediationPrGenerator::propose`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrOutcome {
    /// GitHub PR number.
    pub pull_request_number: u64,
    /// Canonical URL of the opened PR.
    pub url: url::Url,
}

/// Narrow port the generator uses to talk to GitHub.
///
/// The implementation owns transport (octocrab / wiremock / fakes) and
/// is responsible for branch creation, file commits, and PR opening.
/// The generator only hands it the already-validated [`PrProposal`] and
/// the augmented `body` string.
#[async_trait]
pub trait GithubClient: Send + Sync + std::fmt::Debug {
    /// Open a pull request that applies `prop.changes` on the source
    /// branch named by `prop.source_branch`, targeting
    /// `prop.target_branch`, with the supplied `body`.
    async fn open_pull_request(
        &self,
        prop: &PrProposal,
        body: &str,
    ) -> Result<PrOutcome, AutonomyError>;
}

/// Auto-remediation pull-request generator.
///
/// Stateless apart from the configured guards and the shared GitHub
/// client; safe to share via [`Arc`] across tasks.
#[derive(Debug)]
pub struct AutoRemediationPrGenerator<G: GithubClient> {
    client: Arc<G>,
    cfg: PrGeneratorConfig,
    branch_guard: BranchProtectionGuard,
    diff_guard: DiffSizeGuard,
}

impl<G: GithubClient> AutoRemediationPrGenerator<G> {
    /// Build a new generator. Compiles the configured regex list once.
    ///
    /// # Errors
    /// Returns [`AutonomyError::Config`] if any branch-protection regex
    /// fails to compile.
    pub fn new(client: Arc<G>, cfg: PrGeneratorConfig) -> Result<Self, AutonomyError> {
        let branch_guard = BranchProtectionGuard::new(
            cfg.protected_branches.clone(),
            cfg.protected_branch_regexes.clone(),
        )?;
        let diff_guard = DiffSizeGuard::new(cfg.max_diff_loc);
        Ok(Self {
            client,
            cfg,
            branch_guard,
            diff_guard,
        })
    }

    /// Run the safety pipeline and, on success, open the PR.
    ///
    /// # Errors
    /// - [`AutonomyError::ProtectedBranch`] when the target branch is
    ///   refused.
    /// - [`AutonomyError::DiffTooLarge`] when the diff exceeds the
    ///   configured ceiling.
    /// - [`AutonomyError::EmptyChangeSet`] when the proposal contains
    ///   no file changes.
    /// - [`AutonomyError::GithubClient`] if the adapter fails.
    pub async fn propose(&self, prop: PrProposal) -> Result<PrOutcome, AutonomyError> {
        if prop.changes.is_empty() {
            return Err(AutonomyError::EmptyChangeSet);
        }
        self.branch_guard.check(&prop.target_branch)?;
        self.diff_guard.check(&prop.changes)?;

        let body = self.build_body(&prop);
        debug!(
            finding_id = %prop.finding_id,
            target_branch = %prop.target_branch,
            source_branch = %prop.source_branch,
            "auto-remediation PR safety checks passed"
        );

        let outcome = self.client.open_pull_request(&prop, &body).await?;
        info!(
            pull_request_number = outcome.pull_request_number,
            url = %outcome.url,
            "auto-remediation PR opened"
        );
        Ok(outcome)
    }

    /// Construct the augmented PR body:
    ///
    /// ```text
    /// <original body>
    ///
    /// Finding: <finding_id>
    ///
    /// References:
    /// - <ref-1>
    /// - <ref-2>
    ///
    /// Signed-off-by: <configured signature>
    /// ```
    fn build_body(&self, prop: &PrProposal) -> String {
        let mut out = String::with_capacity(prop.body.len() + 256);
        if !prop.body.is_empty() {
            out.push_str(&prop.body);
            if !prop.body.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
        }
        out.push_str("Finding: ");
        out.push_str(&prop.finding_id);
        out.push_str("\n\n");

        if !prop.references.is_empty() {
            out.push_str("References:\n");
            for r in &prop.references {
                out.push_str("- ");
                out.push_str(r.as_ref());
                out.push('\n');
            }
            out.push('\n');
        }

        out.push_str("Signed-off-by: ");
        out.push_str(&self.cfg.signed_off_by);
        out.push('\n');
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::pr_proposal::{FileChange, RepoTarget};
    use std::sync::Mutex;

    /// Records the most recent [`GithubClient::open_pull_request`] call
    /// so tests can assert on it.
    #[derive(Debug, Default)]
    struct FakeGithubClient {
        captured_body: Mutex<Option<String>>,
        captured_proposal: Mutex<Option<PrProposal>>,
        next_number: u64,
    }

    impl FakeGithubClient {
        fn with_number(n: u64) -> Self {
            Self {
                next_number: n,
                ..Self::default()
            }
        }

        fn captured_body(&self) -> Option<String> {
            self.captured_body.lock().ok().and_then(|g| g.clone())
        }

        fn captured_proposal(&self) -> Option<PrProposal> {
            self.captured_proposal.lock().ok().and_then(|g| g.clone())
        }
    }

    #[async_trait]
    impl GithubClient for FakeGithubClient {
        async fn open_pull_request(
            &self,
            prop: &PrProposal,
            body: &str,
        ) -> Result<PrOutcome, AutonomyError> {
            if let Ok(mut g) = self.captured_body.lock() {
                *g = Some(body.to_owned());
            }
            if let Ok(mut g) = self.captured_proposal.lock() {
                *g = Some(prop.clone());
            }
            Ok(PrOutcome {
                pull_request_number: self.next_number,
                url: url::Url::parse("https://github.invalid/acme/site/pull/42").unwrap(),
            })
        }
    }

    fn sample_proposal() -> PrProposal {
        PrProposal::new(
            RepoTarget::new("acme", "site").unwrap(),
            "develop",
            "fix: patch CVE-2024-99999",
            "Original PR body explaining the fix.",
            vec![FileChange::new("src/lib.rs", "ok\n").unwrap()],
            "FIND-42",
            vec![url::Url::parse("https://example.invalid/cve/CVE-2024-99999").unwrap()],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn pr_generator_appends_signed_off_by_to_body() {
        let client = Arc::new(FakeGithubClient::with_number(1));
        let gen =
            AutoRemediationPrGenerator::new(client.clone(), PrGeneratorConfig::default()).unwrap();
        let _ = gen.propose(sample_proposal()).await.unwrap();
        let body = client.captured_body().expect("body captured");
        assert!(
            body.contains("Signed-off-by: SentinelX Autonomy <autonomy@sentinelx.invalid>"),
            "body missing Signed-off-by footer: {body}"
        );
        assert!(body.contains("Finding: FIND-42"));
        assert!(body.contains("Original PR body"));
    }

    #[tokio::test]
    async fn pr_generator_creates_branch_named_sentinelx_auto_fix_finding_id() {
        let client = Arc::new(FakeGithubClient::with_number(7));
        let gen =
            AutoRemediationPrGenerator::new(client.clone(), PrGeneratorConfig::default()).unwrap();
        let _ = gen.propose(sample_proposal()).await.unwrap();
        let prop = client.captured_proposal().expect("proposal captured");
        assert_eq!(prop.source_branch, "sentinelx/auto-fix/FIND-42");
    }

    #[tokio::test]
    async fn pr_generator_calls_github_client_with_built_body() {
        let client = Arc::new(FakeGithubClient::with_number(11));
        let gen =
            AutoRemediationPrGenerator::new(client.clone(), PrGeneratorConfig::default()).unwrap();
        let outcome = gen.propose(sample_proposal()).await.unwrap();
        assert_eq!(outcome.pull_request_number, 11);
        let body = client.captured_body().expect("body captured");
        // Reference list should be present.
        assert!(body.contains("References:"));
        assert!(body.contains("https://example.invalid/cve/CVE-2024-99999"));
    }

    #[tokio::test]
    async fn pr_generator_refuses_protected_branch() {
        let client = Arc::new(FakeGithubClient::with_number(1));
        let gen = AutoRemediationPrGenerator::new(client, PrGeneratorConfig::default()).unwrap();
        let mut prop = sample_proposal();
        prop.target_branch = "main".into();
        let err = gen.propose(prop).await.unwrap_err();
        assert!(matches!(err, AutonomyError::ProtectedBranch(b) if b == "main"));
    }

    #[tokio::test]
    async fn pr_generator_refuses_diff_over_max() {
        let client = Arc::new(FakeGithubClient::with_number(1));
        let cfg = PrGeneratorConfig {
            max_diff_loc: 1,
            ..PrGeneratorConfig::default()
        };
        let gen = AutoRemediationPrGenerator::new(client, cfg).unwrap();
        let mut prop = sample_proposal();
        prop.changes = vec![FileChange::new("a", "1\n2\n3\n").unwrap()];
        let err = gen.propose(prop).await.unwrap_err();
        assert!(matches!(err, AutonomyError::DiffTooLarge { .. }));
    }

    #[tokio::test]
    async fn pr_generator_refuses_empty_change_set() {
        let client = Arc::new(FakeGithubClient::with_number(1));
        let gen = AutoRemediationPrGenerator::new(client, PrGeneratorConfig::default()).unwrap();
        let mut prop = sample_proposal();
        prop.changes.clear();
        let err = gen.propose(prop).await.unwrap_err();
        assert!(matches!(err, AutonomyError::EmptyChangeSet));
    }
}
