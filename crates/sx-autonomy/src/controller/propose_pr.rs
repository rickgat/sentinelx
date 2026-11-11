//! Use case: propose an auto-remediation pull request.
//!
//! Thin wrapper around
//! [`crate::service::pr_generator::AutoRemediationPrGenerator`] so wiring
//! code only has to depend on a single struct.

use std::sync::Arc;

use crate::error::AutonomyError;
use crate::model::pr_proposal::PrProposal;
use crate::service::pr_generator::{AutoRemediationPrGenerator, GithubClient, PrOutcome};

/// Application-layer entry point for auto-PR generation.
#[derive(Debug)]
pub struct ProposePrUseCase<G: GithubClient> {
    generator: Arc<AutoRemediationPrGenerator<G>>,
}

impl<G: GithubClient> ProposePrUseCase<G> {
    /// Build a new use case around the supplied generator.
    #[must_use]
    pub const fn new(generator: Arc<AutoRemediationPrGenerator<G>>) -> Self {
        Self { generator }
    }

    /// Forward the proposal to the underlying generator.
    ///
    /// # Errors
    /// Surfaces any error returned by
    /// [`AutoRemediationPrGenerator::propose`].
    pub async fn execute(&self, prop: PrProposal) -> Result<PrOutcome, AutonomyError> {
        self.generator.propose(prop).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::pr_proposal::{FileChange, RepoTarget};
    use crate::service::pr_generator::PrGeneratorConfig;
    use async_trait::async_trait;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct CountingClient {
        calls: Mutex<u32>,
    }

    #[async_trait]
    impl GithubClient for CountingClient {
        async fn open_pull_request(
            &self,
            _prop: &PrProposal,
            _body: &str,
        ) -> Result<PrOutcome, AutonomyError> {
            if let Ok(mut g) = self.calls.lock() {
                *g += 1;
            }
            Ok(PrOutcome {
                pull_request_number: 1,
                url: url::Url::parse("https://github.invalid/x/y/pull/1").unwrap(),
            })
        }
    }

    fn sample_proposal() -> PrProposal {
        PrProposal::new(
            RepoTarget::new("acme", "site").unwrap(),
            "develop",
            "fix",
            "body",
            vec![FileChange::new("a.rs", "ok\n").unwrap()],
            "FIND-1",
            vec![],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn propose_pr_use_case_forwards_to_generator() {
        let client = Arc::new(CountingClient::default());
        let generator = Arc::new(
            AutoRemediationPrGenerator::new(client.clone(), PrGeneratorConfig::default()).unwrap(),
        );
        let use_case = ProposePrUseCase::new(generator);
        let out = use_case.execute(sample_proposal()).await.unwrap();
        assert_eq!(out.pull_request_number, 1);
        assert_eq!(*client.calls.lock().unwrap(), 1);
    }
}
