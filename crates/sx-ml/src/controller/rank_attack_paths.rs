//! Attack-path ranking use case.

use crate::service::path_ranker::{AttackPathRanker, PathInput, PathScore};

/// Thin wrapper around [`AttackPathRanker`]. Kept as a use case so the
/// API surface stays uniform with the other primitives.
#[derive(Debug, Clone, Copy, Default)]
pub struct RankAttackPathsUseCase {
    ranker: AttackPathRanker,
}

impl RankAttackPathsUseCase {
    /// Build a use case with an explicit ranker configuration.
    #[must_use]
    pub const fn new(ranker: AttackPathRanker) -> Self {
        Self { ranker }
    }

    /// Score and rank the given paths.
    #[must_use]
    pub fn execute(&self, paths: Vec<PathInput>) -> Vec<PathScore> {
        self.ranker.rank(paths)
    }
}
