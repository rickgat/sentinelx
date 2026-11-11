//! Attack-path ranker.
//!
//! This is a Phase-3 approximation of the GraphSAGE-style ranker described
//! in TRD §7. Until a Python sidecar is introduced, we score attack paths
//! by a small linear composite of three signals:
//!
//! - `w_max * max(risk_scores)` — paths that pass through any one
//!   particularly risky node should rank high.
//! - `w_sum * (sum(risk_scores) / length)` — average per-hop risk.
//! - `- w_len * length` — penalise long, low-quality paths.
//!
//! Higher score = more critical.

use serde::{Deserialize, Serialize};

/// Default weight for `max(risk_scores)`.
pub const DEFAULT_W_MAX: f64 = 0.6;
/// Default weight for the average-per-hop risk contribution.
pub const DEFAULT_W_SUM: f64 = 0.3;
/// Default weight for the length penalty.
pub const DEFAULT_W_LEN: f64 = 0.1;

/// Input record for one attack path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathInput {
    /// Stable id for this path (caller-defined).
    pub id: String,
    /// Per-node risk along the path. `risk_scores.len()` typically equals
    /// `length` but is not required to.
    pub risk_scores: Vec<f64>,
    /// Number of hops in the path.
    pub length: usize,
}

/// Output record: an id and its composite score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathScore {
    /// Id of the path (echoed from input).
    pub id: String,
    /// Composite score; higher = more critical.
    pub score: f64,
}

/// Stateless scorer. Cheap to clone.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct AttackPathRanker {
    /// Weight on `max(risk_scores)`.
    pub w_max: f64,
    /// Weight on the per-hop average.
    pub w_sum: f64,
    /// Weight on the length penalty.
    pub w_len: f64,
}

impl Default for AttackPathRanker {
    fn default() -> Self {
        Self::new(DEFAULT_W_MAX, DEFAULT_W_SUM, DEFAULT_W_LEN)
    }
}

impl AttackPathRanker {
    /// Build a ranker with explicit weights.
    #[must_use]
    pub const fn new(w_max: f64, w_sum: f64, w_len: f64) -> Self {
        Self {
            w_max,
            w_sum,
            w_len,
        }
    }

    /// Score a single path. Public for testing / introspection.
    #[must_use]
    pub fn score_one(&self, path: &PathInput) -> f64 {
        let max_score = path
            .risk_scores
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        let max_score = if max_score.is_finite() {
            max_score
        } else {
            0.0
        };
        let sum_score: f64 = path.risk_scores.iter().sum();
        #[allow(clippy::cast_precision_loss)]
        let len = path.length.max(1) as f64;
        let avg = sum_score / len;
        #[allow(clippy::cast_precision_loss)]
        let len_pen = path.length as f64;
        self.w_len
            .mul_add(-len_pen, self.w_max.mul_add(max_score, self.w_sum * avg))
    }

    /// Rank a batch of paths. Output is sorted desc by score; ties are
    /// broken by `id` (lexicographic ascending) for determinism.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rank(&self, paths: Vec<PathInput>) -> Vec<PathScore> {
        let mut out: Vec<PathScore> = paths
            .iter()
            .map(|p| PathScore {
                id: p.id.clone(),
                score: self.score_one(p),
            })
            .collect();
        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        });
        out
    }
}
