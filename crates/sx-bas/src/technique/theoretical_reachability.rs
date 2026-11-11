//! `TheoreticalReachability` — MITRE T1190 reachability analysis.
//!
//! Given a graph snapshot (a `Vec<(from, to)>` edge list of asset ids) and an
//! `entry` asset id, the technique returns the set of asset ids that are
//! reachable from `entry`. **No I/O whatsoever** — pure graph traversal.
//!
//! `max_mode = Theoretical`.

use std::collections::{HashMap, HashSet, VecDeque};

use async_trait::async_trait;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::simulation::{EvidenceRecord, SimulationStepContext, StepResult};
use crate::model::technique::{AttackTechnique, Capabilities, MitreTag};

/// Directed edge between two asset ids.
pub type Edge = (String, String);

/// Pure graph-traversal technique. Does not touch the network.
#[derive(Debug, Clone)]
pub struct TheoreticalReachability {
    edges: Vec<Edge>,
    entry: String,
    max_depth: Option<usize>,
}

impl TheoreticalReachability {
    /// Construct a new instance.
    ///
    /// `max_depth = None` means "unbounded BFS"; `Some(0)` returns only the
    /// entry itself.
    #[must_use]
    pub const fn new(edges: Vec<Edge>, entry: String, max_depth: Option<usize>) -> Self {
        Self {
            edges,
            entry,
            max_depth,
        }
    }

    fn reachable(&self) -> Vec<String> {
        // Build adjacency list.
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        for (from, to) in &self.edges {
            adj.entry(from.as_str()).or_default().push(to.as_str());
        }

        let mut visited: HashSet<String> = HashSet::new();
        let mut frontier: VecDeque<(String, usize)> = VecDeque::new();
        frontier.push_back((self.entry.clone(), 0));
        visited.insert(self.entry.clone());

        while let Some((node, depth)) = frontier.pop_front() {
            if let Some(max) = self.max_depth {
                if depth >= max {
                    continue;
                }
            }
            if let Some(nexts) = adj.get(node.as_str()) {
                for n in nexts {
                    if visited.insert((*n).to_owned()) {
                        frontier.push_back(((*n).to_owned(), depth + 1));
                    }
                }
            }
        }

        let mut out: Vec<String> = visited.into_iter().collect();
        out.sort();
        out
    }
}

#[async_trait]
impl AttackTechnique for TheoreticalReachability {
    fn id(&self) -> &'static str {
        "theoretical_reachability_v1"
    }

    fn mitre(&self) -> MitreTag {
        MitreTag::new("TA0001", "T1190", None)
    }

    fn max_mode(&self) -> AttackMode {
        AttackMode::Theoretical
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::ANALYTICAL
    }

    async fn step(&self, ctx: SimulationStepContext) -> Result<StepResult, BasError> {
        let reachable = self.reachable();

        let mut details = HashMap::new();
        details.insert("entry".to_owned(), self.entry.clone());
        details.insert("reachable_count".to_owned(), reachable.len().to_string());
        details.insert("reachable".to_owned(), reachable.join(","));

        let record = EvidenceRecord {
            technique_id: self.id().to_owned(),
            mode: ctx.mode,
            tenant_id: ctx.tenant_id,
            engagement_id: ctx.engagement_id,
            summary: format!("reachable_from={}: {} assets", self.entry, reachable.len()),
            details: details.clone(),
            recorded_at: time::OffsetDateTime::now_utc(),
        };
        ctx.evidence_sink.record(record).await?;

        Ok(StepResult::Simulated {
            summary: format!(
                "T1190 theoretical reachability — {} assets reachable from {}",
                reachable.len(),
                self.entry
            ),
            details,
        })
    }
}

#[cfg(test)]
// Tests use `panic!` for unexpected-variant assertions.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::TheoreticalReachability;
    use crate::model::mode::AttackMode;
    use crate::model::simulation::{InMemoryEvidenceSink, SimulationStepContext, StepResult};
    use crate::model::technique::AttackTechnique;
    use std::sync::Arc;
    use sx_core::value_object::ids::{EngagementId, TenantId};
    use time::{Duration, OffsetDateTime};
    use tokio::sync::Notify;

    fn ctx(sink: Arc<InMemoryEvidenceSink>) -> SimulationStepContext {
        SimulationStepContext {
            tenant_id: TenantId::new(),
            engagement_id: EngagementId::new(),
            mode: AttackMode::Theoretical,
            kill_switch_signal: Arc::new(Notify::new()),
            deadline: OffsetDateTime::now_utc() + Duration::seconds(30),
            evidence_sink: sink,
        }
    }

    #[tokio::test]
    async fn theoretical_reachability_finds_one_hop() {
        let edges = vec![
            ("a".into(), "b".into()),
            ("b".into(), "c".into()),
            ("d".into(), "e".into()),
        ];
        let t = TheoreticalReachability::new(edges, "a".into(), None);
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let out = t.step(ctx(sink.clone())).await.unwrap();
        match out {
            StepResult::Simulated { details, .. } => {
                let reach = details.get("reachable").unwrap();
                assert!(reach.contains('a'));
                assert!(reach.contains('b'));
                assert!(reach.contains('c'));
                assert!(!reach.contains('d'));
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
        assert_eq!(sink.len().await, 1);
    }

    #[tokio::test]
    async fn theoretical_reachability_respects_max_depth() {
        let edges = vec![
            ("a".into(), "b".into()),
            ("b".into(), "c".into()),
            ("c".into(), "d".into()),
        ];
        let t = TheoreticalReachability::new(edges, "a".into(), Some(1));
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let out = t.step(ctx(sink)).await.unwrap();
        match out {
            StepResult::Simulated { details, .. } => {
                let reach = details.get("reachable").unwrap();
                // depth 1: only a and b
                assert!(reach.contains('a'));
                assert!(reach.contains('b'));
                assert!(!reach.contains('c'));
                assert!(!reach.contains('d'));
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn theoretical_reachability_zero_depth_only_entry() {
        let edges = vec![("a".into(), "b".into())];
        let t = TheoreticalReachability::new(edges, "a".into(), Some(0));
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let out = t.step(ctx(sink)).await.unwrap();
        match out {
            StepResult::Simulated { details, .. } => {
                assert_eq!(details.get("reachable_count").unwrap(), "1");
                assert_eq!(details.get("reachable").unwrap(), "a");
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
    }
}
