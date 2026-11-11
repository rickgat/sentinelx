//! Use-case: query attack paths.
//!
//! Thin wrapper over [`crate::port::KnowledgeGraph::find_attack_paths`]
//! that enforces the documented bounds (`max_depth <= 10`,
//! `max_paths <= 200`) before any I/O occurs.

use std::sync::Arc;

use tracing::instrument;

use crate::error::GraphError;
use crate::model::attack_path::AttackPath;
use crate::port::{AttackPathQuery, KnowledgeGraph};

/// Use-case orchestrator for attack-path discovery.
#[derive(Debug, Clone)]
pub struct FindAttackPathsUseCase {
    graph: Arc<dyn KnowledgeGraph>,
}

impl FindAttackPathsUseCase {
    /// Build a new use-case.
    #[must_use]
    pub fn new(graph: Arc<dyn KnowledgeGraph>) -> Self {
        Self { graph }
    }

    /// Validate the query and execute it against the bound graph port.
    #[instrument(skip(self, query))]
    pub async fn execute(&self, query: &AttackPathQuery) -> Result<Vec<AttackPath>, GraphError> {
        query.validate()?;
        self.graph.find_attack_paths(query).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use sx_core::value_object::ids::TenantId;

    use super::*;
    use crate::model::node::NodeKind;
    use crate::service::InMemoryKnowledgeGraph;

    fn query(max_depth: u8, max_paths: u32) -> AttackPathQuery {
        AttackPathQuery {
            tenant_id: TenantId::new(),
            entry_kind: NodeKind::Asset,
            target_kind: NodeKind::Asset,
            max_depth,
            max_paths,
        }
    }

    #[tokio::test]
    async fn rejects_excessive_depth_before_io() {
        let g: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let uc = FindAttackPathsUseCase::new(g);
        let r = uc.execute(&query(11, 10)).await;
        assert!(matches!(r, Err(GraphError::InvalidQuery(_))));
    }

    #[tokio::test]
    async fn rejects_excessive_paths_before_io() {
        let g: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let uc = FindAttackPathsUseCase::new(g);
        let r = uc.execute(&query(5, 201)).await;
        assert!(matches!(r, Err(GraphError::InvalidQuery(_))));
    }
}
