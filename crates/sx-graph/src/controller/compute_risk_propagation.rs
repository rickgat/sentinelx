//! Use-case: compute risk propagation along a previously discovered path.

use std::sync::Arc;

use tracing::instrument;

use crate::error::GraphError;
use crate::model::attack_path::PropagatedRisk;
use crate::port::KnowledgeGraph;

/// Use-case orchestrator for risk propagation.
#[derive(Debug, Clone)]
pub struct ComputeRiskPropagationUseCase {
    graph: Arc<dyn KnowledgeGraph>,
}

impl ComputeRiskPropagationUseCase {
    /// Build a new use-case.
    #[must_use]
    pub fn new(graph: Arc<dyn KnowledgeGraph>) -> Self {
        Self { graph }
    }

    /// Execute the propagation query for `path_id`.
    #[instrument(skip(self))]
    pub async fn execute(&self, path_id: &str) -> Result<PropagatedRisk, GraphError> {
        if path_id.is_empty() {
            return Err(GraphError::invalid_query("path_id is empty"));
        }
        self.graph.compute_risk_propagation(path_id).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::service::InMemoryKnowledgeGraph;

    #[tokio::test]
    async fn rejects_empty_path_id() {
        let g: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let uc = ComputeRiskPropagationUseCase::new(g);
        let r = uc.execute("").await;
        assert!(matches!(r, Err(GraphError::InvalidQuery(_))));
    }
}
