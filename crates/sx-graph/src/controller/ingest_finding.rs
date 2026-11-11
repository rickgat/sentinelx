//! Use-case: ingest a finding into the knowledge graph.
//!
//! Given a Finding produced elsewhere in the system, this use-case
//! fans it out into the canonical sub-graph:
//!
//! 1. Upsert the affected [`crate::model::node::GraphAsset`].
//! 2. Upsert the [`crate::model::node::GraphFinding`] node with its
//!    `risk_score`.
//! 3. Upsert any associated [`crate::model::node::GraphCve`] nodes and
//!    `MAPS_TO` edges.
//! 4. Upsert any tagged [`crate::model::node::GraphTechnique`] nodes
//!    and `ENABLES` edges.

use std::collections::BTreeMap;
use std::sync::Arc;

use tracing::{info, instrument};

use sx_core::value_object::criticality::AssetCriticality;
use sx_core::value_object::exposure::ExposureLevel;
use sx_core::value_object::ids::{CveId, TenantId};
use sx_core::value_object::severity::Severity;

use crate::error::GraphError;
use crate::model::edge::{EdgeKind, GraphEdge};
use crate::model::node::{GraphAsset, GraphCve, GraphFinding, GraphNode, GraphTechnique, NodeId};
use crate::port::KnowledgeGraph;

/// Input payload for [`IngestFindingUseCase::execute`].
#[derive(Debug, Clone)]
pub struct IngestFindingInput {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Stable id of the asset the finding was observed on.
    pub asset_id: NodeId,
    /// Display name for the asset (used on first sight; ignored on
    /// repeat ingest).
    pub asset_name: String,
    /// Asset exposure level.
    pub asset_exposure: ExposureLevel,
    /// Asset criticality.
    pub asset_criticality: AssetCriticality,
    /// Stable id for the finding.
    pub finding_id: NodeId,
    /// Detection rule id.
    pub rule_id: String,
    /// Short finding title.
    pub finding_title: String,
    /// Finding severity.
    pub severity: Severity,
    /// Per-finding risk contribution to the graph.
    pub risk_score: f64,
    /// Optional CVEs to link via `MAPS_TO`. Provide as canonical CVE
    /// ids (e.g. `"CVE-2024-12345"`).
    pub cves: Vec<CveId>,
    /// Optional ATT&CK technique ids to link via `ENABLES`.
    pub techniques: Vec<String>,
}

/// Outcome of one ingest call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestFindingOutput {
    /// Number of nodes upserted (asset + finding + CVEs + techniques).
    pub nodes_upserted: usize,
    /// Number of edges upserted.
    pub edges_upserted: usize,
}

/// Use-case orchestrator.
#[derive(Debug, Clone)]
pub struct IngestFindingUseCase {
    graph: Arc<dyn KnowledgeGraph>,
}

impl IngestFindingUseCase {
    /// Build a new use-case bound to the supplied graph port.
    #[must_use]
    pub fn new(graph: Arc<dyn KnowledgeGraph>) -> Self {
        Self { graph }
    }

    /// Run the ingest fan-out.
    ///
    /// Returns [`IngestFindingOutput`] with the number of `MERGE`
    /// operations performed.
    #[instrument(skip(self, input), fields(asset_id = %input.asset_id, finding_id = %input.finding_id))]
    pub async fn execute(
        &self,
        input: IngestFindingInput,
    ) -> Result<IngestFindingOutput, GraphError> {
        let mut nodes = 0_usize;
        let mut edges = 0_usize;

        let asset = GraphNode::Asset(GraphAsset {
            id: input.asset_id.clone(),
            tenant_id: input.tenant_id,
            name: input.asset_name,
            exposure: input.asset_exposure,
            criticality: input.asset_criticality,
            risk_score: None,
            properties: BTreeMap::new(),
        });
        self.graph.upsert_node(&asset).await?;
        nodes += 1;

        let finding = GraphNode::Finding(GraphFinding {
            id: input.finding_id.clone(),
            tenant_id: input.tenant_id,
            asset_id: input.asset_id.clone(),
            rule_id: input.rule_id,
            title: input.finding_title,
            severity: input.severity,
            risk_score: input.risk_score,
        });
        self.graph.upsert_node(&finding).await?;
        nodes += 1;

        self.graph
            .upsert_edge(&GraphEdge::new(
                EdgeKind::HasFinding,
                input.asset_id.clone(),
                input.finding_id.clone(),
            ))
            .await?;
        edges += 1;

        for cve in input.cves {
            let cve_node_id: NodeId = cve.clone().into();
            let cve_node = GraphNode::Cve(GraphCve {
                id: cve_node_id.clone(),
                cvss: None,
                epss: None,
                kev: false,
            });
            self.graph.upsert_node(&cve_node).await?;
            nodes += 1;
            self.graph
                .upsert_edge(&GraphEdge::new(
                    EdgeKind::MapsTo,
                    input.finding_id.clone(),
                    cve_node_id,
                ))
                .await?;
            edges += 1;
        }

        for t in input.techniques {
            let t_id = NodeId::new(t.clone());
            let tech_node = GraphNode::Technique(GraphTechnique {
                id: t_id.clone(),
                name: t,
                tactic: String::new(),
            });
            self.graph.upsert_node(&tech_node).await?;
            nodes += 1;
            self.graph
                .upsert_edge(&GraphEdge::new(
                    EdgeKind::Enables,
                    input.finding_id.clone(),
                    t_id,
                ))
                .await?;
            edges += 1;
        }

        info!(
            nodes_upserted = nodes,
            edges_upserted = edges,
            "ingest_finding complete"
        );
        Ok(IngestFindingOutput {
            nodes_upserted: nodes,
            edges_upserted: edges,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::service::InMemoryKnowledgeGraph;

    fn input() -> IngestFindingInput {
        IngestFindingInput {
            tenant_id: TenantId::new(),
            asset_id: NodeId::new("a1"),
            asset_name: "web-1".into(),
            asset_exposure: ExposureLevel::Internet,
            asset_criticality: AssetCriticality::Production,
            finding_id: NodeId::new("f1"),
            rule_id: "r1".into(),
            finding_title: "OpenSSL RCE".into(),
            severity: Severity::Critical,
            risk_score: 9.5,
            cves: vec![CveId::new("CVE-2024-12345").unwrap()],
            techniques: vec!["T1190".into()],
        }
    }

    #[tokio::test]
    async fn ingest_finding_creates_asset_finding_cve_technique_nodes() {
        let graph: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let uc = IngestFindingUseCase::new(graph.clone());
        let out = uc.execute(input()).await.unwrap();
        // asset + finding + 1 CVE + 1 technique = 4
        assert_eq!(out.nodes_upserted, 4);
        // HAS_FINDING + MAPS_TO + ENABLES = 3
        assert_eq!(out.edges_upserted, 3);
    }

    #[tokio::test]
    async fn ingest_finding_idempotent_under_repeat() {
        let mem = InMemoryKnowledgeGraph::new();
        let graph: Arc<dyn KnowledgeGraph> = Arc::new(mem.clone());
        let uc = IngestFindingUseCase::new(graph);
        let _ = uc.execute(input()).await.unwrap();
        let _ = uc.execute(input()).await.unwrap();
        assert_eq!(mem.node_count().await, 4);
        assert_eq!(mem.edge_count().await, 3);
    }
}
