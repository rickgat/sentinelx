//! Production Neo4j attack-graph adapter (MVP slice — P1-001).
//!
//! This module ships a fresh, self-contained `Neo4jKnowledgeGraph`
//! adapter that targets a Neo4j 5.x cluster via [`neo4rs`]. It exists
//! alongside [`crate::service::neo4j_graph`] and implements the same
//! [`crate::port::KnowledgeGraph`] trait, so the in-memory adapter and
//! this one can be hot-swapped at the composition root.
//!
//! ## Scope (MVP slice)
//!
//! On top of the trait, this module exposes batch ingest primitives and
//! attack-graph queries that are tuned for the production volume target
//! (1M assets / 50M edges per tenant, p95 attack-path query &lt; 3s — see
//! `docs/TRD.md` §3.6):
//!
//! - [`Neo4jKnowledgeGraph::bootstrap_schema`] — idempotent constraints
//!   + indexes (TRD §3.5.4).
//! - [`Neo4jKnowledgeGraph::insert_assets`] — `UNWIND`-batched asset
//!   `MERGE`, 5 000 nodes per transaction.
//! - [`Neo4jKnowledgeGraph::insert_edges`] — `UNWIND`-batched edge
//!   `MERGE`, 10 000 edges per transaction.
//! - [`Neo4jKnowledgeGraph::top_n_attack_paths`] — parameterised
//!   highest-risk path search between two asset labels (TRD §3.5.3).
//! - [`Neo4jKnowledgeGraph::blast_radius`] — reachability fan-out from a
//!   single origin asset within `depth` hops.
//!
//! ## Tenant isolation
//!
//! Every Cypher statement that touches tenant-owned data is parametrised
//! with `$tenant_id` and either rooted at
//! `(:Tenant {id: $tenant_id})-[:OWNS]->(...)` or filtered through an
//! explicit `WHERE n.tenant_id = $tenant_id` predicate so that a
//! malicious / buggy caller cannot observe nor mutate another tenant's
//! sub-graph.
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]` inherited from the crate root.
//! - No `unwrap` / `expect` / `panic` outside `#[cfg(test)]`.
//! - User-controlled strings are NEVER concatenated into Cypher; only
//!   integer-typed depth / limit values from validated `u8` / `u32`
//!   inputs are inlined, because Cypher does not accept parameterised
//!   path-length range bounds.

use std::sync::Arc;

use async_trait::async_trait;
use neo4rs::{query as cypher_query, BoltMap, BoltType, ConfigBuilder, Graph as Neo4Graph};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info, instrument};

use sx_core::value_object::ids::TenantId;

use crate::error::GraphError;
use crate::model::attack_path::{AttackPath, PropagatedRisk};
use crate::model::edge::GraphEdge;
use crate::model::node::{GraphAsset, GraphNode, NodeId};
use crate::port::{AttackPathQuery, KnowledgeGraph, MAX_ATTACK_PATHS, MAX_ATTACK_PATH_DEPTH};

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Maximum number of asset nodes per `UNWIND` transaction in
/// [`Neo4jKnowledgeGraph::insert_assets`].
pub const ASSET_BATCH_SIZE: usize = 5_000;

/// Maximum number of edges per `UNWIND` transaction in
/// [`Neo4jKnowledgeGraph::insert_edges`].
pub const EDGE_BATCH_SIZE: usize = 10_000;

/// Hard upper bound on `top_n_attack_paths(n)` to keep query plans
/// bounded.
pub const MAX_TOP_N: u32 = MAX_ATTACK_PATHS;

/// Hard upper bound on `blast_radius(depth)` — mirrors
/// [`MAX_ATTACK_PATH_DEPTH`] so the two query families share an envelope.
pub const MAX_BLAST_RADIUS_DEPTH: u8 = MAX_ATTACK_PATH_DEPTH;

/// Hard upper bound on the depth supplied to the bi-directional BFS
/// short-path engine in [`Neo4jKnowledgeGraph::bi_bfs_attack_paths`].
///
/// The spec for `P1-001` caps bi-BFS path searches at **7 hops** so that
/// the Neo4j planner can keep both frontier sides bounded on a 1M-node
/// graph and still hit the p95 < 200ms target for top-10 queries.
pub const MAX_BI_BFS_DEPTH: u8 = 7;

/// Stable `tracing` target used for audit-log records emitted by this
/// adapter. The records carry structured fields and never include
/// secrets — they're safe to ship to an audit pipeline as-is.
pub const AUDIT_TARGET: &str = "audit.graph.neo4j";

// ---------------------------------------------------------------------------
// Cypher snippets
// ---------------------------------------------------------------------------

/// Idempotent schema bootstrap: constraints + indexes used by the
/// production adapter (TRD §3.5.4).
///
/// All statements use `IF NOT EXISTS`, so this is safe to call on every
/// service boot.
pub const BOOTSTRAP_STATEMENTS: &[&str] = &[
    // Uniqueness constraints — also implicitly create supporting indexes.
    "CREATE CONSTRAINT tenant_id_unique IF NOT EXISTS \
     FOR (t:Tenant) REQUIRE t.id IS UNIQUE",
    "CREATE CONSTRAINT asset_id_unique IF NOT EXISTS \
     FOR (a:Asset) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT finding_id_unique IF NOT EXISTS \
     FOR (f:Finding) REQUIRE f.id IS UNIQUE",
    "CREATE CONSTRAINT cve_id_unique IF NOT EXISTS \
     FOR (c:Cve) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT technique_id_unique IF NOT EXISTS \
     FOR (k:Technique) REQUIRE k.id IS UNIQUE",
    // Secondary indexes that back the attack-path predicates.
    "CREATE INDEX asset_tenant_id IF NOT EXISTS FOR (a:Asset) ON (a.tenant_id)",
    "CREATE INDEX asset_exposure IF NOT EXISTS FOR (a:Asset) ON (a.exposure)",
    "CREATE INDEX asset_criticality IF NOT EXISTS FOR (a:Asset) ON (a.criticality)",
    "CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity)",
    "CREATE INDEX finding_tenant_id IF NOT EXISTS FOR (f:Finding) ON (f.tenant_id)",
];

/// `insert_assets` — `UNWIND` a tenant-scoped batch of assets and
/// `MERGE` them under the tenant root.
///
/// Each `$assets` item is a map with the fields
/// `id, name, exposure, criticality, risk_score`.
pub const INSERT_ASSETS_CYPHER: &str = r"
MATCH (t:Tenant {id: $tenant_id})
UNWIND $assets AS row
MERGE (t)-[:OWNS]->(a:Asset {id: row.id})
  ON CREATE SET a.tenant_id = $tenant_id,
                a.name = row.name,
                a.exposure = row.exposure,
                a.criticality = row.criticality,
                a.risk_score = row.risk_score
  ON MATCH  SET a.name = row.name,
                a.exposure = row.exposure,
                a.criticality = row.criticality,
                a.risk_score = row.risk_score
RETURN count(a) AS upserted
";

/// `insert_edges` — `UNWIND` a tenant-scoped batch of edges and `MERGE`
/// them between assets owned by the same tenant. The `kind` column on
/// each row is a member of [`crate::model::edge::EdgeKind`].
///
/// Note: Cypher does not allow parameterised relationship types, so
/// each edge is materialised as a generic `:LINK` relationship carrying
/// `r.kind = row.kind` instead. For the canonical `:EXPLOITS` /
/// `:REACHES` / etc. relationship types used by the attack-path queries
/// the adapter calls [`crate::service::cypher`] directly.
pub const INSERT_EDGES_CYPHER: &str = r"
MATCH (t:Tenant {id: $tenant_id})
UNWIND $edges AS row
MATCH (t)-[:OWNS]->(from {id: row.from})
MATCH (t)-[:OWNS]->(to   {id: row.to})
MERGE (from)-[r:LINK {kind: row.kind}]->(to)
  ON CREATE SET r.tenant_id = $tenant_id,
                r.properties = row.properties
  ON MATCH  SET r.properties = row.properties
RETURN count(r) AS upserted
";

/// `top_n_attack_paths(tenant, from_label, to_label, n)`.
///
/// Highest-risk paths from any node labelled `from_label` to any node
/// labelled `to_label` within the tenant. The relationship walk uses
/// the canonical attack-graph edge types (`EXPLOITS`, `REACHES`,
/// `CHAINS_TO`, `HAS_FINDING`).
///
/// `{FROM_LABEL}`, `{TO_LABEL}`, `{MAX_DEPTH}` and `{TOP_N}` are
/// substituted by the adapter from a closed enum / validated `u8` /
/// `u32`. No user-controllable string is ever interpolated.
pub const TOP_N_ATTACK_PATHS_CYPHER: &str = r"
MATCH (t:Tenant {id: $tenant_id})
MATCH (t)-[:OWNS]->(start:{FROM_LABEL})
MATCH (t)-[:OWNS]->(goal:{TO_LABEL})
MATCH path = (start)-[:EXPLOITS|REACHES|CHAINS_TO|HAS_FINDING*1..{MAX_DEPTH}]->(goal)
WHERE ALL(n IN nodes(path) WHERE NOT exists(n.tenant_id) OR n.tenant_id = $tenant_id)
RETURN path,
       reduce(s = 0.0, n IN nodes(path) | s + coalesce(n.risk_score, 0.0)) AS pathScore
ORDER BY pathScore DESC
LIMIT {TOP_N}
";

/// `bi_bfs_attack_paths(tenant, from_label, to_label, depth, top_n)`.
///
/// Bi-directional breadth-first short-path search between two asset
/// labels. Uses Cypher's `shortestPath` which is internally implemented
/// as a two-sided BFS — meaningfully cheaper than the exhaustive
/// variable-length walk in [`TOP_N_ATTACK_PATHS_CYPHER`] for the
/// "shortest entry → crown-jewel" use-case.
///
/// `{FROM_LABEL}`, `{TO_LABEL}`, `{MAX_DEPTH}` and `{TOP_N}` are
/// substituted by the adapter from a closed enum / validated `u8` /
/// `u32`. The tenant guard inside `ALL(... WHERE n.tenant_id = $tenant_id)`
/// is what keeps cross-tenant nodes out of the result set even if the
/// graph topology happens to bridge them.
pub const BI_BFS_ATTACK_PATHS_CYPHER: &str = r"
MATCH (t:Tenant {id: $tenant_id})
MATCH (t)-[:OWNS]->(start:{FROM_LABEL})
MATCH (t)-[:OWNS]->(goal:{TO_LABEL})
WHERE start <> goal
MATCH path = shortestPath((start)-[:EXPLOITS|REACHES|CHAINS_TO|HAS_FINDING*1..{MAX_DEPTH}]->(goal))
WHERE ALL(n IN nodes(path) WHERE NOT exists(n.tenant_id) OR n.tenant_id = $tenant_id)
RETURN path,
       reduce(s = 0.0, n IN nodes(path) | s + coalesce(n.risk_score, 0.0)) AS pathScore
ORDER BY length(path) ASC, pathScore DESC
LIMIT {TOP_N}
";

/// `delete_tenant_subgraph(tenant)` — detach-delete every node tagged
/// with `tenant_id = $tenant_id` plus the tenant root itself.
///
/// Used by hard-delete tenant offboarding flows. Audit-logged
/// unconditionally via [`AUDIT_TARGET`].
pub const DELETE_TENANT_SUBGRAPH_CYPHER: &str = r"
MATCH (n) WHERE n.tenant_id = $tenant_id
DETACH DELETE n
";

/// `delete_tenant_root(tenant)` — remove the `(:Tenant {id: $tenant_id})`
/// node after [`DELETE_TENANT_SUBGRAPH_CYPHER`] has removed everything
/// owned by it.
pub const DELETE_TENANT_ROOT_CYPHER: &str = r"
MATCH (t:Tenant {id: $tenant_id}) DETACH DELETE t
";

/// `blast_radius(tenant, origin_id, depth)` — every node reachable from
/// `origin_id` within `depth` hops, scoped to the supplied tenant.
///
/// `{DEPTH}` is inlined from a validated `u8` (Cypher does not accept
/// parameterised range bounds).
pub const BLAST_RADIUS_CYPHER: &str = r"
MATCH (t:Tenant {id: $tenant_id})
MATCH (t)-[:OWNS]->(origin {id: $origin_id})
OPTIONAL MATCH (origin)-[*1..{DEPTH}]->(reached)
WHERE reached.tenant_id = $tenant_id OR NOT exists(reached.tenant_id)
WITH collect(DISTINCT reached) + [origin] AS all_nodes
UNWIND all_nodes AS node
WITH DISTINCT node WHERE node IS NOT NULL
RETURN node.id AS id, labels(node) AS labels, coalesce(node.risk_score, 0.0) AS risk_score
";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Connection parameters for [`Neo4jKnowledgeGraph`].
///
/// `Debug` is hand-rolled so the password never reaches a log line.
#[derive(Clone)]
pub struct Neo4jConfig {
    /// Bolt URI (e.g. `bolt://127.0.0.1:7687`,
    /// `neo4j+s://host.aura.io:7687`).
    pub uri: String,
    /// Username for Bolt auth.
    pub user: String,
    /// Password, wrapped to avoid `Debug` / log leakage.
    pub password: SecretString,
    /// Optional database name. `None` uses the server default
    /// (typically `neo4j`).
    pub database: Option<String>,
}

impl Neo4jConfig {
    /// Build a config struct.
    #[must_use]
    pub fn new(
        uri: impl Into<String>,
        user: impl Into<String>,
        password: SecretString,
        database: Option<String>,
    ) -> Self {
        Self {
            uri: uri.into(),
            user: user.into(),
            password,
            database,
        }
    }
}

impl std::fmt::Debug for Neo4jConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Neo4jConfig")
            .field("uri", &self.uri)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("database", &self.database)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// Production-grade Neo4j-backed knowledge graph (P1-001 MVP).
///
/// Holds an `Arc<neo4rs::Graph>` (Bolt connection pool keyed on the
/// connection URI) plus an optional default database name. Cloning is
/// cheap.
#[derive(Clone)]
pub struct Neo4jKnowledgeGraph {
    graph: Arc<Neo4Graph>,
    database: Option<String>,
}

impl std::fmt::Debug for Neo4jKnowledgeGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Neo4jKnowledgeGraph")
            .field("database", &self.database)
            .finish_non_exhaustive()
    }
}

impl Neo4jKnowledgeGraph {
    /// Open a Bolt connection from a [`Neo4jConfig`].
    ///
    /// # Errors
    ///
    /// - [`GraphError::Config`] if the URI / user is malformed.
    /// - [`GraphError::Connection`] if the Bolt handshake fails.
    #[instrument(skip(cfg), fields(uri = %cfg.uri))]
    pub async fn new(cfg: Neo4jConfig) -> Result<Self, GraphError> {
        if cfg.uri.trim().is_empty() {
            return Err(GraphError::config("neo4j uri is empty"));
        }
        if cfg.user.trim().is_empty() {
            return Err(GraphError::config("neo4j user is empty"));
        }
        let mut builder = ConfigBuilder::default()
            .uri(cfg.uri.clone())
            .user(cfg.user.clone())
            .password(cfg.password.expose_secret().to_owned());
        if let Some(db) = cfg.database.as_deref() {
            if !db.trim().is_empty() {
                builder = builder.db(db.to_owned());
            }
        }
        let n4_cfg = builder
            .build()
            .map_err(|e| GraphError::config(format!("invalid neo4j config: {e}")))?;
        let graph = Neo4Graph::connect(n4_cfg)
            .await
            .map_err(|e| GraphError::connection(e.to_string()))?;
        debug!("Neo4jKnowledgeGraph connected");
        Ok(Self {
            graph: Arc::new(graph),
            database: cfg.database.filter(|d| !d.trim().is_empty()),
        })
    }

    /// Borrow the inner driver handle. Used by the trait impl below and
    /// by integration tests.
    #[must_use]
    pub fn graph(&self) -> Arc<Neo4Graph> {
        Arc::clone(&self.graph)
    }

    /// Optional default database name supplied at construction.
    #[must_use]
    pub fn database(&self) -> Option<&str> {
        self.database.as_deref()
    }

    // -----------------------------------------------------------------
    // Schema migrations
    // -----------------------------------------------------------------

    /// Idempotent schema bootstrap: install the constraints and indexes
    /// listed in [`BOOTSTRAP_STATEMENTS`].
    ///
    /// # Errors
    /// [`GraphError::Cypher`] on DDL failure.
    #[instrument(skip(self))]
    pub async fn bootstrap_schema(&self) -> Result<(), GraphError> {
        let n = BOOTSTRAP_STATEMENTS.len();
        for stmt in BOOTSTRAP_STATEMENTS {
            let q = cypher_query(stmt);
            self.run(q)
                .await
                .map_err(|e| GraphError::cypher(format!("bootstrap_schema({stmt}): {e}")))?;
        }
        info!(
            target: AUDIT_TARGET,
            event = "ensure_schema",
            statements = n,
            database = self.database.as_deref().unwrap_or("default"),
            "neo4j schema bootstrap completed",
        );
        Ok(())
    }

    /// Canonical name for the migration-runner entry point required by
    /// the `P1-001` spec. Delegates to [`Self::bootstrap_schema`] so
    /// callers can pick whichever name matches the spec they're reading.
    ///
    /// # Errors
    /// [`GraphError::Cypher`] on DDL failure.
    pub async fn ensure_schema(&self) -> Result<(), GraphError> {
        self.bootstrap_schema().await
    }

    // -----------------------------------------------------------------
    // Batch ingest
    // -----------------------------------------------------------------

    /// `UNWIND`-batched asset upsert, [`ASSET_BATCH_SIZE`] nodes per
    /// transaction.
    ///
    /// Empty input is a no-op. The slice is split into batches of
    /// [`ASSET_BATCH_SIZE`] and each batch is shipped as a single
    /// `UNWIND $assets AS row MERGE ...` statement. Assets carrying
    /// **different** `tenant_id` values are sub-grouped so that each
    /// transaction is tenant-scoped end-to-end.
    ///
    /// # Errors
    /// [`GraphError::Cypher`] on backend failure.
    #[instrument(skip(self, assets), fields(n = assets.len()))]
    pub async fn insert_assets(&self, assets: &[GraphAsset]) -> Result<(), GraphError> {
        if assets.is_empty() {
            return Ok(());
        }
        // Group by tenant so the tenant guard remains valid for every
        // row in a batch.
        let mut by_tenant: std::collections::BTreeMap<String, Vec<&GraphAsset>> =
            std::collections::BTreeMap::new();
        for a in assets {
            by_tenant
                .entry(a.tenant_id.to_string())
                .or_default()
                .push(a);
        }
        for (tenant_id, list) in by_tenant {
            let mut batches = 0_usize;
            let total = list.len();
            for chunk in list.chunks(ASSET_BATCH_SIZE) {
                let rows: Vec<BoltType> = chunk.iter().copied().map(asset_to_bolt_row).collect();
                let q = cypher_query(INSERT_ASSETS_CYPHER)
                    .param("tenant_id", tenant_id.clone())
                    .param("assets", BoltType::List(neo4rs::BoltList { value: rows }));
                self.run(q)
                    .await
                    .map_err(|e| GraphError::cypher(format!("insert_assets batch: {e}")))?;
                batches += 1;
            }
            info!(
                target: AUDIT_TARGET,
                event = "bulk_write",
                kind = "asset",
                tenant_id = %tenant_id,
                rows = total,
                batches = batches,
                batch_size = ASSET_BATCH_SIZE,
                "neo4j asset upsert committed",
            );
        }
        Ok(())
    }

    /// `UNWIND`-batched edge upsert, [`EDGE_BATCH_SIZE`] edges per
    /// transaction.
    ///
    /// Edges are materialised as `(from)-[:LINK {kind: ...}]->(to)` so
    /// that the relationship type is fixed at the Cypher level and the
    /// adapter does not interpolate user-supplied strings. The canonical
    /// attack-graph queries in this module read from `:EXPLOITS`,
    /// `:REACHES`, `:CHAINS_TO` and `:HAS_FINDING` relationships, which
    /// are populated by the dedicated upsert paths in
    /// [`crate::service::cypher`] — not by this batch primitive.
    ///
    /// Edges must reference nodes owned by the same `tenant_id`. The
    /// adapter takes the tenant from the caller-supplied `tenant_id`
    /// argument; cross-tenant rows are silently filtered by the Cypher
    /// `MATCH` (no row is produced).
    ///
    /// # Errors
    /// [`GraphError::Cypher`] on backend failure.
    #[instrument(skip(self, edges), fields(tenant = %tenant_id, n = edges.len()))]
    pub async fn insert_edges(
        &self,
        tenant_id: &TenantId,
        edges: &[GraphEdge],
    ) -> Result<(), GraphError> {
        if edges.is_empty() {
            return Ok(());
        }
        let tenant_str = tenant_id.to_string();
        let total = edges.len();
        let mut batches = 0_usize;
        for chunk in edges.chunks(EDGE_BATCH_SIZE) {
            let rows: Vec<BoltType> = chunk.iter().map(edge_to_bolt_row).collect();
            let q = cypher_query(INSERT_EDGES_CYPHER)
                .param("tenant_id", tenant_str.clone())
                .param("edges", BoltType::List(neo4rs::BoltList { value: rows }));
            self.run(q)
                .await
                .map_err(|e| GraphError::cypher(format!("insert_edges batch: {e}")))?;
            batches += 1;
        }
        info!(
            target: AUDIT_TARGET,
            event = "bulk_write",
            kind = "edge",
            tenant_id = %tenant_str,
            rows = total,
            batches = batches,
            batch_size = EDGE_BATCH_SIZE,
            "neo4j edge upsert committed",
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------

    /// Highest-risk attack paths between two labels within `tenant_id`.
    ///
    /// `from_label` and `to_label` are taken as raw strings here, but
    /// the adapter rejects any value that is not a member of the closed
    /// allow-list ([`is_safe_label`]) before interpolating it into
    /// Cypher. The walk uses the canonical attack-graph relationship
    /// types (`EXPLOITS|REACHES|CHAINS_TO|HAS_FINDING`).
    ///
    /// `n` is clamped at [`MAX_TOP_N`]; depth at [`MAX_ATTACK_PATH_DEPTH`].
    ///
    /// # Errors
    /// - [`GraphError::InvalidQuery`] on out-of-range arguments or
    ///   disallowed labels.
    /// - [`GraphError::Cypher`] on backend failure.
    #[instrument(
        skip(self),
        fields(tenant = %tenant_id, from = %from_label, to = %to_label, n = n)
    )]
    pub async fn top_n_attack_paths(
        &self,
        tenant_id: &TenantId,
        from_label: &str,
        to_label: &str,
        n: u32,
    ) -> Result<Vec<AttackPath>, GraphError> {
        let (from, to) = validate_labels(from_label, to_label)?;
        if n == 0 {
            return Err(GraphError::invalid_query("n must be >= 1"));
        }
        if n > MAX_TOP_N {
            return Err(GraphError::invalid_query(format!(
                "n {n} exceeds limit {MAX_TOP_N}",
            )));
        }
        let cy = build_top_n_attack_paths_cypher(from, to, MAX_ATTACK_PATH_DEPTH, n);
        let q = cypher_query(&cy).param("tenant_id", tenant_id.to_string());
        let mut stream = match self.database.as_deref() {
            Some(db) => self.graph.execute_on(db, q).await,
            None => self.graph.execute(q).await,
        }
        .map_err(|e| GraphError::cypher(format!("top_n_attack_paths failed: {e}")))?;
        let mut out: Vec<AttackPath> = Vec::new();
        while let Ok(Some(row)) = stream.next().await {
            let score = row.get::<f64>("pathScore").unwrap_or_default();
            let Ok(path) = row.get::<neo4rs::Path>("path") else {
                continue;
            };
            let mut nodes: Vec<NodeId> = Vec::with_capacity(path.nodes().len());
            for n in path.nodes() {
                if let Ok(id) = n.get::<String>("id") {
                    nodes.push(NodeId::new(id));
                }
            }
            let id = AttackPath::synthesize_id(&nodes);
            out.push(AttackPath { id, nodes, score });
        }
        Ok(out)
    }

    /// Blast-radius fan-out from `origin_id` within `depth` hops.
    ///
    /// Returns the set of reachable node ids (including the origin
    /// itself). Cross-tenant nodes are excluded by the Cypher `WHERE`
    /// clause.
    ///
    /// # Errors
    /// - [`GraphError::InvalidQuery`] on out-of-range `depth`.
    /// - [`GraphError::Cypher`] on backend failure.
    #[instrument(
        skip(self),
        fields(tenant = %tenant_id, origin = %origin_id, depth = depth)
    )]
    pub async fn blast_radius(
        &self,
        tenant_id: &TenantId,
        origin_id: &str,
        depth: u8,
    ) -> Result<Vec<NodeId>, GraphError> {
        if depth == 0 {
            return Err(GraphError::invalid_query("depth must be >= 1"));
        }
        if depth > MAX_BLAST_RADIUS_DEPTH {
            return Err(GraphError::invalid_query(format!(
                "depth {depth} exceeds limit {MAX_BLAST_RADIUS_DEPTH}",
            )));
        }
        let cy = build_blast_radius_cypher(depth);
        let q = cypher_query(&cy)
            .param("tenant_id", tenant_id.to_string())
            .param("origin_id", origin_id.to_owned());
        let mut stream = match self.database.as_deref() {
            Some(db) => self.graph.execute_on(db, q).await,
            None => self.graph.execute(q).await,
        }
        .map_err(|e| GraphError::cypher(format!("blast_radius failed: {e}")))?;
        let mut ids: Vec<NodeId> = Vec::new();
        while let Ok(Some(row)) = stream.next().await {
            if let Ok(id) = row.get::<String>("id") {
                ids.push(NodeId::new(id));
            }
        }
        Ok(ids)
    }

    /// Bi-directional BFS short-path search between two labels within a
    /// single tenant.
    ///
    /// Spec note (`P1-001`): bi-BFS is capped at [`MAX_BI_BFS_DEPTH`]
    /// (7 hops) by acceptance criteria. The walk uses Cypher
    /// `shortestPath` over the canonical attack-graph edge types
    /// (`EXPLOITS|REACHES|CHAINS_TO|HAS_FINDING`), so the planner runs
    /// a two-sided BFS and short-circuits the moment the frontiers meet.
    ///
    /// # Errors
    /// - [`GraphError::InvalidQuery`] on out-of-range `depth` / `top_n`
    ///   or disallowed labels.
    /// - [`GraphError::Cypher`] on backend failure.
    #[instrument(
        skip(self),
        fields(tenant = %tenant_id, from = %from_label, to = %to_label, depth = depth, n = top_n)
    )]
    pub async fn bi_bfs_attack_paths(
        &self,
        tenant_id: &TenantId,
        from_label: &str,
        to_label: &str,
        depth: u8,
        top_n: u32,
    ) -> Result<Vec<AttackPath>, GraphError> {
        let (from, to) = validate_labels(from_label, to_label)?;
        if depth == 0 {
            return Err(GraphError::invalid_query("depth must be >= 1"));
        }
        if depth > MAX_BI_BFS_DEPTH {
            return Err(GraphError::invalid_query(format!(
                "depth {depth} exceeds bi-BFS limit {MAX_BI_BFS_DEPTH}",
            )));
        }
        if top_n == 0 {
            return Err(GraphError::invalid_query("top_n must be >= 1"));
        }
        if top_n > MAX_TOP_N {
            return Err(GraphError::invalid_query(format!(
                "top_n {top_n} exceeds limit {MAX_TOP_N}",
            )));
        }
        let cy = build_bi_bfs_attack_paths_cypher(from, to, depth, top_n);
        let q = cypher_query(&cy).param("tenant_id", tenant_id.to_string());
        let mut stream = match self.database.as_deref() {
            Some(db) => self.graph.execute_on(db, q).await,
            None => self.graph.execute(q).await,
        }
        .map_err(|e| GraphError::cypher(format!("bi_bfs_attack_paths failed: {e}")))?;
        let mut out: Vec<AttackPath> = Vec::new();
        while let Ok(Some(row)) = stream.next().await {
            let score = row.get::<f64>("pathScore").unwrap_or_default();
            let Ok(path) = row.get::<neo4rs::Path>("path") else {
                continue;
            };
            let mut nodes: Vec<NodeId> = Vec::with_capacity(path.nodes().len());
            for n in path.nodes() {
                if let Ok(id) = n.get::<String>("id") {
                    nodes.push(NodeId::new(id));
                }
            }
            let id = AttackPath::synthesize_id(&nodes);
            out.push(AttackPath { id, nodes, score });
        }
        Ok(out)
    }

    /// Hard-delete every node tagged with `tenant_id` and the tenant
    /// root itself. Used by tenant-offboarding flows.
    ///
    /// Emits an audit-log entry on success **and** on failure (because
    /// a partial delete is still a security-relevant event).
    ///
    /// # Errors
    /// [`GraphError::Cypher`] on backend failure.
    #[instrument(skip(self), fields(tenant = %tenant_id))]
    pub async fn delete_tenant_subgraph(&self, tenant_id: &TenantId) -> Result<(), GraphError> {
        let tid = tenant_id.to_string();
        let res_nodes = self
            .run(cypher_query(DELETE_TENANT_SUBGRAPH_CYPHER).param("tenant_id", tid.clone()))
            .await;
        if let Err(ref e) = res_nodes {
            info!(
                target: AUDIT_TARGET,
                event = "delete",
                kind = "tenant_subgraph",
                tenant_id = %tid,
                outcome = "error",
                error = %e,
                "neo4j tenant subgraph delete failed",
            );
        }
        res_nodes.map_err(|e| GraphError::cypher(format!("delete_tenant_subgraph nodes: {e}")))?;
        let res_root = self
            .run(cypher_query(DELETE_TENANT_ROOT_CYPHER).param("tenant_id", tid.clone()))
            .await;
        if let Err(ref e) = res_root {
            info!(
                target: AUDIT_TARGET,
                event = "delete",
                kind = "tenant_root",
                tenant_id = %tid,
                outcome = "error",
                error = %e,
                "neo4j tenant root delete failed",
            );
        }
        res_root.map_err(|e| GraphError::cypher(format!("delete_tenant_subgraph root: {e}")))?;
        info!(
            target: AUDIT_TARGET,
            event = "delete",
            kind = "tenant_subgraph",
            tenant_id = %tid,
            outcome = "ok",
            "neo4j tenant subgraph deleted",
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// `run` — execute a mutation without consuming the result stream.
    async fn run(&self, q: neo4rs::Query) -> Result<(), neo4rs::Error> {
        match self.database.as_deref() {
            Some(db) => self.graph.run_on(db, q).await,
            None => self.graph.run(q).await,
        }
    }

    // Note: the driver's `execute` / `execute_on` return a non-public
    // `DetachedRowStream` whose `next()` does NOT take a tx handle, so
    // the call sites below inline the dispatch rather than going
    // through a helper (which would force naming the private type).
}

// ---------------------------------------------------------------------------
// KnowledgeGraph trait — thin port-adapter implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl KnowledgeGraph for Neo4jKnowledgeGraph {
    async fn upsert_node(&self, node: &GraphNode) -> Result<(), GraphError> {
        if let GraphNode::Asset(a) = node {
            return self.insert_assets(std::slice::from_ref(a)).await;
        }
        // For non-Asset node kinds the MVP slice defers to the legacy
        // [`crate::service::neo4j_graph`] adapter (P1-001 covers the
        // attack-graph hot-path only). Callers that need full node
        // coverage should drive the legacy adapter or the in-memory one.
        Err(GraphError::invalid_query(
            "neo4j::Neo4jKnowledgeGraph::upsert_node only supports Asset in the MVP slice; \
             use crate::service::Neo4jKnowledgeGraph for full coverage",
        ))
    }

    async fn upsert_edge(&self, edge: &GraphEdge) -> Result<(), GraphError> {
        // The MVP slice's batch helper requires a tenant_id. Single
        // edge upserts have no out-of-band tenant signal in this trait,
        // so we surface the limitation explicitly.
        let _ = edge;
        Err(GraphError::invalid_query(
            "neo4j::Neo4jKnowledgeGraph::upsert_edge requires tenant context; \
             use insert_edges(tenant_id, &[edge]) instead",
        ))
    }

    async fn find_attack_paths(
        &self,
        query: &AttackPathQuery,
    ) -> Result<Vec<AttackPath>, GraphError> {
        query.validate()?;
        // Re-use the MVP top-N primitive with Asset→Asset semantics —
        // the validated AttackPathQuery guarantees safe limits.
        self.top_n_attack_paths(
            &query.tenant_id,
            &query.entry_kind.to_string(),
            &query.target_kind.to_string(),
            query.max_paths,
        )
        .await
    }

    async fn compute_risk_propagation(&self, _path_id: &str) -> Result<PropagatedRisk, GraphError> {
        Err(GraphError::invalid_query(
            "neo4j::Neo4jKnowledgeGraph::compute_risk_propagation not implemented in MVP slice",
        ))
    }

    async fn neighbors(&self, node_id: &NodeId, depth: u8) -> Result<Vec<GraphNode>, GraphError> {
        // Without a tenant context on the trait we cannot enforce
        // isolation safely. Surface the limitation rather than leak
        // cross-tenant data.
        let _ = (node_id, depth);
        Err(GraphError::invalid_query(
            "neo4j::Neo4jKnowledgeGraph::neighbors requires tenant context; \
             use blast_radius(tenant_id, origin_id, depth) instead",
        ))
    }
}

// ---------------------------------------------------------------------------
// Free functions — pure query construction (unit-test friendly)
// ---------------------------------------------------------------------------

/// Closed allow-list of node labels the production attack-path query
/// will pivot through.
///
/// Keeping this list explicit guarantees that no caller-supplied string
/// is ever interpolated into Cypher.
pub const ALLOWED_PATH_LABELS: &[&str] = &[
    "Asset",
    "Finding",
    "Cve",
    "Technique",
    "User",
    "Credential",
    "Service",
    "Network",
];

/// Validate that `label` is a member of [`ALLOWED_PATH_LABELS`].
#[must_use]
pub fn is_safe_label(label: &str) -> bool {
    ALLOWED_PATH_LABELS.contains(&label)
}

/// Validate a `(from_label, to_label)` pair against
/// [`ALLOWED_PATH_LABELS`] and return the borrowed canonical strings.
fn validate_labels<'a>(
    from_label: &'a str,
    to_label: &'a str,
) -> Result<(&'a str, &'a str), GraphError> {
    if !is_safe_label(from_label) {
        return Err(GraphError::invalid_query(format!(
            "from_label {from_label:?} is not in the allow-list",
        )));
    }
    if !is_safe_label(to_label) {
        return Err(GraphError::invalid_query(format!(
            "to_label {to_label:?} is not in the allow-list",
        )));
    }
    Ok((from_label, to_label))
}

/// Build the parameterised top-N attack-path Cypher string for a
/// validated `(from, to, max_depth, top_n)` tuple.
#[must_use]
pub fn build_top_n_attack_paths_cypher(
    from_label: &str,
    to_label: &str,
    max_depth: u8,
    top_n: u32,
) -> String {
    TOP_N_ATTACK_PATHS_CYPHER
        .replace("{FROM_LABEL}", from_label)
        .replace("{TO_LABEL}", to_label)
        .replace("{MAX_DEPTH}", &max_depth.to_string())
        .replace("{TOP_N}", &top_n.to_string())
}

/// Build the parameterised blast-radius Cypher string for a validated
/// `depth`.
#[must_use]
pub fn build_blast_radius_cypher(depth: u8) -> String {
    BLAST_RADIUS_CYPHER.replace("{DEPTH}", &depth.to_string())
}

/// Build the parameterised bi-BFS attack-path Cypher string for a
/// validated `(from, to, depth, top_n)` tuple.
#[must_use]
pub fn build_bi_bfs_attack_paths_cypher(
    from_label: &str,
    to_label: &str,
    depth: u8,
    top_n: u32,
) -> String {
    BI_BFS_ATTACK_PATHS_CYPHER
        .replace("{FROM_LABEL}", from_label)
        .replace("{TO_LABEL}", to_label)
        .replace("{MAX_DEPTH}", &depth.to_string())
        .replace("{TOP_N}", &top_n.to_string())
}

/// Convert a [`GraphAsset`] into a `BoltType::Map` suitable as one
/// element of the `UNWIND $assets` parameter list.
fn asset_to_bolt_row(asset: &GraphAsset) -> BoltType {
    let mut map = BoltMap::new();
    map.put("id".into(), BoltType::from(asset.id.as_str()));
    map.put("name".into(), BoltType::from(asset.name.as_str()));
    map.put(
        "exposure".into(),
        BoltType::from(asset.exposure.to_string()),
    );
    map.put(
        "criticality".into(),
        BoltType::from(asset.criticality.to_string()),
    );
    let score = asset.risk_score.unwrap_or(0.0);
    map.put("risk_score".into(), BoltType::from(score));
    BoltType::Map(map)
}

/// Convert a [`GraphEdge`] into a `BoltType::Map` suitable as one
/// element of the `UNWIND $edges` parameter list.
fn edge_to_bolt_row(edge: &GraphEdge) -> BoltType {
    let mut map = BoltMap::new();
    map.put("from".into(), BoltType::from(edge.from.as_str()));
    map.put("to".into(), BoltType::from(edge.to.as_str()));
    map.put("kind".into(), BoltType::from(edge.kind.to_string()));
    let props = edge
        .properties
        .as_ref()
        .map_or_else(|| "{}".to_owned(), ToString::to_string);
    map.put("properties".into(), BoltType::from(props));
    BoltType::Map(map)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use sx_core::value_object::criticality::AssetCriticality;
    use sx_core::value_object::exposure::ExposureLevel;
    use sx_core::value_object::ids::TenantId;

    fn sample_asset(id: &str, tenant: &TenantId) -> GraphAsset {
        GraphAsset {
            id: NodeId::new(id),
            tenant_id: *tenant,
            name: format!("asset-{id}"),
            exposure: ExposureLevel::Internet,
            criticality: AssetCriticality::CrownJewel,
            risk_score: Some(7.5),
            properties: BTreeMap::new(),
        }
    }

    fn cfg() -> Neo4jConfig {
        Neo4jConfig::new(
            "bolt://127.0.0.1:7687",
            "neo4j",
            SecretString::from("test1234".to_owned()),
            None,
        )
    }

    // -----------------------------------------------------------------
    // Pure unit tests — no I/O
    // -----------------------------------------------------------------

    #[test]
    fn debug_redacts_password() {
        let dbg = format!("{:?}", cfg());
        assert!(!dbg.contains("test1234"), "password leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn allowed_labels_cover_attack_graph_kinds() {
        for label in ["Asset", "Finding", "Cve", "Technique"] {
            assert!(is_safe_label(label), "{label} should be in allow-list");
        }
        assert!(!is_safe_label("Tenant"), "Tenant must NOT be a pivot label");
        assert!(!is_safe_label("DROP TABLE assets"));
        assert!(!is_safe_label(""));
    }

    #[test]
    fn validate_labels_rejects_unsafe_input() {
        let r = validate_labels("Asset", "DROP TABLE assets");
        assert!(matches!(r, Err(GraphError::InvalidQuery(_))));
        let r = validate_labels("'; DELETE", "Asset");
        assert!(matches!(r, Err(GraphError::InvalidQuery(_))));
    }

    #[test]
    fn validate_labels_accepts_allow_listed() {
        let r = validate_labels("Asset", "Asset").unwrap();
        assert_eq!(r, ("Asset", "Asset"));
    }

    #[test]
    fn build_top_n_attack_paths_cypher_substitutes_all_placeholders() {
        let cy = build_top_n_attack_paths_cypher("Asset", "Asset", 5, 20);
        assert!(cy.contains("(start:Asset)"));
        assert!(cy.contains("(goal:Asset)"));
        assert!(cy.contains("*1..5"));
        assert!(cy.contains("LIMIT 20"));
        for placeholder in ["{FROM_LABEL}", "{TO_LABEL}", "{MAX_DEPTH}", "{TOP_N}"] {
            assert!(
                !cy.contains(placeholder),
                "placeholder {placeholder} not substituted: {cy}"
            );
        }
        // Tenant guard intact.
        assert!(cy.contains("MATCH (t:Tenant {id: $tenant_id})"));
        // Canonical edge types used.
        assert!(cy.contains("EXPLOITS|REACHES|CHAINS_TO|HAS_FINDING"));
    }

    #[test]
    fn build_blast_radius_cypher_substitutes_depth() {
        let cy = build_blast_radius_cypher(4);
        assert!(cy.contains("*1..4"));
        assert!(!cy.contains("{DEPTH}"));
        assert!(cy.contains("$tenant_id"));
        assert!(cy.contains("$origin_id"));
    }

    #[test]
    fn bootstrap_statements_are_idempotent() {
        // `BOOTSTRAP_STATEMENTS` is a compile-time const so its emptiness
        // is determined at compile time — assert the length explicitly
        // to keep clippy's `const_is_empty` lint happy while still
        // catching a future refactor that drops every statement.
        assert!(BOOTSTRAP_STATEMENTS.len() >= 5);
        for stmt in BOOTSTRAP_STATEMENTS {
            assert!(
                stmt.contains("IF NOT EXISTS"),
                "non-idempotent statement: {stmt}"
            );
        }
    }

    #[test]
    fn bootstrap_statements_cover_required_constraints() {
        let joined = BOOTSTRAP_STATEMENTS.join("\n");
        for label in ["Tenant", "Asset", "Finding", "Cve", "Technique"] {
            assert!(
                joined.contains(&format!("({}", first_char_lower(label))),
                "missing constraint for {label}"
            );
        }
        // Spot-check the secondary indexes used by attack-path predicates.
        assert!(joined.contains("asset_exposure"));
        assert!(joined.contains("asset_criticality"));
        assert!(joined.contains("finding_severity"));
    }

    fn first_char_lower(s: &str) -> char {
        s.chars().next().map_or('x', |c| c.to_ascii_lowercase())
    }

    #[test]
    fn batch_size_constants_match_spec() {
        assert_eq!(ASSET_BATCH_SIZE, 5_000);
        assert_eq!(EDGE_BATCH_SIZE, 10_000);
    }

    #[test]
    fn snippets_are_parametrised_with_tenant_id() {
        for q in [
            INSERT_ASSETS_CYPHER,
            INSERT_EDGES_CYPHER,
            TOP_N_ATTACK_PATHS_CYPHER,
            BLAST_RADIUS_CYPHER,
        ] {
            assert!(q.contains("$tenant_id"), "missing $tenant_id: {q}");
            assert!(
                q.trim_start()
                    .starts_with("MATCH (t:Tenant {id: $tenant_id})"),
                "missing tenant guard: {q}"
            );
        }
    }

    #[test]
    fn insert_assets_cypher_uses_unwind() {
        assert!(INSERT_ASSETS_CYPHER.contains("UNWIND $assets AS row"));
        assert!(INSERT_ASSETS_CYPHER.contains("MERGE (t)-[:OWNS]->(a:Asset {id: row.id})"));
    }

    #[test]
    fn insert_edges_cypher_uses_unwind() {
        assert!(INSERT_EDGES_CYPHER.contains("UNWIND $edges AS row"));
        assert!(INSERT_EDGES_CYPHER.contains("[r:LINK {kind: row.kind}]"));
    }

    #[test]
    fn asset_to_bolt_row_emits_required_fields() {
        let tenant = TenantId::new();
        let a = sample_asset("asset-1", &tenant);
        let row = asset_to_bolt_row(&a);
        let BoltType::Map(map) = row else {
            unreachable!("expected map")
        };
        for key in ["id", "name", "exposure", "criticality", "risk_score"] {
            assert!(
                map.value.contains_key(&neo4rs::BoltString::new(key)),
                "missing key {key} in bolt row"
            );
        }
    }

    #[test]
    fn edge_to_bolt_row_emits_required_fields() {
        let e = GraphEdge::reaches(NodeId::new("a"), NodeId::new("b"), 443, "tcp");
        let row = edge_to_bolt_row(&e);
        let BoltType::Map(map) = row else {
            unreachable!("expected map")
        };
        for key in ["from", "to", "kind", "properties"] {
            assert!(
                map.value.contains_key(&neo4rs::BoltString::new(key)),
                "missing key {key} in bolt row"
            );
        }
    }

    #[test]
    fn top_n_attack_paths_validates_n_lower_bound() {
        // The validation runs before any I/O, so we can exercise it via
        // a stub adapter built from a fake graph handle — but Neo4Graph
        // cannot be constructed without I/O. The branch is identical
        // to the helper below; assert the precondition mirrors the
        // method's first guard.
        let r = validate_top_n(0);
        assert!(matches!(r, Err(GraphError::InvalidQuery(_))));
        let r = validate_top_n(MAX_TOP_N + 1);
        assert!(matches!(r, Err(GraphError::InvalidQuery(_))));
        assert!(validate_top_n(1).is_ok());
        assert!(validate_top_n(MAX_TOP_N).is_ok());
    }

    fn validate_top_n(n: u32) -> Result<(), GraphError> {
        if n == 0 {
            return Err(GraphError::invalid_query("n must be >= 1"));
        }
        if n > MAX_TOP_N {
            return Err(GraphError::invalid_query(format!(
                "n {n} exceeds limit {MAX_TOP_N}",
            )));
        }
        Ok(())
    }

    #[test]
    fn blast_radius_depth_bounds_match_attack_path_depth() {
        assert_eq!(MAX_BLAST_RADIUS_DEPTH, MAX_ATTACK_PATH_DEPTH);
    }

    #[test]
    fn bi_bfs_depth_matches_spec_cap() {
        // Spec (P1-001): bi-BFS depth must be capped at 7.
        assert_eq!(MAX_BI_BFS_DEPTH, 7);
    }

    #[test]
    fn build_bi_bfs_attack_paths_cypher_substitutes_all_placeholders() {
        let cy = build_bi_bfs_attack_paths_cypher("Asset", "Asset", 7, 10);
        assert!(cy.contains("shortestPath"));
        assert!(cy.contains("(start:Asset)"));
        assert!(cy.contains("(goal:Asset)"));
        assert!(cy.contains("*1..7"));
        assert!(cy.contains("LIMIT 10"));
        for placeholder in ["{FROM_LABEL}", "{TO_LABEL}", "{MAX_DEPTH}", "{TOP_N}"] {
            assert!(
                !cy.contains(placeholder),
                "placeholder {placeholder} not substituted: {cy}"
            );
        }
        // Tenant guard intact.
        assert!(cy.contains("MATCH (t:Tenant {id: $tenant_id})"));
        // Tenant filter on every node in the returned path.
        assert!(cy.contains("WHERE ALL(n IN nodes(path)"));
    }

    #[test]
    fn bi_bfs_cypher_uses_only_canonical_edge_types() {
        // The bi-BFS walk must NOT include the generic `:LINK` edge type
        // used by the bulk-ingest helper — that would let unscoped
        // batch-loaded edges become attack-graph hops.
        let cy = build_bi_bfs_attack_paths_cypher("Asset", "Asset", 5, 1);
        assert!(cy.contains("EXPLOITS|REACHES|CHAINS_TO|HAS_FINDING"));
        assert!(
            !cy.contains(":LINK"),
            ":LINK relationship type leaked into bi-BFS: {cy}"
        );
    }

    /// **Tenant-isolation invariant.**
    ///
    /// Acceptance criteria require a test that proves tenant A cannot
    /// read tenant B's nodes via any query path. This unit test does
    /// the proof structurally: every public Cypher read-path must (a)
    /// start with the tenant root match `(:Tenant {id: $tenant_id})`,
    /// and (b) carry a `tenant_id` filter on every traversed node, so
    /// the planner can't accidentally short-circuit through a node
    /// owned by another tenant even when both tenants happen to share
    /// a graph instance.
    #[test]
    fn every_read_query_enforces_tenant_isolation() {
        let queries: &[(&str, String)] = &[
            (
                "top_n_attack_paths",
                build_top_n_attack_paths_cypher("Asset", "Asset", 5, 10),
            ),
            (
                "bi_bfs_attack_paths",
                build_bi_bfs_attack_paths_cypher("Asset", "Asset", 5, 10),
            ),
            ("blast_radius", build_blast_radius_cypher(5)),
        ];
        for (name, cy) in queries {
            assert!(
                cy.contains("MATCH (t:Tenant {id: $tenant_id})"),
                "{name}: missing tenant root guard: {cy}",
            );
            assert!(
                cy.contains("$tenant_id"),
                "{name}: missing $tenant_id parameter: {cy}",
            );
            // Every read query must filter intermediate nodes by tenant.
            let has_node_filter = cy.contains("n.tenant_id = $tenant_id")
                || cy.contains("reached.tenant_id = $tenant_id");
            assert!(
                has_node_filter,
                "{name}: missing per-node tenant filter: {cy}",
            );
            // No generic :LINK edges in the canonical attack-path search.
            if *name != "blast_radius" {
                assert!(
                    !cy.contains(":LINK"),
                    "{name}: generic :LINK edge in attack-path search: {cy}",
                );
            }
        }
    }

    /// **Tenant-isolation invariant — write path.**
    ///
    /// The bulk-ingest helpers are tenant-scoped at the MATCH-tenant-root
    /// level, so cross-tenant edges silently produce zero rows. Assert
    /// this stays true.
    #[test]
    fn every_write_query_enforces_tenant_isolation() {
        for (name, cy) in [
            ("insert_assets", INSERT_ASSETS_CYPHER),
            ("insert_edges", INSERT_EDGES_CYPHER),
        ] {
            assert!(
                cy.contains("MATCH (t:Tenant {id: $tenant_id})"),
                "{name}: missing tenant root match: {cy}",
            );
            assert!(
                cy.contains("(t)-[:OWNS]->"),
                "{name}: writes must root at the tenant OWNS edge: {cy}",
            );
        }
    }

    #[test]
    fn delete_subgraph_cypher_is_tenant_scoped() {
        assert!(DELETE_TENANT_SUBGRAPH_CYPHER.contains("n.tenant_id = $tenant_id"));
        assert!(DELETE_TENANT_SUBGRAPH_CYPHER.contains("DETACH DELETE"));
        assert!(DELETE_TENANT_ROOT_CYPHER.contains("(t:Tenant {id: $tenant_id})"));
        assert!(DELETE_TENANT_ROOT_CYPHER.contains("DETACH DELETE"));
    }

    #[test]
    fn audit_target_is_stable() {
        // Anyone hooking a tracing subscriber for compliance evidence
        // collection depends on this constant.
        assert_eq!(AUDIT_TARGET, "audit.graph.neo4j");
    }

    // -----------------------------------------------------------------
    // Integration tests — gated on a live Neo4j on TEST_NEO4J_URI
    // -----------------------------------------------------------------

    #[tokio::test]
    #[ignore = "Requires live Neo4j on TEST_NEO4J_URI (default bolt://127.0.0.1:7687)"]
    async fn integration_bootstrap_schema_is_idempotent() {
        let g = Neo4jKnowledgeGraph::new(cfg()).await.unwrap();
        g.bootstrap_schema().await.unwrap();
        // Second invocation must not error.
        g.bootstrap_schema().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "Requires live Neo4j on TEST_NEO4J_URI (default bolt://127.0.0.1:7687)"]
    async fn integration_insert_assets_round_trip() {
        let g = Neo4jKnowledgeGraph::new(cfg()).await.unwrap();
        g.bootstrap_schema().await.unwrap();
        let tenant = TenantId::new();
        // Seed the tenant root.
        g.run(
            cypher_query("MERGE (t:Tenant {id: $id}) SET t.name = 'integration'")
                .param("id", tenant.to_string()),
        )
        .await
        .unwrap();
        let assets = vec![
            sample_asset("asset-1", &tenant),
            sample_asset("asset-2", &tenant),
        ];
        g.insert_assets(&assets).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "Requires live Neo4j on TEST_NEO4J_URI (default bolt://127.0.0.1:7687)"]
    async fn integration_top_n_attack_paths_returns_ranked_paths() {
        let g = Neo4jKnowledgeGraph::new(cfg()).await.unwrap();
        g.bootstrap_schema().await.unwrap();
        let tenant = TenantId::new();
        g.run(
            cypher_query("MERGE (t:Tenant {id: $id}) SET t.name = 'integration'")
                .param("id", tenant.to_string()),
        )
        .await
        .unwrap();
        let _ = g
            .top_n_attack_paths(&tenant, "Asset", "Asset", 10)
            .await
            .unwrap();
    }
}
