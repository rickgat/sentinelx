//! Parametrised Cypher snippets shared by the Neo4j adapter.
//!
//! ## Parametrisation contract
//!
//! Every snippet in this module uses Neo4j 5.x `$paramName` parameter
//! syntax for caller-supplied values. The only string substitutions
//! the adapter performs at runtime are:
//!
//! 1. Node labels — produced from [`crate::model::node::NodeKind`]
//!    via its `Display` impl. Cypher does not accept parametrised
//!    labels, so the closed enum's string form is the canonical source.
//! 2. Relationship types — produced from
//!    [`crate::model::edge::EdgeKind`] in the same way.
//! 3. Path-length range bounds (`*1..N`) — Cypher does not accept
//!    parametrised range bounds. The adapter inlines a validated
//!    `u8 max_depth` after [`crate::port::AttackPathQuery::validate`]
//!    has clamped it to [`crate::port::MAX_ATTACK_PATH_DEPTH`].
//!
//! **No caller-supplied string is ever interpolated.**
//!
//! ## Tenant isolation
//!
//! Every tenant-scoped query starts with
//!
//! ```text
//! MATCH (t:Tenant {id: $tenant_id})
//! ```
//!
//! and creates/matches all related nodes/edges through `(t)-[:OWNS]->`
//! so that even a malicious node `id` cannot escape the tenant
//! sub-graph. The adapter MUST pass `$tenant_id` as a string parameter
//! on every call.
//!
//! ## Schema indexes
//!
//! The Neo4j adapter expects the indexes in [`INDEX_STATEMENTS`] to be
//! present (created by
//! [`crate::service::Neo4jKnowledgeGraph::ensure_indexes`]).

/// Index DDL statements run by `ensure_indexes`. All statements are
/// idempotent (`IF NOT EXISTS`).
pub const INDEX_STATEMENTS: &[&str] = &[
    "CREATE INDEX tenant_id IF NOT EXISTS FOR (t:Tenant) ON (t.id)",
    "CREATE INDEX asset_id IF NOT EXISTS FOR (a:Asset) ON (a.id)",
    "CREATE INDEX finding_id IF NOT EXISTS FOR (f:Finding) ON (f.id)",
    "CREATE INDEX cve_id IF NOT EXISTS FOR (c:Cve) ON (c.id)",
    "CREATE INDEX technique_id IF NOT EXISTS FOR (t:Technique) ON (t.id)",
    "CREATE INDEX asset_tenant_id IF NOT EXISTS FOR (a:Asset) ON (a.tenant_id)",
    "CREATE INDEX asset_exposure IF NOT EXISTS FOR (a:Asset) ON (a.exposure)",
    "CREATE INDEX asset_criticality IF NOT EXISTS FOR (a:Asset) ON (a.criticality)",
    "CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity)",
    "CREATE INDEX finding_tenant_id IF NOT EXISTS FOR (f:Finding) ON (f.tenant_id)",
];

// ---------------------------------------------------------------------------
// CRUD: tenant-scoped CREATE / MERGE
// ---------------------------------------------------------------------------

/// `add_asset_node(tenant, asset_id, kind, identifier)`.
///
/// Tenant-isolated: the asset is `MERGE`d as a child of
/// `(:Tenant {id: $tenant_id})`. If the node already exists but is
/// owned by a different tenant, the read-back will return no row and
/// the adapter raises [`crate::error::GraphError::TenantBoundary`].
///
/// Parameters:
/// - `$tenant_id` — owning tenant.
/// - `$asset_id` — stable asset identifier (`MERGE` key).
/// - `$kind` — asset kind tag stored on the node (e.g. `"host"`,
///   `"service"`); free-form, scoped through Tenant.
/// - `$identifier` — human-friendly identifier (hostname, ARN, ...).
pub const ADD_ASSET_NODE: &str = r"
MATCH (t:Tenant {id: $tenant_id})
MERGE (t)-[:OWNS]->(a:Asset {id: $asset_id})
  ON CREATE SET a.tenant_id = $tenant_id,
                a.kind = $kind,
                a.identifier = $identifier
  ON MATCH  SET a.kind = $kind,
                a.identifier = $identifier
RETURN a.id AS id, a.tenant_id AS tenant_id
";

/// `add_finding_node(tenant, finding_id, severity)`.
///
/// Tenant-isolated through the `Tenant` root.
///
/// Parameters:
/// - `$tenant_id` — owning tenant.
/// - `$finding_id` — stable finding identifier (`MERGE` key).
/// - `$severity` — severity tag (`"CRITICAL"`, `"HIGH"`, ...).
pub const ADD_FINDING_NODE: &str = r"
MATCH (t:Tenant {id: $tenant_id})
MERGE (t)-[:OWNS]->(f:Finding {id: $finding_id})
  ON CREATE SET f.tenant_id = $tenant_id,
                f.severity = $severity
  ON MATCH  SET f.severity = $severity
RETURN f.id AS id, f.tenant_id AS tenant_id
";

/// `add_exploits_edge(tenant, from_asset, to_asset, technique)`.
///
/// Creates `(from)-[:EXPLOITS {technique: $technique}]->(to)` only
/// when **both** endpoint assets are owned by the same `$tenant_id`.
/// If either asset belongs to a different tenant, the `MATCH` fails
/// and the adapter raises
/// [`crate::error::GraphError::TenantBoundary`].
///
/// Parameters:
/// - `$tenant_id` — owning tenant.
/// - `$from_asset` — source asset id.
/// - `$to_asset` — destination asset id.
/// - `$technique` — MITRE ATT&CK technique id (e.g. `"T1190"`).
pub const ADD_EXPLOITS_EDGE: &str = r"
MATCH (t:Tenant {id: $tenant_id})
MATCH (t)-[:OWNS]->(from:Asset {id: $from_asset})
MATCH (t)-[:OWNS]->(to:Asset {id: $to_asset})
MERGE (from)-[r:EXPLOITS]->(to)
  ON CREATE SET r.technique = $technique
  ON MATCH  SET r.technique = $technique
RETURN from.id AS from_id, to.id AS to_id, r.technique AS technique
";

// ---------------------------------------------------------------------------
// Read-side: attack paths
// ---------------------------------------------------------------------------

/// `attack_paths(tenant, start_asset, max_depth)`.
///
/// Parameters:
/// - `$tenant_id` — owning tenant.
/// - `$start_asset` — entry asset id.
/// - `{MAX_DEPTH}` — placeholder inlined at adapter side from a
///   validated `u8` (`1..=MAX_ATTACK_PATH_DEPTH`); Cypher does not
///   accept parametrised range bounds.
///
/// The query is tenant-isolated through the `Tenant` root and verifies
/// every node on the path is owned by `$tenant_id`.
pub const ATTACK_PATHS_FROM_ASSET: &str = r"
MATCH (t:Tenant {id: $tenant_id})
MATCH (t)-[:OWNS]->(start:Asset {id: $start_asset})
MATCH path = (start)-[:EXPLOITS*1..{MAX_DEPTH}]->(target:Asset)
WHERE (t)-[:OWNS]->(target)
  AND ALL(n IN nodes(path) WHERE (t)-[:OWNS]->(n))
RETURN path,
       reduce(s = 0.0, n IN nodes(path) | s + coalesce(n.risk_score, 0.0)) AS pathScore
ORDER BY pathScore DESC
";

// ---------------------------------------------------------------------------
// Legacy / generic templates kept for the existing port API
// ---------------------------------------------------------------------------

/// Generic attack-path query used by
/// [`crate::port::KnowledgeGraph::find_attack_paths`].
///
/// Tenant-scoped through `$tenant_id`. `{MAX_DEPTH}` and `{MAX_PATHS}`
/// are inlined at adapter side from a validated [`crate::port::AttackPathQuery`].
pub const ATTACK_PATHS_QUERY: &str = r"
MATCH (t:Tenant {id: $tenant_id})
MATCH (t)-[:OWNS]->(entry:Asset {exposure: 'EXTERNAL'})
MATCH path = (entry)
    -[:HAS_FINDING]->(:Finding {severity: 'CRITICAL'})
    -[:ENABLES]->(:Technique)-[:CHAINS_TO*1..{MAX_DEPTH}]->(:Technique)
WHERE (entry)-[:REACHES*1..6]->(crown:Asset {criticality: 'CROWN_JEWEL'})
  AND (t)-[:OWNS]->(crown)
  AND ALL(n IN nodes(path) WHERE NOT (n:Asset) OR (t)-[:OWNS]->(n))
RETURN path, reduce(s=0.0, n IN nodes(path) | s + coalesce(n.risk_score, 0.0)) AS pathScore
ORDER BY pathScore DESC
LIMIT {MAX_PATHS}
";

/// Cypher used by `compute_risk_propagation`.
///
/// The existing port method does not carry a `$tenant_id` parameter,
/// so this snippet is intentionally tenant-agnostic. New code paths
/// must use the tenant-scoped CRUD primitives ([`ADD_ASSET_NODE`] et
/// al.) instead.
///
/// Parameters:
/// - `$node_ids` — list of node ids that make up the path.
pub const RISK_PROPAGATION_QUERY: &str = r"
UNWIND $node_ids AS nid
MATCH (n {id: nid})
WITH collect({id: n.id, score: coalesce(n.risk_score, 0.0)}) AS scored
RETURN
    reduce(s = 0.0, x IN scored | s + x.score) AS composite,
    reduce(b = scored[0], x IN scored | CASE WHEN x.score > b.score THEN x ELSE b END) AS bottleneck
";

/// Cypher used by `neighbors`.
///
/// The existing port method does not carry a `$tenant_id` parameter,
/// so this snippet is intentionally tenant-agnostic.
///
/// Parameters:
/// - `$id` — the root node id.
/// - `$depth` — inlined at adapter side (parametrised range bounds
///   are not supported by Cypher).
pub const NEIGHBORS_QUERY: &str = r"
MATCH (root {id: $id})
OPTIONAL MATCH (root)-[*1..{DEPTH}]-(n)
WITH collect(DISTINCT n) + [root] AS all_nodes
UNWIND all_nodes AS node
WITH DISTINCT node WHERE node IS NOT NULL
RETURN node
";

/// Cypher template for `upsert_node`. The adapter substitutes
/// `{LABEL}` with the validated label string from
/// [`crate::model::node::NodeKind`] (closed enum, never user input).
///
/// Two flavours:
///
/// * Tenant-scoped path — driven by [`UPSERT_NODE_QUERY`] when the
///   incoming node carries a `tenant_id` (i.e. `Asset`, `Finding`,
///   `User`). The adapter passes `$tenant_id` and the node is merged
///   as a child of `(:Tenant {id: $tenant_id})`.
/// * Tenant-less path — used for global nodes (`Tenant`, `Cve`,
///   `Technique`, …). See [`UPSERT_NODE_GLOBAL_QUERY`].
///
/// Parameters (tenant-scoped):
/// - `$tenant_id` — owning tenant.
/// - `$id` — node id (`MERGE` key).
/// - `$props` — JSON-serialised node property map.
pub const UPSERT_NODE_QUERY: &str = r"
MATCH (t:Tenant {id: $tenant_id})
MERGE (t)-[:OWNS]->(n:{LABEL} {id: $id})
SET n += $props,
    n.tenant_id = $tenant_id
RETURN n
";

/// Tenant-less `upsert_node` template.
///
/// Used for global nodes (`Tenant`, `Cve`, `Technique`, …) that are
/// not owned by any single tenant. The adapter substitutes `{LABEL}`
/// exactly as for [`UPSERT_NODE_QUERY`].
///
/// Parameters:
/// - `$id` — node id (`MERGE` key).
/// - `$props` — JSON-serialised node property map.
pub const UPSERT_NODE_GLOBAL_QUERY: &str = r"
MERGE (n:{LABEL} {id: $id})
SET n += $props
RETURN n
";

/// Cypher template for `upsert_edge`. The adapter substitutes `{REL}`
/// with the validated relationship string from
/// [`crate::model::edge::EdgeKind`] (closed enum, never user input).
///
/// Parameters:
/// - `$from` — source node id.
/// - `$to` — destination node id.
/// - `$props` — JSON-serialised relationship property map.
pub const UPSERT_EDGE_QUERY: &str = r"
MATCH (a {id: $from})
MATCH (b {id: $to})
MERGE (a)-[r:{REL}]->(b)
SET r += $props
RETURN r
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_asset_node_query_uses_parameters() {
        // Exact-string verification: this test pins the contract so a
        // refactor that accidentally interpolates user input will
        // break loudly.
        let expected = "\nMATCH (t:Tenant {id: $tenant_id})\nMERGE (t)-[:OWNS]->(a:Asset {id: \
                        $asset_id})\n  ON CREATE SET a.tenant_id = $tenant_id,\n                \
                        a.kind = $kind,\n                a.identifier = $identifier\n  ON MATCH  \
                        SET a.kind = $kind,\n                a.identifier = $identifier\nRETURN \
                        a.id AS id, a.tenant_id AS tenant_id\n";
        assert_eq!(ADD_ASSET_NODE, expected);

        // Belt + braces: every required parameter is present, and no
        // bare label/identifier ever leaks in.
        for p in ["$tenant_id", "$asset_id", "$kind", "$identifier"] {
            assert!(
                ADD_ASSET_NODE.contains(p),
                "ADD_ASSET_NODE missing parameter {p}"
            );
        }
        assert!(ADD_ASSET_NODE.starts_with("\nMATCH (t:Tenant {id: $tenant_id})"));
    }

    #[test]
    fn add_finding_node_query_uses_parameters() {
        for p in ["$tenant_id", "$finding_id", "$severity"] {
            assert!(
                ADD_FINDING_NODE.contains(p),
                "ADD_FINDING_NODE missing parameter {p}"
            );
        }
        assert!(ADD_FINDING_NODE.contains("MATCH (t:Tenant {id: $tenant_id})"));
        assert!(ADD_FINDING_NODE.contains("MERGE (t)-[:OWNS]->(f:Finding"));
    }

    #[test]
    fn add_exploits_edge_query_uses_parameters() {
        for p in ["$tenant_id", "$from_asset", "$to_asset", "$technique"] {
            assert!(
                ADD_EXPLOITS_EDGE.contains(p),
                "ADD_EXPLOITS_EDGE missing parameter {p}"
            );
        }
        // Both endpoints must be matched THROUGH the tenant.
        assert!(ADD_EXPLOITS_EDGE.contains("(t)-[:OWNS]->(from:Asset {id: $from_asset})"));
        assert!(ADD_EXPLOITS_EDGE.contains("(t)-[:OWNS]->(to:Asset {id: $to_asset})"));
        assert!(ADD_EXPLOITS_EDGE.contains("MERGE (from)-[r:EXPLOITS]->(to)"));
    }

    #[test]
    fn attack_paths_query_caps_at_max_depth_param() {
        // Placeholder is present in the constant so the adapter MUST
        // substitute it before issuing the query.
        assert!(ATTACK_PATHS_FROM_ASSET.contains("[:EXPLOITS*1..{MAX_DEPTH}]"));
        assert!(ATTACK_PATHS_FROM_ASSET.contains("$tenant_id"));
        assert!(ATTACK_PATHS_FROM_ASSET.contains("$start_asset"));
        // The placeholder is the literal token, not a $-parameter: the
        // adapter does *not* try to pass it as a Bolt parameter.
        assert!(!ATTACK_PATHS_FROM_ASSET.contains("$max_depth"));
        // Tenant-isolation guard MUST be the first clause.
        assert!(
            ATTACK_PATHS_FROM_ASSET
                .trim_start()
                .starts_with("MATCH (t:Tenant {id: $tenant_id})"),
            "ATTACK_PATHS_FROM_ASSET must start with tenant MATCH"
        );
        // The path must walk only nodes owned by the tenant.
        assert!(ATTACK_PATHS_FROM_ASSET.contains("ALL(n IN nodes(path) WHERE (t)-[:OWNS]->(n))"));
    }

    #[test]
    fn snippets_are_parametrised() {
        for q in [
            ADD_ASSET_NODE,
            ADD_FINDING_NODE,
            ADD_EXPLOITS_EDGE,
            ATTACK_PATHS_FROM_ASSET,
            ATTACK_PATHS_QUERY,
            RISK_PROPAGATION_QUERY,
            NEIGHBORS_QUERY,
            UPSERT_NODE_QUERY,
            UPSERT_NODE_GLOBAL_QUERY,
            UPSERT_EDGE_QUERY,
        ] {
            assert!(q.contains('$'), "snippet should use $-parameters: {q}");
        }
    }

    #[test]
    fn every_tenant_scoped_query_starts_with_tenant_match() {
        // Tenant-isolation invariant: every query that takes a
        // $tenant_id parameter MUST begin with the tenant guard.
        // (Methods on the legacy port that do NOT carry tenant_id —
        // `neighbors`, `compute_risk_propagation`, and the
        // tenant-less `upsert_node` path — are intentionally omitted.)
        let guards = [
            ADD_ASSET_NODE,
            ADD_FINDING_NODE,
            ADD_EXPLOITS_EDGE,
            ATTACK_PATHS_FROM_ASSET,
            ATTACK_PATHS_QUERY,
            UPSERT_NODE_QUERY,
        ];
        for q in guards {
            assert!(
                q.trim_start()
                    .starts_with("MATCH (t:Tenant {id: $tenant_id})"),
                "query is not tenant-guarded: {q}"
            );
        }
    }

    #[test]
    fn index_statements_are_idempotent() {
        for s in INDEX_STATEMENTS {
            assert!(s.contains("IF NOT EXISTS"), "non-idempotent index: {s}");
        }
    }
}
