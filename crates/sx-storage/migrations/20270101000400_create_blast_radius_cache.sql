-- Cloud blast-radius cache (P1-010).
--
-- Each row memoises a computed blast-radius report keyed by the seed
-- asset id. The `sx_graph::service::blast_radius` BFS is pure CPU but
-- can churn through a few thousand edges on a dense graph; persisting
-- the resulting `BlastRadiusReport` JSON lets multiple dashboard tabs
-- and copilot follow-up calls reuse the answer without re-traversing.
--
-- ## Freshness contract
--
-- A row is considered fresh while `computed_at >= now() - interval '1
-- hour'` — any older entry is stale and MUST be ignored / recomputed
-- by the adapter. The TTL index below makes the
-- `computed_at < now() - INTERVAL '1 hour'` predicate a cheap scan so
-- a periodic cleanup job (or the adapter itself on read) can drop
-- stale rows without a sequential table scan.
--
-- ## Multi-tenant isolation
--
-- Identical to every other tenant-scoped table in this schema: RLS is
-- enabled + FORCED, and a `tenant_isolation_blast_radius_cache` policy
-- pins reads/writes to the `app_current_tenant()` GUC. A
-- compromised-asset graph from one tenant must never leak into
-- another tenant's session, even via the cache layer.

CREATE TABLE blast_radius_cache (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    seed_asset_id   TEXT NOT NULL CHECK (length(seed_asset_id) BETWEEN 1 AND 512),
    max_depth       SMALLINT NOT NULL CHECK (max_depth BETWEEN 1 AND 5),
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    report          JSONB NOT NULL,
    -- One cached report per `(tenant, seed, depth)` triple — recomputes
    -- overwrite the row via `ON CONFLICT DO UPDATE`.
    UNIQUE (tenant_id, seed_asset_id, max_depth)
);

CREATE INDEX blast_radius_cache_tenant_idx
    ON blast_radius_cache (tenant_id);
CREATE INDEX blast_radius_cache_seed_idx
    ON blast_radius_cache (tenant_id, seed_asset_id);
-- TTL cleanup index: lets a periodic job DELETE stale rows in O(log n).
-- The 1-hour staleness contract is enforced by the adapter, this index
-- only accelerates the eventual cleanup pass.
CREATE INDEX blast_radius_cache_ttl_idx
    ON blast_radius_cache (computed_at);

-- Row-Level Security: identical to every other tenant-scoped table.
ALTER TABLE blast_radius_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE blast_radius_cache FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_blast_radius_cache ON blast_radius_cache
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
