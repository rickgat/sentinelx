-- P2-015 — Lateral-movement chain replay history.
--
-- Each row records one full execution of a `LateralChain` through the
-- BAS `ChainExecutor`. The HTTP surface
-- (`POST /v1/bas/chains/{id}/run`) writes the row once the executor
-- returns; subsequent `GET /v1/bas/chains/runs/{id}` lookups read the
-- same row scoped to the calling tenant.
--
-- ## Schema
--
-- The per-step ledger (`steps`) is stored as JSONB so the wire shape
-- (`ChainStepRecordView`) round-trips without a join. The status enum
-- is held as TEXT and constrained by a CHECK rather than a Postgres
-- enum to keep migrations forward-compatible with new statuses
-- (`running`, `completed`, `failed`, `aborted` today).
--
-- ## Multi-tenant isolation
--
-- Identical RLS contract to every other tenant-scoped table:
-- the `tenant_isolation_bas_chain_runs` policy pins reads and writes
-- to the `app_current_tenant()` GUC. A chain run from one tenant must
-- never leak into another tenant's session.

CREATE TABLE bas_chain_runs (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_id   UUID NOT NULL,
    chain_id        TEXT NOT NULL CHECK (length(chain_id) BETWEEN 1 AND 128),
    status          TEXT NOT NULL CHECK (status IN ('running','completed','failed','aborted')),
    steps           JSONB NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX bas_chain_runs_tenant_idx
    ON bas_chain_runs (tenant_id);
CREATE INDEX bas_chain_runs_engagement_idx
    ON bas_chain_runs (tenant_id, engagement_id);
CREATE INDEX bas_chain_runs_chain_idx
    ON bas_chain_runs (tenant_id, chain_id);
CREATE INDEX bas_chain_runs_started_idx
    ON bas_chain_runs (tenant_id, started_at DESC);

-- Row-Level Security: identical to every other tenant-scoped table.
ALTER TABLE bas_chain_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE bas_chain_runs FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_bas_chain_runs ON bas_chain_runs
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
