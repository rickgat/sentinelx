-- Durable store for the SOAR low-code automation builder (P3-005).
--
-- The composition root bound SOAR to an in-memory map, so every saved
-- automation workflow and its run history was lost on a monolith restart and
-- invisible across instances. These two tables persist them.
--
-- The action registry / DAG executor is static orchestration (not data-loss)
-- and stays in code; only workflows + runs are durable here. Each `Workflow`
-- / `WorkflowRun` aggregate is stored losslessly as JSONB keyed by
-- `(tenant_id, id)`, with scalar projections (`name` / `enabled`;
-- `workflow_id` / `started_at`) for listing and ordering.
--
-- Both ids are globally-unique UUIDs and every query carries an explicit
-- `tenant_id` predicate, so — like the other id-keyed stores in this program
-- — the tables are intentionally NOT under tenant RLS.

CREATE TABLE soar_workflows (
    tenant_id    UUID        NOT NULL,
    workflow_id  UUID        NOT NULL,
    name         TEXT        NOT NULL,
    enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
    aggregate    JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workflow_id)
);

CREATE TABLE soar_runs (
    tenant_id    UUID        NOT NULL,
    run_id       UUID        NOT NULL,
    workflow_id  UUID        NOT NULL,
    started_at   TEXT        NOT NULL,
    aggregate    JSONB       NOT NULL,
    PRIMARY KEY (tenant_id, run_id)
);

-- Newest-first run history per tenant (started_at is RFC-3339, which sorts
-- lexicographically in chronological order).
CREATE INDEX soar_runs_tenant_started_idx
    ON soar_runs (tenant_id, started_at DESC);
