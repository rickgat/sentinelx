-- Engagements are scoped pentests / security assessments. Their
-- `scope` is a JSONB document encoding include/exclude lists, address
-- ranges, allowed techniques, and rules of engagement.

CREATE TABLE engagements (
    id                      UUID PRIMARY KEY,
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    scope                   JSONB NOT NULL DEFAULT '{}'::jsonb,
    window_start            TIMESTAMPTZ NOT NULL,
    window_end              TIMESTAMPTZ NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN (
                                'Draft', 'PendingApproval', 'Approved',
                                'Active', 'Paused', 'Closed', 'Cancelled')),
    requires_dual_approval  BOOLEAN NOT NULL DEFAULT FALSE,
    intensity               TEXT NOT NULL CHECK (intensity IN (
                                'light', 'standard', 'intense')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (window_end > window_start)
);

CREATE INDEX engagements_tenant_idx ON engagements (tenant_id);
CREATE INDEX engagements_tenant_status_idx ON engagements (tenant_id, status);
CREATE INDEX engagements_tenant_created_idx ON engagements (tenant_id, created_at);
CREATE INDEX engagements_window_idx ON engagements (tenant_id, window_start, window_end);

-- GIN index over the scope document for membership queries like
-- "which engagements include this asset class?".
CREATE INDEX engagements_scope_gin_idx ON engagements USING GIN (scope jsonb_path_ops);
