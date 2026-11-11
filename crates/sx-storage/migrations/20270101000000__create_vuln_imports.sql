-- Credentialed-scanner ingest import audit (P0-002).
--
-- One row per accepted scanner import (Nessus / OpenVAS). Records the
-- audit trail of *which tenant* imported *what kind* of report, *when*,
-- and the resulting `asset_count` / `finding_count` summary so the
-- dashboard can render an import-history table without re-parsing the
-- original payload.
--
-- The `findings` themselves are NOT stored here — they are folded into
-- the main `findings` table by the adapter once the parser/dedup
-- pipeline returns. This table is the *receipt*: small, append-only,
-- read often.
--
-- Tenant isolation follows the same Row-Level Security pattern as every
-- other tenant-scoped table: RLS is ENABLED + FORCED, and a
-- `tenant_isolation_vuln_imports` policy keys off the
-- `app.current_tenant_id` GUC set by `TenantContext::apply`.

CREATE TABLE vuln_imports (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    source          TEXT NOT NULL CHECK (source IN ('nessus','openvas')),
    asset_count     INTEGER NOT NULL DEFAULT 0 CHECK (asset_count >= 0),
    finding_count   INTEGER NOT NULL DEFAULT 0 CHECK (finding_count >= 0),
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          TEXT NOT NULL CHECK (status IN ('ok','failed','partial'))
);
CREATE INDEX vuln_imports_tenant_ingested_idx
    ON vuln_imports (tenant_id, ingested_at DESC);

ALTER TABLE vuln_imports ENABLE ROW LEVEL SECURITY;
ALTER TABLE vuln_imports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_vuln_imports ON vuln_imports
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
