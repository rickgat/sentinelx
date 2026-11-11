-- Multicloud CSPM findings table (P1-009).
--
-- One row per **(tenant_id, asset_id, check_id)** finding ingested from a
-- Prowler v4 native-JSON report. Covers GCP and Azure; AWS findings flow
-- through the OCSF scanner path into the main `findings` table so this
-- table is **not** double-populated for AWS.
--
-- The dedupe key is enforced by a UNIQUE constraint on the three fields
-- the in-batch deduplicator already keys on
-- (`sx_discovery::prowler_import::DedupeKey`). Re-uploading the same
-- report is a no-op for already-seen `(tenant_id, asset_id, check_id)`
-- triples — the adapter performs an `INSERT … ON CONFLICT (tenant_id,
-- asset_id, check_id) DO UPDATE SET severity = EXCLUDED.severity, …`.
--
-- Tenant isolation follows the same Row-Level Security pattern as every
-- other tenant-scoped table in the schema: RLS is ENABLED + FORCED, and
-- `tenant_isolation_cspm_findings_multicloud` keys off the
-- `app.current_tenant_id` GUC set by `TenantContext::apply`.

CREATE TABLE cspm_findings_multicloud (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID NOT NULL,
    check_id              TEXT NOT NULL,
    prowler_check_id      TEXT NOT NULL,
    cloud_provider        TEXT NOT NULL CHECK (cloud_provider IN ('gcp','azure')),
    account_id            TEXT NOT NULL,
    region                TEXT,
    asset_id              TEXT NOT NULL,
    resource_name         TEXT,
    resource_type         TEXT,
    severity              TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    original_severity     TEXT NOT NULL CHECK (original_severity IN ('info','low','medium','high','critical')),
    kev_uplifted          BOOLEAN NOT NULL DEFAULT FALSE,
    status_extended       TEXT,
    description           TEXT,
    remediation           TEXT,
    compliance_refs       TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT cspm_findings_multicloud_dedupe
        UNIQUE (tenant_id, asset_id, check_id)
);

-- Hot read paths: per-tenant dashboards filtered by provider + severity.
CREATE INDEX cspm_findings_multicloud_tenant_provider_idx
    ON cspm_findings_multicloud (tenant_id, cloud_provider, severity);
CREATE INDEX cspm_findings_multicloud_tenant_created_idx
    ON cspm_findings_multicloud (tenant_id, created_at DESC);
-- Drill-down by account / project / subscription.
CREATE INDEX cspm_findings_multicloud_tenant_account_idx
    ON cspm_findings_multicloud (tenant_id, cloud_provider, account_id);

ALTER TABLE cspm_findings_multicloud ENABLE ROW LEVEL SECURITY;
ALTER TABLE cspm_findings_multicloud FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_cspm_findings_multicloud
    ON cspm_findings_multicloud
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());

-- Companion audit-receipt table for the import itself. Mirrors the
-- `vuln_imports` row-shape so the dashboard can render a unified
-- import-history view. The actual finding rows are in
-- `cspm_findings_multicloud` above.
CREATE TABLE cspm_prowler_imports (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID NOT NULL,
    actor                 TEXT NOT NULL,
    upload_digest         TEXT NOT NULL,
    upload_bytes          BIGINT NOT NULL CHECK (upload_bytes >= 0),
    parsed_findings       INTEGER NOT NULL DEFAULT 0 CHECK (parsed_findings >= 0),
    written_findings      INTEGER NOT NULL DEFAULT 0 CHECK (written_findings >= 0),
    rejected_cross_tenant INTEGER NOT NULL DEFAULT 0 CHECK (rejected_cross_tenant >= 0),
    deduplicated          INTEGER NOT NULL DEFAULT 0 CHECK (deduplicated >= 0),
    kev_uplifts_applied   INTEGER NOT NULL DEFAULT 0 CHECK (kev_uplifts_applied >= 0),
    unmapped_check_ids    INTEGER NOT NULL DEFAULT 0 CHECK (unmapped_check_ids >= 0),
    recorded_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX cspm_prowler_imports_tenant_recorded_idx
    ON cspm_prowler_imports (tenant_id, recorded_at DESC);

ALTER TABLE cspm_prowler_imports ENABLE ROW LEVEL SECURITY;
ALTER TABLE cspm_prowler_imports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_cspm_prowler_imports
    ON cspm_prowler_imports
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
