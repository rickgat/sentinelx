-- P1-004 — Automated compliance evidence collector.
--
-- Two tenant-scoped tables back the SOC 2 / ISO 27001 / PCI DSS
-- evidence-collection pipeline shipped under
-- `sx_compliance::p1_004`:
--
--   * `compliance_evidence_runs`  — one row per collection run; carries the
--                                   lifecycle status + (once the bundle is
--                                   exported) the WORM bundle key + HMAC-
--                                   signed SHA-256 of the bundle bytes.
--   * `compliance_evidence_files` — append-only ledger of evidence files
--                                   produced inside a run. The `object_key`
--                                   points at an S3 Object Lock (Compliance
--                                   mode, 7-year retention) bucket.
--
-- Both tables have Row-Level Security ENABLED + FORCED with a
-- `tenant_id = app_current_tenant()` policy so a misconfigured
-- application path cannot leak cross-tenant evidence even if the
-- application-side filter is dropped from a query.
--
-- The Postgres-backed adapter is deferred — the MVP application layer
-- uses the in-memory `InMemoryEvidenceStore` reference implementation
-- exposed by the `sx_compliance::p1_004::store` module. This migration is
-- registered now so the schema snapshots used by integration tests
-- already carry the tables, and a future agent can plug a
-- `PgEvidenceStore` behind the existing trait without a schema change.

-- ---------------------------------------------------------------------
-- compliance_evidence_runs
-- ---------------------------------------------------------------------
--
-- Columns:
--
-- * `id`             — uuid primary key of the run; matches the value
--                      the application returns to the API caller in
--                      `CollectEvidenceResponse.run_id`.
-- * `tenant_id`      — owning tenant. RLS keys off this column.
-- * `started_at`     — wall-clock time the run row was opened.
-- * `finished_at`    — wall-clock time the run reached a terminal state.
-- * `status`         — `running`, `succeeded`, or `failed`. The
--                      application enforces append-only transitions
--                      (`running -> succeeded|failed`).
-- * `bundle_key`     — WORM object key (`tenant/<tid>/bundles/<run>.zip`)
--                      populated once the ZIP bundle is exported. NULL
--                      until then. Once written, must never be rewritten.
-- * `bundle_sha256`  — lowercase hex SHA-256 over the bundle bytes,
--                      populated alongside `bundle_key`.

CREATE TABLE compliance_evidence_runs (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    started_at    TIMESTAMPTZ NOT NULL,
    finished_at   TIMESTAMPTZ NULL,
    status        TEXT NOT NULL CHECK (status IN (
        'running', 'succeeded', 'failed'
    )),
    bundle_key    TEXT NULL,
    bundle_sha256 TEXT NULL,
    -- Either both bundle fields are populated, or neither is — the
    -- bundle export is atomic from the application's perspective.
    CONSTRAINT compliance_evidence_runs_bundle_pair_chk
        CHECK ((bundle_key IS NULL) = (bundle_sha256 IS NULL))
);

CREATE INDEX compliance_evidence_runs_tenant_started_idx
    ON compliance_evidence_runs (tenant_id, started_at DESC);

CREATE INDEX compliance_evidence_runs_tenant_bundle_idx
    ON compliance_evidence_runs (tenant_id, bundle_key)
    WHERE bundle_key IS NOT NULL;

ALTER TABLE compliance_evidence_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_evidence_runs FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_compliance_evidence_runs
    ON compliance_evidence_runs
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

-- ---------------------------------------------------------------------
-- compliance_evidence_files
-- ---------------------------------------------------------------------
--
-- Append-only — one row per evidence file produced inside a run. The
-- file bytes themselves live in the WORM object store; the row records
-- the digest + length + WORM key so an auditor can verify the bytes
-- without re-running the collector.
--
-- Columns:
--
-- * `id`           — uuid primary key.
-- * `tenant_id`    — repeated here as well as on `runs` so RLS can
--                    filter without a join. Must match the parent run.
-- * `run_id`       — FK to `compliance_evidence_runs.id` (ON DELETE
--                    CASCADE so a tenant-deletion sweep removes the
--                    history cleanly).
-- * `control_id`   — SentinelX control identifier (`SX-...`).
-- * `object_key`   — WORM key the bytes were written to (always
--                    `tenant/<tid>/runs/<run_id>/files/<control_id>.json`).
-- * `sha256`       — lowercase hex SHA-256 over the file bytes.
-- * `byte_len`     — BIGINT byte length.
-- * `collected_at` — wall-clock time the collector returned the bytes.

CREATE TABLE compliance_evidence_files (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id       UUID NOT NULL REFERENCES compliance_evidence_runs(id)
                                  ON DELETE CASCADE,
    control_id   TEXT NOT NULL,
    object_key   TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    byte_len     BIGINT NOT NULL CHECK (byte_len >= 0),
    collected_at TIMESTAMPTZ NOT NULL,

    -- Each (run, control) pair appears at most once — the WORM
    -- semantics on the object store mirror this constraint at the
    -- storage layer.
    CONSTRAINT compliance_evidence_files_run_control_uq
        UNIQUE (run_id, control_id),
    -- Object keys are unique tenant-wide (defence in depth against a
    -- bug that would have two runs write to the same key).
    CONSTRAINT compliance_evidence_files_object_key_uq
        UNIQUE (tenant_id, object_key)
);

CREATE INDEX compliance_evidence_files_tenant_run_idx
    ON compliance_evidence_files (tenant_id, run_id);

CREATE INDEX compliance_evidence_files_tenant_collected_idx
    ON compliance_evidence_files (tenant_id, collected_at DESC);

ALTER TABLE compliance_evidence_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_evidence_files FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_compliance_evidence_files
    ON compliance_evidence_files
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
