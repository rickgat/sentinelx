-- Differential-report snapshot storage — P2-003.
--
-- One row per saved point-in-time snapshot of an engagement's open
-- finding inventory, keyed by `(tenant_id, engagement_id, captured_at)`.
-- The differential renderer (`sx-report::diff::InMemoryReportDiffService`)
-- currently computes diffs on-the-fly from the canonical finding
-- repository; this table is the persistence target for a future agent
-- that wants to retain a frozen "as of last Friday" view independent of
-- the live finding store.
--
-- The migration is registered now so the schema snapshots used by
-- integration tests already carry it and so the matching `PgReportSnapshot`
-- adapter can be wired without a database migration churn later.
--
-- Columns:
--
-- * `id`             — primary key uuid.
-- * `tenant_id`      — uuid of the owning tenant. RLS keys off this column.
-- * `engagement_id`  — uuid of the engagement the snapshot belongs to.
-- * `captured_at`    — wall-clock timestamp at which the snapshot was taken.
--                     Two snapshots taken within the same engagement form
--                     the `[since, until]` window for a `POST /v1/reports/diff`
--                     call.
-- * `finding_count`  — total number of open findings in the snapshot.
-- * `risk_score`     — aggregate risk score (0-100) used by the
--                     "risk-score delta" line on the diff cover page.
-- * `payload`        — JSONB blob of the serialised `Vec<FindingSnapshot>`.
--                     Stored compressed by Postgres's TOAST.
-- * `created_by`     — operator / system identifier that triggered the
--                     capture; surfaced on the audit log.

CREATE TABLE report_snapshots (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_id  UUID NOT NULL,
    captured_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finding_count  INTEGER NOT NULL DEFAULT 0
        CHECK (finding_count >= 0),
    risk_score     REAL NOT NULL DEFAULT 0
        CHECK (risk_score >= 0 AND risk_score <= 100),
    payload        JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by     TEXT NOT NULL DEFAULT 'system'
);

-- Lookup pattern: "give me the two newest snapshots in
-- `[since, until]` for engagement E" — covered by the
-- `(tenant_id, engagement_id, captured_at DESC)` index.
CREATE INDEX report_snapshots_lookup_idx
    ON report_snapshots (tenant_id, engagement_id, captured_at DESC);

-- Tenant-scoped global listing (admin UI).
CREATE INDEX report_snapshots_tenant_captured_idx
    ON report_snapshots (tenant_id, captured_at DESC);

-- Row-Level Security — refuse cross-tenant access even when the
-- application drops the WHERE clause.
ALTER TABLE report_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_snapshots FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_report_snapshots
    ON report_snapshots
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
