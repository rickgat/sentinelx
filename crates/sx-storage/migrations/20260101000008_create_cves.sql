-- CVE catalogue. This is *reference data* shared across all tenants,
-- so it has no tenant_id and no RLS policy. EPSS is stored as DOUBLE
-- PRECISION clamped to [0.0, 1.0]; CVSS vector + scores live in JSONB.

CREATE TABLE cves (
    cve_id          TEXT PRIMARY KEY
                    CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    description     TEXT NOT NULL DEFAULT '',
    cvss            JSONB NOT NULL DEFAULT '{}'::jsonb,
    epss            DOUBLE PRECISION NOT NULL DEFAULT 0.0
                    CHECK (epss >= 0.0 AND epss <= 1.0),
    kev             BOOLEAN NOT NULL DEFAULT FALSE,
    published_at    TIMESTAMPTZ NOT NULL,
    modified_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX cves_kev_idx ON cves (kev) WHERE kev = TRUE;
CREATE INDEX cves_epss_idx ON cves (epss DESC);
CREATE INDEX cves_published_idx ON cves (published_at DESC);
CREATE INDEX cves_cvss_gin_idx ON cves USING GIN (cvss jsonb_path_ops);
