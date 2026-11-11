-- CVE master catalogue (TRD §21.2).
--
-- Aggregates the three authoritative vuln sources we ingest:
--   * NVD CVE 2.0   — descriptive metadata + CVSS v3/v4 vectors and scores
--   * CISA KEV      — Known Exploited Vulnerabilities catalogue (boolean + date)
--   * FIRST EPSS    — Exploit Prediction Scoring System (probability + percentile)
--
-- This is *reference data* shared across every tenant — no `tenant_id`,
-- no RLS policy. The pre-existing `cves` table (008_create_cves.sql) is a
-- lightweight summary kept for legacy SCA matchers; `cve_master` is the
-- richer, fetcher-populated table used by the new intel pipeline.

CREATE TABLE cve_master (
    cve_id              TEXT PRIMARY KEY
                        CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    published_at        TIMESTAMPTZ NOT NULL,
    last_modified_at    TIMESTAMPTZ NOT NULL,
    cvss_v3_score       DOUBLE PRECISION
                        CHECK (cvss_v3_score IS NULL
                               OR (cvss_v3_score >= 0.0 AND cvss_v3_score <= 10.0)),
    cvss_v3_vector      TEXT,
    cvss_v4_score       DOUBLE PRECISION
                        CHECK (cvss_v4_score IS NULL
                               OR (cvss_v4_score >= 0.0 AND cvss_v4_score <= 10.0)),
    cvss_v4_vector      TEXT,
    epss                DOUBLE PRECISION NOT NULL DEFAULT 0.0
                        CHECK (epss >= 0.0 AND epss <= 1.0),
    epss_percentile     DOUBLE PRECISION NOT NULL DEFAULT 0.0
                        CHECK (epss_percentile >= 0.0 AND epss_percentile <= 1.0),
    kev                 BOOLEAN NOT NULL DEFAULT FALSE,
    kev_added_at        TIMESTAMPTZ,
    description         TEXT NOT NULL DEFAULT '',
    cpes                TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[]
);

-- Hot read paths.
CREATE INDEX cve_master_kev_idx          ON cve_master (kev)          WHERE kev = TRUE;
CREATE INDEX cve_master_epss_idx         ON cve_master (epss DESC);
CREATE INDEX cve_master_published_idx    ON cve_master (published_at DESC);
CREATE INDEX cve_master_last_modified_idx ON cve_master (last_modified_at DESC);
CREATE INDEX cve_master_cpes_gin_idx     ON cve_master USING GIN (cpes);
