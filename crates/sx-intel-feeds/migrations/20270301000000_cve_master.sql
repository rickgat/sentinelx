-- P0-006 — NVD / KEV / EPSS scheduled fetcher (sx-intel-feeds owner crate).
--
-- This crate-local migration mirrors the canonical DDL in
--   crates/sx-storage/migrations/20260801000000_create_cve_master.sql
-- and exists so the `sx-intel-feeds` crate ships its own self-contained
-- migrations directory (per the P0-006 acceptance criteria). Application
-- bootstrap continues to run the `sx-storage` migration set; this file is
-- idempotent and may be applied side-by-side by a per-crate migrator.
--
-- Schema:
--   * cve_master — global (cross-tenant) catalogue of CVEs, merged from
--     the three authoritative public sources.
--       NVD CVE 2.0   — descriptive metadata + CVSS v3/v4 vectors and scores
--       CISA KEV      — Known Exploited Vulnerabilities catalogue
--       FIRST EPSS    — Exploit Prediction Scoring System
--   * cve_master_sync_state — high-water-mark + bookkeeping for the
--     scheduled fetcher, so a restarted process resumes an incremental
--     sync instead of re-doing the 5-year backfill.

CREATE TABLE IF NOT EXISTS cve_master (
    cve_id              TEXT PRIMARY KEY
                        CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    published_at        TIMESTAMPTZ NOT NULL,
    last_modified_at    TIMESTAMPTZ NOT NULL,
    cvss_v3_score       DOUBLE PRECISION
                        CHECK (cvss_v3_score IS NULL
                               OR (cvss_v3_score >= 0.0 AND cvss_v3_score <= 10.0)),
    cvss_v3_vector      TEXT,
    cvss_v3             JSONB,
    cvss_v4_score       DOUBLE PRECISION
                        CHECK (cvss_v4_score IS NULL
                               OR (cvss_v4_score >= 0.0 AND cvss_v4_score <= 10.0)),
    cvss_v4_vector      TEXT,
    cvss_v4             JSONB,
    epss                NUMERIC(6, 5) NOT NULL DEFAULT 0.0
                        CHECK (epss >= 0.0 AND epss <= 1.0),
    epss_percentile     NUMERIC(6, 5) NOT NULL DEFAULT 0.0
                        CHECK (epss_percentile >= 0.0 AND epss_percentile <= 1.0),
    kev                 BOOLEAN NOT NULL DEFAULT FALSE,
    kev_added_at        TIMESTAMPTZ,
    description         TEXT NOT NULL DEFAULT '',
    cpes                TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[]
);

CREATE INDEX IF NOT EXISTS cve_master_kev_idx
    ON cve_master (kev) WHERE kev = TRUE;
CREATE INDEX IF NOT EXISTS cve_master_epss_idx
    ON cve_master (epss DESC);
CREATE INDEX IF NOT EXISTS cve_master_published_idx
    ON cve_master (published_at DESC);
CREATE INDEX IF NOT EXISTS cve_master_last_modified_idx
    ON cve_master (last_modified_at DESC);
CREATE INDEX IF NOT EXISTS cve_master_cpes_gin_idx
    ON cve_master USING GIN (cpes);

-- Per-source high-water-mark bookkeeping for the scheduled fetcher.
-- One row per `source` in {'nvd', 'kev', 'epss'}.
CREATE TABLE IF NOT EXISTS cve_master_sync_state (
    source              TEXT PRIMARY KEY
                        CHECK (source IN ('nvd', 'kev', 'epss')),
    last_synced_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- High-water-mark for NVD's `lastModStartDate` parameter so the
    -- next incremental sweep only re-fetches rows modified since the
    -- previous successful sync.
    high_water_mark     TIMESTAMPTZ,
    -- Number of rows touched in the last successful sync (debugging /
    -- ops dashboards). NOT used by the fetcher logic.
    last_row_count      BIGINT NOT NULL DEFAULT 0,
    -- Whether the initial 5-year backfill has completed for this
    -- source. Stays FALSE across restarts until a full run lands.
    backfill_complete   BOOLEAN NOT NULL DEFAULT FALSE
);
