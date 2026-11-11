-- TAXII 2.1 / STIX 2.1 intel ingestion persistence (P0-001).
--
-- Registered as:
--   * M38_TENANT_IOCS         — per-tenant indicator-of-compromise store.
--   * M39_INTEL_FEED_STATUS   — per-tenant per-feed poll status / health.
--
-- ## Tenant isolation
--
-- Both tables follow the platform-wide RLS pattern: ENABLED + FORCED row
-- level security keyed on the `app.current_tenant_id` GUC the storage
-- layer sets at the start of every repository transaction (see
-- `20260101000010_enable_rls.sql`).
--
-- ## Capacity / LRU
--
-- `tenant_iocs` is capped at 1_000_000 rows per tenant by application
-- logic (see `sx_intel_feeds::feeds::TenantIocRepository::evict_lru`).
-- The eviction policy scores each indicator by
--   score = severity_weight * recency_factor
-- and removes the lowest-scoring rows when the per-tenant count would
-- exceed the cap. The `score` column is denormalised here so the
-- repository can ORDER BY directly without recomputing on every prune.
--
-- ## `intel_feed_status`
--
-- One row per `(tenant_id, feed_id)`. `feed_id` is the operator-supplied
-- logical name for the TAXII feed (e.g. "alienvault-otx" or
-- "internal-pdns"). The row carries the poll-loop telemetry that a
-- separate alert rule consumes to flag silent feeds (>24h since
-- `last_success_at`).

CREATE TABLE tenant_iocs (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    feed_id       TEXT NOT NULL,
    kind          TEXT NOT NULL
                       CHECK (kind IN (
                           'ipv4', 'ipv6', 'domain', 'url', 'email',
                           'file_hash_md5', 'file_hash_sha1', 'file_hash_sha256'
                       )),
    value         TEXT NOT NULL,
    confidence    SMALLINT,
    severity      SMALLINT NOT NULL DEFAULT 50
                       CHECK (severity BETWEEN 0 AND 100),
    score         DOUBLE PRECISION NOT NULL DEFAULT 0,
    valid_from    TIMESTAMPTZ NOT NULL,
    valid_until   TIMESTAMPTZ,
    labels        JSONB NOT NULL DEFAULT '[]'::JSONB,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, kind, value)
);

CREATE INDEX tenant_iocs_tenant_score_idx
    ON tenant_iocs (tenant_id, score ASC);
CREATE INDEX tenant_iocs_tenant_lastseen_idx
    ON tenant_iocs (tenant_id, last_seen_at DESC);
CREATE INDEX tenant_iocs_tenant_kind_idx
    ON tenant_iocs (tenant_id, kind);

ALTER TABLE tenant_iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_iocs FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_iocs
    ON tenant_iocs
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE TABLE intel_feed_status (
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    feed_id          TEXT NOT NULL,
    last_poll_at     TIMESTAMPTZ,
    last_success_at  TIMESTAMPTZ,
    last_error       TEXT,
    error_count_24h  INTEGER NOT NULL DEFAULT 0,
    indicators_total BIGINT  NOT NULL DEFAULT 0,
    indicators_added BIGINT  NOT NULL DEFAULT 0,
    indicators_evicted BIGINT NOT NULL DEFAULT 0,
    cursor_added_after TEXT,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, feed_id)
);

ALTER TABLE intel_feed_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel_feed_status FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_intel_feed_status
    ON intel_feed_status
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
