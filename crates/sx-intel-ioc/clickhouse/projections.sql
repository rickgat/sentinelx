-- SentinelX cold-storage projections (ClickHouse).
--
-- These tables back the long-retention analytics layer. The hot path (Postgres)
-- remains the source of truth; rows are mirrored here for trend analysis,
-- compliance retention, and cheap large-window aggregates.
--
-- Cluster / database wiring is left to deployment (Helm, Terraform, etc.).
-- The CREATE statements below are sketches: production deploys should add
-- `ON CLUSTER`, replication engines (`ReplicatedMergeTree`), TTLs, and
-- distributed/local table pairs.
--
-- Run order: projections depend on no other objects.

-- ---------------------------------------------------------------------------
-- findings_projection
--
-- One row per finding emitted by the scanners. Partitioned monthly so old
-- months can be dropped in O(1). Ordered by (tenant_id, severity, ts) so the
-- two most common queries -- "high severity findings for tenant X in window
-- W" and "all findings for tenant X in window W" -- prefix-match the sort
-- key. `severity` and `action` use LowCardinality(String) because the
-- distinct-value count is small (4 severities, ~30 actions) and the
-- dictionary encoding crushes storage.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings_projection
(
    id          UUID,
    tenant_id   UUID,
    severity    LowCardinality(String),
    cvss        Float64,
    ts          DateTime
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, severity, ts);

-- ---------------------------------------------------------------------------
-- audit_projection
--
-- One row per audit event. The hot audit log assigns a per-tenant monotonic
-- sequence number; we preserve it as the secondary sort key so tail reads
-- ("everything since seq=N for tenant T") stay cheap. No partitioning on
-- timestamp here -- audit retention is policy-driven, and ORDER BY tenant
-- already gives us per-tenant locality.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_projection
(
    tenant_id   UUID,
    seq         UInt64,
    action      LowCardinality(String),
    actor       String,
    ts          DateTime
)
ENGINE = MergeTree
ORDER BY (tenant_id, seq);
