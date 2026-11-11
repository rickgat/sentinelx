-- DLP per-tenant detector configuration (P2-006 durability).
--
-- Persists the per-tenant DLP policy — the enabled-detector set and the
-- minimum-confidence threshold — set via `PUT /v1/dlp/config` and
-- `PUT /v1/admin/dlp/thresholds`. Before this table the config lived in a
-- process-local map, so any admin override silently reverted to the
-- permissive-all default on every restart (a security-relevant data loss:
-- disabled detectors would quietly re-enable, a raised confidence floor
-- would quietly drop back to 0.0).
--
-- ## Storage shape
--
-- One row per tenant. The config is a JSONB document owned by
-- `sx_dlp::TenantDetectorConfig` (a `{enabled: [kind], min_confidence}`
-- shape) so adding a detector kind never needs a migration.
--
-- ## Tenant isolation
--
-- Keyed by `tenant_id` with every query carrying an explicit
-- `tenant_id = $1` predicate, so this table does NOT use row-level
-- security — the same convention as `risk_tuning_overrides`. The DLP port
-- accepts a free-form tenant identifier (it is permissive by contract and
-- is exercised in tests with non-UUID ids), so the column is TEXT with no
-- FK to `tenants`.

CREATE TABLE dlp_detector_config (
    tenant_id   TEXT PRIMARY KEY,
    config      JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
