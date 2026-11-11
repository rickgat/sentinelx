-- Durable store for per-tenant risk-model tuning overrides (P1-014).
--
-- The composition root bound the risk-tuning store to an in-memory map, so a
-- tenant's risk-model override (its optional composite-weight + score-band
-- dials, set via `PUT /v1/risk/tuning`) was lost on a monolith restart,
-- silently reverting the tenant to the platform defaults. This table
-- persists it.
--
-- One row per tenant; the `TenantRiskOverride` aggregate (the two optional
-- dial sets) is stored as JSONB. A missing row means "no override" — the
-- tenant inherits the platform defaults — matching the in-memory store's
-- `get` returning `TenantRiskOverride::empty()`.
--
-- Keyed by `tenant_id` alone with no cross-tenant query, so no tenant RLS is
-- needed; isolation is by the single-row key.

CREATE TABLE risk_tuning_overrides (
    tenant_id   TEXT        PRIMARY KEY,
    override_   JSONB       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
