-- Plugin marketplace registry + dispatch history (P3-007 durability).
--
-- Persists installed plugins and their outbound-webhook dispatch log,
-- which previously lived in a process-local map and were wiped on every
-- restart — losing user-installed plugin registrations (manifest + the
-- HMAC webhook signing secret) and the dispatch audit trail.
--
-- ## Secret at rest
--
-- The per-plugin HMAC signing secret is written to `secret_enc` through
-- the `sx_webhooks::SecretCipher` seam (the same seam the webhook
-- signing-key store uses). In the default build the composition root
-- wires `PlaintextCipher`; configuring a KMS-backed cipher makes the
-- column true ciphertext with no schema change.
--
-- ## Storage shape
--
-- `plugins`: one row per (tenant, plugin). The manifest/registration is a
-- JSONB aggregate owned by `sx_plugins::RegisteredPlugin`; `registered_at`
-- is projected out for newest-first ordering.
--
-- `plugin_dispatches`: one row per dispatch, JSONB aggregate owned by
-- `sx_plugins::DispatchRecord`; `(tenant_id, plugin_id, ts)` projected for
-- the per-plugin newest-first history query.
--
-- ## Tenant isolation
--
-- Keyed by `tenant_id` (TEXT) with every query carrying an explicit
-- `tenant_id = $1` predicate — NO row-level security, the same convention
-- as `risk_tuning_overrides` / `dlp_detector_config`. The plugins port
-- accepts a free-form tenant identifier by contract, so there is no FK to
-- `tenants`.

CREATE TABLE plugins (
    tenant_id      TEXT NOT NULL,
    id             UUID NOT NULL,
    aggregate      JSONB NOT NULL,
    secret_enc     TEXT NOT NULL,
    registered_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE plugin_dispatches (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    plugin_id   UUID NOT NULL,
    aggregate   JSONB NOT NULL,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX plugin_dispatches_tenant_plugin_ts_idx
    ON plugin_dispatches (tenant_id, plugin_id, ts DESC);
