-- CRIT-005 — threat-intel commercial credential rotation state.
--
-- One row per (tenant, secret_id). The rotation scheduler reads
-- `next_due_at` to decide what to rotate; writes back
-- `last_rotated_at`, `last_error`, and `attempts` per cycle.
--
-- Multi-tenant invariant: every row carries a `tenant_id`, every read
-- and write is keyed on it, and the unique constraint pins
-- `(tenant_id, secret_id)`.

CREATE TABLE IF NOT EXISTS intel_credential_rotation_state (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    -- Provider-opaque identifier (Vault key name, AWS SM ARN, GCP
    -- resource path).
    secret_id           TEXT NOT NULL,
    -- Provider tag for audit attribution: 'vault-transit' | 'aws-sm' |
    -- 'gcp-sm'.
    vendor              TEXT NOT NULL,
    -- Rotation cadence configured for this row (seconds). Defaults
    -- come from RotationPolicy::standard()/pci() at insertion time.
    cadence_secs        BIGINT NOT NULL CHECK (cadence_secs > 0),
    last_rotated_at     TIMESTAMPTZ,
    next_due_at         TIMESTAMPTZ NOT NULL,
    -- Last *non-recoverable* failure observed by the scheduler.
    -- Cleared on a successful rotation. Cap below is enforced at the
    -- application layer so partial restores don't lose the message.
    last_error          TEXT,
    -- Count of *consecutive* failures (cleared on success). Used by the
    -- failure-mode escalation: 3 strikes -> audit ERROR + keep old
    -- credential active.
    attempts            INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, secret_id)
);

CREATE INDEX IF NOT EXISTS intel_credential_rotation_state_due_idx
    ON intel_credential_rotation_state (next_due_at);

CREATE INDEX IF NOT EXISTS intel_credential_rotation_state_tenant_idx
    ON intel_credential_rotation_state (tenant_id);
