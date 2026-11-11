-- UEBA baseline lifecycle state — HIGH-010 (anti-poisoning freeze mode).
--
-- Adds two tenant-scoped tables to back the freeze-aware UEBA orchestration
-- layer shipped in `crates/sx-ueba`:
--
--   * `ueba_baseline_state` — one row per (tenant_id, user_id) carrying
--                             the current lifecycle state and (when
--                             `state = 'frozen'`) the captured snapshot
--                             counters + freeze-time wall-clock.
--   * `ueba_baseline_audit` — append-only audit row per state transition,
--                             so investigations can reconstruct every
--                             freeze / unfreeze decision.
--
-- Both tables enable + FORCE Row-Level Security with a
-- `tenant_id = app_current_tenant()` policy. The FORCE flag is critical:
-- it makes the policy apply even to the table owner role, eliminating an
-- entire class of "forgot to set GUC" cross-tenant data leaks.
--
-- The MVP `crates/sx-ueba` implementation keeps state in-memory; this
-- migration lands the schema now so the persistent adapter can be plugged
-- in later without churning the test snapshots. Today's read/write path
-- against these tables is a no-op stub — the integration tests in this
-- crate don't depend on it.

-- ---------------------------------------------------------------------
-- ueba_baseline_state
-- ---------------------------------------------------------------------
--
-- One row per `(tenant_id, user_id)` carrying the freeze-aware lifecycle
-- state plus an optional snapshot payload.
--
-- Columns:
--
-- * `tenant_id`        — uuid of the owning tenant; composite PK part.
-- * `user_id`          — uuid of the subject; composite PK part.
-- * `state`            — TEXT discriminant (`'learning'` / `'active'` /
--                        `'frozen'`). Matches `BaselineState::code()`
--                        in `crates/sx-ueba/src/state.rs`.
-- * `snapshot`         — JSONB payload mirroring `BaselineSnapshot`. NULL
--                        when `state <> 'frozen'`.
-- * `frozen_at`        — wall-clock the snapshot was captured; NULL when
--                        the row has never been frozen.
-- * `updated_at`       — last mutation time; bumped on every transition.

CREATE TABLE ueba_baseline_state (
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL,
    state       TEXT NOT NULL DEFAULT 'learning'
                CHECK (state IN ('learning', 'active', 'frozen')),
    snapshot    JSONB NULL,
    frozen_at   TIMESTAMPTZ NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id),
    -- Frozen MUST carry a snapshot; non-frozen MUST NOT (defence in depth
    -- so a sloppy migration cannot leave a "phantom" snapshot row that
    -- would otherwise be silently used by the scorer once the state
    -- flipped back to active).
    CONSTRAINT ueba_baseline_state_snapshot_consistency CHECK (
        (state = 'frozen' AND snapshot IS NOT NULL AND frozen_at IS NOT NULL)
        OR
        (state <> 'frozen' AND snapshot IS NULL)
    )
);

CREATE INDEX ueba_baseline_state_tenant_state_idx
    ON ueba_baseline_state (tenant_id, state);

ALTER TABLE ueba_baseline_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_baseline_state FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_ueba_baseline_state
    ON ueba_baseline_state
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

-- ---------------------------------------------------------------------
-- ueba_baseline_audit
-- ---------------------------------------------------------------------
--
-- Append-only audit row per state transition. Reads by the
-- investigation playbook to answer "who froze alice's baseline, when,
-- and why?".
--
-- Columns:
--
-- * `id`           — uuid v7 of the audit row (monotonic for ordering).
-- * `tenant_id`    — owning tenant; RLS keys off this.
-- * `user_id`      — subject of the transition.
-- * `from_state`   — state before the transition.
-- * `to_state`     — state after the transition.
-- * `actor`        — operator identity (email / sub) or NULL for the
--                    auto-promotion path (Learning → Active on warm-up).
-- * `reason`       — free-text operator reason (incident id, ticket).
-- * `at`           — wall-clock time the transition was recorded.

CREATE TABLE ueba_baseline_audit (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL,
    from_state   TEXT NOT NULL
                 CHECK (from_state IN ('learning', 'active', 'frozen')),
    to_state     TEXT NOT NULL
                 CHECK (to_state IN ('learning', 'active', 'frozen')),
    actor        TEXT NULL,
    reason       TEXT NULL,
    at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ueba_baseline_audit_tenant_at_idx
    ON ueba_baseline_audit (tenant_id, at DESC);
CREATE INDEX ueba_baseline_audit_tenant_user_idx
    ON ueba_baseline_audit (tenant_id, user_id);

ALTER TABLE ueba_baseline_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_baseline_audit FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_ueba_baseline_audit
    ON ueba_baseline_audit
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
