-- LOW-007 — Per-signal breakdown column on the RBA decision audit table.
--
-- Extends `rba_decisions` (from `20270101000300_create_rba_decisions.sql`)
-- with a JSONB column carrying the per-signal sub-score / weight /
-- weighted contribution breakdown the scorer emitted at decision time.
--
-- ## Why a new column rather than re-purposing `signals`
--
-- The existing `signals` column carries the raw collected SIGNAL
-- INPUTS (country code, velocity count, business-hours status, …).
-- LOW-007 needs the per-signal CONTRIBUTION TO THE COMPOSITE — a
-- different thing. Stuffing both into one JSONB blob would conflate
-- "what did the engine SEE" with "how did the engine VOTE", which is
-- exactly what an investigator needs to disentangle.
--
-- ## Shape
--
-- Each row in the JSONB array mirrors `sx_rba::SignalContribution`:
--
--   [
--     { "signal": "ip_geo",            "sub_score":  80, "weight": 0.25, "weighted": 20.0 },
--     { "signal": "velocity",          "sub_score":  10, "weight": 0.20, "weighted":  2.0 },
--     { "signal": "business_hours",    "sub_score":  60, "weight": 0.10, "weighted":  6.0 },
--     { "signal": "device_fp",         "sub_score":  30, "weight": 0.15, "weighted":  4.5 },
--     { "signal": "mfa_recent",        "sub_score":  10, "weight": 0.10, "weighted":  1.0 },
--     { "signal": "success_rate",      "sub_score":  20, "weight": 0.05, "weighted":  1.0 },
--     { "signal": "impossible_travel", "sub_score":   0, "weight": 0.15, "weighted":  0.0 }
--   ]
--
-- A *disabled* signal (per `feature_flags`) is OMITTED from the array.
-- A *zero-weight* signal (operator chose `0.0`) is included with
-- `weighted = 0.0` — the operator's intent stays visible on the row.
--
-- ## Back-compat
--
-- The column is `NULL`-able so existing pre-LOW-007 rows continue to
-- decode. The engine populates the column for every NEW decision; the
-- repository read path treats a NULL value as "row predates LOW-007"
-- and the API view layer projects it as an absent `signals` field
-- (same wire shape as a non-admin caller's response).
--
-- ## Row-Level Security
--
-- The column inherits the existing `tenant_isolation_rba_decisions`
-- policy on the parent table — no policy change required.
--
-- ## Indexing
--
-- We DO NOT create a GIN index on the new column. The intended access
-- pattern is "show me the breakdown for decision X" (already covered by
-- the `id` PK lookup) or "show me the last N decisions for tenant T
-- with their breakdown" (already covered by the existing
-- `rba_decisions_tenant_decided_idx`). Per-signal querying ("show me
-- every decision where impossible_travel voted ≥ 80") is a Sprint-6+
-- ask; reserve the GIN index for then so we don't pay write
-- amplification on every decision-row insert today.

ALTER TABLE rba_decisions
    ADD COLUMN signal_contributions JSONB NULL;

COMMENT ON COLUMN rba_decisions.signal_contributions IS
    'LOW-007: per-signal sub-score/weight/weighted breakdown the scorer '
    'emitted at decision time. NULL only for pre-LOW-007 rows; new '
    'rows always populate it. JSON shape: array of '
    '{signal, sub_score, weight, weighted}.';
