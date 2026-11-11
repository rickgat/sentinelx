-- Replace the legacy `assets.criticality` CHECK constraint with the
-- canonical `AssetCriticality` value-object variants used everywhere
-- else in the codebase.
--
-- The previous migration (20260101000006_create_assets) constrained
-- `criticality` to `'Low' | 'Medium' | 'High' | 'Critical'`, which has
-- no counterpart in the Rust domain model. The Rust enum
-- `sx_core::value_object::criticality::AssetCriticality` emits
-- `'unknown' | 'dev' | 'staging' | 'production' | 'crown_jewel'` via
-- its `Display` impl, and the read-side adapter
-- (`row_to_asset_view`) now decodes the column straight into
-- `AssetView::criticality`. Without this migration any insert from
-- the application layer would be rejected by the CHECK constraint.
--
-- Migration ordering:
--   1. Drop the old constraint (idempotent — uses IF EXISTS so reruns
--      against a fresh DB that never had the legacy constraint do not
--      fail).
--   2. Backfill any rows whose value is not in the new vocabulary to
--      `'production'`. The legacy values are case-sensitive `Low /
--      Medium / High / Critical`; nothing in production today uses
--      this column meaningfully, so collapsing all legacy values to
--      `'production'` keeps the upgrade lossless from a scoring
--      perspective (a defaulted Production matches what the risk
--      adapter falls back to today — see
--      `services/sx-monolith/src/adapters/risk.rs` Phase-3.5+2
--      docblock).
--   3. Flip the column default to the new canonical `'production'`.
--   4. Re-attach the CHECK with the new five-value vocabulary.

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_criticality_check;

UPDATE assets
   SET criticality = 'production'
 WHERE criticality NOT IN ('unknown', 'dev', 'staging', 'production', 'crown_jewel');

ALTER TABLE assets ALTER COLUMN criticality SET DEFAULT 'production';

ALTER TABLE assets
    ADD CONSTRAINT assets_criticality_check
    CHECK (criticality IN ('unknown', 'dev', 'staging', 'production', 'crown_jewel'));
