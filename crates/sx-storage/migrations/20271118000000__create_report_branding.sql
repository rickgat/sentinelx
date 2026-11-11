-- Per-tenant report branding (P2-002 MSSP white-label) — durable store.
--
-- Graduates the in-memory BrandingStore to Postgres (#1 persistence). One
-- row per tenant holds the white-label logo, primary colour, and optional
-- cover / footer Markdown that the report renderers apply.
--
-- Columns:
-- * tenant_id          — uuid of the tenant; the primary key (one brand per
--                        tenant) and the RLS key.
-- * logo_png           — optional PNG bytes (<= 200 KiB, enforced in-app).
-- * primary_color_hex  — `#RRGGBB`; defaults to the house red.
-- * cover_md/footer_md — optional Markdown.
-- * updated_at         — last write timestamp.
--
-- RLS is ENABLED + FORCED to match every other tenant-scoped table; the
-- policy keys off `app_current_tenant()` set by `TenantContext::apply`.

CREATE TABLE report_branding (
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    logo_png          BYTEA,
    primary_color_hex TEXT NOT NULL DEFAULT '#C71920'
                           CHECK (primary_color_hex ~ '^#[0-9A-Fa-f]{6}$'),
    cover_md          TEXT CHECK (cover_md IS NULL OR length(cover_md) <= 20000),
    footer_md         TEXT CHECK (footer_md IS NULL OR length(footer_md) <= 4000),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id)
);

ALTER TABLE report_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_branding FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_report_branding
    ON report_branding
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
