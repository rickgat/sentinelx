-- Assets are the discoverable entities (hosts, services, web apps,
-- cloud resources) under test in an engagement. `fingerprint` is the
-- canonical identifier used for deduplication; it is unique per tenant.

CREATE TABLE assets (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_id   UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN (
                        'Host', 'Service', 'Webapp', 'Cloud', 'Identity',
                        'Network', 'Container', 'Dns')),
    fingerprint     TEXT NOT NULL CHECK (length(fingerprint) BETWEEN 1 AND 512),
    exposure        TEXT NOT NULL CHECK (exposure IN (
                        'Internet', 'Internal', 'Restricted', 'Unknown')),
    criticality     TEXT NOT NULL CHECK (criticality IN (
                        'Low', 'Medium', 'High', 'Critical')),
    tags            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, fingerprint)
);

CREATE INDEX assets_tenant_idx ON assets (tenant_id);
CREATE INDEX assets_tenant_engagement_idx ON assets (tenant_id, engagement_id);
CREATE INDEX assets_tenant_kind_idx ON assets (tenant_id, kind);
CREATE INDEX assets_tenant_criticality_idx ON assets (tenant_id, criticality);
CREATE INDEX assets_tags_gin_idx ON assets USING GIN (tags jsonb_path_ops);
