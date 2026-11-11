-- Findings are detected security issues attached to an asset within
-- an engagement. Severity and status are checked enums; evidence is a
-- JSONB list of references (URIs, file hashes, screenshot ids).

CREATE TABLE findings (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_id   UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 256),
    severity        TEXT NOT NULL CHECK (severity IN (
                        'Info', 'Low', 'Medium', 'High', 'Critical')),
    status          TEXT NOT NULL CHECK (status IN (
                        'New', 'Triaged', 'InProgress',
                        'Resolved', 'FalsePositive', 'AcceptedRisk')),
    title           TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 512),
    description     TEXT NOT NULL DEFAULT '',
    evidence_refs   JSONB NOT NULL DEFAULT '[]'::jsonb,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    triaged_at      TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    -- Resolved findings must have a resolved_at timestamp.
    CHECK (
        (status IN ('Resolved', 'FalsePositive', 'AcceptedRisk') AND resolved_at IS NOT NULL)
        OR
        (status NOT IN ('Resolved', 'FalsePositive', 'AcceptedRisk'))
    )
);

CREATE INDEX findings_tenant_idx ON findings (tenant_id);
CREATE INDEX findings_tenant_engagement_idx ON findings (tenant_id, engagement_id);
CREATE INDEX findings_tenant_asset_idx ON findings (tenant_id, asset_id);
CREATE INDEX findings_tenant_status_idx ON findings (tenant_id, status);
CREATE INDEX findings_tenant_severity_idx ON findings (tenant_id, severity);
CREATE INDEX findings_tenant_detected_idx ON findings (tenant_id, detected_at DESC);
CREATE INDEX findings_evidence_gin_idx ON findings USING GIN (evidence_refs jsonb_path_ops);
