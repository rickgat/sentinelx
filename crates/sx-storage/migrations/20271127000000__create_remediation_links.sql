-- Durable store for remediation-link tracking (finding → PR / ticket).
--
-- The composition root built remediation-link tracking unconditionally
-- in-memory, so a link created via `PATCH /v1/findings/{id}/remediation-link`
-- (the PR/ticket URL + comment an operator attaches to a finding) was lost on
-- a monolith restart, even on Postgres deployments. This table persists it.
--
-- The `RemediationLinkView` (pr_url, ticket_url, comment, linked_at,
-- linked_by) is stored as JSONB keyed by `(tenant_id, finding_id)` — one link
-- per finding; a re-link upserts in place.
--
-- Both ids are bound explicitly on every statement, so — like the other
-- id-keyed IAM stores in this program — the table is intentionally NOT under
-- tenant RLS; isolation is by the composite key.

CREATE TABLE remediation_links (
    tenant_id   UUID        NOT NULL,
    finding_id  UUID        NOT NULL,
    aggregate   JSONB       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, finding_id)
);
