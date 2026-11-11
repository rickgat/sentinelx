-- External audit-chain anchor records (P1-015).
--
-- Each row is a published anchor for one (tenant, window) pair. The
-- window aggregates a contiguous slice of `audit_log` rows
-- ([audit_seq_from, audit_seq_to] inclusive) under a SHA-256 Merkle
-- root; that root is then submitted to one or more external trust
-- anchors (RFC 3161 TSA today, optional blockchain anchor in the
-- premium tier). Storing the TSA token verbatim lets future verifier
-- code re-prove the Merkle root was bound to the issuer's timestamp
-- without re-contacting the TSA.

CREATE TABLE audit_anchor_external (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    audit_seq_from  BIGINT NOT NULL,
    audit_seq_to    BIGINT NOT NULL,
    merkle_root     BYTEA NOT NULL,
    tsa_provider    TEXT NOT NULL,
    tsa_timestamp   TIMESTAMPTZ NOT NULL,
    tsa_token       BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE audit_anchor_external ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchor_external FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_audit_anchor_external ON audit_anchor_external
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
