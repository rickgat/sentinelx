-- Wire the IR incident store (the in-app NIST SP 800-61 playbook runner) to
-- the durable `ir_incidents` table created in 20270101001403.
--
-- That table was shipped (columns + `steps` JSONB + a tenant RLS policy) but
-- the composition root still bound IR to an in-memory map, so open incidents
-- and their step-audit trail were lost on a monolith restart — including the
-- `audit_chain_compromise` incidents auto-fired on a tamper-evidence break.
--
-- The existing columns (`playbook_id`, `state`, `title`, `severity`, `steps`,
-- timestamps) stay authoritative for the CHECK constraints, the RLS policy,
-- and the auto-fire dedup scan (`tenant_id, state, playbook_id`). This adds a
-- lossless `aggregate` JSONB column holding the full `sx_ir_playbooks::
-- Incident` (its step list AND the step-audit trail), so a read reconstructs
-- the incident verbatim — including the audit entries — without a join or any
-- enum round-tripping. Same projection-plus-aggregate shape as
-- `engagement_aggregates`.

ALTER TABLE ir_incidents
    ADD COLUMN IF NOT EXISTS aggregate JSONB NOT NULL DEFAULT '{}'::jsonb;
