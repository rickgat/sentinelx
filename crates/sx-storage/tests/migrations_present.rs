//! Smoke test: every shipped migration file is present and non-empty.
//!
//! This catches accidental deletion or truncation of migration files
//! via the `include_str!` mechanism, which fails at compile time if
//! the path does not exist.

const M01: &str = include_str!("../migrations/20260101000001_init_extensions.sql");
const M02: &str = include_str!("../migrations/20260101000002_create_tenants.sql");
const M03: &str = include_str!("../migrations/20260101000003_create_users.sql");
const M04: &str = include_str!("../migrations/20260101000004_create_roles_permissions.sql");
const M05: &str = include_str!("../migrations/20260101000005_create_engagements.sql");
const M06: &str = include_str!("../migrations/20260101000006_create_assets.sql");
const M07: &str = include_str!("../migrations/20260101000007_create_findings.sql");
const M08: &str = include_str!("../migrations/20260101000008_create_cves.sql");
const M09: &str = include_str!("../migrations/20260101000009_create_audit_log.sql");
const M10: &str = include_str!("../migrations/20260101000010_enable_rls.sql");
const M11: &str = include_str!("../migrations/20260101000011_create_bas_approvals.sql");
const M12: &str = include_str!("../migrations/20260101000012_create_soc_rules.sql");
const M13: &str =
    include_str!("../migrations/20260101000013_create_sx_resolve_engagement_tenant.sql");
const M14: &str = include_str!("../migrations/20260101000014_create_tenant_deks.sql");
const M15: &str = include_str!("../migrations/20260101000015_assets_criticality_value_object.sql");
const M16: &str = include_str!("../migrations/20261015000000_create_audit_anchor_external.sql");
const M17: &str = include_str!("../migrations/20260801000000_create_cve_master.sql");
const M18: &str = include_str!("../migrations/20260901000000_create_user_webauthn_credentials.sql");
const M19: &str = include_str!("../migrations/20260815000000_create_tenant_risk_weights.sql");
const M20_VULN_IMPORTS: &str =
    include_str!("../migrations/20270101000000__create_vuln_imports.sql");
const M21_LOG_INGEST_STATUS: &str =
    include_str!("../migrations/20270101000100__create_log_ingest_state.sql");
const M22_SCIM_TOKENS: &str = include_str!("../migrations/20270101000200__create_scim_tokens.sql");
const M23_SCIM_AUDIT: &str = include_str!("../migrations/20270101000201__create_scim_audit.sql");
const M24_RBA_DECISIONS: &str =
    include_str!("../migrations/20270101000300_create_rba_decisions.sql");
const M25_RBA_CONFIG: &str = include_str!("../migrations/20270101000301_create_rba_config.sql");
const M26_BLAST_RADIUS_CACHE: &str =
    include_str!("../migrations/20270101000400_create_blast_radius_cache.sql");
const M27_REMEDIATION_OUTCOMES: &str =
    include_str!("../migrations/20270101000500_create_remediation_outcomes.sql");
const M28_REGRESSION_EVENTS: &str = M27_REMEDIATION_OUTCOMES;
const M29_COPILOT_APPROVALS: &str =
    include_str!("../migrations/20270101000600__create_copilot_approvals.sql");
const M30_REPORT_SCHEDULES: &str =
    include_str!("../migrations/20270101000700__create_report_schedules.sql");
const M34_UEBA_BASELINES: &str =
    include_str!("../migrations/20270101001000__create_ueba_state.sql");
const M35_UEBA_ANOMALIES: &str =
    include_str!("../migrations/20270101001000__create_ueba_state.sql");
const M36_SCIM_TOKENS_ROTATION: &str =
    include_str!("../migrations/20271117000002__scim_tokens.sql");
/// LOW-007: per-signal breakdown column on the RBA decision audit table.
const M37_RBA_DECISIONS_SIGNAL_CONTRIBUTIONS: &str =
    include_str!("../migrations/20271117000001__rba_decisions_signal_contributions.sql");
/// PRG-02: durable combined-pentest run store (graduates the in-memory repo).
const M38_PENTEST_RUNS: &str =
    include_str!("../migrations/20271119000000__create_pentest_runs.sql");

const ALL: &[(&str, &str)] = &[
    ("01_init_extensions", M01),
    ("02_create_tenants", M02),
    ("03_create_users", M03),
    ("04_create_roles_permissions", M04),
    ("05_create_engagements", M05),
    ("06_create_assets", M06),
    ("07_create_findings", M07),
    ("08_create_cves", M08),
    ("09_create_audit_log", M09),
    ("10_enable_rls", M10),
    ("11_create_bas_approvals", M11),
    ("12_create_soc_rules", M12),
    ("13_create_sx_resolve_engagement_tenant", M13),
    ("14_create_tenant_deks", M14),
    ("15_assets_criticality_value_object", M15),
    ("16_create_audit_anchor_external", M16),
    ("17_create_cve_master", M17),
    ("18_create_user_webauthn_credentials", M18),
    ("19_create_tenant_risk_weights", M19),
    ("20_create_vuln_imports", M20_VULN_IMPORTS),
    ("21_create_log_ingest_state", M21_LOG_INGEST_STATUS),
    ("22_create_scim_tokens", M22_SCIM_TOKENS),
    ("23_create_scim_audit", M23_SCIM_AUDIT),
    ("24_create_rba_decisions", M24_RBA_DECISIONS),
    ("25_create_rba_config", M25_RBA_CONFIG),
    ("26_blast_radius_cache", M26_BLAST_RADIUS_CACHE),
    ("27_remediation_outcomes", M27_REMEDIATION_OUTCOMES),
    ("28_regression_events", M28_REGRESSION_EVENTS),
    ("29_copilot_approvals", M29_COPILOT_APPROVALS),
    ("30_create_report_schedules", M30_REPORT_SCHEDULES),
    ("34_ueba_baselines", M34_UEBA_BASELINES),
    ("35_ueba_anomalies", M35_UEBA_ANOMALIES),
    ("36_scim_tokens_rotation", M36_SCIM_TOKENS_ROTATION),
    (
        "37_rba_decisions_signal_contributions",
        M37_RBA_DECISIONS_SIGNAL_CONTRIBUTIONS,
    ),
    ("38_pentest_runs", M38_PENTEST_RUNS),
];

#[test]
fn every_migration_non_empty() {
    for (name, body) in ALL {
        assert!(!body.trim().is_empty(), "migration {name} is empty",);
    }
}

#[test]
fn tenants_migration_mentions_slug_unique() {
    assert!(
        M02.contains("UNIQUE") && M02.to_ascii_uppercase().contains("SLUG"),
        "tenants migration must declare slug uniqueness",
    );
}

#[test]
fn rls_migration_enables_rls() {
    assert!(M10.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M10.contains("FORCE ROW LEVEL SECURITY"));
}

#[test]
fn rls_migration_creates_policies_for_core_tables() {
    for table in ["users", "engagements", "assets", "findings", "audit_log"] {
        let needle = format!("tenant_isolation_{table}");
        assert!(
            M10.contains(&needle),
            "RLS migration missing policy {needle}",
        );
    }
}

#[test]
fn audit_log_has_composite_pk() {
    assert!(M09.contains("PRIMARY KEY (tenant_id, seq)"));
}

#[test]
fn cves_migration_validates_cve_id_format() {
    assert!(M08.contains("CVE-"));
}

#[test]
fn migration_count_matches_registry() {
    assert_eq!(ALL.len(), 35);
}

#[test]
fn pentest_runs_migration_is_tenant_isolated() {
    // The durable pentest-run store (PRG-02) must carry the same fail-closed
    // RLS as every other tenant-scoped table, or a buyer's runs could leak
    // across tenants.
    assert!(M38_PENTEST_RUNS.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M38_PENTEST_RUNS.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M38_PENTEST_RUNS.contains("tenant_isolation_pentest_runs"));
    assert!(M38_PENTEST_RUNS.contains("app_current_tenant()"));
}

#[test]
fn scim_tokens_rotation_migration_extends_columns_and_rls() {
    // MED-005 extension migration MUST add the four lifecycle columns
    // + the scopes JSONB, and re-assert FORCE-RLS.
    for col in [
        "scopes",
        "activated_at",
        "expires_at",
        "retired_at",
        "revoked_at",
    ] {
        assert!(
            M36_SCIM_TOKENS_ROTATION.contains(col),
            "scim_tokens MED-005 migration missing column {col}",
        );
    }
    assert!(M36_SCIM_TOKENS_ROTATION.contains("JSONB"));
    assert!(M36_SCIM_TOKENS_ROTATION.contains("FORCE ROW LEVEL SECURITY"));
    // Both rotation-scheduler indices.
    assert!(M36_SCIM_TOKENS_ROTATION.contains("scim_tokens_expires_at_idx"));
    assert!(M36_SCIM_TOKENS_ROTATION.contains("scim_tokens_lifecycle_idx"));
    // Extended scim_audit action whitelist for the new lifecycle events.
    for action in [
        "mint_token",
        "rotate_token",
        "revoke_token",
        "scope_violation",
    ] {
        assert!(
            M36_SCIM_TOKENS_ROTATION.contains(&format!("'{action}'")),
            "scim_audit action whitelist must include {action}",
        );
    }
}

#[test]
fn rba_decisions_signal_contributions_migration_alters_table() {
    // LOW-007: the migration must extend `rba_decisions` (not create a
    // new table). Pin the ALTER TABLE shape so a refactor that moves
    // the column to a sidecar table is caught here.
    assert!(M37_RBA_DECISIONS_SIGNAL_CONTRIBUTIONS.contains("ALTER TABLE rba_decisions"));
    assert!(M37_RBA_DECISIONS_SIGNAL_CONTRIBUTIONS.contains("ADD COLUMN signal_contributions"));
    assert!(M37_RBA_DECISIONS_SIGNAL_CONTRIBUTIONS.contains("JSONB"));
    // Must be nullable so pre-LOW-007 rows decode cleanly.
    assert!(M37_RBA_DECISIONS_SIGNAL_CONTRIBUTIONS.contains("NULL"));
    // Documentation: a COMMENT ON COLUMN keeps the column's purpose
    // discoverable from psql + pgAdmin without crawling git history.
    assert!(M37_RBA_DECISIONS_SIGNAL_CONTRIBUTIONS.contains("COMMENT ON COLUMN"));
}

#[test]
fn report_schedules_migration_enables_rls() {
    assert!(M30_REPORT_SCHEDULES.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M30_REPORT_SCHEDULES.contains("FORCE ROW LEVEL SECURITY"));
    assert!(M30_REPORT_SCHEDULES.contains("tenant_isolation_report_schedules"));
}

#[test]
fn report_schedules_migration_declares_required_columns() {
    for col in [
        "tenant_id",
        "engagement_id",
        "format",
        "cron_expr",
        "recipients",
        "last_run_at",
        "last_status",
        "created_at",
    ] {
        assert!(
            M30_REPORT_SCHEDULES.contains(col),
            "report_schedules migration missing column {col}",
        );
    }
    assert!(M30_REPORT_SCHEDULES.contains("recipients      JSONB NOT NULL"));
}

#[test]
fn scim_tokens_migration_declares_required_columns_and_rls() {
    for col in [
        "tenant_id",
        "token_hash",
        "name",
        "created_at",
        "last_used_at",
    ] {
        assert!(
            M22_SCIM_TOKENS.contains(col),
            "scim_tokens migration missing column {col}",
        );
    }
    assert!(M22_SCIM_TOKENS.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M22_SCIM_TOKENS.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M22_SCIM_TOKENS.contains("tenant_isolation_scim_tokens"));
    assert!(M22_SCIM_TOKENS.contains("octet_length(token_hash) = 32"));
}

#[test]
fn scim_audit_migration_declares_required_columns_and_rls() {
    for col in ["tenant_id", "scim_user_id", "action", "payload", "ts"] {
        assert!(
            M23_SCIM_AUDIT.contains(col),
            "scim_audit migration missing column {col}",
        );
    }
    assert!(M23_SCIM_AUDIT.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M23_SCIM_AUDIT.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M23_SCIM_AUDIT.contains("tenant_isolation_scim_audit"));
    assert!(M23_SCIM_AUDIT.contains("JSONB"));
    for action in ["create_user", "replace_user", "delete_user", "create_group"] {
        assert!(
            M23_SCIM_AUDIT.contains(&format!("'{action}'")),
            "scim_audit action CHECK must include {action}",
        );
    }
}

#[test]
fn blast_radius_cache_migration_enables_rls() {
    assert!(M26_BLAST_RADIUS_CACHE.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M26_BLAST_RADIUS_CACHE.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M26_BLAST_RADIUS_CACHE.contains("tenant_isolation_blast_radius_cache"));
}

#[test]
fn blast_radius_cache_migration_has_required_columns() {
    for col in [
        "id",
        "tenant_id",
        "seed_asset_id",
        "max_depth",
        "computed_at",
        "report",
    ] {
        assert!(
            M26_BLAST_RADIUS_CACHE.contains(col),
            "blast_radius_cache migration missing column {col}",
        );
    }
}

#[test]
fn rba_decisions_migration_enables_rls() {
    assert!(M24_RBA_DECISIONS.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M24_RBA_DECISIONS.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M24_RBA_DECISIONS.contains("tenant_isolation_rba_decisions"));
}

#[test]
fn rba_decisions_migration_has_required_columns() {
    for col in [
        "id",
        "tenant_id",
        "user_id",
        "ip",
        "score",
        "action",
        "signals",
        "decided_at",
    ] {
        assert!(
            M24_RBA_DECISIONS.contains(col),
            "rba_decisions migration missing column {col}",
        );
    }
}

#[test]
fn rba_decisions_migration_constrains_action_enum() {
    for v in ["allow", "step_up_mfa", "block"] {
        assert!(
            M24_RBA_DECISIONS.contains(&format!("'{v}'")),
            "rba_decisions action CHECK must include {v}",
        );
    }
}

#[test]
fn rba_decisions_migration_constrains_score_range() {
    assert!(M24_RBA_DECISIONS.contains("score >= 0"));
    assert!(M24_RBA_DECISIONS.contains("score <= 100"));
}

#[test]
fn rba_config_migration_enables_rls() {
    assert!(M25_RBA_CONFIG.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M25_RBA_CONFIG.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M25_RBA_CONFIG.contains("tenant_isolation_rba_config"));
}

#[test]
fn rba_config_migration_uses_uuid_pk() {
    assert!(M25_RBA_CONFIG.contains("tenant_id            UUID PRIMARY KEY"));
}

#[test]
fn rba_config_migration_declares_threshold_band_check() {
    assert!(
        M25_RBA_CONFIG.contains("rba_thresholds_band"),
        "rba_config must name the band CHECK",
    );
    assert!(M25_RBA_CONFIG.contains("allow_threshold < block_threshold"));
}

#[test]
fn rba_config_migration_has_required_columns() {
    for col in [
        "tenant_id",
        "allow_threshold",
        "block_threshold",
        "weights",
        "business_tz",
        "business_hours_start",
        "business_hours_end",
    ] {
        assert!(
            M25_RBA_CONFIG.contains(col),
            "rba_config migration missing column {col}",
        );
    }
}

#[test]
fn blast_radius_cache_migration_declares_unique_triple() {
    assert!(
        M26_BLAST_RADIUS_CACHE.contains("UNIQUE (tenant_id, seed_asset_id, max_depth)"),
        "must constrain cache key as (tenant_id, seed_asset_id, max_depth)",
    );
}

#[test]
fn blast_radius_cache_migration_has_ttl_cleanup_index() {
    assert!(
        M26_BLAST_RADIUS_CACHE.contains("blast_radius_cache_ttl_idx"),
        "TTL cleanup index must be named blast_radius_cache_ttl_idx",
    );
    assert!(
        M26_BLAST_RADIUS_CACHE.contains("computed_at"),
        "TTL index must be on computed_at",
    );
}

#[test]
fn remediation_outcomes_migration_creates_both_tables() {
    assert!(M27_REMEDIATION_OUTCOMES.contains("CREATE TABLE remediation_outcomes"));
    assert!(M27_REMEDIATION_OUTCOMES.contains("CREATE TABLE regression_events"));
}

#[test]
fn remediation_outcomes_migration_enables_rls() {
    assert!(M27_REMEDIATION_OUTCOMES.contains("tenant_isolation_remediation_outcomes"));
    assert!(M27_REMEDIATION_OUTCOMES.contains("tenant_isolation_regression_events"));
    let force_rls_hits = M27_REMEDIATION_OUTCOMES
        .matches("FORCE  ROW LEVEL SECURITY")
        .count();
    assert_eq!(
        force_rls_hits, 2,
        "FORCE ROW LEVEL SECURITY must appear once per table",
    );
}

#[test]
fn remediation_outcomes_migration_constrains_method_enum() {
    for m in [
        "auto-patch",
        "manual-patch",
        "risk-accepted",
        "false-positive",
        "config-change",
        "unspecified",
    ] {
        assert!(
            M27_REMEDIATION_OUTCOMES.contains(&format!("'{m}'")),
            "method CHECK must include {m}",
        );
    }
}

#[test]
fn tenant_deks_migration_enables_rls() {
    assert!(M14.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M14.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M14.contains("tenant_isolation_tenant_deks"));
}

#[test]
fn tenant_deks_migration_declares_primary_key_and_columns() {
    assert!(M14.contains("tenant_id   UUID PRIMARY KEY"));
    assert!(M14.contains("version     INTEGER NOT NULL CHECK (version >= 0)"));
    assert!(M14.contains("wrapped     TEXT NOT NULL"));
    assert!(M14.contains("created_at  TIMESTAMPTZ NOT NULL"));
}

#[test]
fn assets_criticality_value_object_migration_lists_all_five_variants() {
    for v in ["unknown", "dev", "staging", "production", "crown_jewel"] {
        assert!(
            M15.contains(&format!("'{v}'")),
            "criticality CHECK must include {v}",
        );
    }
    assert!(M15.to_ascii_uppercase().contains("DROP CONSTRAINT"));
    assert!(M15.to_ascii_uppercase().contains("ADD CONSTRAINT"));
}

#[test]
fn audit_anchor_external_migration_enables_rls() {
    assert!(M16.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M16.contains("FORCE ROW LEVEL SECURITY"));
    assert!(M16.contains("tenant_isolation_audit_anchor_external"));
}

#[test]
fn audit_anchor_external_migration_has_required_columns() {
    for col in [
        "tenant_id",
        "window_start",
        "window_end",
        "audit_seq_from",
        "audit_seq_to",
        "merkle_root",
        "tsa_provider",
        "tsa_timestamp",
        "tsa_token",
    ] {
        assert!(
            M16.contains(col),
            "audit_anchor_external migration missing column {col}",
        );
    }
}

#[test]
fn cve_master_migration_declares_primary_key_and_indices() {
    assert!(M17.contains("CREATE TABLE cve_master"));
    assert!(M17.contains("cve_id"));
    assert!(M17.contains("PRIMARY KEY") || M17.contains("PRIMARY KEY,"));
    assert!(M17.contains("cve_master_kev_idx"));
    assert!(M17.contains("cve_master_epss_idx"));
    assert!(M17.contains("cve_master_published_idx"));
    assert!(M17.contains("cve_master_cpes_gin_idx"));
}

#[test]
fn bas_approvals_migration_declares_unique_triple() {
    assert!(M11.contains("UNIQUE (engagement_id, technique_id, approver_email)"));
}

#[test]
fn bas_approvals_migration_enables_rls() {
    assert!(M11.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M11.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M11.contains("tenant_isolation_bas_approvals"));
}

#[test]
fn soc_rules_migration_declares_unique_pair() {
    assert!(M12.contains("UNIQUE (tenant_id, rule_id)"));
}

#[test]
fn soc_rules_migration_enables_rls() {
    assert!(M12.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M12.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M12.contains("tenant_isolation_soc_rules"));
}

#[test]
fn soc_rules_migration_has_when_json_jsonb() {
    // The match condition column must be JSONB (not TEXT) so callers
    // can index/filter on its contents at the engine layer.
    assert!(M12.contains("when_json"));
    assert!(M12.to_ascii_uppercase().contains("JSONB"));
}

#[test]
fn soc_rules_migration_constrains_severity() {
    // The four-valued severity enum must be enforced at the DB layer.
    for s in ["low", "medium", "high", "critical"] {
        assert!(
            M12.contains(&format!("'{s}'")),
            "soc_rules severity CHECK must include {s}",
        );
    }
}

#[test]
fn user_webauthn_credentials_migration_declares_unique_cred_id() {
    assert!(M18.contains("UNIQUE (tenant_id, cred_id)"));
}

#[test]
fn user_webauthn_credentials_migration_enables_rls() {
    assert!(M18.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M18.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M18.contains("tenant_isolation_user_webauthn_credentials"));
}

#[test]
fn user_webauthn_credentials_migration_constrains_counter_to_u32() {
    assert!(M18.contains("counter >= 0"));
    assert!(M18.contains("4294967295"));
}

#[test]
fn user_webauthn_credentials_migration_constrains_aaguid_length() {
    assert!(M18.contains("octet_length(aaguid) = 16"));
}

#[test]
fn tenant_risk_weights_migration_declares_sum_in_range_check() {
    assert!(
        M19.contains("weights_sum_in_range"),
        "migration must name the sum CHECK constraint",
    );
    assert!(
        M19.contains("BETWEEN 0.99 AND 1.01"),
        "migration must enforce sum in [0.99, 1.01]",
    );
    for col in [
        "w_severity",
        "w_exploit",
        "w_exposure",
        "w_criticality",
        "w_business_impact",
        "w_chain",
    ] {
        assert!(
            M19.contains(col),
            "migration must mention weight column {col}",
        );
    }
}

#[test]
fn tenant_risk_weights_migration_enables_rls() {
    assert!(M19.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M19.contains("FORCE ROW LEVEL SECURITY"));
    assert!(M19.contains("tenant_isolation_tenant_risk_weights"));
    assert!(M19.contains("tenant_id = app_current_tenant()"));
}

#[test]
fn tenant_risk_weights_migration_uses_uuid_pk() {
    assert!(M19.contains("tenant_id          UUID PRIMARY KEY"));
}

#[test]
fn vuln_imports_migration_enables_rls_and_creates_policy() {
    assert!(M20_VULN_IMPORTS.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M20_VULN_IMPORTS.contains("FORCE ROW LEVEL SECURITY"));
    assert!(M20_VULN_IMPORTS.contains("tenant_isolation_vuln_imports"));
    assert!(M20_VULN_IMPORTS.contains("tenant_id = app_current_tenant()"));
}

#[test]
fn vuln_imports_migration_declares_required_columns() {
    for col in [
        "id",
        "tenant_id",
        "source",
        "asset_count",
        "finding_count",
        "ingested_at",
        "status",
    ] {
        assert!(
            M20_VULN_IMPORTS.contains(col),
            "vuln_imports migration missing column {col}",
        );
    }
}

#[test]
fn vuln_imports_migration_constrains_source_and_status() {
    for s in ["nessus", "openvas"] {
        assert!(
            M20_VULN_IMPORTS.contains(&format!("'{s}'")),
            "vuln_imports source CHECK must include {s}",
        );
    }
    for s in ["ok", "failed", "partial"] {
        assert!(
            M20_VULN_IMPORTS.contains(&format!("'{s}'")),
            "vuln_imports status CHECK must include {s}",
        );
    }
}

#[test]
fn copilot_approvals_migration_enables_rls() {
    assert!(M29_COPILOT_APPROVALS.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M29_COPILOT_APPROVALS.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M29_COPILOT_APPROVALS.contains("tenant_isolation_copilot_approvals"));
}

#[test]
fn copilot_approvals_migration_has_required_columns() {
    for col in [
        "token        UUID PRIMARY KEY",
        "tenant_id    UUID NOT NULL",
        "action       JSONB NOT NULL",
        "status       TEXT NOT NULL",
        "proposed_at  TIMESTAMPTZ NOT NULL",
        "decided_at   TIMESTAMPTZ NULL",
        "decided_by   TEXT NULL",
        "reason       TEXT NULL",
        "expires_at   TIMESTAMPTZ NOT NULL",
    ] {
        assert!(
            M29_COPILOT_APPROVALS.contains(col),
            "copilot_approvals migration missing column: {col}",
        );
    }
}

#[test]
fn copilot_approvals_migration_status_check_includes_all_states() {
    for s in ["pending", "approved", "rejected", "expired"] {
        assert!(
            M29_COPILOT_APPROVALS.contains(&format!("'{s}'")),
            "copilot_approvals status CHECK must include {s}",
        );
    }
}

#[test]
fn sx_resolve_engagement_tenant_migration_declares_security_definer() {
    // Pins the `SECURITY DEFINER` keyword in the migration body: the
    // whole point of this function is to let the adapter resolve a
    // tenant without `BYPASSRLS` or `row_security = off`, so a
    // refactor that demotes it to `SECURITY INVOKER` (the default)
    // would silently re-introduce the RLS-bypass requirement on
    // every caller. We also pin the pinned `search_path` and the
    // signature so a rename or schema change is caught here too.
    assert!(
        M13.contains("SECURITY DEFINER"),
        "migration must declare SECURITY DEFINER",
    );
    assert!(
        M13.contains("SET search_path = public"),
        "migration must pin search_path to public",
    );
    assert!(
        M13.contains("CREATE OR REPLACE FUNCTION sx_resolve_engagement_tenant(engagement UUID)"),
        "migration must define sx_resolve_engagement_tenant(UUID)",
    );
    assert!(M13.contains("RETURNS UUID"), "migration must return UUID",);
    assert!(
        M13.contains("REVOKE ALL ON FUNCTION sx_resolve_engagement_tenant(UUID) FROM PUBLIC"),
        "migration must REVOKE default PUBLIC grants before re-granting",
    );
}

#[test]
fn log_ingest_status_migration_declares_uuid_pk_and_columns() {
    assert!(M21_LOG_INGEST_STATUS.contains("CREATE TABLE log_ingest_status"));
    assert!(M21_LOG_INGEST_STATUS.contains("tenant_id      UUID PRIMARY KEY"));
    assert!(M21_LOG_INGEST_STATUS.contains("last_event_at  TIMESTAMPTZ"));
    assert!(M21_LOG_INGEST_STATUS.contains("event_count    BIGINT NOT NULL"));
    assert!(M21_LOG_INGEST_STATUS.contains("event_count >= 0"));
}

#[test]
fn log_ingest_status_migration_enables_rls() {
    assert!(M21_LOG_INGEST_STATUS.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M21_LOG_INGEST_STATUS.contains("FORCE ROW LEVEL SECURITY"));
    assert!(M21_LOG_INGEST_STATUS.contains("tenant_isolation_log_ingest_status"));
    assert!(M21_LOG_INGEST_STATUS.contains("tenant_id = app_current_tenant()"));
}

#[test]
fn ueba_baselines_migration_enables_rls_and_creates_policy() {
    assert!(M34_UEBA_BASELINES.contains("CREATE TABLE ueba_baselines"));
    assert!(M34_UEBA_BASELINES.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M34_UEBA_BASELINES.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M34_UEBA_BASELINES.contains("tenant_isolation_ueba_baselines"));
    assert!(M34_UEBA_BASELINES.contains("tenant_id = app_current_tenant()"));
}

#[test]
fn ueba_baselines_migration_declares_required_columns() {
    for col in [
        "tenant_id",
        "user_id",
        "login_hour_counts",
        "ip_prefixes",
        "accessed_assets",
        "updated_at",
    ] {
        assert!(
            M34_UEBA_BASELINES.contains(col),
            "ueba_baselines migration missing column {col}",
        );
    }
    // Composite primary key.
    assert!(M34_UEBA_BASELINES.contains("PRIMARY KEY (tenant_id, user_id)"));
    // 24-bucket cardinality CHECK.
    assert!(M34_UEBA_BASELINES.contains("array_length(login_hour_counts, 1) = 24"));
}

#[test]
fn ueba_anomalies_migration_enables_rls_and_creates_policy() {
    assert!(M35_UEBA_ANOMALIES.contains("CREATE TABLE ueba_anomalies"));
    assert!(M35_UEBA_ANOMALIES.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(M35_UEBA_ANOMALIES.contains("FORCE  ROW LEVEL SECURITY"));
    assert!(M35_UEBA_ANOMALIES.contains("tenant_isolation_ueba_anomalies"));
    assert!(M35_UEBA_ANOMALIES.contains("tenant_id = app_current_tenant()"));
}

#[test]
fn ueba_anomalies_migration_declares_required_columns_and_severity_check() {
    for col in [
        "id           UUID PRIMARY KEY",
        "tenant_id",
        "user_id",
        "event_id",
        "score        REAL",
        "dimensions   JSONB",
        "severity",
        "detected_at",
    ] {
        assert!(
            M35_UEBA_ANOMALIES.contains(col),
            "ueba_anomalies migration missing column {col}",
        );
    }
    for s in ["critical", "high", "medium", "low", "info"] {
        assert!(
            M35_UEBA_ANOMALIES.contains(&format!("'{s}'")),
            "ueba_anomalies severity CHECK must include {s}",
        );
    }
}
