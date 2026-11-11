//! View layer — response DTOs and the standard JSON envelope.
//!
//! Views are the **only** types the API crate hands to `serde_json` for
//! serialisation. Domain entities never appear on the wire; instead they
//! are projected into a `View` first. This keeps the public schema
//! decoupled from internal storage shape.

pub mod admin_view;
pub mod ai_audit_view;
pub mod api_dast_view;
pub mod asset_view;
pub mod audit_anchor_view;
pub mod audit_view;
pub mod auth_view;
pub mod autonomy_view;
pub mod bas_view;
pub mod blast_radius_view;
pub mod branding_view;
pub mod bugbounty_view;
pub mod cloud_drift_view;
pub mod cloud_view;
pub mod collab_view;
pub mod compliance_evidence_view;
pub mod compliance_view;
pub mod comprehensive_report_view;
pub mod copilot_approval_view;
pub mod copilot_view;
pub mod customer_auth_view;
pub mod device_trust_view;
pub mod dlp_view;
pub mod engagement_view;
pub mod envelope;
pub mod finding_view;
pub mod graph_view;
pub mod grc_view;
pub mod hunt_view;
pub mod intel_view;
pub mod ir_view;
pub mod k8s_admission_view;
pub mod log_ingest_view;
pub mod mfa_view;
pub mod ml_view;
pub mod oidc_client_view;
pub mod pagination;
pub mod pentest_view;
pub mod plugins_view;
pub mod predictive_view;
pub mod prowler_import_view;
pub mod rba_view;
pub mod redteam_view;
pub mod remediation_outcomes_view;
pub mod remediation_view;
pub mod report_schedule_view;
pub mod report_view;
pub mod risk_tuning_view;
pub mod risk_view;
pub mod roles_view;
pub mod runtime_view;
pub mod saml_view;
pub mod scan_view;
pub mod scim_view;
pub mod secrets_admin_view;
pub mod soar_view;
pub mod soc_view;
pub mod tenant_view;
pub mod twin_view;
pub mod ueba_admin_view;
pub mod ueba_view;
pub mod vuln_ingest_view;
pub mod webauthn_view;
pub mod webhooks_admin_view;
