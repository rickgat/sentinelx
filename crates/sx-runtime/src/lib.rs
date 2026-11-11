//! # `sx-runtime` — container-runtime security (Falco integration)
//!
//! Implements **P2-016** of the security-gap remediation plan. The crate
//! consumes [Falco](https://falco.org) runtime-security alerts over an HTTP
//! webhook, normalises each alert to the canonical OCSF event model from
//! [`sx_log_ingest::schema::ocsf`], and emits one [`RuntimeFinding`] per
//! alert for downstream correlation.
//!
//! ## Layout
//!
//! - [`alert`] — Falco wire shape ([`alert::FalcoAlert`]) and the family of
//!   priorities we map onto `SentinelX` severities.
//! - [`finding`] — [`finding::RuntimeFinding`] DTO emitted to the SOC
//!   pipeline plus the deterministic severity mapping.
//! - [`normalize`] — pure projection of a Falco alert onto an
//!   [`sx_log_ingest::schema::ocsf::OcsfEvent`] (Process Activity / Application
//!   Activity, classes `1007`/`6002`).
//! - [`asset`] — best-effort K8s asset-id resolution from
//!   `container.image` + `k8s.pod.name`.
//! - [`auth`] — per-tenant HMAC-SHA256 webhook authentication, replay-window
//!   bounded, constant-time comparison.
//! - [`tenant_key`] — [`tenant_key::TenantKeyStore`] backed by an
//!   `sx_secrets::SecretsProvider` for the per-tenant ingestion key.
//! - [`audit`] — minimal audit-row sink so each ingestion batch is recorded
//!   independently of which storage layer is wired in by the composition
//!   root.
//! - [`service`] — the [`service::FalcoIngestService`] facade that wires
//!   the pieces together for HTTP handlers.
//! - [`http`] — an opinionated [`axum`] router exposing
//!   `POST /v1/runtime/falco/alerts` so embedders can mount the route
//!   without re-implementing extractor glue.
//!
//! ## Security posture
//!
//! - `#![forbid(unsafe_code)]` — workspace lints enforce no `unsafe`.
//! - All HMAC comparisons go through [`subtle::ConstantTimeEq`].
//! - The signing key is wrapped in [`secrecy::SecretString`] and never
//!   logged; tracing fields are restricted to `tenant_id`, rule, and outcome.
//! - The ingestion pipeline is per-tenant: the [`auth::WebhookAuth`]
//!   extractor pulls the tenant-id from a non-sensitive header and resolves
//!   the signing key via [`tenant_key::TenantKeyStore`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod alert;
pub mod asset;
pub mod audit;
pub mod auth;
pub mod error;
pub mod finding;
pub mod http;
pub mod normalize;
pub mod override_audit;
pub mod override_store;
pub mod overrides;
pub mod service;
pub mod tenant_key;

pub use crate::alert::{FalcoAlert, FalcoPriority};
pub use crate::asset::{resolve_asset_id, AssetHint};
pub use crate::audit::{
    AuditOutcome, IngestionAuditEvent, IngestionAuditSink, NullAuditSink, RecordingAuditSink,
};
pub use crate::auth::{
    verify_hmac, RUNTIME_REPLAY_WINDOW_SECS, SIGNATURE_HEADER, TENANT_HEADER, TIMESTAMP_HEADER,
};
pub use crate::error::RuntimeError;
pub use crate::finding::{RuntimeFinding, RuntimeSeverity};
pub use crate::normalize::falco_to_ocsf;
pub use crate::override_audit::{
    NullOverrideAuditSink, OverrideAuditEvent, OverrideAuditKind, OverrideAuditSink,
    RecordingOverrideAuditSink,
};
pub use crate::override_store::{MemOverrideStore, OverrideStore};
pub use crate::overrides::{
    alert_subkey, evaluate as evaluate_override, OverrideAction, OverrideDecision, RuleOverride,
    SUBKEY_WILDCARD,
};
pub use crate::service::{FalcoIngestService, IngestionReport};
pub use crate::tenant_key::{TenantKeyStore, FALCO_KEY_VAULT_PREFIX};
