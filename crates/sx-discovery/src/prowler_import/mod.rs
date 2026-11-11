//! Prowler v4 native-JSON import pipeline for GCP and Azure (P1-009).
//!
//! The CSPM [`scanner::cspm`](crate::scanner::cspm) shells out to Prowler
//! itself for AWS, parses OCSF, and emits per-finding `Observation`s. P1-009
//! covers the *import* of an **externally-produced** Prowler v4 native JSON
//! report — typically uploaded over HTTP — and persists deduplicated findings
//! into a per-tenant `cspm_findings_multicloud` table. The two paths share no
//! state; this module is a self-contained parser, normaliser and writer.
//!
//! ## Why a separate path?
//!
//! - The OCSF schema Prowler emits when invoked with `--output-formats
//!   json-ocsf` is lossy for multicloud-specific fields (GCP labels, Azure
//!   resource groups). Customers also commonly feed Prowler reports they
//!   generated themselves and want `SentinelX` to ingest the **native**
//!   schema verbatim.
//! - Large uploads (100 MB cap) need to be streamed and chunked through a
//!   background worker; that machinery is unrelated to the scanner trait.
//! - Importing a static file does not need credentials, rate limiting, scope
//!   validation or a kill switch — the safety surface is just bytes, JSON,
//!   tenant ID and audit logging.
//!
//! ## Architecture
//!
//! ```text
//!  POST /v1/discovery/prowler/import  (multipart, 100 MB max)
//!         │
//!         ▼
//!  controller::import_prowler (returns 202 in < 5 s)
//!         │
//!         ▼
//!  Background worker (chunked):
//!    ┌───────────────────────────────┐
//!    │ parser::parse_prowler_v4_json │
//!    └────────────┬──────────────────┘
//!                 ▼
//!    ┌────────────────────────────────┐
//!    │ resource::build_resource_id    │   (ARN-equivalent)
//!    └────────────┬───────────────────┘
//!                 ▼
//!    ┌────────────────────────────────┐
//!    │ registry::map_check_id         │   (prowler → sx check_id)
//!    └────────────┬───────────────────┘
//!                 ▼
//!    ┌────────────────────────────────┐
//!    │ kev::uplift_severity           │   (KEV match ⇒ uplift)
//!    └────────────┬───────────────────┘
//!                 ▼
//!    ┌────────────────────────────────┐
//!    │ dedupe by (tenant, asset, cid) │
//!    └────────────┬───────────────────┘
//!                 ▼
//!    ┌────────────────────────────────┐
//!    │ MulticloudFindingSink::write   │   (per-tenant table)
//!    └────────────────────────────────┘
//! ```
//!
//! ## Multi-tenancy
//!
//! Every public entry point takes a `TenantId`. The dedupe key is
//! `(tenant_id, asset_id, check_id)` so two tenants reporting the same
//! `(asset, check_id)` are stored independently. The
//! [`importer::ImportProwlerUseCase`] rejects any finding whose embedded
//! provider account / project / subscription is not registered for the
//! caller's tenant, surfacing the rejection as
//! [`error::ProwlerImportError::CrossTenant`].
//!
//! ## Audit
//!
//! Each successful import emits one [`audit::ProwlerImportAuditEvent`] via
//! the configured [`audit::AuditSink`]. The event records the actor,
//! tenant, file checksum, finding counts and rejected-finding counts.

pub mod audit;
pub mod dedupe;
pub mod error;
pub mod importer;
pub mod kev;
pub mod model;
pub mod parser;
pub mod registry;
pub mod resource;

pub use audit::{AuditSink, NullAuditSink, ProwlerImportAuditEvent, RecordingAuditSink};
pub use dedupe::{DedupeKey, Deduplicator};
pub use error::ProwlerImportError;
pub use importer::{
    ImportProwlerInput, ImportProwlerOutput, ImportProwlerUseCase, InMemoryMulticloudSink,
    MulticloudFindingSink, TenantCloudRegistry,
};
pub use kev::{KevCatalog, NullKevCatalog};
pub use model::{CloudProvider, MulticloudCspmFinding, ProwlerFinding, ProwlerStatus, Severity};
pub use parser::parse_prowler_v4_json;
pub use registry::{CheckIdRegistry, MappedCheck};
pub use resource::{build_resource_id, ResourceIdParts};
