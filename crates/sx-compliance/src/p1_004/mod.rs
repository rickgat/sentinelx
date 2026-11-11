//! P1-004 — Automated compliance evidence collector (multi-tenant).
//!
//! This module is the production slice of the spec at
//! `docs/SECURITY_GAP_REMEDIATION_TASKS.md#p1-004`. It exists side-by-side
//! with the legacy `evidence::` filesystem collectors (kept for the
//! `sx-cli evidence ship` flow) and the trait-based
//! [`crate::collector::EvidenceCollector`] framework — both of which are
//! complementary, not competitors.
//!
//! ## What's here
//!
//! - [`control`] — `ControlId` newtype + the canonical built-in catalogue
//!   (`SX-MFA-ENROLLMENT-RATE`, `SX-AWS-IAM-PASSWORD-POLICY`,
//!   `SX-VAULT-SEALED-STATE`, `SX-KILL-SWITCH-TESTED-RECENTLY`,
//!   `SX-AUDIT-CHAIN-INTEGRITY-VERIFY`).
//! - [`collector`] — the trait every concrete collector implements
//!   (`EvidenceCollector { id() -> ControlId; collect() -> Evidence }`)
//!   plus the five built-in implementations.
//! - [`schedule`] — per-control cron-style cadence (default Weekly).
//! - [`store`] — Postgres-shaped repository traits + an in-memory
//!   reference implementation used by both the unit-test suite and the
//!   `tenant_isolation` integration test.
//! - [`worm`] — S3 Object-Lock semantics: an `EvidenceObjectStore`
//!   trait that *refuses to overwrite* existing keys, plus the
//!   in-memory implementation that backs the tests. The production
//!   wiring (an S3 adapter on top of `aws-sdk-s3`) lives downstream in
//!   `sx-monolith` and binds to this trait.
//! - [`bundle`] — ZIP exporter (`manifest.json` + HMAC-SHA256-signed
//!   per-file hashes) using a STORE-only ZIP writer so the output is
//!   byte-deterministic for snapshot tests.
//! - [`service`] — the application-level `EvidenceCollectionService`
//!   that ties the pieces together: run collectors, persist run + files,
//!   emit audit events, never cross tenant boundaries.
//! - [`api`] — DTOs the gateway (sx-api) re-exports for the three
//!   endpoints (`POST /v1/compliance/evidence/collect`,
//!   `GET /v1/compliance/evidence/bundles`,
//!   `GET /v1/compliance/evidence/bundles/{id}/download`).
//!
//! ## Multi-tenant invariants
//!
//! Every type that touches a row, a key, or a bundle is parameterised on
//! a `TenantId`. The repository traits **must** filter by `tenant_id` on
//! every read; the WORM store keys are prefixed by tenant; the bundle
//! signer pulls its HMAC key from `sx-secrets` per-tenant. Cross-tenant
//! reads are rejected explicitly — see `tests/p1_004_tenant_isolation.rs`.
//!
//! ## WORM correctness
//!
//! `EvidenceObjectStore::put_immutable` refuses to overwrite any key
//! that already exists. The default production adapter must set the
//! S3 Object Lock retention to **Compliance mode, 7-year retention** at
//! upload time. The in-memory adapter mirrors the no-overwrite
//! semantics so tests catch any code path that would clobber prior
//! evidence.

pub mod api;
pub mod bundle;
pub mod collector;
pub mod control;
pub mod schedule;
pub mod service;
pub mod store;
pub mod worm;

pub use api::{
    BundleSummary, CollectEvidenceRequest, CollectEvidenceResponse, DownloadBundleResponse,
    ListBundlesResponse,
};
pub use bundle::{build_bundle, BundleError, BundleManifest, ManifestFileEntry};
pub use collector::{
    AuditChainVerifyCollector, ChainVerifyOutcome, ChainVerifyProbe,
    EvidenceCollector as P1004Collector, IamPasswordPolicy, IamPasswordPolicyCollector,
    IamPasswordPolicyFetcher, KillSwitchEventReader, KillSwitchRecentCollector,
    MfaEnrollmentCollector, MfaEnrollmentQuery, MfaEnrollmentStats, P1004CollectError,
    VaultSealStatus, VaultSealedStateCollector, VaultStatusProbe,
};
pub use control::{builtin_controls, ControlId, ControlMeta, FrameworkLabel};
pub use schedule::{ControlSchedule, ScheduleKind};
pub use service::{AuditSink, EvidenceCollectionService, ServiceError, TenantHmacKeyProvider};
pub use store::{
    EvidenceFileRow, EvidenceRunRow, EvidenceRunStatus, EvidenceStore, InMemoryEvidenceStore,
    StoreError, TenantId,
};
pub use worm::{InMemoryWormStore, ObjectStoreError, WormStore};

/// Crate-internal "default" retention window for WORM evidence
/// uploads, expressed in **days** so the constant is auditor-readable.
/// 7 calendar years; leap years are inclusive of the safe-side rounding.
pub const WORM_RETENTION_DAYS: i64 = 365 * 7 + 2;
