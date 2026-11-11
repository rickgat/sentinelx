//! # `sx-secrets`
//!
//! `HashiCorp` Vault KV v2 client with TTL-cached reads for `SentinelX`.
//!
//! The crate is intentionally *standalone*: it does not wire itself into
//! `sx-monolith` yet. Instead it exposes a small, well-typed surface that
//! later rounds can plumb into the configuration / IAM pipelines:
//!
//! * [`provider::SecretsProvider`] — the async trait every backend
//!   implements. `get` returns a [`secrecy::SecretString`]; `put` stores
//!   one.
//! * [`provider::InMemoryProvider`] — process-local fixture for tests and
//!   ephemeral dev runs. Backed by a `tokio::sync::Mutex<HashMap>`.
//! * [`vault::VaultProvider`] — HTTP client for Vault's KV v2 secrets
//!   engine. Authentication is bearer-token via `X-Vault-Token`, never
//!   logged.
//! * [`cache::CachedProvider`] — decorator wrapping another provider with
//!   a `moka::future::Cache`. Reads are memoised for a configurable TTL
//!   (default 60s); writes invalidate the cached entry so the next read
//!   sees the new value.
//! * [`error::SecretsError`] — the error variants surfaced across all
//!   provider implementations.
//!
//! ## KV v2 endpoint mapping
//!
//! | Operation | HTTP        | Path                              | Body shape                |
//! |-----------|-------------|-----------------------------------|---------------------------|
//! | `get`     | `GET`       | `/v1/{mount}/data/{path}`         | `.data.data.value`        |
//! | `put`     | `POST`      | `/v1/{mount}/data/{path}`         | `{ "data": { "value": v } }` |
//!
//! ## Safety & observability
//!
//! * `#![forbid(unsafe_code)]`.
//! * The Vault token is wrapped in [`secrecy::SecretString`] and the
//!   custom `Debug` impl redacts it.
//! * Tracing emits only the *path*, *outcome*, and *duration* — never the
//!   token or the secret value.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cache;
pub mod dek;
pub mod dek_pg;
pub mod dek_rotation;
pub mod dek_rotation_pg;
pub mod envelope;
pub mod error;
pub mod kek;
pub mod kms;
pub mod provider;
pub mod rotation;
pub mod shred;
pub mod vault;

pub use crate::cache::CachedProvider;
pub use crate::dek::{DekManager, DekStore, InMemoryDekStore, RotationPolicy, StoredDek, TenantId};
pub use crate::dek_pg::PgDekStore;
pub use crate::dek_rotation::{
    audit_event_types as dek_rotation_audit_event_types, DekRotationAuditEvent,
    DekRotationAuditSink, DekRotationError, DekRotationJob, DekRotationScheduler,
    DekRotationSeverity, InMemoryDekRotationAuditSink, InMemoryRotationPolicyStore,
    InMemoryRotationProgressStore, ReencryptionVisitor, RotationCheckpoint,
    RotationConfig as DekRotationConfig, RotationJobStatus, RotationPolicyRow, RotationPolicyStore,
    RotationProgressStore, VisitorBatchOutcome, DEFAULT_CADENCE_DAYS,
    DEFAULT_DEK_ROTATION_BATCH_SIZE, DEFAULT_DEK_ROTATION_MAX_CONCURRENT,
    DEFAULT_DEK_ROTATION_SWEEP_INTERVAL, PCI_CADENCE_DAYS,
};
pub use crate::dek_rotation_pg::{PgRotationPolicyStore, PgRotationProgressStore};
pub use crate::envelope::EnvelopeKeyManager;
pub use crate::error::SecretsError;
pub use crate::kek::{EncryptionContext, KekError, KekProvider, NewKeyVersion, SecretVec};
pub use crate::kms::{Ciphertext, KeyVersion, KmsKeyProvider, VaultTransitKms, WrappedDek};
pub use crate::provider::{InMemoryProvider, SecretsProvider};
pub use crate::rotation::{
    AwsSecretsManagerApi, AwsSecretsManagerRotation, GcpAuthenticator, GcpSecretManagerRotation,
    GcpStaticToken, NewCredential, RotationError, RotationPolicy as CredentialRotationPolicy,
    RotationPort, VaultTransitRotation,
};
pub use crate::shred::crypto_erase_tenant;
pub use crate::vault::VaultProvider;
