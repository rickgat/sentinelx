//! KMS (Key Management Service) abstraction layer for envelope encryption.
//!
//! This module provides a provider-agnostic interface for key management
//! operations used by `SentinelX`'s envelope-encryption pipeline:
//!
//! * [`provider::KmsKeyProvider`] — the async trait every backend
//!   implements (Vault Transit today; AWS KMS / GCP KMS planned).
//! * [`vault_transit::VaultTransitKms`] — HTTP client for Vault's Transit
//!   secret engine.
//!
//! ## Envelope encryption model
//!
//! Each tenant has a *Data Encryption Key* (DEK) wrapped (encrypted) by a
//! tenant-scoped *Key Encryption Key* (KEK) that lives inside the KMS and
//! never leaves it. To encrypt a payload:
//!
//! 1. The KMS generates a fresh DEK (e.g. via `/datakey/plaintext/{name}`).
//! 2. The application encrypts the payload locally using the plaintext DEK.
//! 3. The plaintext DEK is discarded; the wrapped (ciphertext) DEK is
//!    stored alongside the payload.
//!
//! To decrypt, the application asks the KMS to unwrap the DEK, performs
//! local decryption, and discards the plaintext DEK again.
//!
//! This module owns only the KMS-facing portion; see [`crate::dek`] for the
//! per-tenant DEK lifecycle and [`crate::shred`] for crypto-erase.

pub mod provider;
pub mod vault_transit;

pub use provider::{Ciphertext, KeyVersion, KmsKeyProvider, WrappedDek};
pub use vault_transit::VaultTransitKms;
