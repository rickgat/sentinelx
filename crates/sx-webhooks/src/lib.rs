//! # sx-webhooks
//!
//! Signature-verified inbound webhook handling for `SentinelX`. Provides
//! per-provider modules ([`github`], [`slack`], [`jira`]) that share a
//! common [`common::WebhookEvent`] projection so downstream consumers can
//! treat all inbound events uniformly.
//!
//! ## Quality bar
//!
//! * `#![forbid(unsafe_code)]` — enforced via workspace lints.
//! * All signature verification uses constant-time comparison
//!   ([`subtle::ConstantTimeEq`]) — never `==` on raw bytes.
//! * `tracing` never logs the raw HTTP body, header bytes, or any portion
//!   of a signing key. Errors carry only structural categories
//!   ([`error::WebhookError`]), never sensitive material.
//! * Slack signatures honour a strict 5-minute replay window.
//!
//! This crate is intentionally *not* wired into any binary in this
//! workspace. It exposes building blocks ([`common::WebhookHandler`],
//! [`github::verify_and_parse`], …) so application code can mount these
//! into its own [`axum`] router.

#![doc(html_root_url = "https://docs.rs/sx-webhooks/0.1.0")]

pub mod common;
pub mod error;
pub mod github;
pub mod jira;
pub mod push;
pub mod signing;
pub mod slack;

pub use common::{WebhookEvent, WebhookHandler};
pub use error::WebhookError;
pub use push::{
    ApnsCredentials, DeviceId, DeviceRecord, DeviceRegistry, FcmCredentials, FindingSeverity,
    InMemoryAuditSink, InMemoryDeviceRegistry, InMemoryTenantPushCredentials, MobilePlatform,
    NewDeviceRegistration, PushAuditEvent, PushAuditSink, PushDispatcher, PushDispatcherConfig,
    PushError, PushFinding, RegistryEvent, TenantPushCredentials,
};
pub use signing::{
    InMemoryRotationAuditSink, InMemorySigningKeyStore, Kid, PlaintextCipher, RotationAuditEvent,
    RotationAuditSink, RotationError as SigningRotationError, RotationOutcome, RotationPolicy,
    SecretCipher, SignedPayload, SignerError, SigningKey, SigningKeyId, SigningKeyStore,
    StoreError as SigningStoreError, VerifierError, WebhookKeyRotator, WebhookSigner,
    WebhookVerifier, KID_HEADER, SIGNATURE_HEADER,
};
