//! Per-tenant outbound webhook HMAC signing-key rotation (MED-003).
//!
//! ## Pieces
//!
//! - [`key::SigningKey`] / [`key::Kid`] — opaque kid + secret pair.
//! - [`store::SigningKeyStore`] — persistence port; in-memory +
//!   Postgres impls. Signers and verifiers depend on the trait, not
//!   the concrete store.
//! - [`signer::WebhookSigner`] — computes HMAC-SHA256 over the raw
//!   request body and stamps the `X-SentinelX-Kid` + signature
//!   headers.
//! - [`verifier::WebhookVerifier`] — accepts every kid whose row is
//!   still valid at request time. Constant-time comparison.
//! - [`rotator::WebhookKeyRotator`] — mints + retires keys per the
//!   per-tenant policy; both an admin-driven `force_rotate` and the
//!   background-loop path land here.
//! - [`audit::AuditSink`] — local sink trait emitted on every
//!   rotation event. Wired to `sx-audit` at the composition root.
//!
//! ## Encryption
//!
//! Stored secrets are envelope-encrypted via a
//! [`secret_cipher::SecretCipher`] trait. The default
//! [`secret_cipher::PlaintextCipher`] is a no-op for tests; production
//! deployments inject an adapter that delegates to
//! `sx_secrets::EnvelopeKeyManager` (the same KMS-backed envelope used
//! for DEK rotation).

pub mod audit;
pub mod key;
pub mod rotator;
pub mod secret_cipher;
pub mod signer;
pub mod store;
pub mod verifier;

pub use audit::{InMemoryRotationAuditSink, RotationAuditEvent, RotationAuditSink};
pub use key::{Kid, SigningKey, SigningKeyId, KID_HEADER, SIGNATURE_HEADER};
pub use rotator::{RotationError, RotationOutcome, RotationPolicy, WebhookKeyRotator};
pub use secret_cipher::{PlaintextCipher, SecretCipher};
pub use signer::{SignedPayload, SignerError, WebhookSigner};
pub use store::{InMemorySigningKeyStore, SigningKeyStore, StoreError};
pub use verifier::{VerifierError, WebhookVerifier};
