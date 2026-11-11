//! External audit-chain anchoring runs (P1-015).
//!
//! Sits on top of [`crate::anchor_external`] (the low-level RFC 3161
//! transport) and the per-tenant hash chain in [`crate::chain`]. The
//! orchestration logic in this module:
//!
//! 1. Collects the window of chain hashes for one tenant.
//! 2. Computes the Merkle root via [`crate::anchor_external::MerkleTreeBuilder`].
//! 3. Hands the root to a [`TsaAnchorClient`](crate::anchor_external::TsaAnchorClient)
//!    (typically [`crate::anchor_external::FreeTsaClient`]) to obtain a
//!    signed TSA reply.
//! 4. Verifies the TSA reply signature against a *pinned per-tenant CA
//!    certificate* using [`TsaTokenVerifier`].
//! 5. Persists one [`AuditAnchorRun`] row through an
//!    [`AnchorRunRepository`] (per-tenant `audit_anchor_runs` table).
//! 6. On verification failure emits a CRITICAL audit event via a
//!    [`CriticalEventSink`].
//!
//! # TSA reply format (`SentinelX` RFC 3161 token wrapper)
//!
//! Parsing a real CMS `SignedData` carrying a TSA `TSTInfo` payload is
//! an ASN.1-heavy exercise (RFC 5652, RFC 3161 §2.4.2). For the MVP
//! slice we accept a **deterministic, schema-versioned token** that
//! still exercises the full *cryptographic* verification path (RSA
//! signature over `SHA256(payload)` plus pinned-CA chain validation).
//! Production deployments swap in a full CMS parser via the
//! [`TsaTokenVerifier`] trait without touching the surrounding
//! orchestration code.
//!
//! The token bytes are a single JSON object (UTF-8) of shape:
//!
//! ```json
//! {
//!   "v": 1,
//!   "serial": "0x1234abcd",
//!   "gen_time": "2026-01-01T00:00:00Z",
//!   "merkle_root_hex": "<64-char hex>",
//!   "tsa_cert_pem": "-----BEGIN CERTIFICATE-----\n…",
//!   "ca_cert_signature_b64": "<base64 RSA-PKCS1-v1.5 SHA256 sig over tsa_cert_pem by CA>",
//!   "signature_b64": "<base64 RSA-PKCS1-v1.5 SHA256 sig over canonical_bytes by TSA>"
//! }
//! ```
//!
//! `tsa_cert_pem` carries the *TSA*'s public key as a PEM-encoded
//! `RsaPublicKey` (i.e. SPKI form). `ca_cert_signature_b64` is the
//! pinned CA cert's signature over the bytes of `tsa_cert_pem` — that
//! second hop is what binds the TSA cert to the operator-pinned root
//! of trust.
//!
//! The "canonical bytes" the inner `signature_b64` covers are the
//! concatenation `serial || gen_time || merkle_root` written with
//! pipe (`|`) separators, exactly the bytes [`canonical_payload`]
//! produces. Both the signer (fixtures, see `tests/anchor_run_tsa.rs`)
//! and the verifier compute these bytes the same way so the test fixtures
//! drive the production verifier byte-for-byte.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{error, instrument, warn};
use uuid::Uuid;

use sx_core::value_object::ids::TenantId;

use crate::anchor_external::{
    AnchorError, AnchorRequest, FreeTsaClient, MerkleTreeBuilder, TsaAnchorClient,
    TsaAnchorResponse, SHA256_LEN,
};

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Unique identifier of a single anchor run.
///
/// Wraps a UUID v4 minted at the moment the run is recorded. We keep
/// the newtype rather than expose `Uuid` directly so accidental misuse
/// (e.g. passing a `RunId` where a `TenantId` is expected) is a type
/// error at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AnchorRunId(pub Uuid);

impl AnchorRunId {
    /// Mint a fresh random run id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Inner UUID accessor.
    #[must_use]
    pub const fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for AnchorRunId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AnchorRunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for AnchorRunId {
    type Err = AnchorRunError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|e| AnchorRunError::Invalid(format!("invalid run id: {e}")))
    }
}

/// One row in the per-tenant `audit_anchor_runs` table (P1-015).
///
/// Columns map 1:1 to the spec:
///
/// | Column         | Field                               |
/// |----------------|--------------------------------------|
/// | `run_id`       | [`AuditAnchorRun::run_id`]          |
/// | `tenant_id`    | [`AuditAnchorRun::tenant_id`]       |
/// | `merkle_root`  | [`AuditAnchorRun::merkle_root`]     |
/// | `tsa_serial`   | [`AuditAnchorRun::tsa_serial`]      |
/// | `tsa_genTime`  | [`AuditAnchorRun::tsa_gen_time`]    |
/// | `anchored_at`  | [`AuditAnchorRun::anchored_at`]     |
/// | `payload_bytes`| [`AuditAnchorRun::payload_bytes`]   |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorRun {
    /// Unique id of this run.
    pub run_id: AnchorRunId,
    /// Tenant whose chain window this row anchors.
    pub tenant_id: TenantId,
    /// SHA-256 Merkle root over the window's chain hashes.
    #[serde(with = "hex_array_serde")]
    pub merkle_root: [u8; SHA256_LEN],
    /// TSA-issued serial number (hex string; opaque to callers).
    pub tsa_serial: String,
    /// `genTime` extracted from the TSA reply, in UTC.
    #[serde(with = "time::serde::rfc3339")]
    pub tsa_gen_time: OffsetDateTime,
    /// Wall-clock time the row was inserted, in UTC.
    #[serde(with = "time::serde::rfc3339")]
    pub anchored_at: OffsetDateTime,
    /// Raw TSA reply bytes (the verbatim `payload_bytes` blob).
    ///
    /// Stored on disk so the run can be re-verified at any future
    /// point without re-contacting the TSA. The HTTP surface MUST NOT
    /// expose the raw bytes (only the base64-encoded length); the
    /// verify endpoint loads them server-side.
    ///
    /// In a 2-of-3 quorum run (MED-002) this holds the first verified
    /// TSA's token (the "anchor leader") for backward compatibility
    /// with the legacy verify-run API. The full set of signatures
    /// lives on [`Self::quorum`] alongside the per-TSA verify status.
    #[serde(with = "bytes_b64_serde")]
    pub payload_bytes: Vec<u8>,
    /// Quorum sidecar (MED-002). `None` when the row was produced by
    /// the legacy single-TSA pipeline (or by a `quorum_required = 1`
    /// configuration that semantically collapses to first-wins). When
    /// `Some`, the variant carries all TSA signatures collected at
    /// anchor time + the quorum decision (which N-of-M verified).
    ///
    /// Persisted as a JSONB sidecar column in production storage; the
    /// in-memory adapter serialises through `serde_json` end-to-end.
    /// Omitted from the wire view via `skip_serializing_if` so legacy
    /// clients keep seeing the historic shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum: Option<crate::tsa_fallback::QuorumAnchorRecord>,
}

/// Errors produced by the anchor-run layer.
#[derive(Debug, Error)]
pub enum AnchorRunError {
    /// Caller supplied an empty input window — Merkle root would be
    /// vacuous and we refuse to anchor it.
    #[error("empty window: nothing to anchor")]
    EmptyWindow,

    /// Caller-supplied input was malformed.
    #[error("invalid input: {0}")]
    Invalid(String),

    /// Run id not found in the repository.
    #[error("anchor run not found")]
    NotFound,

    /// Cross-tenant access attempt — the looked-up row belongs to a
    /// different tenant than the caller's claims.
    #[error("forbidden: cross-tenant access denied")]
    Forbidden,

    /// Underlying TSA / Merkle / DER plumbing failure.
    #[error("anchor: {0}")]
    Anchor(#[from] AnchorError),

    /// TSA reply did not satisfy the pinned-CA verifier.
    #[error("tsa verification failed: {0}")]
    Verification(String),

    /// Repository / persistence error.
    #[error("repository: {0}")]
    Repository(String),
}

// ---------------------------------------------------------------------------
// TSA reply parsing + verification
// ---------------------------------------------------------------------------

/// Parsed shape of the `SentinelX` RFC 3161 token wrapper.
///
/// Described in the module-level docs. `Deserialize` is derived
/// directly from the JSON document — strict parsing (unknown fields
/// rejected) is intentional so accidental schema drift surfaces as a
/// verification failure rather than a silent dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TsaToken {
    /// Schema version. Only `1` is accepted today.
    pub v: u8,
    /// Hex-encoded TSA-issued serial (e.g. `"0x1234abcd"`).
    pub serial: String,
    /// TSA-reported `genTime` (RFC 3339).
    pub gen_time: String,
    /// Hex (lowercase) of the SHA-256 Merkle root the TSA timestamped.
    pub merkle_root_hex: String,
    /// PEM-encoded SPKI public key of the TSA's signing certificate.
    pub tsa_cert_pem: String,
    /// Base64 RSA-PKCS1-v1.5 SHA-256 signature by the pinned CA over
    /// the UTF-8 bytes of `tsa_cert_pem`.
    pub ca_cert_signature_b64: String,
    /// Base64 RSA-PKCS1-v1.5 SHA-256 signature by the TSA over
    /// [`canonical_payload`] bytes.
    pub signature_b64: String,
}

/// Canonical bytes the TSA signs and the verifier reproduces.
///
/// `serial`, `gen_time`, and `merkle_root_hex` are joined with `|`. The
/// format is identical in the test fixture and the verifier so byte-
/// for-byte equality is the only contract.
#[must_use]
pub fn canonical_payload(serial: &str, gen_time: &str, merkle_root_hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(serial.len() + gen_time.len() + merkle_root_hex.len() + 2);
    out.extend_from_slice(serial.as_bytes());
    out.push(b'|');
    out.extend_from_slice(gen_time.as_bytes());
    out.push(b'|');
    out.extend_from_slice(merkle_root_hex.as_bytes());
    out
}

/// Outcome of a successful [`TsaTokenVerifier::verify`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaVerification {
    /// Hex serial extracted from the token.
    pub serial: String,
    /// `genTime` parsed into UTC.
    pub gen_time: OffsetDateTime,
    /// Merkle root the TSA signed (echoed back from the token).
    pub merkle_root: [u8; SHA256_LEN],
}

/// Verifier port for the TSA reply.
///
/// Production deployments will swap in a real CMS `SignedData` parser
/// without touching the surrounding orchestration code.
pub trait TsaTokenVerifier: Send + Sync + std::fmt::Debug {
    /// Verify `payload_bytes` against `pinned_ca_cert_pem`.
    ///
    /// Returns the extracted serial / genTime / Merkle root so the
    /// caller can persist them on the `audit_anchor_runs` row.
    fn verify(
        &self,
        payload_bytes: &[u8],
        pinned_ca_cert_pem: &str,
    ) -> Result<TsaVerification, AnchorRunError>;
}

/// Reference verifier — parses the `SentinelX` RFC 3161 token wrapper
/// (see module docs) and performs the full RSA-PKCS1-v1.5 SHA-256
/// signature chain check:
///
/// 1. Deserialise the JSON token (rejects unknown fields).
/// 2. Verify the TSA cert was signed by the pinned CA cert (the
///    `ca_cert_signature_b64` field).
/// 3. Verify the TSA's signature over [`canonical_payload`] using the
///    TSA cert's public key (the `signature_b64` field).
///
/// Any tampering (wrong CA, swapped TSA cert, mutated payload) trips
/// step 2 or 3 and surfaces as [`AnchorRunError::Verification`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultTsaTokenVerifier;

impl TsaTokenVerifier for DefaultTsaTokenVerifier {
    fn verify(
        &self,
        payload_bytes: &[u8],
        pinned_ca_cert_pem: &str,
    ) -> Result<TsaVerification, AnchorRunError> {
        // 1. JSON parse (strict).
        let token: TsaToken = serde_json::from_slice(payload_bytes)
            .map_err(|e| AnchorRunError::Verification(format!("token parse: {e}")))?;
        if token.v != 1 {
            return Err(AnchorRunError::Verification(format!(
                "unsupported token version: {}",
                token.v,
            )));
        }

        // 2. Parse the pinned CA cert as an RSA public key (PEM SPKI).
        let ca_key = RsaPublicKey::from_public_key_pem(pinned_ca_cert_pem)
            .map_err(|e| AnchorRunError::Verification(format!("ca pem: {e}")))?;
        let ca_sig_bytes = B64
            .decode(token.ca_cert_signature_b64.as_bytes())
            .map_err(|e| AnchorRunError::Verification(format!("ca sig b64: {e}")))?;
        let ca_sig = Signature::try_from(ca_sig_bytes.as_slice())
            .map_err(|e| AnchorRunError::Verification(format!("ca sig parse: {e}")))?;
        let ca_verifier: VerifyingKey<Sha256> = VerifyingKey::new(ca_key);
        ca_verifier
            .verify(token.tsa_cert_pem.as_bytes(), &ca_sig)
            .map_err(|e| AnchorRunError::Verification(format!("ca verify: {e}")))?;

        // 3. Parse the TSA cert PEM as an RSA public key.
        let tsa_key = RsaPublicKey::from_public_key_pem(&token.tsa_cert_pem)
            .map_err(|e| AnchorRunError::Verification(format!("tsa pem: {e}")))?;
        let tsa_sig_bytes = B64
            .decode(token.signature_b64.as_bytes())
            .map_err(|e| AnchorRunError::Verification(format!("tsa sig b64: {e}")))?;
        let tsa_sig = Signature::try_from(tsa_sig_bytes.as_slice())
            .map_err(|e| AnchorRunError::Verification(format!("tsa sig parse: {e}")))?;
        let tsa_verifier: VerifyingKey<Sha256> = VerifyingKey::new(tsa_key);
        let canon = canonical_payload(&token.serial, &token.gen_time, &token.merkle_root_hex);
        tsa_verifier
            .verify(&canon, &tsa_sig)
            .map_err(|e| AnchorRunError::Verification(format!("tsa verify: {e}")))?;

        // 4. Parse out the structured fields.
        let gen_time = OffsetDateTime::parse(&token.gen_time, &Rfc3339)
            .map_err(|e| AnchorRunError::Verification(format!("gen_time parse: {e}")))?;
        let root_raw = hex::decode(&token.merkle_root_hex)
            .map_err(|e| AnchorRunError::Verification(format!("merkle root hex: {e}")))?;
        if root_raw.len() != SHA256_LEN {
            return Err(AnchorRunError::Verification(format!(
                "merkle root length: expected {SHA256_LEN}, got {}",
                root_raw.len(),
            )));
        }
        let mut merkle_root = [0u8; SHA256_LEN];
        merkle_root.copy_from_slice(&root_raw);
        Ok(TsaVerification {
            serial: token.serial,
            gen_time,
            merkle_root,
        })
    }
}

// ---------------------------------------------------------------------------
// JSON-wrapper TSA client
// ---------------------------------------------------------------------------

/// TSA client that speaks the `SentinelX` JSON wrapper documented at the
/// top of this module.
///
/// Wraps [`FreeTsaClient`] but interprets the response as the JSON
/// wrapper rather than a raw RFC 3161 `TimeStampResp`. This is the
/// client production deployments wire up while the full CMS parser is
/// still in development; it round-trips byte-for-byte against the
/// fixture in `tests/anchor_run_tsa.rs`.
///
/// The transport itself (request DER body, content-type headers, error
/// handling) is unchanged — only the response-body sanity check is
/// relaxed to accept any non-empty body. The actual signature
/// verification happens inside [`DefaultTsaTokenVerifier`].
#[derive(Debug, Clone)]
pub struct JsonTsaClient {
    inner: reqwest::Client,
    url: String,
    provider: String,
}

impl JsonTsaClient {
    /// New client targeting `url` with `DEFAULT_TIMEOUT` from
    /// [`FreeTsaClient`].
    pub fn new(url: impl Into<String>) -> Result<Self, AnchorError> {
        let url = url.into();
        let provider = url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("unknown")
            .to_owned();
        let inner = reqwest::Client::builder()
            .timeout(FreeTsaClient::DEFAULT_TIMEOUT)
            .build()
            .map_err(|e| AnchorError::Transport(e.to_string()))?;
        Ok(Self {
            inner,
            url,
            provider,
        })
    }

    /// Override the provider label.
    #[must_use]
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = provider.into();
        self
    }

    /// The TSA URL the client targets.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[async_trait]
impl TsaAnchorClient for JsonTsaClient {
    #[instrument(skip(self, req), fields(provider = %self.provider, tenant = %req.tenant_id))]
    async fn anchor(&self, req: &AnchorRequest) -> Result<TsaAnchorResponse, AnchorError> {
        let body = crate::anchor_external::tsa_der::encode_timestamp_request(&req.merkle_root);
        // Body bytes are intentionally NOT logged.
        let resp = self
            .inner
            .post(&self.url)
            .header(
                reqwest::header::CONTENT_TYPE,
                FreeTsaClient::CONTENT_TYPE_REQ,
            )
            .header(reqwest::header::ACCEPT, FreeTsaClient::CONTENT_TYPE_RESP)
            .body(body)
            .send()
            .await
            .map_err(|e| AnchorError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(AnchorError::Transport(format!(
                "tsa returned non-2xx status: {status}",
            )));
        }
        let token = resp
            .bytes()
            .await
            .map_err(|e| AnchorError::Transport(e.to_string()))?
            .to_vec();
        if token.is_empty() {
            return Err(AnchorError::InvalidResponse(
                "tsa response body was empty".to_owned(),
            ));
        }
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&token);
        Ok(TsaAnchorResponse {
            tsa_provider: self.provider.clone(),
            timestamp: OffsetDateTime::now_utc(),
            token,
            signature_b64,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository port
// ---------------------------------------------------------------------------

/// Per-tenant repository port for [`AuditAnchorRun`] rows.
///
/// The trait is intentionally narrow: insert, list, fetch-by-id. The
/// Postgres adapter lives in `sx-storage` and applies RLS on the
/// `audit_anchor_runs` table; the in-memory adapter in this module is
/// used by the monolith dev mode and by unit tests.
#[async_trait]
pub trait AnchorRunRepository: Send + Sync + std::fmt::Debug {
    /// Persist a new run row.
    async fn insert(&self, run: AuditAnchorRun) -> Result<(), AnchorRunError>;

    /// List the runs for `tenant_id`, newest first, capped at `limit`.
    async fn list_for_tenant(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<Vec<AuditAnchorRun>, AnchorRunError>;

    /// Fetch a single run by id, scoped to `tenant_id`. Returns
    /// [`AnchorRunError::NotFound`] if missing **and**
    /// [`AnchorRunError::Forbidden`] when the row exists but belongs
    /// to a different tenant (the test suite asserts both branches).
    async fn get_for_tenant(
        &self,
        tenant_id: &TenantId,
        run_id: &AnchorRunId,
    ) -> Result<AuditAnchorRun, AnchorRunError>;
}

/// In-memory repository — dev / test default. Keyed by `(tenant_id,
/// run_id)`; a single `Mutex<HashMap>` is enough for the volumes we
/// expect (one row per hour per tenant).
#[derive(Debug, Default)]
pub struct InMemoryAnchorRunRepository {
    inner: Mutex<HashMap<AnchorRunId, AuditAnchorRun>>,
}

impl InMemoryAnchorRunRepository {
    /// New empty repo.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AnchorRunRepository for InMemoryAnchorRunRepository {
    async fn insert(&self, run: AuditAnchorRun) -> Result<(), AnchorRunError> {
        {
            let mut g = self.inner.lock().await;
            g.insert(run.run_id, run);
        }
        Ok(())
    }

    async fn list_for_tenant(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<Vec<AuditAnchorRun>, AnchorRunError> {
        let mut rows: Vec<AuditAnchorRun> = {
            let g = self.inner.lock().await;
            g.values()
                .filter(|r| &r.tenant_id == tenant_id)
                .cloned()
                .collect()
        };
        // Newest first.
        rows.sort_by(|a, b| b.anchored_at.cmp(&a.anchored_at));
        rows.truncate(limit);
        Ok(rows)
    }

    async fn get_for_tenant(
        &self,
        tenant_id: &TenantId,
        run_id: &AnchorRunId,
    ) -> Result<AuditAnchorRun, AnchorRunError> {
        let row = {
            let g = self.inner.lock().await;
            g.get(run_id).cloned().ok_or(AnchorRunError::NotFound)?
        };
        if &row.tenant_id != tenant_id {
            return Err(AnchorRunError::Forbidden);
        }
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// Critical event sink
// ---------------------------------------------------------------------------

/// Sink for the CRITICAL `sx-audit` event emitted when verification of a
/// TSA reply fails (acceptance criterion: "Auto-failure if signature
/// invalid → emit `sx-audit` CRITICAL event").
///
/// Implementations forward to whatever audit channel the host process
/// uses (the in-process buffered sink, the SOC alert correlator, …).
/// A no-op default impl is provided for unit tests that only care
/// about the verification verdict.
#[async_trait]
pub trait CriticalEventSink: Send + Sync + std::fmt::Debug {
    /// Emit a CRITICAL event tagged `sx-audit`.
    async fn emit_critical(&self, tenant_id: &TenantId, message: &str);
}

/// No-op sink for tests where the surrounding code already asserts the
/// orchestration path was reached.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopCriticalEventSink;

#[async_trait]
impl CriticalEventSink for NoopCriticalEventSink {
    async fn emit_critical(&self, _tenant_id: &TenantId, _message: &str) {}
}

/// Recording sink — captures `(tenant_id, message)` pairs in a Vec so
/// tests can assert exactly which events fired. Wraps a `Mutex<Vec>`;
/// volumes are tiny.
#[derive(Debug, Default)]
pub struct RecordingCriticalEventSink {
    events: Mutex<Vec<(TenantId, String)>>,
}

impl RecordingCriticalEventSink {
    /// New empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the events recorded so far.
    pub async fn events(&self) -> Vec<(TenantId, String)> {
        self.events.lock().await.clone()
    }
}

#[async_trait]
impl CriticalEventSink for RecordingCriticalEventSink {
    async fn emit_critical(&self, tenant_id: &TenantId, message: &str) {
        self.events
            .lock()
            .await
            .push((*tenant_id, message.to_owned()));
    }
}

// ---------------------------------------------------------------------------
// Tenant configuration
// ---------------------------------------------------------------------------

/// Per-tenant configuration for the anchor runner.
///
/// `tsa_url` and `pinned_ca_cert_pem` live per-tenant so an operator
/// can opt one tenant into a higher-assurance TSA (e.g. an internal
/// HSM-backed one) without affecting any other. The default schedule
/// is 1 h (`DEFAULT_INTERVAL`).
#[derive(Debug, Clone)]
pub struct TenantAnchorConfig {
    /// Tenant the row applies to.
    pub tenant_id: TenantId,
    /// Fully-qualified TSA URL (`https://…`). Optional — when `None`
    /// the runner skips this tenant.
    pub tsa_url: Option<String>,
    /// Pinned PEM-encoded RSA public key of the CA the operator
    /// trusts to sign TSA certs for this tenant. Required when
    /// `tsa_url` is set.
    pub pinned_ca_cert_pem: Option<String>,
    /// How often the runner should anchor this tenant. Defaults to
    /// `DEFAULT_INTERVAL` (1 hour).
    pub interval: std::time::Duration,
}

impl TenantAnchorConfig {
    /// Default cadence — 1 hour, matching the spec.
    pub const DEFAULT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3_600);
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// Outcome of a single [`AnchorRunner::run_once`] invocation.
///
/// `Anchored` carries the inserted row id; `Skipped` carries a
/// human-readable reason (no window, no TSA URL configured, …). The
/// verification-failure path returns an `Err` instead so the caller
/// can surface it as a 5xx + CRITICAL event.
#[derive(Debug, Clone)]
pub enum RunOutcome {
    /// A new row was inserted into the `audit_anchor_runs` table.
    Anchored(AnchorRunId),
    /// Nothing to do this tick (empty window, no TSA configured, …).
    Skipped(String),
}

/// Orchestrator that turns a per-tenant chain-hash window into a
/// persisted anchor run.
///
/// All collaborators are trait-objects so the unit tests can substitute
/// in-memory implementations without touching wire protocols.
#[derive(Debug, Clone)]
pub struct AnchorRunner {
    /// TSA client (typically [`crate::anchor_external::FreeTsaClient`]).
    tsa_client: Arc<dyn TsaAnchorClient>,
    /// Verifier for the TSA reply.
    verifier: Arc<dyn TsaTokenVerifier>,
    /// Repository for [`AuditAnchorRun`] rows.
    repo: Arc<dyn AnchorRunRepository>,
    /// CRITICAL event sink invoked on verification failure.
    critical: Arc<dyn CriticalEventSink>,
}

impl AnchorRunner {
    /// Build a new orchestrator from its four collaborators.
    #[must_use]
    pub fn new(
        tsa_client: Arc<dyn TsaAnchorClient>,
        verifier: Arc<dyn TsaTokenVerifier>,
        repo: Arc<dyn AnchorRunRepository>,
        critical: Arc<dyn CriticalEventSink>,
    ) -> Self {
        Self {
            tsa_client,
            verifier,
            repo,
            critical,
        }
    }

    /// Borrowed access to the underlying repository — handy for the
    /// HTTP layer to share state.
    #[must_use]
    pub fn repo(&self) -> Arc<dyn AnchorRunRepository> {
        Arc::clone(&self.repo)
    }

    /// Run one anchoring tick for `cfg.tenant_id` over `chain_hashes`.
    ///
    /// The caller (typically the per-tenant scheduler tick) is
    /// responsible for fetching the chain-hash window from the audit
    /// log. We don't reach into the chain directly so this stays
    /// trivially testable.
    #[instrument(skip_all, fields(tenant = %cfg.tenant_id, leaves = chain_hashes.len()))]
    pub async fn run_once(
        &self,
        cfg: &TenantAnchorConfig,
        chain_hashes: &[[u8; SHA256_LEN]],
        window_start: OffsetDateTime,
        window_end: OffsetDateTime,
        audit_seqs: (u64, u64),
    ) -> Result<RunOutcome, AnchorRunError> {
        // Guard rails — empty window or no configured TSA.
        if chain_hashes.is_empty() {
            return Ok(RunOutcome::Skipped("empty window".to_owned()));
        }
        let Some(ref tsa_url) = cfg.tsa_url else {
            return Ok(RunOutcome::Skipped("no tsa configured".to_owned()));
        };
        let Some(ref pinned_ca_pem) = cfg.pinned_ca_cert_pem else {
            return Err(AnchorRunError::Invalid(
                "tsa configured without pinned ca cert".to_owned(),
            ));
        };
        // We log only the URL host; the chain hashes themselves are
        // intentionally not logged ("never log raw bytes of
        // TimeStampReq/Reply", per the engineering bar).
        tracing::debug!(tsa = %tsa_url, "anchor run beginning");

        // 1. Merkle root over the window.
        let builder = MerkleTreeBuilder::new();
        let merkle_root = builder.build(chain_hashes)?;

        // 2. Send to TSA, receive payload bytes.
        let req = AnchorRequest {
            tenant_id: cfg.tenant_id,
            window_start,
            window_end,
            merkle_root,
            audit_seqs,
        };
        let resp = self.tsa_client.anchor(&req).await?;
        let payload_bytes = resp.token.clone();

        // 3. Verify signature against pinned CA. On failure emit
        // CRITICAL and return an Err so the scheduler does NOT persist
        // a corrupted row.
        let verification = match self.verifier.verify(&payload_bytes, pinned_ca_pem) {
            Ok(v) => v,
            Err(err) => {
                error!(error = %err, "tsa reply failed verification");
                self.critical
                    .emit_critical(
                        &cfg.tenant_id,
                        &format!("tsa anchor verification failed: {err}"),
                    )
                    .await;
                return Err(err);
            }
        };

        // Sanity check: the Merkle root the TSA signed must match what
        // we sent. A mismatch is a verification failure (cf. tampered
        // token tests).
        if verification.merkle_root != merkle_root {
            warn!("tsa reply merkle root mismatch — verification failed");
            self.critical
                .emit_critical(
                    &cfg.tenant_id,
                    "tsa anchor verification failed: merkle root mismatch",
                )
                .await;
            return Err(AnchorRunError::Verification(
                "merkle root mismatch".to_owned(),
            ));
        }

        // 4. Persist.
        let run = AuditAnchorRun {
            run_id: AnchorRunId::new(),
            tenant_id: cfg.tenant_id,
            merkle_root,
            tsa_serial: verification.serial,
            tsa_gen_time: verification.gen_time,
            anchored_at: OffsetDateTime::now_utc(),
            payload_bytes,
            // Legacy single-TSA path: no quorum sidecar (MED-002).
            quorum: None,
        };
        let run_id = run.run_id;
        self.repo.insert(run).await?;
        Ok(RunOutcome::Anchored(run_id))
    }

    /// MED-002 — Re-verify a persisted quorum anchor row.
    ///
    /// Walks every TSA signature stored on
    /// [`AuditAnchorRun::quorum`], re-runs the verifier against the
    /// caller-supplied per-TSA CA resolver, and returns a fresh
    /// [`crate::tsa_fallback::QuorumAnchorRecord`] reflecting which
    /// signatures still verify. If fewer than the record's `required`
    /// still verify, the method emits a CRITICAL audit event and
    /// surfaces an [`AnchorRunError::Verification`]. Otherwise the
    /// record's `meets_quorum()` returns true and the row remains
    /// trustworthy.
    ///
    /// Backward compatibility: when the row has `quorum == None`
    /// (legacy single-TSA pipeline) this method falls back to the
    /// classic [`Self::verify_run`] path and synthesises a 1-of-1
    /// record so callers see a unified shape.
    #[instrument(skip_all, fields(tenant = %tenant_id, run = %run_id))]
    pub async fn verify_run_quorum(
        &self,
        tenant_id: &TenantId,
        run_id: &AnchorRunId,
        ca_for: &(dyn Fn(&str) -> Option<String> + Send + Sync),
    ) -> Result<crate::tsa_fallback::QuorumAnchorRecord, AnchorRunError> {
        use crate::tsa_fallback::{
            audit_event, QuorumAnchorRecord, QuorumSignatureStatus, QuorumTsaSignature,
        };

        let row = self.repo.get_for_tenant(tenant_id, run_id).await?;
        let Some(existing) = row.quorum.as_ref() else {
            // Legacy 1-of-1 row — delegated to a helper for clippy
            // line-count hygiene.
            return self.verify_run_quorum_legacy(tenant_id, &row, ca_for).await;
        };

        // Quorum row — re-verify every signature slot.
        let mut updated: Vec<QuorumTsaSignature> = Vec::with_capacity(existing.signatures.len());
        let mut verified_count: usize = 0;
        let mut failure_reasons: Vec<String> = Vec::new();
        for sig in &existing.signatures {
            let label = sig.label.clone();
            if matches!(sig.status, QuorumSignatureStatus::NotAttempted) || sig.token.is_empty() {
                // Preserve as-is; nothing to re-verify.
                updated.push(QuorumTsaSignature {
                    status: QuorumSignatureStatus::NotAttempted,
                    ..sig.clone()
                });
                continue;
            }
            let Some(pinned) = ca_for(&label) else {
                failure_reasons.push(format!("{label}: no pinned CA configured"));
                updated.push(QuorumTsaSignature {
                    label,
                    tsa_serial: sig.tsa_serial.clone(),
                    tsa_gen_time: sig.tsa_gen_time,
                    token: sig.token.clone(),
                    status: QuorumSignatureStatus::Failed,
                    reason: Some("no pinned CA configured".to_owned()),
                });
                continue;
            };
            match self.verifier.verify(&sig.token, &pinned) {
                Ok(v) if v.merkle_root == row.merkle_root => {
                    verified_count = verified_count.saturating_add(1);
                    updated.push(QuorumTsaSignature {
                        label,
                        tsa_serial: v.serial,
                        tsa_gen_time: v.gen_time,
                        token: sig.token.clone(),
                        status: QuorumSignatureStatus::Verified,
                        reason: None,
                    });
                }
                Ok(_) => {
                    failure_reasons.push(format!("{label}: merkle root mismatch"));
                    updated.push(QuorumTsaSignature {
                        label,
                        tsa_serial: sig.tsa_serial.clone(),
                        tsa_gen_time: sig.tsa_gen_time,
                        token: sig.token.clone(),
                        status: QuorumSignatureStatus::Failed,
                        reason: Some("merkle root mismatch".to_owned()),
                    });
                }
                Err(err) => {
                    let msg = err.to_string();
                    failure_reasons.push(format!("{label}: {msg}"));
                    updated.push(QuorumTsaSignature {
                        label,
                        tsa_serial: sig.tsa_serial.clone(),
                        tsa_gen_time: sig.tsa_gen_time,
                        token: sig.token.clone(),
                        status: QuorumSignatureStatus::Failed,
                        reason: Some(msg),
                    });
                }
            }
        }

        let required = existing.required as usize;
        if verified_count < required {
            self.critical
                .emit_critical(
                    tenant_id,
                    &format!(
                        "{}: verified={verified_count}/{required} reasons=[{}]",
                        audit_event::ANCHOR_QUORUM_VERIFY_SHORTFALL,
                        failure_reasons.join("; "),
                    ),
                )
                .await;
            return Err(AnchorRunError::Verification(format!(
                "quorum verify shortfall: verified={verified_count}/{required}"
            )));
        }
        Ok(QuorumAnchorRecord {
            required: existing.required,
            total: existing.total,
            signatures: updated,
            leader_label: existing.leader_label.clone(),
        })
    }

    /// Helper for [`Self::verify_run_quorum`] when the row was produced
    /// by the legacy single-TSA pipeline (`quorum == None`). Synthesises
    /// a 1-of-1 [`crate::tsa_fallback::QuorumAnchorRecord`] so callers
    /// see a uniform shape regardless of which path persisted the row.
    async fn verify_run_quorum_legacy(
        &self,
        tenant_id: &TenantId,
        row: &AuditAnchorRun,
        ca_for: &(dyn Fn(&str) -> Option<String> + Send + Sync),
    ) -> Result<crate::tsa_fallback::QuorumAnchorRecord, AnchorRunError> {
        use crate::tsa_fallback::{QuorumAnchorRecord, QuorumSignatureStatus, QuorumTsaSignature};

        let label = "legacy".to_owned();
        let Some(pinned) = ca_for(&label).or_else(|| ca_for("primary")) else {
            return Err(AnchorRunError::Verification(
                "verify_run_quorum: no pinned CA for legacy row".to_owned(),
            ));
        };
        match self.verifier.verify(&row.payload_bytes, &pinned) {
            Ok(v) if v.merkle_root == row.merkle_root => Ok(QuorumAnchorRecord {
                required: 1,
                total: 1,
                signatures: vec![QuorumTsaSignature {
                    label,
                    tsa_serial: v.serial,
                    tsa_gen_time: v.gen_time,
                    token: row.payload_bytes.clone(),
                    status: QuorumSignatureStatus::Verified,
                    reason: None,
                }],
                leader_label: "legacy".to_owned(),
            }),
            Ok(_) => {
                self.critical
                    .emit_critical(
                        tenant_id,
                        "tsa anchor re-verification failed: merkle root mismatch",
                    )
                    .await;
                Err(AnchorRunError::Verification(
                    "merkle root mismatch on re-verify".to_owned(),
                ))
            }
            Err(err) => {
                self.critical
                    .emit_critical(
                        tenant_id,
                        &format!("tsa anchor re-verification failed: {err}"),
                    )
                    .await;
                Err(err)
            }
        }
    }

    /// Re-verify a persisted run on demand — backs the
    /// `POST /v1/audit/anchors/verify/{run_id}` endpoint.
    ///
    /// Returns the verification details on success. On failure emits a
    /// CRITICAL event (the row's signature is no longer trustworthy)
    /// and surfaces the verifier error.
    #[instrument(skip_all, fields(tenant = %tenant_id, run = %run_id))]
    pub async fn verify_run(
        &self,
        tenant_id: &TenantId,
        run_id: &AnchorRunId,
        pinned_ca_cert_pem: &str,
    ) -> Result<TsaVerification, AnchorRunError> {
        let row = self.repo.get_for_tenant(tenant_id, run_id).await?;
        match self.verifier.verify(&row.payload_bytes, pinned_ca_cert_pem) {
            Ok(v) if v.merkle_root == row.merkle_root => Ok(v),
            Ok(_) => {
                self.critical
                    .emit_critical(
                        tenant_id,
                        "tsa anchor re-verification failed: merkle root mismatch",
                    )
                    .await;
                Err(AnchorRunError::Verification(
                    "merkle root mismatch on re-verify".to_owned(),
                ))
            }
            Err(err) => {
                self.critical
                    .emit_critical(
                        tenant_id,
                        &format!("tsa anchor re-verification failed: {err}"),
                    )
                    .await;
                Err(err)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serde helpers
// ---------------------------------------------------------------------------

/// Hex (de)serializer for the fixed-length `[u8; SHA256_LEN]` field on
/// [`AuditAnchorRun::merkle_root`].
mod hex_array_serde {
    use super::SHA256_LEN;
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; SHA256_LEN],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<[u8; SHA256_LEN], D::Error> {
        let s = String::deserialize(de)?;
        let raw = hex::decode(&s).map_err(D::Error::custom)?;
        if raw.len() != SHA256_LEN {
            return Err(D::Error::custom(format!(
                "expected {SHA256_LEN}-byte hex, got {} bytes",
                raw.len()
            )));
        }
        let mut out = [0u8; SHA256_LEN];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

/// Base64 (de)serializer for the variable-length `Vec<u8>` payload
/// field on [`AuditAnchorRun::payload_bytes`].
mod bytes_b64_serde {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&B64.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        B64.decode(s.as_bytes()).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]
mod tests {
    use super::*;

    fn tenant(n: u128) -> TenantId {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&n.to_be_bytes());
        bytes[6] = (bytes[6] & 0x0F) | 0x70;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        Uuid::from_bytes(bytes).into()
    }

    #[test]
    fn canonical_payload_is_pipe_joined_utf8() {
        let bytes = canonical_payload("0x01", "2026-01-01T00:00:00Z", "abcdef");
        assert_eq!(bytes, b"0x01|2026-01-01T00:00:00Z|abcdef".to_vec());
    }

    #[test]
    fn anchor_run_id_round_trips_via_string() {
        let id = AnchorRunId::new();
        let s = id.to_string();
        let parsed: AnchorRunId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn anchor_run_id_rejects_garbage() {
        let r: Result<AnchorRunId, _> = "not-a-uuid".parse();
        assert!(matches!(r, Err(AnchorRunError::Invalid(_))));
    }

    #[tokio::test]
    async fn in_memory_repo_round_trips_a_row() {
        let repo = InMemoryAnchorRunRepository::new();
        let t = tenant(1);
        let run = AuditAnchorRun {
            run_id: AnchorRunId::new(),
            tenant_id: t,
            merkle_root: [0x11; SHA256_LEN],
            tsa_serial: "0xdead".into(),
            tsa_gen_time: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            anchored_at: OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap(),
            payload_bytes: vec![1, 2, 3],
            quorum: None,
        };
        let id = run.run_id;
        repo.insert(run.clone()).await.unwrap();
        let got = repo.get_for_tenant(&t, &id).await.unwrap();
        assert_eq!(got, run);
        let listed = repo.list_for_tenant(&t, 10).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].run_id, id);
    }

    #[tokio::test]
    async fn in_memory_repo_rejects_cross_tenant_lookup() {
        let repo = InMemoryAnchorRunRepository::new();
        let t1 = tenant(1);
        let t2 = tenant(2);
        let run = AuditAnchorRun {
            run_id: AnchorRunId::new(),
            tenant_id: t1,
            merkle_root: [0x22; SHA256_LEN],
            tsa_serial: "0xbeef".into(),
            tsa_gen_time: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            anchored_at: OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap(),
            payload_bytes: vec![],
            quorum: None,
        };
        let id = run.run_id;
        repo.insert(run).await.unwrap();
        // Existing id, wrong tenant — must surface as Forbidden, NOT
        // NotFound (the API distinguishes the two for telemetry).
        let err = repo.get_for_tenant(&t2, &id).await.unwrap_err();
        assert!(matches!(err, AnchorRunError::Forbidden));
        // Missing id, any tenant — NotFound.
        let other = AnchorRunId::new();
        let err = repo.get_for_tenant(&t1, &other).await.unwrap_err();
        assert!(matches!(err, AnchorRunError::NotFound));
    }

    #[tokio::test]
    async fn in_memory_repo_list_returns_newest_first_and_caps_at_limit() {
        let repo = InMemoryAnchorRunRepository::new();
        let t = tenant(3);
        for i in 0..5u32 {
            let row = AuditAnchorRun {
                run_id: AnchorRunId::new(),
                tenant_id: t,
                merkle_root: [u8::try_from(i).unwrap(); SHA256_LEN],
                tsa_serial: format!("0x{i:04x}"),
                tsa_gen_time: OffsetDateTime::from_unix_timestamp(1_700_000_000 + i64::from(i))
                    .unwrap(),
                anchored_at: OffsetDateTime::from_unix_timestamp(1_700_000_100 + i64::from(i))
                    .unwrap(),
                payload_bytes: vec![],
                quorum: None,
            };
            repo.insert(row).await.unwrap();
        }
        let rows = repo.list_for_tenant(&t, 3).await.unwrap();
        assert_eq!(rows.len(), 3);
        // anchored_at descending.
        for w in rows.windows(2) {
            assert!(w[0].anchored_at >= w[1].anchored_at);
        }
    }

    #[tokio::test]
    async fn recording_critical_sink_captures_calls() {
        let sink = RecordingCriticalEventSink::new();
        let t = tenant(9);
        sink.emit_critical(&t, "boom").await;
        let events = sink.events().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, t);
        assert_eq!(events[0].1, "boom");
    }

    #[test]
    fn default_verifier_rejects_garbage_json() {
        let v = DefaultTsaTokenVerifier;
        let res = v.verify(
            b"not json",
            "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----",
        );
        assert!(matches!(res, Err(AnchorRunError::Verification(_))));
    }

    #[test]
    fn default_verifier_rejects_wrong_version() {
        let v = DefaultTsaTokenVerifier;
        let token = serde_json::json!({
            "v": 99,
            "serial": "0x1",
            "gen_time": "2026-01-01T00:00:00Z",
            "merkle_root_hex": "00".repeat(32),
            "tsa_cert_pem": "x",
            "ca_cert_signature_b64": "x",
            "signature_b64": "x"
        });
        let res = v.verify(token.to_string().as_bytes(), "irrelevant");
        let err = res.unwrap_err();
        match err {
            AnchorRunError::Verification(m) => assert!(m.contains("version")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn tenant_anchor_default_interval_is_one_hour() {
        assert_eq!(TenantAnchorConfig::DEFAULT_INTERVAL.as_secs(), 3_600);
    }
}
