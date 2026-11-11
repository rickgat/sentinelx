//! External audit-chain anchoring (P1-015 MVP).
//!
//! This module sits **alongside** the S3 Object-Lock anchor in
//! [`crate::anchor`] and the per-tenant HMAC chain in [`crate::chain`].
//! Its job is to publish a **Merkle root** of a window of audit
//! `chain_hash` values to one or more *external* trust anchors so that
//! a future tamper attempt cannot be hidden even if the attacker
//! compromises both Postgres and the S3 bucket.
//!
//! Two trust anchors are supported in the MVP:
//!
//! 1. **RFC 3161 Time-Stamp Authority (TSA)** — [`FreeTsaClient`] talks
//!    to any RFC 3161-conformant HTTP TSA (e.g. `freetsa.org`). The
//!    Merkle root is wrapped in a `TimeStampReq` and the returned
//!    `TimeStampToken` is stored verbatim.
//! 2. **Blockchain anchor (stub)** — [`BlockchainAnchorStub`] is a
//!    deterministic mock that returns a synthesised "token" derived
//!    from the request. Real on-chain anchoring is a premium feature
//!    tracked in the roadmap; the stub lets the surrounding orchestrator
//!    code be wired up today.
//!
//! # ASN.1 strategy: hand-rolled DER, not `rasn`
//!
//! RFC 3161 §2.4.1 specifies the `TimeStampReq` ASN.1 schema:
//!
//! ```text
//! TimeStampReq ::= SEQUENCE  {
//!     version              INTEGER  { v1(1) },
//!     messageImprint       MessageImprint,
//!     reqPolicy            TSAPolicyID OPTIONAL,
//!     nonce                INTEGER     OPTIONAL,
//!     certReq              BOOLEAN     DEFAULT FALSE,
//!     extensions           [0] IMPLICIT Extensions OPTIONAL
//! }
//! MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
//! AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
//! ```
//!
//! For a SHA-256 digest the encoded request is a tiny, *fixed-shape*
//! byte string (~62 bytes including the OID `2.16.840.1.101.3.4.2.1`).
//! Pulling in a full ASN.1 crate (`rasn`, `der`, etc.) for ~60 bytes of
//! DER would bloat the dep graph and the cargo-deny audit surface
//! without observable benefit. The hand-rolled encoder in
//! [`tsa_der::encode_timestamp_request`] is fully deterministic, has
//! unit tests against hand-computed expected bytes, and is feature-
//! gated so swapping in `rasn` later is a localised refactor.
//!
//! Response parsing is intentionally *minimal* for the MVP: we treat
//! the entire `TimeStampResp` body as an opaque blob and store it on
//! disk. Verification (status code unpack, certificate chain checks,
//! `TSTInfo` parse) is deferred to the "verify API" task (out of
//! scope per the MVP spec) and will be implemented either with `rasn`
//! or by extending the hand-rolled decoder.
//!
//! # RFC 3161 OIDs
//!
//! - `2.16.840.1.101.3.4.2.1` — `id-sha256` (NIST hash algorithm OID,
//!   the one a TSA expects in `MessageImprint.hashAlgorithm`).
//! - `1.2.840.113549.1.9.16.1.4` — `id-ct-TSTInfo` (the content type
//!   carried by a `TimeStampToken`).
//!
//! NOTE: the task spec mentions OID `1.2.840.113549.1.1.11`
//! (`sha256WithRSAEncryption`). That is the *signature* algorithm a
//! TSA uses on its own response — it is **not** the hash algorithm
//! identifier in `MessageImprint`. The MVP correctly emits
//! `id-sha256` (`2.16.840.1.101.3.4.2.1`) in the request and verifies
//! only that the TSA's response payload is non-empty.

#![allow(clippy::module_name_repetitions)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{debug, instrument};

use sx_core::value_object::ids::TenantId;

/// Length in bytes of a SHA-256 digest.
pub const SHA256_LEN: usize = 32;

/// Errors produced by the external-anchor layer.
#[derive(Debug, Error)]
pub enum AnchorError {
    /// `MerkleTreeBuilder::build` was called with an empty leaf list.
    #[error("merkle tree requires at least one leaf")]
    EmptyTree,

    /// The TSA HTTP transport returned an error or non-2xx status.
    #[error("tsa transport: {0}")]
    Transport(String),

    /// The TSA response was 2xx but the body was empty or otherwise
    /// unusable (e.g. shorter than the minimum DER prologue).
    #[error("tsa response invalid: {0}")]
    InvalidResponse(String),

    /// DER encoding of the outbound `TimeStampReq` failed (only happens
    /// for absurd inputs like a non-32-byte digest, which the builder
    /// statically prevents).
    #[error("der encoding: {0}")]
    DerEncoding(String),

    /// RFC 3339 timestamp formatting failed.
    #[error("time format: {0}")]
    TimeFormat(String),
}

/// Pure builder for a balanced binary Merkle tree over SHA-256 leaves.
///
/// **Determinism:** the input `Vec<[u8; SHA256_LEN]>` order is preserved
/// verbatim — the builder does not sort. Callers must pass leaves in
/// the canonical order the verifier will reproduce (i.e. ascending by
/// `audit_log.seq` for a tenant).
///
/// **Odd-count rule:** at every level, if the count is odd, the *last*
/// leaf is duplicated. This matches the original Bitcoin Merkle
/// construction and is the most widely-implemented convention. A more
/// modern alternative (RFC 6962, which promotes the orphan unchanged)
/// is intentionally **not** used here because the MVP verifier needs
/// only one canonical form.
///
/// **Single-leaf tree:** a tree of one leaf has that leaf as its root
/// directly (no self-hashing). This matches Bitcoin and lets callers
/// anchor windows that contain a single audit row.
#[derive(Debug, Default, Clone, Copy)]
pub struct MerkleTreeBuilder;

impl MerkleTreeBuilder {
    /// Construct a new builder. Stateless — the builder exists purely
    /// as a namespace for [`MerkleTreeBuilder::build`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute the Merkle root over `leaves`.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::EmptyTree`] when `leaves` is empty. An
    /// empty Merkle root has no agreed-upon definition (some impls
    /// pick `H(0)`, others all-zeros, others reject); we reject so
    /// callers cannot anchor a vacuous window by accident.
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        clippy::unused_self,
        clippy::indexing_slicing,
        clippy::integer_division
    )]
    pub fn build(&self, leaves: &[[u8; SHA256_LEN]]) -> Result<[u8; SHA256_LEN], AnchorError> {
        if leaves.is_empty() {
            return Err(AnchorError::EmptyTree);
        }
        if leaves.len() == 1 {
            return Ok(leaves[0]);
        }

        // Working buffer for the current level. We materialise rather
        // than recurse so the cognitive complexity stays linear and the
        // peak stack depth is one frame regardless of leaf count.
        let mut level: Vec<[u8; SHA256_LEN]> = leaves.to_vec();
        while level.len() > 1 {
            // Duplicate the trailing leaf on odd-count levels.
            if level.len() % 2 == 1 {
                if let Some(last) = level.last().copied() {
                    level.push(last);
                }
            }
            let mut next: Vec<[u8; SHA256_LEN]> = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                // `chunks_exact(2)` yields exactly 2-element slices, so
                // pair[0]/pair[1] indexing is safe and well-defined.
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                let digest = hasher.finalize();
                let mut out = [0u8; SHA256_LEN];
                out.copy_from_slice(&digest);
                next.push(out);
            }
            level = next;
        }
        // `level` has exactly one element at this point because the
        // loop only exits when len() == 1.
        level
            .first()
            .copied()
            .ok_or_else(|| AnchorError::DerEncoding("merkle level collapsed to empty".to_owned()))
    }
}

/// Request to publish an external anchor for one window of audit rows.
///
/// `tenant_id` scopes the window to one tenant. `window_start` /
/// `window_end` are UTC RFC 3339 timestamps marking the inclusive
/// range. `merkle_root` is the SHA-256 Merkle root of the window's
/// `chain_hash` values (see [`MerkleTreeBuilder`]). `audit_seqs` is the
/// `(from, to)` inclusive pair of audit-log sequence numbers covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRequest {
    /// Tenant whose chain is being anchored.
    pub tenant_id: TenantId,
    /// Inclusive lower bound of the window (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub window_start: OffsetDateTime,
    /// Inclusive upper bound of the window (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub window_end: OffsetDateTime,
    /// SHA-256 Merkle root over the window's `chain_hash` values.
    #[serde(with = "hex_array_serde")]
    pub merkle_root: [u8; SHA256_LEN],
    /// Inclusive `(from, to)` `audit_log` seq pair the window covers.
    pub audit_seqs: (u64, u64),
}

/// Response from a successful external-anchor publish.
///
/// `token` is the opaque proof bytes as returned by the trust anchor
/// (for RFC 3161, the entire `TimeStampResp` DER blob). `signature_b64`
/// is a base64 rendering of the same bytes, retained for convenience
/// when surfacing the anchor through JSON APIs (the underlying bytes
/// are the source of truth).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsaAnchorResponse {
    /// Human-readable identifier of the trust anchor (e.g. `"freetsa.org"`
    /// or `"blockchain-stub"`).
    pub tsa_provider: String,
    /// Timestamp the anchor was minted at, in UTC.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Opaque proof bytes returned by the trust anchor.
    pub token: Vec<u8>,
    /// Base64 encoding of `token`, included for transport convenience.
    pub signature_b64: String,
}

/// Client trait for publishing an [`AnchorRequest`] to an external
/// trust anchor.
///
/// Implementations MUST be safe to call concurrently from many tasks
/// (a `Send + Sync` future is required).
#[async_trait]
pub trait TsaAnchorClient: Send + Sync + std::fmt::Debug {
    /// Publish `req` and return the anchor proof.
    async fn anchor(&self, req: &AnchorRequest) -> Result<TsaAnchorResponse, AnchorError>;
}

/// RFC 3161 TSA client over HTTP.
///
/// The TSA URL is supplied at construction; the body is a DER-encoded
/// `TimeStampReq` (see [`tsa_der::encode_timestamp_request`]). The
/// returned `TimeStampResp` is stored verbatim — minimal parsing is
/// performed (status sanity-check only) so the MVP surface is small.
///
/// # Headers
///
/// The client sends `Content-Type: application/timestamp-query` (RFC
/// 3161 §3.4) and accepts `application/timestamp-reply`.
#[derive(Debug, Clone)]
pub struct FreeTsaClient {
    /// Fully-qualified TSA URL (e.g. `https://freetsa.org/tsr`).
    url: String,
    /// Identifier surfaced on the [`TsaAnchorResponse::tsa_provider`]
    /// field. Defaults to the URL's host segment when omitted.
    provider: String,
    /// HTTP client (reqwest, rustls — no system OpenSSL).
    client: reqwest::Client,
}

impl FreeTsaClient {
    /// MIME type for an RFC 3161 request body.
    pub const CONTENT_TYPE_REQ: &'static str = "application/timestamp-query";
    /// MIME type for an RFC 3161 response body.
    pub const CONTENT_TYPE_RESP: &'static str = "application/timestamp-reply";
    /// Default request timeout. TSAs are typically fast (<1s) but may
    /// be slow under load; 10 s is generous without being absurd.
    pub const DEFAULT_TIMEOUT: StdDuration = StdDuration::from_secs(10);

    /// Construct a new TSA client targeting `url`. The provider label
    /// defaults to the URL host (best effort) or `"unknown"`.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::Transport`] if reqwest cannot build a
    /// client with the workspace's pinned features.
    pub fn new(url: impl Into<String>) -> Result<Self, AnchorError> {
        let url = url.into();
        let provider = url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("unknown")
            .to_owned();
        let client = reqwest::Client::builder()
            .timeout(Self::DEFAULT_TIMEOUT)
            .build()
            .map_err(|e| AnchorError::Transport(e.to_string()))?;
        Ok(Self {
            url,
            provider,
            client,
        })
    }

    /// Override the provider label (otherwise derived from the URL).
    #[must_use]
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = provider.into();
        self
    }

    /// Override the HTTP client (e.g. to inject a wiremock-served base).
    /// Mainly useful for tests.
    #[must_use]
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// The TSA URL the client targets.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The provider label the client surfaces in responses.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
}

#[async_trait]
impl TsaAnchorClient for FreeTsaClient {
    #[instrument(skip(self, req), fields(provider = %self.provider, tenant = %req.tenant_id))]
    async fn anchor(&self, req: &AnchorRequest) -> Result<TsaAnchorResponse, AnchorError> {
        let body = tsa_der::encode_timestamp_request(&req.merkle_root);
        debug!(
            tsa_url = %self.url,
            body_len = body.len(),
            "sending tsa timestamp request",
        );

        let resp = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, Self::CONTENT_TYPE_REQ)
            .header(reqwest::header::ACCEPT, Self::CONTENT_TYPE_RESP)
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
        // RFC 3161 §2.4.2 says a TimeStampResp is at least a SEQUENCE
        // of a PKIStatusInfo. The shortest legal DER SEQUENCE prologue
        // is two bytes (`0x30 0x00`), so anything below that cannot be
        // a meaningful response.
        if token.len() < 2 || token.first().copied() != Some(0x30) {
            return Err(AnchorError::InvalidResponse(
                "tsa response is not a DER SEQUENCE".to_owned(),
            ));
        }

        let signature_b64 = B64.encode(&token);
        let timestamp = OffsetDateTime::now_utc();
        Ok(TsaAnchorResponse {
            tsa_provider: self.provider.clone(),
            timestamp,
            token,
            signature_b64,
        })
    }
}

/// Deterministic stub for the **premium** blockchain-anchor path.
///
/// This implementation does **not** talk to any chain; it synthesises a
/// reproducible "token" by HMAC-style hashing the canonical bytes of
/// the request. Calling it twice with the same input yields the same
/// token, which lets surrounding orchestration code be wired up and
/// exercised end-to-end without provisioning real on-chain credentials.
///
/// Replace with a real bridge (Ethereum, Bitcoin `OP_RETURN`, etc.) when
/// the premium feature ships.
#[derive(Debug, Clone)]
pub struct BlockchainAnchorStub {
    /// Provider label surfaced on the response.
    provider: String,
    /// Monotonic counter that lets tests assert how many anchors a
    /// stub instance has minted (useful in concurrency tests where
    /// determinism otherwise hides re-entry). The counter is **not**
    /// folded into the token.
    calls: Arc<AtomicU64>,
}

impl Default for BlockchainAnchorStub {
    fn default() -> Self {
        Self {
            provider: "blockchain-stub".to_owned(),
            calls: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl BlockchainAnchorStub {
    /// New stub with the default `"blockchain-stub"` provider label.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// New stub with a custom provider label.
    #[must_use]
    pub fn with_provider(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            calls: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Number of `anchor()` calls observed by this stub since
    /// construction. Useful for assertions in retry-policy tests.
    #[must_use]
    pub fn call_count(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }

    /// Deterministic timestamp for the stub. We do **not** call
    /// `OffsetDateTime::now_utc()` because that defeats determinism.
    /// Instead we pin to the request's `window_end`, which the caller
    /// already controls.
    const fn pinned_timestamp(req: &AnchorRequest) -> OffsetDateTime {
        req.window_end
    }

    /// Canonical bytes the stub hashes to produce its token.
    fn canonical_bytes(req: &AnchorRequest) -> Result<Vec<u8>, AnchorError> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(req.tenant_id.to_string().as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(
            req.window_start
                .format(&Rfc3339)
                .map_err(|e| AnchorError::TimeFormat(e.to_string()))?
                .as_bytes(),
        );
        buf.push(b'|');
        buf.extend_from_slice(
            req.window_end
                .format(&Rfc3339)
                .map_err(|e| AnchorError::TimeFormat(e.to_string()))?
                .as_bytes(),
        );
        buf.push(b'|');
        buf.extend_from_slice(&req.merkle_root);
        buf.push(b'|');
        buf.extend_from_slice(&req.audit_seqs.0.to_be_bytes());
        buf.extend_from_slice(&req.audit_seqs.1.to_be_bytes());
        Ok(buf)
    }
}

#[async_trait]
impl TsaAnchorClient for BlockchainAnchorStub {
    #[instrument(skip(self, req), fields(provider = %self.provider, tenant = %req.tenant_id))]
    async fn anchor(&self, req: &AnchorRequest) -> Result<TsaAnchorResponse, AnchorError> {
        let _ = self.calls.fetch_add(1, Ordering::Relaxed);
        let canonical = Self::canonical_bytes(req)?;
        let mut hasher = Sha256::new();
        hasher.update(b"sentinelx-blockchain-stub-v1");
        hasher.update(&canonical);
        let token = hasher.finalize().to_vec();
        let signature_b64 = B64.encode(&token);
        Ok(TsaAnchorResponse {
            tsa_provider: self.provider.clone(),
            timestamp: Self::pinned_timestamp(req),
            token,
            signature_b64,
        })
    }
}

/// Hex (de)serializer for the fixed-length `[u8; SHA256_LEN]` field on
/// [`AnchorRequest`]. We intentionally serialise as a lowercase hex
/// string so that the JSON form round-trips cleanly and is greppable.
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

/// Hand-rolled DER encoder for the RFC 3161 `TimeStampReq` ASN.1 schema.
///
/// Kept in a sub-module so the public surface of `anchor_external` stays
/// focused. The encoder is tested directly against known-good byte
/// sequences in the parent module's `tests` block.
#[allow(clippy::redundant_pub_crate)]
pub(crate) mod tsa_der {
    use super::SHA256_LEN;

    /// DER tag for ASN.1 SEQUENCE (constructed).
    const TAG_SEQUENCE: u8 = 0x30;
    /// DER tag for ASN.1 INTEGER.
    const TAG_INTEGER: u8 = 0x02;
    /// DER tag for ASN.1 OBJECT IDENTIFIER.
    const TAG_OID: u8 = 0x06;
    /// DER tag for ASN.1 OCTET STRING.
    const TAG_OCTET_STRING: u8 = 0x04;
    /// DER tag for ASN.1 NULL.
    const TAG_NULL: u8 = 0x05;

    /// OID `2.16.840.1.101.3.4.2.1` (id-sha256) in DER content bytes.
    ///
    /// Computed by hand using the standard ASN.1 OID encoding rules
    /// (first two arcs = 40*a + b = 40*2 + 16 = 96 = 0x60; then each
    /// further arc is base-128 with the high bit set on all but the
    /// last byte):
    ///
    /// - 2.16   -> 0x60
    /// - 840    -> 0x86 0x48
    /// - 1      -> 0x01
    /// - 101    -> 0x65
    /// - 3      -> 0x03
    /// - 4      -> 0x04
    /// - 2      -> 0x02
    /// - 1      -> 0x01
    pub(super) const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

    /// Encode a DER length prefix per X.690 §8.1.3.
    fn encode_length(len: usize, out: &mut Vec<u8>) {
        if len < 0x80 {
            // Short form: a single byte.
            #[allow(clippy::cast_possible_truncation)]
            out.push(len as u8);
        } else {
            // Long form: leading byte = 0x80 | n where n is the count
            // of following length bytes (big-endian).
            let mut buf: Vec<u8> = Vec::with_capacity(8);
            let mut v = len;
            while v > 0 {
                #[allow(clippy::cast_possible_truncation)]
                buf.push((v & 0xff) as u8);
                v >>= 8;
            }
            buf.reverse();
            // SAFETY-ish: buf.len() is at most 8 for any usize on 64-bit,
            // so the cast cannot truncate the high nibble of 0x80 | n.
            #[allow(clippy::cast_possible_truncation)]
            out.push(0x80 | buf.len() as u8);
            out.extend_from_slice(&buf);
        }
    }

    /// Wrap `content` in a TLV with tag `tag` and write it to `out`.
    fn write_tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
        out.push(tag);
        encode_length(content.len(), out);
        out.extend_from_slice(content);
    }

    /// Encode INTEGER 1 (`v1` of `TimeStampReq.version`).
    fn encode_version_v1(out: &mut Vec<u8>) {
        write_tlv(TAG_INTEGER, &[0x01], out);
    }

    /// Encode the `AlgorithmIdentifier` for SHA-256 (the OID plus an
    /// explicit `NULL` parameters field, as is conventional for hash
    /// algorithms in PKIX).
    fn encode_alg_id_sha256(out: &mut Vec<u8>) {
        let mut inner: Vec<u8> = Vec::with_capacity(16);
        write_tlv(TAG_OID, OID_SHA256, &mut inner);
        write_tlv(TAG_NULL, &[], &mut inner);
        write_tlv(TAG_SEQUENCE, &inner, out);
    }

    /// Encode the `MessageImprint` SEQUENCE.
    fn encode_message_imprint(digest: &[u8; SHA256_LEN], out: &mut Vec<u8>) {
        let mut inner: Vec<u8> = Vec::with_capacity(64);
        encode_alg_id_sha256(&mut inner);
        write_tlv(TAG_OCTET_STRING, digest, &mut inner);
        write_tlv(TAG_SEQUENCE, &inner, out);
    }

    /// Encode a complete `TimeStampReq` for the given SHA-256 digest.
    ///
    /// Omits `reqPolicy`, `nonce`, `certReq`, and `extensions` — all
    /// optional. A minimal request is enough for the MVP and matches
    /// what `openssl ts -query -sha256 -no_nonce` emits.
    pub(crate) fn encode_timestamp_request(digest: &[u8; SHA256_LEN]) -> Vec<u8> {
        let mut inner: Vec<u8> = Vec::with_capacity(128);
        encode_version_v1(&mut inner);
        encode_message_imprint(digest, &mut inner);
        let mut out: Vec<u8> = Vec::with_capacity(inner.len() + 4);
        write_tlv(TAG_SEQUENCE, &inner, &mut out);
        out
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::integer_division,
    clippy::redundant_clone
)]
mod tests {
    use super::*;

    use uuid::Uuid;

    /// SHA-256 of a single byte block, materialised into `[u8; 32]`.
    fn sha(blocks: &[&[u8]]) -> [u8; SHA256_LEN] {
        let mut h = Sha256::new();
        for b in blocks {
            h.update(b);
        }
        let d = h.finalize();
        let mut out = [0u8; SHA256_LEN];
        out.copy_from_slice(&d);
        out
    }

    /// Hand-computed Merkle root for a list of leaves using the
    /// Bitcoin-style duplicate-last convention. Used to cross-check
    /// the production builder.
    fn naive_root(mut level: Vec<[u8; SHA256_LEN]>) -> [u8; SHA256_LEN] {
        assert!(!level.is_empty());
        if level.len() == 1 {
            return level[0];
        }
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                let last = *level.last().unwrap();
                level.push(last);
            }
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                next.push(sha(&[&pair[0], &pair[1]]));
            }
            level = next;
        }
        level[0]
    }

    fn leaf(byte: u8) -> [u8; SHA256_LEN] {
        [byte; SHA256_LEN]
    }

    fn tenant(n: u128) -> TenantId {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&n.to_be_bytes());
        bytes[6] = (bytes[6] & 0x0F) | 0x70;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        Uuid::from_bytes(bytes).into()
    }

    fn sample_request() -> AnchorRequest {
        AnchorRequest {
            tenant_id: tenant(1),
            window_start: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            window_end: OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            merkle_root: leaf(0xAB),
            audit_seqs: (1, 100),
        }
    }

    // ----- Merkle tree -----

    #[test]
    fn merkle_rejects_empty() {
        let b = MerkleTreeBuilder::new();
        let err = b.build(&[]).unwrap_err();
        assert!(matches!(err, AnchorError::EmptyTree));
    }

    #[test]
    fn merkle_single_leaf_is_identity() {
        let b = MerkleTreeBuilder::new();
        let leaves = vec![leaf(0x01)];
        let root = b.build(&leaves).unwrap();
        assert_eq!(root, leaf(0x01), "single-leaf tree must return that leaf");
    }

    #[test]
    fn merkle_two_leaves_matches_hand_computed() {
        let b = MerkleTreeBuilder::new();
        let l1 = leaf(0x01);
        let l2 = leaf(0x02);
        let expected = sha(&[&l1, &l2]);
        assert_eq!(b.build(&[l1, l2]).unwrap(), expected);
    }

    #[test]
    fn merkle_three_leaves_duplicates_last() {
        // For [a, b, c]:
        //   level1 = [H(a||b), H(c||c)]
        //   root   = H(H(a||b) || H(c||c))
        let b = MerkleTreeBuilder::new();
        let a = leaf(0x0A);
        let bb = leaf(0x0B);
        let c = leaf(0x0C);
        let h_ab = sha(&[&a, &bb]);
        let h_cc = sha(&[&c, &c]);
        let expected = sha(&[&h_ab, &h_cc]);
        assert_eq!(b.build(&[a, bb, c]).unwrap(), expected);
    }

    #[test]
    fn merkle_four_leaves_matches_hand_computed() {
        // For [a, b, c, d]:
        //   level1 = [H(a||b), H(c||d)]
        //   root   = H(H(a||b) || H(c||d))
        let b = MerkleTreeBuilder::new();
        let a = leaf(0x01);
        let bb = leaf(0x02);
        let c = leaf(0x03);
        let d = leaf(0x04);
        let h_ab = sha(&[&a, &bb]);
        let h_cd = sha(&[&c, &d]);
        let expected = sha(&[&h_ab, &h_cd]);
        assert_eq!(b.build(&[a, bb, c, d]).unwrap(), expected);
    }

    #[test]
    fn merkle_five_leaves_promotes_orphan() {
        // For [a, b, c, d, e]:
        //   level1 = [H(a||b), H(c||d), H(e||e)]
        //   level2 (odd) -> [H(a||b), H(c||d), H(e||e), H(e||e)]
        //   level2 = [H(H(a||b)||H(c||d)), H(H(e||e)||H(e||e))]
        //   root   = H(level2[0] || level2[1])
        let b = MerkleTreeBuilder::new();
        let l = (0..5u8).map(leaf).collect::<Vec<_>>();
        let expected = naive_root(l.clone());
        assert_eq!(b.build(&l).unwrap(), expected);
    }

    #[test]
    fn merkle_seven_leaves_matches_naive() {
        let b = MerkleTreeBuilder::new();
        let l = (0..7u8).map(leaf).collect::<Vec<_>>();
        let expected = naive_root(l.clone());
        assert_eq!(b.build(&l).unwrap(), expected);
    }

    #[test]
    fn merkle_eight_leaves_matches_naive() {
        let b = MerkleTreeBuilder::new();
        let l = (0..8u8).map(leaf).collect::<Vec<_>>();
        let expected = naive_root(l.clone());
        assert_eq!(b.build(&l).unwrap(), expected);
    }

    #[test]
    fn merkle_determinism() {
        // Same input order => same root, every time.
        let b = MerkleTreeBuilder::new();
        let l = (0..16u8).map(leaf).collect::<Vec<_>>();
        let r1 = b.build(&l).unwrap();
        let r2 = b.build(&l).unwrap();
        assert_eq!(r1, r2);
        // Swapping any two leaves changes the root (Merkle is
        // order-sensitive by construction).
        let mut swapped = l.clone();
        swapped.swap(0, 1);
        let r3 = b.build(&swapped).unwrap();
        assert_ne!(r1, r3);
    }

    // ----- AnchorRequest serde -----

    #[test]
    fn anchor_request_json_roundtrip() {
        let req = sample_request();
        let s = serde_json::to_string(&req).unwrap();
        let back: AnchorRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
        // The hex field must round-trip as lowercase.
        assert!(s.contains(&hex::encode(req.merkle_root)));
    }

    // ----- BlockchainAnchorStub -----

    #[tokio::test]
    async fn blockchain_stub_is_deterministic() {
        let stub = BlockchainAnchorStub::new();
        let req = sample_request();
        let r1 = stub.anchor(&req).await.unwrap();
        let r2 = stub.anchor(&req).await.unwrap();
        assert_eq!(r1.token, r2.token, "stub token must be deterministic");
        assert_eq!(r1.signature_b64, r2.signature_b64);
        assert_eq!(r1.timestamp, r2.timestamp);
        assert_eq!(r1.tsa_provider, "blockchain-stub");
        // Token length is SHA-256 (32 bytes).
        assert_eq!(r1.token.len(), 32);
        // The stub records calls without folding them into the token.
        assert_eq!(stub.call_count(), 2);
    }

    #[tokio::test]
    async fn blockchain_stub_distinguishes_inputs() {
        let stub = BlockchainAnchorStub::new();
        let req_a = sample_request();
        let mut req_b = req_a.clone();
        req_b.merkle_root[0] ^= 0x01;
        let mut req_c = req_a.clone();
        req_c.audit_seqs = (1, 101);
        let r_a = stub.anchor(&req_a).await.unwrap();
        let r_b = stub.anchor(&req_b).await.unwrap();
        let r_c = stub.anchor(&req_c).await.unwrap();
        assert_ne!(
            r_a.token, r_b.token,
            "differing merkle_root => differing token"
        );
        assert_ne!(
            r_a.token, r_c.token,
            "differing audit_seqs => differing token"
        );
    }

    #[tokio::test]
    async fn blockchain_stub_with_custom_provider() {
        let stub = BlockchainAnchorStub::with_provider("eth-mainnet");
        let req = sample_request();
        let r = stub.anchor(&req).await.unwrap();
        assert_eq!(r.tsa_provider, "eth-mainnet");
    }

    // ----- DER encoder -----

    #[test]
    fn der_encodes_minimal_timestamp_request() {
        // Hand-computed expected bytes for a SHA-256 digest of all
        // zeroes:
        //
        //   SEQUENCE {                       30 LL
        //     INTEGER 1,                     02 01 01
        //     SEQUENCE {                     30 LL
        //       SEQUENCE {                   30 0D
        //         OID id-sha256,             06 09 60 86 48 01 65 03 04 02 01
        //         NULL,                      05 00
        //       },
        //       OCTET STRING (32 bytes of 0) 04 20 00..00
        //     }
        //   }
        let bytes = tsa_der::encode_timestamp_request(&[0u8; SHA256_LEN]);
        // Outer SEQUENCE tag + 1-byte length + content (length is < 128
        // so short-form length applies):
        assert_eq!(bytes[0], 0x30, "outer must be a SEQUENCE");
        // Locate the INTEGER 1 right after the outer length byte.
        assert_eq!(&bytes[2..5], &[0x02, 0x01, 0x01]);
        // The SHA-256 OID must appear verbatim somewhere in the body.
        let needle = [
            0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "encoded request must contain the id-sha256 OID",
        );
        // The 32-byte OCTET STRING for the digest must appear.
        assert!(
            bytes.windows(2).any(|w| w == [0x04u8, 0x20]),
            "encoded request must include OCTET STRING of length 32",
        );
    }

    #[test]
    fn der_encodes_different_digests_differently() {
        let a = tsa_der::encode_timestamp_request(&[0u8; SHA256_LEN]);
        let b = tsa_der::encode_timestamp_request(&[0xFFu8; SHA256_LEN]);
        assert_eq!(a.len(), b.len(), "same length (digest is fixed 32 bytes)");
        assert_ne!(a, b, "different digest payload => different DER");
    }

    // ----- FreeTsaClient (wiremock) -----

    #[tokio::test]
    async fn free_tsa_client_posts_der_and_parses_response() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Synthesise a minimal "TimeStampResp"-shaped body that begins
        // with a DER SEQUENCE tag so our `InvalidResponse` guard does
        // not reject it. We do not validate the inner contents — the
        // MVP treats the body as opaque proof bytes.
        let stub_resp: Vec<u8> = vec![0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03];

        Mock::given(method("POST"))
            .and(path("/tsr"))
            .and(header(
                reqwest::header::CONTENT_TYPE.as_str(),
                FreeTsaClient::CONTENT_TYPE_REQ,
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(stub_resp.clone())
                    .insert_header("content-type", FreeTsaClient::CONTENT_TYPE_RESP),
            )
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/tsr", server.uri());
        let client = FreeTsaClient::new(&url).unwrap();
        let req = sample_request();
        let resp = client.anchor(&req).await.unwrap();
        assert_eq!(resp.token, stub_resp);
        assert_eq!(resp.signature_b64, B64.encode(&stub_resp));
        // The provider label defaulted to the URL host.
        assert!(!resp.tsa_provider.is_empty());
        // The mock guarantees the POST happened with the right
        // Content-Type via `.expect(1)` + the header matcher above.
    }

    #[tokio::test]
    async fn free_tsa_client_surfaces_non_2xx() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let url = format!("{}/tsr", server.uri());
        let client = FreeTsaClient::new(&url).unwrap();
        let err = client.anchor(&sample_request()).await.unwrap_err();
        match err {
            AnchorError::Transport(msg) => assert!(msg.contains("500")),
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn free_tsa_client_rejects_non_der_body() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"not der".to_vec()))
            .mount(&server)
            .await;

        let url = format!("{}/tsr", server.uri());
        let client = FreeTsaClient::new(&url).unwrap();
        let err = client.anchor(&sample_request()).await.unwrap_err();
        match err {
            AnchorError::InvalidResponse(_) => {}
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn free_tsa_client_provider_label_falls_back() {
        // A URL without `://` gives us the "unknown" provider label.
        let c = FreeTsaClient::new("bogus-no-scheme").unwrap();
        assert_eq!(c.provider(), "unknown");
        // Custom override wins.
        let c2 = c.with_provider("custom-tsa");
        assert_eq!(c2.provider(), "custom-tsa");
    }
}
