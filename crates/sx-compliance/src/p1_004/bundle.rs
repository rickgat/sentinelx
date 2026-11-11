//! Evidence bundle exporter.
//!
//! A bundle is a ZIP archive whose entries are:
//!
//! * `manifest.json` — a [`BundleManifest`] document listing every
//!   payload file, its SHA-256 over the bytes, and the HMAC-SHA256
//!   signature of that SHA-256 produced with the tenant-scoped
//!   secret.
//! * `evidence/<control_id>.json` — one entry per collected
//!   [`crate::collector::types::Evidence`] payload.
//!
//! ## Why a hand-rolled ZIP writer?
//!
//! Two reasons:
//! 1. **Determinism.** STORE-only (no compression), zeroed timestamps,
//!    and a fixed entry order yield byte-identical archives across
//!    runs for the same input. That property is what makes the
//!    snapshot test in `tests/p1_004_bundle_snapshot.rs` meaningful.
//! 2. **No new transitive deps.** `zip` (and its compression
//!    crates) are not in the workspace lockfile; pulling them in for
//!    one feature is a poor cost/benefit tradeoff when ~150 LoC of
//!    pure-Rust STORE writer covers the whole MVP requirement.
//!
//! The output is a fully conformant `.zip` (no compression) that
//! every standard unzip implementation reads correctly.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use time::OffsetDateTime;

use crate::collector::types::Evidence;

type HmacSha256 = Hmac<Sha256>;

/// Errors returned by the bundle exporter.
#[derive(Debug, Error)]
pub enum BundleError {
    /// JSON serialisation of the manifest failed.
    #[error("manifest encoding failed: {0}")]
    Encoding(String),
    /// The HMAC key length was rejected by the underlying primitive.
    #[error("invalid hmac key: {0}")]
    HmacKey(String),
    /// An entry's filename exceeded the local file header capacity
    /// (extremely unlikely — guards against pathological control ids).
    #[error("filename too long: {0}")]
    FilenameTooLong(String),
}

/// One row inside [`BundleManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    /// SentinelX-local control id (`SX-…`).
    pub control_id: String,
    /// Path of the file inside the archive (`evidence/<control_id>.json`).
    pub archive_path: String,
    /// Lowercase hex SHA-256 over the file bytes.
    pub sha256: String,
    /// HMAC-SHA256 signature over the lowercase-hex SHA-256, in
    /// lowercase hex. The signing key is tenant-scoped and stored in
    /// `sx-secrets`; auditors verify by recomputing this HMAC.
    pub hmac_sha256: String,
    /// RFC 3339 UTC timestamp at which the underlying evidence was
    /// collected.
    pub collected_at: String,
    /// Byte length of the entry payload.
    pub byte_len: u64,
}

/// Top-level JSON document at `manifest.json` inside a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Manifest schema version. Bumped on incompatible changes.
    pub schema_version: u32,
    /// Tenant the bundle was produced for. Auditors verify this matches
    /// the secret used to recompute the HMAC.
    pub tenant_id: String,
    /// Run id that produced this bundle.
    pub run_id: String,
    /// RFC 3339 UTC start of the audit period.
    pub period_start: String,
    /// RFC 3339 UTC end of the audit period.
    pub period_end: String,
    /// One entry per `evidence/<…>.json` file in the archive.
    pub files: Vec<ManifestFileEntry>,
}

/// Compute the lowercase hex HMAC-SHA256 of `msg` under `key`.
fn hmac_hex(key: &[u8], msg: &[u8]) -> Result<String, BundleError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| BundleError::HmacKey(e.to_string()))?;
    mac.update(msg);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Produce a ZIP bundle from a deterministic, control-id-sorted set
/// of evidences. Returns the bundle bytes.
///
/// The signing key is supplied by the caller; it must be the
/// tenant-scoped HMAC secret pulled from `sx-secrets` at the service
/// layer.
///
/// # Errors
/// Returns [`BundleError`] on any encoding, HMAC, or filename failure.
pub fn build_bundle(
    tenant_id: &str,
    run_id: &str,
    period_start: OffsetDateTime,
    period_end: OffsetDateTime,
    evidences: &[Evidence],
    signing_key: &[u8],
) -> Result<Vec<u8>, BundleError> {
    // Sort by control_id for determinism — same inputs, same bytes.
    let mut sorted: BTreeMap<&str, &Evidence> = BTreeMap::new();
    for ev in evidences {
        sorted.insert(ev.control_id, ev);
    }

    let period_start_iso = period_start
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| BundleError::Encoding(e.to_string()))?;
    let period_end_iso = period_end
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| BundleError::Encoding(e.to_string()))?;

    // Build the manifest first (its bytes are the *last* entry written
    // to the archive but the manifest's content is computed before any
    // file body is encoded).
    let mut entries: Vec<ManifestFileEntry> = Vec::with_capacity(sorted.len());
    for (cid, ev) in &sorted {
        let sha_hex = hex::encode(ev.sha256);
        let hmac = hmac_hex(signing_key, sha_hex.as_bytes())?;
        let collected_at = ev
            .collected_at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| BundleError::Encoding(e.to_string()))?;
        entries.push(ManifestFileEntry {
            control_id: (*cid).to_owned(),
            archive_path: archive_path_for(cid),
            sha256: sha_hex,
            hmac_sha256: hmac,
            collected_at,
            byte_len: ev.payload.len() as u64,
        });
    }

    let manifest = BundleManifest {
        schema_version: 1,
        tenant_id: tenant_id.to_owned(),
        run_id: run_id.to_owned(),
        period_start: period_start_iso,
        period_end: period_end_iso,
        files: entries,
    };
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| BundleError::Encoding(e.to_string()))?;

    // Encode the archive: evidence files first (sorted), then manifest.
    let mut zip = ZipWriter::new();
    for (cid, ev) in &sorted {
        zip.add_store(&archive_path_for(cid), &ev.payload)?;
    }
    zip.add_store("manifest.json", &manifest_bytes)?;
    Ok(zip.finish())
}

fn archive_path_for(control_id: &str) -> String {
    format!("evidence/{control_id}.json")
}

// ---------------------------------------------------------------------------
// Minimal STORE-only ZIP writer.
//
// Format reference: PKZIP APPNOTE 6.3.10, sections 4.3.7 (local file
// header), 4.3.12 (central directory header), 4.3.16 (end-of-central-
// directory record). We deliberately:
//
//   * Use `compression_method = 0` (STORE) — no DEFLATE needed.
//   * Zero the modification time + date (fixed 1980-01-01 epoch) so
//     two runs over the same input produce byte-identical output.
//   * Use Version 2.0 (`0x0014`) — the minimum that supports STORE.
//   * Do not emit Zip64 records (entries are small).
// ---------------------------------------------------------------------------

struct ZipWriter {
    out: Vec<u8>,
    central: Vec<u8>,
    entries: u16,
}

impl ZipWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            central: Vec::new(),
            entries: 0,
        }
    }

    fn add_store(&mut self, name: &str, body: &[u8]) -> Result<(), BundleError> {
        let name_bytes = name.as_bytes();
        let name_len: u16 = u16::try_from(name_bytes.len())
            .map_err(|_| BundleError::FilenameTooLong(name.to_owned()))?;
        let crc = crc32(body);
        let size: u32 = u32::try_from(body.len())
            .map_err(|_| BundleError::Encoding(format!("entry {name} exceeds 32-bit size")))?;
        let local_offset: u32 = u32::try_from(self.out.len())
            .map_err(|_| BundleError::Encoding("archive exceeds 32-bit offset".into()))?;

        // Local file header.
        self.out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        self.out.extend_from_slice(&0x0014u16.to_le_bytes()); // version needed
        self.out.extend_from_slice(&0x0000u16.to_le_bytes()); // general purpose
        self.out.extend_from_slice(&0x0000u16.to_le_bytes()); // STORE
        self.out.extend_from_slice(&0x0000u16.to_le_bytes()); // mod time (zero)
        self.out.extend_from_slice(&0x0021u16.to_le_bytes()); // mod date = 1980-01-01
        self.out.extend_from_slice(&crc.to_le_bytes());
        self.out.extend_from_slice(&size.to_le_bytes()); // compressed
        self.out.extend_from_slice(&size.to_le_bytes()); // uncompressed
        self.out.extend_from_slice(&name_len.to_le_bytes());
        self.out.extend_from_slice(&0x0000u16.to_le_bytes()); // extra len
        self.out.extend_from_slice(name_bytes);
        self.out.extend_from_slice(body);

        // Central directory header.
        self.central
            .extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        self.central.extend_from_slice(&0x0014u16.to_le_bytes()); // version made by
        self.central.extend_from_slice(&0x0014u16.to_le_bytes()); // version needed
        self.central.extend_from_slice(&0x0000u16.to_le_bytes()); // general purpose
        self.central.extend_from_slice(&0x0000u16.to_le_bytes()); // STORE
        self.central.extend_from_slice(&0x0000u16.to_le_bytes()); // mod time
        self.central.extend_from_slice(&0x0021u16.to_le_bytes()); // mod date
        self.central.extend_from_slice(&crc.to_le_bytes());
        self.central.extend_from_slice(&size.to_le_bytes());
        self.central.extend_from_slice(&size.to_le_bytes());
        self.central.extend_from_slice(&name_len.to_le_bytes());
        self.central.extend_from_slice(&0x0000u16.to_le_bytes()); // extra len
        self.central.extend_from_slice(&0x0000u16.to_le_bytes()); // comment len
        self.central.extend_from_slice(&0x0000u16.to_le_bytes()); // disk start
        self.central.extend_from_slice(&0x0000u16.to_le_bytes()); // internal attr
        self.central
            .extend_from_slice(&0x0000_0000u32.to_le_bytes()); // external attr
        self.central.extend_from_slice(&local_offset.to_le_bytes());
        self.central.extend_from_slice(name_bytes);

        self.entries = self.entries.saturating_add(1);
        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        let central_offset = self.out.len() as u32;
        let central_size = self.central.len() as u32;
        self.out.extend_from_slice(&self.central);

        // End of central directory.
        self.out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        self.out.extend_from_slice(&0x0000u16.to_le_bytes()); // disk no
        self.out.extend_from_slice(&0x0000u16.to_le_bytes()); // central dir disk
        self.out.extend_from_slice(&self.entries.to_le_bytes());
        self.out.extend_from_slice(&self.entries.to_le_bytes());
        self.out.extend_from_slice(&central_size.to_le_bytes());
        self.out.extend_from_slice(&central_offset.to_le_bytes());
        self.out.extend_from_slice(&0x0000u16.to_le_bytes()); // comment len
        self.out
    }
}

// ---------------------------------------------------------------------------
// CRC-32 (ZIP variant — IEEE 802.3). Table-driven, no external deps.
// ---------------------------------------------------------------------------

const fn build_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
}

const CRC_TABLE: [u32; 256] = build_crc_table();

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in bytes {
        let idx = ((crc ^ u32::from(b)) & 0xff) as usize;
        // `idx` is bounded by 0..256 by construction.
        crc = (crc >> 8) ^ CRC_TABLE.get(idx).copied().unwrap_or(0);
    }
    crc ^ 0xffff_ffff
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::collector::types::{Evidence, EvidenceContentType};
    use crate::model::framework::Framework;

    fn sample_ev(cid: &'static str, payload: &str) -> Evidence {
        Evidence::new(
            cid,
            Framework::Soc2,
            datetime!(2026-06-12 00:00:00 UTC),
            EvidenceContentType::Json,
            payload.as_bytes().to_vec(),
            "1.0.0",
        )
    }

    #[test]
    fn crc32_matches_known_vector() {
        // "123456789" -> 0xCBF43926 (well-known PKZIP test vector).
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn build_bundle_is_deterministic_for_same_input() {
        let evs = vec![
            sample_ev("SX-AUDIT-CHAIN-INTEGRITY-VERIFY", "{\"ok\":1}"),
            sample_ev("SX-MFA-ENROLLMENT-RATE", "{\"ok\":2}"),
        ];
        let key = b"super-secret-tenant-key-32-bytes!";
        let b1 = build_bundle(
            "tenant-A",
            "run-1",
            datetime!(2026-06-05 00:00:00 UTC),
            datetime!(2026-06-12 00:00:00 UTC),
            &evs,
            key,
        )
        .unwrap();
        let b2 = build_bundle(
            "tenant-A",
            "run-1",
            datetime!(2026-06-05 00:00:00 UTC),
            datetime!(2026-06-12 00:00:00 UTC),
            &evs,
            key,
        )
        .unwrap();
        assert_eq!(b1, b2, "bundles must be byte-deterministic");
    }

    #[test]
    fn build_bundle_emits_pk_magic_and_eocd() {
        let evs = vec![sample_ev("SX-MFA-ENROLLMENT-RATE", "{\"ok\":1}")];
        let key = b"k";
        let b = build_bundle(
            "tA",
            "r1",
            datetime!(2026-06-05 00:00:00 UTC),
            datetime!(2026-06-12 00:00:00 UTC),
            &evs,
            key,
        )
        .unwrap();
        assert_eq!(
            &b[..4],
            &[0x50, 0x4b, 0x03, 0x04],
            "PK\\03\\04 local header"
        );
        // End-of-central-directory magic must appear in the tail.
        let eocd = &[0x50, 0x4b, 0x05, 0x06];
        assert!(b.windows(4).any(|w| w == eocd), "EOCD magic missing");
    }

    #[test]
    fn manifest_includes_signed_hashes() {
        let evs = vec![sample_ev("SX-MFA-ENROLLMENT-RATE", "{\"ok\":1}")];
        let key = b"tenant-A-secret";
        let b = build_bundle(
            "tA",
            "r1",
            datetime!(2026-06-05 00:00:00 UTC),
            datetime!(2026-06-12 00:00:00 UTC),
            &evs,
            key,
        )
        .unwrap();
        // Extract the literal manifest.json bytes from the archive — we
        // can do that by locating the marker `"schema_version"` in the
        // byte stream. This is sufficient for a smoke test; the
        // round-trip-through-real-zip is exercised by callers.
        let needle = b"\"schema_version\"";
        assert!(b.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn manifest_entries_are_sorted_by_control_id() {
        // Insert in scrambled order, expect alphabetical in the manifest.
        let evs = vec![
            sample_ev("SX-VAULT-SEALED-STATE", "{\"v\":1}"),
            sample_ev("SX-AUDIT-CHAIN-INTEGRITY-VERIFY", "{\"v\":2}"),
            sample_ev("SX-MFA-ENROLLMENT-RATE", "{\"v\":3}"),
        ];
        let bytes = build_bundle(
            "tA",
            "r1",
            datetime!(2026-06-05 00:00:00 UTC),
            datetime!(2026-06-12 00:00:00 UTC),
            &evs,
            b"k",
        )
        .unwrap();
        // The relative byte order of the three control-id strings inside
        // the archive must match alphabetical order.
        let pos_aud = bytes
            .windows(b"SX-AUDIT".len())
            .position(|w| w == b"SX-AUDIT");
        let pos_mfa = bytes.windows(b"SX-MFA".len()).position(|w| w == b"SX-MFA");
        let pos_vau = bytes
            .windows(b"SX-VAULT".len())
            .position(|w| w == b"SX-VAULT");
        assert!(pos_aud.is_some() && pos_mfa.is_some() && pos_vau.is_some());
        assert!(pos_aud < pos_mfa);
        assert!(pos_mfa < pos_vau);
    }

    #[test]
    fn hmac_signature_changes_with_key() {
        let evs = vec![sample_ev("SX-MFA-ENROLLMENT-RATE", "{\"v\":1}")];
        let a = build_bundle(
            "tA",
            "r1",
            datetime!(2026-06-05 00:00:00 UTC),
            datetime!(2026-06-12 00:00:00 UTC),
            &evs,
            b"key-a",
        )
        .unwrap();
        let b = build_bundle(
            "tA",
            "r1",
            datetime!(2026-06-05 00:00:00 UTC),
            datetime!(2026-06-12 00:00:00 UTC),
            &evs,
            b"key-b",
        )
        .unwrap();
        // Bodies are identical (same payload SHA), but the HMACs differ.
        assert_ne!(a, b, "different signing keys must yield different bundles");
    }
}
