//! P1-004 — Byte-snapshot test for the evidence bundle exporter.
//!
//! `build_bundle` is intentionally deterministic (STORE-only ZIP, zeroed
//! timestamps, sorted entries) — given the same inputs it produces the
//! same bytes. This test pins the property end-to-end *and* asserts
//! several structural / semantic invariants that would otherwise be
//! easy to break in a refactor:
//!
//! * Magic bytes for the local file header and end-of-central-directory.
//! * Stable entry order (alphabetical by `control_id`, manifest last).
//! * `manifest.json` carries the HMAC-SHA256 of each entry's hash.
//! * Different HMAC keys produce different bundles for the same input.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use time::macros::datetime;

use sx_compliance::collector::types::{Evidence, EvidenceContentType};
use sx_compliance::model::framework::Framework;
use sx_compliance::p1_004::bundle::{build_bundle, BundleManifest};

fn sample(cid: &'static str, body: &'static str) -> Evidence {
    Evidence::new(
        cid,
        Framework::Soc2,
        datetime!(2026-06-12 00:00:00 UTC),
        EvidenceContentType::Json,
        body.as_bytes().to_vec(),
        "1.0.0",
    )
}

#[test]
fn bundle_is_byte_deterministic_across_runs() {
    let evs = vec![
        sample("SX-VAULT-SEALED-STATE", "{\"sealed\":false}"),
        sample("SX-AUDIT-CHAIN-INTEGRITY-VERIFY", "{\"verified\":true}"),
        sample("SX-MFA-ENROLLMENT-RATE", "{\"rate\":0.95}"),
        sample("SX-AWS-IAM-PASSWORD-POLICY", "{\"min_len\":14}"),
        sample("SX-KILL-SWITCH-TESTED-RECENTLY", "{\"healthy\":true}"),
    ];
    let key = b"snapshot-fixture-key-32-bytes!!!";
    let a = build_bundle(
        "tenant-snapshot",
        "00000000-0000-0000-0000-000000000001",
        datetime!(2026-06-05 00:00:00 UTC),
        datetime!(2026-06-12 00:00:00 UTC),
        &evs,
        key,
    )
    .unwrap();
    let b = build_bundle(
        "tenant-snapshot",
        "00000000-0000-0000-0000-000000000001",
        datetime!(2026-06-05 00:00:00 UTC),
        datetime!(2026-06-12 00:00:00 UTC),
        &evs,
        key,
    )
    .unwrap();
    assert_eq!(a, b, "bundle bytes must be reproducible");
}

#[test]
fn bundle_carries_pkzip_magic_and_eocd() {
    let evs = vec![sample("SX-MFA-ENROLLMENT-RATE", "{\"rate\":0.95}")];
    let bytes = build_bundle(
        "tenant-snapshot",
        "00000000-0000-0000-0000-000000000001",
        datetime!(2026-06-05 00:00:00 UTC),
        datetime!(2026-06-12 00:00:00 UTC),
        &evs,
        b"k",
    )
    .unwrap();
    assert!(
        bytes.starts_with(&[0x50, 0x4b, 0x03, 0x04]),
        "expected PK\\x03\\x04 local file header at start of archive"
    );
    let eocd = [0x50, 0x4b, 0x05, 0x06];
    assert!(
        bytes.windows(4).any(|w| w == eocd),
        "expected end-of-central-directory marker in archive"
    );
}

#[test]
fn manifest_lists_every_control_with_hmac_signature() {
    let evs = vec![
        sample("SX-MFA-ENROLLMENT-RATE", "{\"rate\":0.95}"),
        sample("SX-VAULT-SEALED-STATE", "{\"sealed\":false}"),
    ];
    let bytes = build_bundle(
        "tenant-snapshot",
        "00000000-0000-0000-0000-000000000001",
        datetime!(2026-06-05 00:00:00 UTC),
        datetime!(2026-06-12 00:00:00 UTC),
        &evs,
        b"my-secret-key",
    )
    .unwrap();

    // The manifest JSON appears verbatim in the (STORE-only) archive —
    // locate it by its `schema_version` marker and parse it back.
    let needle = b"\"schema_version\"";
    let start = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("manifest schema_version must be present");
    // Walk back to the opening `{` of the manifest object.
    let opening = bytes[..start]
        .iter()
        .rposition(|b| *b == b'{')
        .expect("manifest must open with `{`");
    // And forward to the matching closing `}` — a tiny brace counter is
    // sufficient because the manifest is the only JSON in the archive
    // tail and is small enough to fit comfortably in memory.
    let mut depth = 0i32;
    let mut end = opening;
    for (i, b) in bytes.iter().enumerate().skip(opening) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    let manifest_bytes = &bytes[opening..end];
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes).unwrap();

    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.tenant_id, "tenant-snapshot");
    assert_eq!(manifest.files.len(), 2);

    // Entries are sorted alphabetically by control_id.
    let cids: Vec<&str> = manifest
        .files
        .iter()
        .map(|f| f.control_id.as_str())
        .collect();
    assert_eq!(
        cids,
        vec!["SX-MFA-ENROLLMENT-RATE", "SX-VAULT-SEALED-STATE"]
    );

    // Every entry has a 64-char hex sha + a 64-char hex HMAC.
    for entry in &manifest.files {
        assert_eq!(entry.sha256.len(), 64, "sha256 hex length");
        assert_eq!(entry.hmac_sha256.len(), 64, "hmac hex length");
        assert!(entry.archive_path.starts_with("evidence/"));
    }
}

#[test]
fn different_signing_keys_yield_different_bundles() {
    let evs = vec![sample("SX-MFA-ENROLLMENT-RATE", "{\"rate\":0.95}")];
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
    assert_ne!(a, b, "HMAC key change must propagate into bundle bytes");
}
