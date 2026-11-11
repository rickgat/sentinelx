//! Ship collected evidence artifacts to an S3-like object store.
//!
//! This module is intentionally split into:
//!
//! - [`EvidenceSink`]: a tiny async trait describing what a destination
//!   must be able to do — receive a `(key, body, tags)` tuple.
//! - [`MockSink`]: an in-memory sink used by the unit tests (and the CLI
//!   `Ship` subcommand for dry-run / offline operation).
//! - [`sdk::SdkS3Sink`]: the production `aws-sdk-s3`-backed sink. Opt-in
//!   from the CLI via `sx evidence ship --real`.
//! - [`ship_directory`]: the orchestrator that walks a directory of
//!   `*.json` artifacts, uploads each one with a stable key + tag set,
//!   and produces an [`EvidenceManifest`].
//!
//! ## Security
//!
//! The sink trait surface intentionally never accepts or stores AWS
//! credentials — those are the responsibility of the real adapter and
//! must be passed via the SDK's default credential chain. No code in
//! this module logs AWS keys, secrets, or session tokens. Errors emitted
//! by sinks must follow the same rule: never include credential
//! material in [`ShipError::Sink`] messages.

pub mod sdk;

pub use sdk::SdkS3Sink;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use super::manifest::{EvidenceManifest, ManifestEntry};

/// Errors returned by the shipper and sink implementations.
#[derive(Debug, Error)]
pub enum ShipError {
    /// An I/O error occurred while reading the source directory.
    #[error("io error at {path}: {source}")]
    Io {
        /// Path that triggered the failure.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The source directory contained zero `*.json` artifacts.
    #[error("source directory contains no .json artifacts: {0}")]
    EmptyDirectory(PathBuf),

    /// An uploaded artifact was not valid JSON.
    #[error("artifact {path} is not valid JSON: {source}")]
    InvalidArtifact {
        /// Path of the offending artifact.
        path: PathBuf,
        /// Parse error from `serde_json`.
        #[source]
        source: serde_json::Error,
    },

    /// Timestamp formatting failed.
    #[error("timestamp formatting failed: {0}")]
    Time(String),

    /// JSON serialization failed.
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),

    /// The destination sink rejected the upload.
    ///
    /// Implementations MUST scrub credential material from the message.
    #[error("sink rejected upload: {0}")]
    Sink(String),
}

/// A destination capable of receiving evidence artifact uploads.
///
/// Implementations are expected to be cheap to clone (or wrap a shared
/// connection pool internally) and safe to share between async tasks.
#[async_trait]
pub trait EvidenceSink: Send + Sync {
    /// Upload `body` to `key`, attaching the supplied `tags`.
    ///
    /// Tags follow the AWS S3 object-tag convention: simple `(key, value)`
    /// pairs. Implementations MUST NOT log tag values in plain text if
    /// they happen to contain sensitive material.
    ///
    /// # Errors
    /// Returns [`ShipError::Sink`] on any transport failure. The error
    /// message MUST NOT include AWS credentials.
    async fn ship(
        &self,
        key: &str,
        body: &[u8],
        tags: &[(String, String)],
    ) -> Result<(), ShipError>;
}

/// A single recorded upload, captured by [`MockSink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedUpload {
    /// Destination key the body was shipped to.
    pub key: String,
    /// Raw bytes that were shipped.
    pub body: Vec<u8>,
    /// Tags attached to the upload, in the order they were supplied.
    pub tags: Vec<(String, String)>,
}

/// In-memory [`EvidenceSink`] used by the test-suite (and the CLI
/// `evidence ship` subcommand until the real S3 adapter lands).
///
/// All uploads are recorded into an internal `Vec` and can be retrieved
/// via [`MockSink::uploads`].
#[derive(Debug, Default)]
pub struct MockSink {
    uploads: Mutex<Vec<RecordedUpload>>,
}

impl MockSink {
    /// Construct an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded uploads. Returns an empty vec on lock
    /// poisoning rather than panicking.
    #[must_use]
    pub fn uploads(&self) -> Vec<RecordedUpload> {
        self.uploads.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Convenience: number of recorded uploads.
    #[must_use]
    pub fn upload_count(&self) -> usize {
        self.uploads.lock().map(|g| g.len()).unwrap_or(0)
    }
}

#[async_trait]
impl EvidenceSink for MockSink {
    async fn ship(
        &self,
        key: &str,
        body: &[u8],
        tags: &[(String, String)],
    ) -> Result<(), ShipError> {
        let rec = RecordedUpload {
            key: key.to_owned(),
            body: body.to_owned(),
            tags: tags.to_vec(),
        };
        match self.uploads.lock() {
            Ok(mut g) => {
                g.push(rec);
                Ok(())
            }
            Err(_) => Err(ShipError::Sink("mock sink lock poisoned".into())),
        }
    }
}

/// Walk every `*.json` artifact in `from`, ship each to `sink`, and
/// return the resulting [`EvidenceManifest`].
///
/// The manifest itself is also shipped as the final upload at
/// `<bucket_prefix>/<framework>/<yyyymmdd>/manifest.json`, so an
/// auditor pulling just the manifest can verify every referenced
/// artifact by its SHA-256.
///
/// # Key & tag scheme
///
/// - Key: `<bucket_prefix>/<framework>/<yyyymmdd>/<filename>` where
///   `<yyyymmdd>` is the UTC date at which shipment started.
/// - Tags applied to every artifact upload:
///     - `framework` — the supplied framework label
///     - `control_id` — taken from the artifact JSON's `control_id` field
///     - `collected_at` — RFC-3339 timestamp from the artifact JSON
///
/// # Errors
/// - [`ShipError::Io`] if `from` cannot be read or an entry stats fails.
/// - [`ShipError::EmptyDirectory`] if `from` contains no `*.json` files.
/// - [`ShipError::InvalidArtifact`] if a `.json` file fails to parse.
/// - [`ShipError::Sink`] propagated from the supplied sink.
pub async fn ship_directory(
    sink: &dyn EvidenceSink,
    from: &Path,
    bucket_prefix: &str,
    framework: &str,
) -> Result<EvidenceManifest, ShipError> {
    let started = OffsetDateTime::now_utc();
    let started_str = started
        .format(&Rfc3339)
        .map_err(|e| ShipError::Time(e.to_string()))?;
    let date_segment = format_yyyymmdd(started)?;

    let mut artifacts = collect_json_files(from)?;
    if artifacts.is_empty() {
        return Err(ShipError::EmptyDirectory(from.to_path_buf()));
    }
    // Stable order so manifests are reproducible.
    artifacts.sort();

    let run_id = Uuid::new_v4().to_string();
    let mut manifest = EvidenceManifest::new(run_id, framework.to_owned(), started_str);

    let prefix_trimmed = bucket_prefix.trim_end_matches('/');

    for path in &artifacts {
        let bytes = fs::read(path).map_err(|source| ShipError::Io {
            path: path.clone(),
            source,
        })?;

        let (control_id, collected_at) = parse_artifact_meta(path, &bytes)?;

        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("artifact.json");
        let key = format!("{prefix_trimmed}/{framework}/{date_segment}/{file_name}");

        let tags = vec![
            ("framework".to_owned(), framework.to_owned()),
            ("control_id".to_owned(), control_id.clone()),
            ("collected_at".to_owned(), collected_at),
        ];

        sink.ship(&key, &bytes, &tags).await?;

        let sha = sha256_hex(&bytes);
        manifest.push(ManifestEntry {
            control_id,
            s3_key: key,
            sha256: sha,
        });
    }

    let finished = OffsetDateTime::now_utc();
    manifest.finished_at = finished
        .format(&Rfc3339)
        .map_err(|e| ShipError::Time(e.to_string()))?;

    // Ship the manifest itself as the final upload.
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_key = format!("{prefix_trimmed}/{framework}/{date_segment}/manifest.json");
    let manifest_tags = vec![
        ("framework".to_owned(), framework.to_owned()),
        ("control_id".to_owned(), "_manifest".to_owned()),
        ("collected_at".to_owned(), manifest.finished_at.clone()),
    ];
    sink.ship(&manifest_key, &manifest_bytes, &manifest_tags)
        .await?;

    Ok(manifest)
}

fn collect_json_files(dir: &Path) -> Result<Vec<PathBuf>, ShipError> {
    let read = fs::read_dir(dir).map_err(|source| ShipError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut out = Vec::new();
    for entry in read {
        let entry = entry.map_err(|source| ShipError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext == "json")
        {
            out.push(path);
        }
    }
    Ok(out)
}

fn parse_artifact_meta(path: &Path, bytes: &[u8]) -> Result<(String, String), ShipError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|source| ShipError::InvalidArtifact {
        path: path.to_path_buf(),
        source,
    })?;
    let control_id = v
        .get("control_id")
        .and_then(Value::as_str)
        .unwrap_or("_unknown")
        .to_owned();
    let collected_at = v
        .get("collected_at")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    Ok((control_id, collected_at))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn format_yyyymmdd(ts: OffsetDateTime) -> Result<String, ShipError> {
    let date = ts.date();
    let y = date.year();
    let m: u8 = date.month().into();
    let d = date.day();
    // i32::abs_diff on years would be unusual; clamp the formatting to
    // a 4-digit year for sanity.
    let y_u = u32::try_from(y).map_err(|e| ShipError::Time(e.to_string()))?;
    Ok(format!("{y_u:04}{m:02}{d:02}"))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use serde_json::json;

    use super::*;

    fn tmpdir(label: &str) -> PathBuf {
        let nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("sx-ship-{label}-{nano}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_artifact(dir: &Path, name: &str, control_id: &str) -> PathBuf {
        let p = dir.join(name);
        let body = json!({
            "control_id": control_id,
            "framework": "soc2",
            "collected_at": "2026-05-31T12:00:00Z",
            "evidence": {"ok": true}
        });
        let mut f = File::create(&p).unwrap();
        f.write_all(serde_json::to_string_pretty(&body).unwrap().as_bytes())
            .unwrap();
        p
    }

    #[tokio::test]
    async fn mock_sink_records_uploads() {
        let sink = MockSink::new();
        sink.ship(
            "s3://b/k1",
            b"hello",
            &[("framework".into(), "soc2".into())],
        )
        .await
        .unwrap();
        sink.ship("s3://b/k2", b"world", &[]).await.unwrap();
        let ups = sink.uploads();
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0].key, "s3://b/k1");
        assert_eq!(ups[0].body, b"hello");
        assert_eq!(
            ups[0].tags,
            vec![("framework".to_owned(), "soc2".to_owned())]
        );
        assert_eq!(ups[1].key, "s3://b/k2");
        assert_eq!(sink.upload_count(), 2);
    }

    #[tokio::test]
    async fn ship_directory_uploads_each_json_plus_manifest() {
        let dir = tmpdir("upload-each");
        write_artifact(&dir, "soc2__CC1_1.json", "CC1.1");
        write_artifact(&dir, "soc2__CC6_1.json", "CC6.1");
        write_artifact(&dir, "soc2__CC7_2.json", "CC7.2");
        // Non-JSON should be ignored.
        let mut f = File::create(dir.join("note.txt")).unwrap();
        f.write_all(b"ignored").unwrap();

        let sink = MockSink::new();
        let manifest = ship_directory(&sink, &dir, "s3://bucket/evidence", "soc2")
            .await
            .unwrap();

        // 3 artifacts + 1 manifest = 4 uploads.
        assert_eq!(sink.upload_count(), 4);
        assert_eq!(manifest.artifacts.len(), 3);
        assert_eq!(manifest.framework, "soc2");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn ship_directory_attaches_required_tags() {
        let dir = tmpdir("tags");
        write_artifact(&dir, "soc2__CC1_1.json", "CC1.1");

        let sink = MockSink::new();
        let _ = ship_directory(&sink, &dir, "s3://bucket/ev", "soc2")
            .await
            .unwrap();
        let ups = sink.uploads();
        // First upload is the artifact, second is the manifest.
        let artifact_tags = &ups[0].tags;
        let names: Vec<&str> = artifact_tags.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["framework", "control_id", "collected_at"]);
        let by_key: std::collections::HashMap<&str, &str> = artifact_tags
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(by_key.get("framework"), Some(&"soc2"));
        assert_eq!(by_key.get("control_id"), Some(&"CC1.1"));
        assert_eq!(by_key.get("collected_at"), Some(&"2026-05-31T12:00:00Z"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn ship_directory_writes_manifest_json_as_final_upload() {
        let dir = tmpdir("manifest");
        write_artifact(&dir, "soc2__CC1_1.json", "CC1.1");
        write_artifact(&dir, "soc2__CC6_1.json", "CC6.1");

        let sink = MockSink::new();
        let m = ship_directory(&sink, &dir, "s3://b/ev", "soc2")
            .await
            .unwrap();
        let ups = sink.uploads();
        let last = ups.last().unwrap();
        assert!(
            last.key.ends_with("/manifest.json"),
            "manifest key was {}",
            last.key
        );
        let parsed: EvidenceManifest = serde_json::from_slice(&last.body).unwrap();
        assert_eq!(parsed.artifacts.len(), 2);
        assert_eq!(parsed.framework, "soc2");
        // The returned manifest and the shipped one must agree.
        assert_eq!(parsed, m);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn ship_directory_rejects_empty_directory() {
        let dir = tmpdir("empty");
        let sink = MockSink::new();
        let err = ship_directory(&sink, &dir, "s3://b/ev", "soc2")
            .await
            .unwrap_err();
        assert!(matches!(err, ShipError::EmptyDirectory(_)));
        assert_eq!(sink.upload_count(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn ship_directory_uses_expected_key_format() {
        let dir = tmpdir("keyfmt");
        write_artifact(&dir, "soc2__CC1_1.json", "CC1.1");

        let sink = MockSink::new();
        let _ = ship_directory(&sink, &dir, "s3://bucket/evidence/", "soc2")
            .await
            .unwrap();
        let ups = sink.uploads();
        let key = &ups[0].key;
        // Pattern: s3://bucket/evidence/soc2/YYYYMMDD/soc2__CC1_1.json
        let parts: Vec<&str> = key.split('/').collect();
        // ["s3:", "", "bucket", "evidence", "soc2", "YYYYMMDD", "filename"]
        assert_eq!(parts.first().copied(), Some("s3:"));
        assert_eq!(parts.get(2).copied(), Some("bucket"));
        assert_eq!(parts.get(3).copied(), Some("evidence"));
        assert_eq!(parts.get(4).copied(), Some("soc2"));
        let date = parts.get(5).copied().unwrap_or("");
        assert_eq!(date.len(), 8, "date segment was {date}");
        assert!(date.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(parts.last().copied(), Some("soc2__CC1_1.json"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn ship_directory_rejects_invalid_json_artifact() {
        let dir = tmpdir("badjson");
        let p = dir.join("broken.json");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"not json").unwrap();

        let sink = MockSink::new();
        let err = ship_directory(&sink, &dir, "s3://b/ev", "soc2")
            .await
            .unwrap_err();
        assert!(matches!(err, ShipError::InvalidArtifact { .. }));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn ship_directory_assigns_unique_run_id() {
        let dir = tmpdir("runid");
        write_artifact(&dir, "x.json", "CC1.1");
        let sink = MockSink::new();
        let m1 = ship_directory(&sink, &dir, "s3://b/ev", "soc2")
            .await
            .unwrap();
        let m2 = ship_directory(&sink, &dir, "s3://b/ev", "soc2")
            .await
            .unwrap();
        assert_ne!(m1.run_id, m2.run_id);
        fs::remove_dir_all(&dir).unwrap();
    }
}
