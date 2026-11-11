//! Evidence collection for compliance frameworks.
//!
//! This module exposes the [`EvidenceCollector`] trait and the
//! [`EvidenceArtifact`] / [`EvidenceError`] data types that the
//! `sx-cli evidence` subcommands use to produce per-control JSON
//! artifacts.
//!
//! Collectors are deliberately small and read-only: they only inspect
//! the local filesystem (counting files, hashing config samples, etc.)
//! so they are deterministic and safe to run in CI pipelines without
//! credentials.
//!
//! ## Layout
//!
//! ```text
//! evidence/
//!   mod.rs       ── EvidenceCollector trait + EvidenceArtifact/Error.
//!   soc2.rs      ── 5 starter collectors for SOC 2 TSC.
//!   iso27001.rs  ── 5 starter collectors for ISO/IEC 27001:2022 Annex A.
//! ```

pub mod iso27001;
pub mod manifest;
pub mod s3_ship;
pub mod soc2;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Error surface for evidence collection.
#[derive(Debug, Error)]
pub enum EvidenceError {
    /// An I/O error occurred while reading a source file or directory.
    #[error("io error reading {path}: {source}")]
    Io {
        /// Path that triggered the failure.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// A required source did not exist on disk.
    #[error("source not found: {0}")]
    NotFound(PathBuf),

    /// JSON serialisation failed.
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),

    /// Timestamp formatting failed.
    #[error("timestamp formatting failed: {0}")]
    Time(String),

    /// Internal / programmer error.
    #[error("internal: {0}")]
    Internal(String),
}

/// A single evidence artifact produced by an [`EvidenceCollector`].
///
/// Artifacts are designed to be persisted as standalone JSON files in
/// the operator-supplied output directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    /// Framework-local control identifier (e.g. `"CC6.1"`, `"A.8.2"`).
    pub control_id: String,
    /// Framework code matching [`sx_compliance::model::framework::Framework`]
    /// — `"soc2"` or `"iso27001"`.
    pub framework: String,
    /// RFC 3339 UTC timestamp at which the artifact was collected.
    pub collected_at: String,
    /// Free-form JSON object containing the deterministic data points
    /// gathered for this control.
    pub evidence: serde_json::Value,
}

impl EvidenceArtifact {
    /// Construct a new artifact, stamping `collected_at` from the
    /// supplied `now`. Provided as an explicit argument so the unit
    /// tests can stamp a deterministic time.
    ///
    /// # Errors
    /// Returns [`EvidenceError::Time`] if the supplied timestamp cannot
    /// be formatted as RFC 3339 (effectively never in practice).
    pub fn new(
        control_id: impl Into<String>,
        framework: impl Into<String>,
        now: OffsetDateTime,
        evidence: serde_json::Value,
    ) -> Result<Self, EvidenceError> {
        let collected_at = now
            .format(&Rfc3339)
            .map_err(|e| EvidenceError::Time(e.to_string()))?;
        Ok(Self {
            control_id: control_id.into(),
            framework: framework.into(),
            collected_at,
            evidence,
        })
    }
}

/// A collector produces an [`EvidenceArtifact`] for a single control.
///
/// Implementations must be deterministic — given the same filesystem
/// state, the JSON payload should compare equal between runs (the
/// `collected_at` timestamp is the only intentional non-determinism).
pub trait EvidenceCollector {
    /// Framework-local control identifier.
    fn id(&self) -> &str;

    /// Framework code (e.g. `"soc2"`, `"iso27001"`).
    fn frame(&self) -> &str;

    /// Gather the data points for this control.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] on any I/O or serialisation failure.
    fn collect(&self) -> Result<EvidenceArtifact, EvidenceError>;
}

/// Count files in `dir` whose name matches the provided extension
/// (case-sensitive, no dot). Returns `0` if the directory does not exist.
///
/// # Errors
/// Returns [`EvidenceError::Io`] on any failure other than `NotFound`,
/// which is treated as a count of `0`.
pub fn count_files_with_extension(dir: &Path, extension: &str) -> Result<u64, EvidenceError> {
    let read = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(source) => {
            return Err(EvidenceError::Io {
                path: dir.to_path_buf(),
                source,
            })
        }
    };
    let mut n: u64 = 0;
    for entry in read {
        let entry = entry.map_err(|source| EvidenceError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext == extension)
        {
            n = n.saturating_add(1);
        }
    }
    Ok(n)
}

/// Compute the lowercase hex SHA-256 of the bytes at `path`.
///
/// Returns `None` (wrapped in `Ok`) when the file does not exist so
/// collectors degrade gracefully on partially-populated checkouts.
///
/// # Errors
/// Returns [`EvidenceError::Io`] on any read failure other than `NotFound`.
pub fn sha256_of_file(path: &Path) -> Result<Option<String>, EvidenceError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(EvidenceError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Ok(Some(hex::encode(digest)))
}

/// Check whether `path` exists (file or directory).
#[must_use]
pub fn path_exists(path: &Path) -> bool {
    path.exists()
}

/// Locate the workspace root by walking parents until a `Cargo.toml`
/// containing `[workspace]` is found. Falls back to the current
/// directory when the walk is unsuccessful.
#[must_use]
pub fn workspace_root() -> PathBuf {
    // Prefer the `CARGO_MANIFEST_DIR` of this crate, walked upward to
    // the workspace marker. Using the env var keeps tests stable
    // regardless of the working directory the runner chose.
    let manifest_dir = env_var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let start = if manifest_dir.is_empty() {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        PathBuf::from(manifest_dir)
    };
    let mut cur: &Path = start.as_path();
    loop {
        let candidate = cur.join("Cargo.toml");
        if candidate.is_file() {
            if let Ok(contents) = fs::read_to_string(&candidate) {
                if contents.contains("[workspace]") {
                    return cur.to_path_buf();
                }
            }
        }
        match cur.parent() {
            Some(parent) => cur = parent,
            None => return start,
        }
    }
}

#[allow(clippy::disallowed_methods)]
fn env_var(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use serde_json::json;
    use time::macros::datetime;

    use super::*;

    fn tmpdir(label: &str) -> PathBuf {
        let nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("sx-evi-{label}-{nano}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn artifact_serialises_with_iso_timestamp() {
        let ts = datetime!(2026-05-31 12:00:00 UTC);
        let a = EvidenceArtifact::new("CC1.1", "soc2", ts, json!({"ok": true})).unwrap();
        assert_eq!(a.control_id, "CC1.1");
        assert_eq!(a.framework, "soc2");
        assert_eq!(a.collected_at, "2026-05-31T12:00:00Z");
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("\"control_id\":\"CC1.1\""));
    }

    #[test]
    fn count_files_returns_zero_when_missing() {
        let p = std::env::temp_dir().join("definitely-not-here-sx-evi");
        let _ = fs::remove_dir_all(&p);
        assert_eq!(count_files_with_extension(&p, "md").unwrap(), 0);
    }

    #[test]
    fn count_files_counts_matching_extension() {
        let dir = tmpdir("count");
        for name in ["a.md", "b.md", "c.yaml"] {
            let mut f = File::create(dir.join(name)).unwrap();
            f.write_all(b"x").unwrap();
        }
        assert_eq!(count_files_with_extension(&dir, "md").unwrap(), 2);
        assert_eq!(count_files_with_extension(&dir, "yaml").unwrap(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sha256_of_missing_file_is_none() {
        let p = std::env::temp_dir().join("sx-evi-nope.bin");
        let _ = fs::remove_file(&p);
        assert!(sha256_of_file(&p).unwrap().is_none());
    }

    #[test]
    fn sha256_of_known_bytes_is_stable() {
        let dir = tmpdir("sha");
        let p = dir.join("payload.bin");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"hello").unwrap();
        let d = sha256_of_file(&p).unwrap().unwrap();
        assert_eq!(
            d,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
