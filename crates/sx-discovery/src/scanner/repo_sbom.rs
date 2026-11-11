//! Repository SBOM scanner driven by [syft](https://github.com/anchore/syft).
//!
//! Given a path to a git checkout (or any directory tree), shells out to
//! `syft` and asks for a `CycloneDX` JSON SBOM, then parses it into the
//! flattened [`CycloneDx`] value object below.
//!
//! ## Why a subprocess?
//!
//! `syft` ships its own ecosystem catalogers (Cargo, npm, Go modules,
//! Maven, …) and updates them continuously. Embedding it would couple
//! ``SentinelX``'s release cadence to `syft`'s. The shell-out matches the
//! design used by the SCA, container, secret, and `IaC` scanners in this
//! crate.
//!
//! ## Safety
//!
//! - The binary path is captured at construction time. `detect()` searches
//!   `$PATH` once during initialisation; after that, only the absolute
//!   resolved path is used (no further `PATH` lookups).
//! - `tokio::process::Command` performs `execvp`-style execution; there is
//!   no shell interpolation.
//! - Repository paths are not interpolated into a shell string — they pass
//!   as a single argv entry.
//! - Parse failures degrade to [`ScannerError::Parse`], never a panic.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use tokio::process::Command;
use tokio::time::timeout;

/// Errors specific to the SBOM scanner.
///
/// Kept as a thin local enum (rather than reusing
/// [`crate::error::DiscoveryError`]) because the scanner is consumed by
/// non-engagement code paths (e.g. CLI sbom-print, supply-chain risk
/// pipeline) where the broader discovery error vocabulary would force
/// callers to handle variants that cannot occur here.
#[derive(Debug, Error)]
pub enum ScannerError {
    /// The `syft` binary failed to launch.
    #[error("syft spawn failed: {0}")]
    Spawn(String),
    /// The `syft` subprocess exited with a non-zero status.
    #[error("syft exited with status {status}: {stderr}")]
    NonZeroExit {
        /// Exit status string (e.g. `"exit code: 2"`).
        status: String,
        /// First 256 bytes of stderr, sanitised.
        stderr: String,
    },
    /// Stdout could not be parsed as `CycloneDX` JSON.
    #[error("cyclonedx parse error: {0}")]
    Parse(String),
    /// The wall-clock budget expired.
    #[error("syft execution timed out")]
    Timeout,
    /// The configured repo path does not exist or is not a directory.
    #[error("invalid repo path: {0}")]
    InvalidRepoPath(String),
}

/// Default wall-clock budget for a single syft invocation.
pub const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum number of stderr bytes captured into an error message.
const STDERR_PREVIEW_BYTES: usize = 256;

/// Flattened `CycloneDX` SBOM. Only the fields `SentinelX` consumes
/// downstream are projected; everything else is discarded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CycloneDx {
    /// `CycloneDX` spec version string (e.g. `"1.5"`).
    pub spec_version: Option<String>,
    /// Serial number assigned by the producer.
    pub serial_number: Option<String>,
    /// Components inventoried in the SBOM.
    pub components: Vec<Component>,
}

/// A single component entry inside the SBOM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// Component name (e.g. `"tokio"`).
    pub name: String,
    /// Component version, when reported.
    pub version: Option<String>,
    /// Package URL identifier, when reported.
    pub purl: Option<String>,
    /// Licence identifiers (SPDX expressions or free-text names).
    pub licenses: Vec<String>,
}

/// SBOM scanner that drives `syft` over a repository checkout.
#[derive(Debug, Clone)]
pub struct RepoSbomScanner {
    /// Absolute path to the resolved `syft` binary.
    pub syft_binary: PathBuf,
    /// Wall-clock budget per invocation.
    pub exec_timeout: Duration,
}

impl RepoSbomScanner {
    /// Build a scanner directly from an absolute path. Use this when the
    /// binary path is supplied through configuration.
    #[must_use]
    pub const fn new(syft_binary: PathBuf) -> Self {
        Self {
            syft_binary,
            exec_timeout: DEFAULT_EXEC_TIMEOUT,
        }
    }

    /// Override the default execution timeout.
    #[must_use]
    pub const fn with_timeout(mut self, exec_timeout: Duration) -> Self {
        self.exec_timeout = exec_timeout;
        self
    }

    /// Locate `syft` on `$PATH`. Returns `None` when the binary is missing,
    /// not executable, or `$PATH` is empty.
    #[must_use]
    pub fn detect() -> Option<Self> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let candidate = dir.join("syft");
            if is_executable_file(&candidate) {
                return Some(Self::new(candidate));
            }
            let candidate_exe = dir.join("syft.exe");
            if is_executable_file(&candidate_exe) {
                return Some(Self::new(candidate_exe));
            }
        }
        None
    }

    /// Run `syft <repo_path> -o cyclonedx-json` and parse the resulting
    /// SBOM.
    pub async fn scan(&self, repo_path: &Path) -> Result<CycloneDx, ScannerError> {
        if !repo_path.is_dir() {
            return Err(ScannerError::InvalidRepoPath(
                repo_path.display().to_string(),
            ));
        }
        let mut cmd = Command::new(&self.syft_binary);
        cmd.arg(repo_path).arg("-o").arg("cyclonedx-json").arg("-q");
        cmd.kill_on_drop(true);

        let exec = cmd.output();
        let output = timeout(self.exec_timeout, exec)
            .await
            .map_err(|_| ScannerError::Timeout)?
            .map_err(|e| ScannerError::Spawn(e.to_string()))?;

        if !output.status.success() {
            let preview_len = output.stderr.len().min(STDERR_PREVIEW_BYTES);
            let preview = output
                .stderr
                .get(..preview_len)
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .unwrap_or_default();
            return Err(ScannerError::NonZeroExit {
                status: output.status.to_string(),
                stderr: preview,
            });
        }
        parse_cyclonedx(&output.stdout)
    }
}

/// Parse a `CycloneDX` JSON byte slice into a [`CycloneDx`].
///
/// Tolerates missing optional fields (`version`, `purl`, `licenses`) by
/// projecting them as `None`/`Vec::new()`. Fully malformed JSON returns
/// [`ScannerError::Parse`].
pub fn parse_cyclonedx(bytes: &[u8]) -> Result<CycloneDx, ScannerError> {
    let doc: RawCycloneDx =
        serde_json::from_slice(bytes).map_err(|e| ScannerError::Parse(e.to_string()))?;
    let components = doc
        .components
        .unwrap_or_default()
        .into_iter()
        .map(Component::from)
        .collect();
    Ok(CycloneDx {
        spec_version: doc.spec_version,
        serial_number: doc.serial_number,
        components,
    })
}

fn is_executable_file(p: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCycloneDx {
    spec_version: Option<String>,
    serial_number: Option<String>,
    components: Option<Vec<RawComponent>>,
}

#[derive(Debug, Deserialize)]
struct RawComponent {
    name: Option<String>,
    version: Option<String>,
    purl: Option<String>,
    #[serde(default)]
    licenses: Vec<RawLicenseEntry>,
}

#[derive(Debug, Deserialize)]
struct RawLicenseEntry {
    #[serde(default)]
    license: Option<RawLicense>,
    #[serde(default)]
    expression: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawLicense {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

impl From<RawComponent> for Component {
    fn from(raw: RawComponent) -> Self {
        let licenses: Vec<String> = raw
            .licenses
            .into_iter()
            .filter_map(|entry| {
                if let Some(expr) = entry.expression {
                    return Some(expr);
                }
                let lic = entry.license?;
                lic.id.or(lic.name)
            })
            .collect();
        Self {
            name: raw.name.unwrap_or_default(),
            version: raw.version,
            purl: raw.purl,
            licenses,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn detect_with_empty_path_returns_none() {
        // Snapshot existing PATH so we can restore it.
        let saved = std::env::var_os("PATH");
        std::env::set_var("PATH", "");
        let outcome = RepoSbomScanner::detect();
        // Restore before asserting so a failure does not leak state.
        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        assert!(
            outcome.is_none(),
            "empty PATH must not locate a syft binary"
        );
    }

    #[test]
    fn parse_cyclonedx_fixture_extracts_components() {
        let payload = br#"{
          "bomFormat": "CycloneDX",
          "specVersion": "1.5",
          "serialNumber": "urn:uuid:12345678-aaaa-bbbb-cccc-1234567890ab",
          "components": [
            {
              "type": "library",
              "name": "tokio",
              "version": "1.40.0",
              "purl": "pkg:cargo/tokio@1.40.0",
              "licenses": [
                {"license": {"id": "MIT"}}
              ]
            },
            {
              "type": "library",
              "name": "serde",
              "version": "1.0.210",
              "purl": "pkg:cargo/serde@1.0.210",
              "licenses": [
                {"expression": "MIT OR Apache-2.0"}
              ]
            },
            {
              "type": "library",
              "name": "openssl-sys",
              "version": "0.9.103",
              "licenses": [
                {"license": {"name": "Apache License, Version 2.0"}}
              ]
            }
          ]
        }"#;
        let sbom = parse_cyclonedx(payload).unwrap();
        assert_eq!(sbom.spec_version.as_deref(), Some("1.5"));
        assert_eq!(
            sbom.serial_number.as_deref(),
            Some("urn:uuid:12345678-aaaa-bbbb-cccc-1234567890ab")
        );
        assert_eq!(sbom.components.len(), 3);

        let tokio = &sbom.components[0];
        assert_eq!(tokio.name, "tokio");
        assert_eq!(tokio.version.as_deref(), Some("1.40.0"));
        assert_eq!(tokio.purl.as_deref(), Some("pkg:cargo/tokio@1.40.0"));
        assert_eq!(tokio.licenses, vec!["MIT".to_owned()]);

        let serde = &sbom.components[1];
        assert_eq!(serde.name, "serde");
        assert_eq!(serde.licenses, vec!["MIT OR Apache-2.0".to_owned()]);

        let openssl = &sbom.components[2];
        assert_eq!(openssl.name, "openssl-sys");
        assert!(openssl.purl.is_none());
        assert_eq!(
            openssl.licenses,
            vec!["Apache License, Version 2.0".to_owned()]
        );
    }

    #[test]
    fn parse_empty_components_returns_empty_vec() {
        let payload = br#"{
          "bomFormat": "CycloneDX",
          "specVersion": "1.5",
          "components": []
        }"#;
        let sbom = parse_cyclonedx(payload).unwrap();
        assert!(sbom.components.is_empty());
        assert_eq!(sbom.spec_version.as_deref(), Some("1.5"));
    }

    #[test]
    fn parse_omitted_components_returns_empty_vec() {
        let payload = br#"{
          "bomFormat": "CycloneDX",
          "specVersion": "1.5"
        }"#;
        let sbom = parse_cyclonedx(payload).unwrap();
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn parse_malformed_json_returns_parse_error() {
        let err = parse_cyclonedx(b"not json at all").unwrap_err();
        assert!(matches!(err, ScannerError::Parse(_)));
        let err2 = parse_cyclonedx(b"").unwrap_err();
        assert!(matches!(err2, ScannerError::Parse(_)));
        let err3 = parse_cyclonedx(b"{\"components\": \"oops\"}").unwrap_err();
        assert!(matches!(err3, ScannerError::Parse(_)));
    }

    #[test]
    fn parse_component_missing_name_yields_empty_string() {
        let payload = br#"{
          "specVersion": "1.5",
          "components": [{"type": "library", "version": "0.1.0"}]
        }"#;
        let sbom = parse_cyclonedx(payload).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "");
        assert_eq!(sbom.components[0].version.as_deref(), Some("0.1.0"));
        assert!(sbom.components[0].licenses.is_empty());
    }

    #[tokio::test]
    async fn scan_rejects_nonexistent_path() {
        let scanner = RepoSbomScanner::new(PathBuf::from("/usr/local/bin/syft"));
        let bogus = PathBuf::from("/this/path/does/not/exist/for-sentinelx-test");
        let err = scanner.scan(&bogus).await.unwrap_err();
        assert!(matches!(err, ScannerError::InvalidRepoPath(_)));
    }

    #[tokio::test]
    #[ignore = "Requires syft binary"]
    async fn live_syft_scan_of_current_repo_produces_components() {
        let scanner = RepoSbomScanner::detect().expect("syft binary present");
        // Scan the current package directory — small and self-contained.
        let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let sbom = scanner.scan(&here).await.expect("scan succeeds");
        assert!(
            !sbom.components.is_empty(),
            "expected at least one component from cargo manifest"
        );
    }
}
