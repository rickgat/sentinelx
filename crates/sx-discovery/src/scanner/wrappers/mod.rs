//! CLI-subprocess wrappers for third-party security scanners.
//!
//! Each submodule wraps a scanner binary that ships its own engine and rule
//! set. The wrappers are intentionally **thinner** than the [`Scanner`] trait
//! implementations in the parent [`crate::scanner`] module — they
//!
//! - locate (or accept) the binary,
//! - spawn it against a path-on-disk target,
//! - apply a default 5-minute wall-clock budget,
//! - parse the JSON / SARIF stdout into a normalized
//!   [`ScannerFinding`] list,
//! - never panic on malformed output.
//!
//! The wrappers do **not** implement the [`Scanner`] trait — they are a
//! lower-level building block that controllers can compose into richer
//! scanners or run directly from a CLI sub-command.
//!
//! ## Subprocess hygiene
//!
//! - [`tokio::process::Command`] with `kill_on_drop(true)` is used everywhere.
//! - Each invocation is wrapped in [`tokio::time::timeout`].
//! - Targets are validated as existing filesystem paths *before* spawn —
//!   no user-supplied strings ever reach the child's argv.
//! - Stderr is captured and surfaced via
//!   [`ScannerError::ProcessFailed`] when the child exits non-zero
//!   (and stdout is empty).
//!
//! ## Severity normalisation
//!
//! Every wrapper maps its scanner-specific severity vocabulary onto the
//! shared [`Severity`] enum. The mapping tables live in each submodule.
//!
//! [`Scanner`]: crate::service::scanner::Scanner

pub mod checkov;
pub mod dockle;
pub mod kics;
pub mod kubebench;
pub mod testssl;
pub mod tfsec;
pub mod trivy;

use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

pub use checkov::CheckovScanner;
pub use dockle::DockleScanner;
pub use kics::KicsScanner;
pub use kubebench::KubeBenchScanner;
pub use testssl::TestSslScanner;
pub use tfsec::TfsecScanner;
pub use trivy::TrivyScanner;

/// Default per-invocation wall-clock budget shared by every wrapper.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Normalised severity vocabulary used across all wrappers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Highest impact — exploitable, no preconditions.
    Critical,
    /// Exploitable but with limited blast radius or non-default preconditions.
    High,
    /// Material risk; mitigation expected within standard SLA.
    Medium,
    /// Hardening recommendation.
    Low,
    /// Informational / hygiene signal.
    Info,
}

impl Severity {
    /// Lowercased string form (`"critical"`, `"high"`, …).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    /// Map an arbitrary scanner vocabulary token (case-insensitive) onto a
    /// normalised severity. Unknown tokens degrade to [`Severity::Info`].
    #[must_use]
    pub fn from_token(token: &str) -> Self {
        match token.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" | "fatal" | "blocker" => Self::Critical,
            "high" | "error" | "err" | "severe" => Self::High,
            "medium" | "moderate" | "warning" | "warn" | "med" => Self::Medium,
            "low" | "minor" | "note" => Self::Low,
            _ => Self::Info,
        }
    }
}

/// One normalised finding from a CLI scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerFinding {
    /// Scanner-assigned id (CVE-…, CKV_…, etc.). Stable across runs.
    pub id: String,
    /// Normalised severity.
    pub severity: Severity,
    /// Short human-readable title.
    pub title: String,
    /// Long-form description (may be empty).
    pub description: String,
    /// File the finding is anchored to, when applicable.
    pub file_path: Option<String>,
    /// 1-based line number, when applicable.
    pub line: Option<u32>,
    /// Rule / check identifier (`CKV_AWS_20`, `AVD-AWS-0001`, …).
    pub rule_id: Option<String>,
}

/// Errors a wrapper can return.
#[derive(Debug, Error)]
pub enum ScannerError {
    /// The target path does not exist or is not accessible.
    #[error("target path not found: {0}")]
    TargetMissing(String),

    /// The configured binary path could not be invoked.
    #[error("failed to spawn binary: {0}")]
    Spawn(String),

    /// The child exited non-zero and produced no usable stdout.
    #[error("scanner failed (exit {exit_code:?}): {stderr_excerpt}")]
    ProcessFailed {
        /// Numeric exit code, if available.
        exit_code: Option<i32>,
        /// First 512 bytes of stderr, lossily decoded.
        stderr_excerpt: String,
    },

    /// The 5-minute wall-clock budget elapsed.
    #[error("scanner timed out")]
    Timeout,

    /// The stdout was not parseable into the expected shape.
    #[error("parse: {0}")]
    Parse(String),

    /// Misconfiguration (e.g. relative binary path).
    #[error("config: {0}")]
    Config(String),
}

/// Walk the colon-separated `path_env` looking for an executable.
///
/// Returns the first match for `name`. Pure function — used both at
/// runtime (with the process `PATH`) and from tests (with a forged
/// `PATH`).
#[must_use]
pub fn detect_in(name: &str, path_env: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    for dir in path_env.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Walk the process `PATH` for `name`.
#[must_use]
pub fn detect_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let path = path.to_string_lossy().into_owned();
    detect_in(name, &path)
}

fn is_executable(p: &Path) -> bool {
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

/// Validate that a binary path is configured correctly. We require absolute
/// paths to forbid PATH-injection surprises in production callers.
pub(crate) fn check_binary(binary: &Path) -> Result<(), ScannerError> {
    if binary.as_os_str().is_empty() {
        return Err(ScannerError::Config("binary path is empty".to_owned()));
    }
    if !binary.is_absolute() {
        return Err(ScannerError::Config(format!(
            "binary path must be absolute: {}",
            binary.display()
        )));
    }
    Ok(())
}

/// Validate that a scan target exists on disk.
pub(crate) fn check_target(target: &Path) -> Result<(), ScannerError> {
    if !target.exists() {
        return Err(ScannerError::TargetMissing(target.display().to_string()));
    }
    Ok(())
}

/// Truncate stderr to the first `max` bytes for inclusion in
/// [`ScannerError::ProcessFailed`].
pub(crate) fn stderr_excerpt(stderr: &[u8], max: usize) -> String {
    let n = stderr.len().min(max);
    // `n` is bounded by `stderr.len()` so the slice cannot panic.
    let head = stderr.get(..n).unwrap_or(stderr);
    String::from_utf8_lossy(head).trim().to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn severity_from_token_canonical() {
        assert_eq!(Severity::from_token("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::from_token("High"), Severity::High);
        assert_eq!(Severity::from_token("medium"), Severity::Medium);
        assert_eq!(Severity::from_token(" low "), Severity::Low);
        assert_eq!(Severity::from_token("info"), Severity::Info);
    }

    #[test]
    fn severity_from_token_synonyms() {
        assert_eq!(Severity::from_token("blocker"), Severity::Critical);
        assert_eq!(Severity::from_token("error"), Severity::High);
        assert_eq!(Severity::from_token("warning"), Severity::Medium);
        assert_eq!(Severity::from_token("note"), Severity::Low);
    }

    #[test]
    fn severity_unknown_degrades_to_info() {
        assert_eq!(Severity::from_token("magenta"), Severity::Info);
        assert_eq!(Severity::from_token(""), Severity::Info);
    }

    #[test]
    fn severity_as_str_round_trips() {
        for s in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            assert_eq!(Severity::from_token(s.as_str()), s);
        }
    }

    #[test]
    fn detect_in_returns_none_with_empty_path() {
        assert!(detect_in("trivy", "").is_none());
    }

    #[test]
    fn detect_in_returns_none_for_unknown_binary() {
        // Use a name that surely does not exist on $PATH.
        assert!(detect_in("__sx_definitely_not_a_real_binary__", "/usr/bin:/bin").is_none());
    }

    #[test]
    fn detect_in_returns_none_for_empty_name() {
        assert!(detect_in("", "/usr/bin").is_none());
    }

    #[test]
    fn check_binary_rejects_relative_paths() {
        assert!(matches!(
            check_binary(Path::new("trivy")),
            Err(ScannerError::Config(_))
        ));
    }

    #[test]
    fn check_binary_accepts_absolute_paths() {
        assert!(check_binary(Path::new("/usr/local/bin/trivy")).is_ok());
    }

    #[test]
    fn check_target_rejects_missing() {
        assert!(matches!(
            check_target(Path::new("/does/not/exist/anywhere/__x__")),
            Err(ScannerError::TargetMissing(_))
        ));
    }

    #[test]
    fn stderr_excerpt_truncates() {
        let buf = vec![b'x'; 600];
        let s = stderr_excerpt(&buf, 100);
        assert_eq!(s.len(), 100);
    }

    #[test]
    fn stderr_excerpt_trims_whitespace() {
        assert_eq!(stderr_excerpt(b"  hello\n", 64), "hello");
    }
}
