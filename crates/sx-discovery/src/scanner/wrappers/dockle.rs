//! [Dockle](https://github.com/goodwithtech/dockle) CLI wrapper.
//!
//! Dockle is a container-image linter — it inspects the layers of a built
//! image against the CIS Benchmark for Docker and a handful of best-practice
//! rules.
//!
//! Dockle's positional argument is an image reference (`alpine:3.20`), not a
//! filesystem path. To honour the unified `Path`-typed `scan()` signature
//! while keeping user-supplied strings out of `argv`, the wrapper treats
//! `target` as a small text file whose **first non-empty line** is the image
//! reference. This file-based hand-off is the same pattern testssl uses for
//! its mass-test mode.
//!
//! # Severity mapping
//!
//! Dockle reports `FATAL`, `WARN`, `INFO`, `SKIP`, `PASS`:
//!
//! | Dockle  | Normalised             |
//! |---------|------------------------|
//! | `FATAL` | [`Severity::Critical`] |
//! | `WARN`  | [`Severity::High`]     |
//! | `INFO`  | [`Severity::Info`]     |
//! | `SKIP`  | dropped                |
//! | `PASS`  | dropped                |

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;

use super::{
    check_binary, check_target, detect_in_path, stderr_excerpt, ScannerError, ScannerFinding,
    Severity, DEFAULT_TIMEOUT,
};

/// Wrapper around the `dockle` CLI.
#[derive(Debug, Clone)]
pub struct DockleScanner {
    binary: PathBuf,
    timeout: Duration,
}

impl DockleScanner {
    /// Build a wrapper from a binary path.
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the default 5-minute wall-clock budget.
    #[must_use]
    pub const fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Resolve `dockle` from the process `PATH`.
    #[must_use]
    pub fn detect() -> Option<Self> {
        detect_in_path("dockle").map(Self::new)
    }

    /// Read the image reference from `target` and scan it.
    pub async fn scan(&self, target: &Path) -> Result<Vec<ScannerFinding>, ScannerError> {
        check_binary(&self.binary)?;
        check_target(target)?;

        let raw = tokio::fs::read_to_string(target)
            .await
            .map_err(|e| ScannerError::Parse(format!("read target: {e}")))?;
        let image = first_non_empty_line(&raw).ok_or_else(|| {
            ScannerError::Config(format!(
                "dockle target file {} has no image reference",
                target.display()
            ))
        })?;
        validate_image_ref(image)?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("--no-color")
            .arg("--format")
            .arg("json")
            .arg("--exit-code")
            .arg("0")
            .arg(image);
        cmd.kill_on_drop(true);

        let exec = cmd.output();
        let output = timeout(self.timeout, exec)
            .await
            .map_err(|_| ScannerError::Timeout)?
            .map_err(|e| ScannerError::Spawn(e.to_string()))?;

        if !output.status.success() && output.stdout.is_empty() {
            return Err(ScannerError::ProcessFailed {
                exit_code: output.status.code(),
                stderr_excerpt: stderr_excerpt(&output.stderr, 512),
            });
        }
        Ok(parse_dockle_json(&output.stdout))
    }
}

fn first_non_empty_line(s: &str) -> Option<&str> {
    s.lines().map(str::trim).find(|l| !l.is_empty())
}

/// Reject anything that could be misinterpreted as a flag or shell trickery.
fn validate_image_ref(image: &str) -> Result<(), ScannerError> {
    if image.is_empty() || image.starts_with('-') {
        return Err(ScannerError::Config(format!(
            "dockle: refusing image reference '{image}'"
        )));
    }
    let allowed =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '@');
    if !image.chars().all(allowed) {
        return Err(ScannerError::Config(format!(
            "dockle: image reference contains disallowed characters: '{image}'"
        )));
    }
    Ok(())
}

/// Parse dockle's `--format json` stdout. The shape is
/// `{"details":[{"code","title","level","alerts":[...]}]}`.
#[must_use]
pub fn parse_dockle_json(bytes: &[u8]) -> Vec<ScannerFinding> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let Some(details) = root.get("details").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<ScannerFinding> = Vec::new();
    for d in details {
        if let Some(f) = parse_detail(d) {
            out.push(f);
        }
    }
    out
}

fn parse_detail(d: &Value) -> Option<ScannerFinding> {
    let code = d.get("code").and_then(Value::as_str)?;
    let level = d.get("level").and_then(Value::as_str).unwrap_or("");
    let severity = match level {
        "FATAL" => Severity::Critical,
        "WARN" => Severity::High,
        "INFO" => Severity::Info,
        _ => return None,
    };
    let title = d
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or(code)
        .to_owned();
    let alerts = d
        .get("alerts")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default();
    Some(ScannerFinding {
        id: code.to_owned(),
        severity,
        title,
        description: alerts,
        file_path: None,
        line: None,
        rule_id: Some(code.to_owned()),
    })
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
    use std::path::PathBuf;

    #[test]
    fn dockle_scanner_detect_returns_none_when_binary_missing() {
        use crate::scanner::wrappers::detect_in;
        assert!(detect_in("dockle", "").is_none());
    }

    #[test]
    fn dockle_scanner_parses_sample_output() {
        let payload = br#"{
          "details": [
            {
              "code": "CIS-DI-0001",
              "title": "Create a user for the container",
              "level": "FATAL",
              "alerts": ["Last user should not be root"]
            },
            {
              "code": "DKL-DI-0006",
              "title": "Avoid latest tag",
              "level": "WARN",
              "alerts": ["Avoid 'latest' tag"]
            },
            {
              "code": "CIS-DI-0005",
              "title": "Enable Content trust for Docker",
              "level": "INFO",
              "alerts": []
            },
            {
              "code": "X",
              "title": "y",
              "level": "PASS"
            }
          ]
        }"#;
        let findings = parse_dockle_json(payload);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].id, "CIS-DI-0001");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].description.contains("root"));
        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[2].severity, Severity::Info);
    }

    #[test]
    fn dockle_parser_tolerates_garbage() {
        assert!(parse_dockle_json(b"").is_empty());
        assert!(parse_dockle_json(b"{}").is_empty());
        assert!(parse_dockle_json(b"{\"details\":\"x\"}").is_empty());
    }

    #[test]
    fn dockle_validate_image_ref_accepts_simple() {
        assert!(validate_image_ref("alpine:3.20").is_ok());
        assert!(validate_image_ref("registry.io/library/nginx@sha256:abc123").is_ok());
    }

    #[test]
    fn dockle_validate_image_ref_rejects_flags() {
        assert!(validate_image_ref("-rm").is_err());
        assert!(validate_image_ref("").is_err());
    }

    #[test]
    fn dockle_validate_image_ref_rejects_shell_metas() {
        assert!(validate_image_ref("alpine;rm -rf /").is_err());
        assert!(validate_image_ref("alpine|cat").is_err());
        assert!(validate_image_ref("alpine`whoami`").is_err());
        assert!(validate_image_ref("alpine$IFS").is_err());
    }

    #[test]
    fn dockle_first_non_empty_line_skips_blanks() {
        assert_eq!(
            first_non_empty_line("\n\n  alpine:3.20\nfoo"),
            Some("alpine:3.20")
        );
        assert_eq!(first_non_empty_line(""), None);
        assert_eq!(first_non_empty_line("   "), None);
    }

    #[tokio::test]
    async fn dockle_scan_rejects_missing_target() {
        let s = DockleScanner::new(PathBuf::from("/usr/local/bin/dockle"));
        let err = s
            .scan(Path::new("/does/not/exist/__d__"))
            .await
            .expect_err("missing target should fail");
        assert!(matches!(err, ScannerError::TargetMissing(_)));
    }

    #[tokio::test]
    #[ignore = "requires dockle binary"]
    async fn dockle_scanner_smoke() {
        let Some(scanner) = DockleScanner::detect() else {
            return;
        };
        let scratch = std::env::temp_dir().join("sx-dockle-smoke-image.txt");
        let _ = tokio::fs::write(&scratch, b"alpine:3.20\n").await;
        let _ = scanner.scan(&scratch).await;
        let _ = tokio::fs::remove_file(&scratch).await;
    }
}
