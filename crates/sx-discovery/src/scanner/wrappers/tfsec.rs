//! [tfsec](https://github.com/aquasecurity/tfsec) CLI wrapper.
//!
//! Targets a Terraform module directory. Runs
//! `tfsec --format json --soft-fail <path>` and parses the `results` array.
//!
//! # Severity mapping
//!
//! | tfsec      | Normalised             |
//! |------------|------------------------|
//! | `CRITICAL` | [`Severity::Critical`] |
//! | `HIGH`     | [`Severity::High`]     |
//! | `MEDIUM`   | [`Severity::Medium`]   |
//! | `LOW`      | [`Severity::Low`]      |
//! | `INFO`     | [`Severity::Info`]     |

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;

use super::{
    check_binary, check_target, detect_in_path, stderr_excerpt, ScannerError, ScannerFinding,
    Severity, DEFAULT_TIMEOUT,
};

/// Wrapper around the `tfsec` CLI.
#[derive(Debug, Clone)]
pub struct TfsecScanner {
    binary: PathBuf,
    timeout: Duration,
}

impl TfsecScanner {
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

    /// Resolve `tfsec` from the process `PATH`.
    #[must_use]
    pub fn detect() -> Option<Self> {
        detect_in_path("tfsec").map(Self::new)
    }

    /// Scan `target` and return findings.
    pub async fn scan(&self, target: &Path) -> Result<Vec<ScannerFinding>, ScannerError> {
        check_binary(&self.binary)?;
        check_target(target)?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("--format")
            .arg("json")
            .arg("--soft-fail")
            .arg("--no-colour")
            .arg(target);
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
        Ok(parse_tfsec_json(&output.stdout))
    }
}

/// Parse tfsec's JSON envelope (`{"results": [...]}`).
#[must_use]
pub fn parse_tfsec_json(bytes: &[u8]) -> Vec<ScannerFinding> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let Some(results) = root.get("results").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<ScannerFinding> = Vec::new();
    for r in results {
        if let Some(f) = parse_result(r) {
            out.push(f);
        }
    }
    out
}

fn parse_result(r: &Value) -> Option<ScannerFinding> {
    let rule_id = r
        .get("rule_id")
        .and_then(Value::as_str)
        .or_else(|| r.get("long_id").and_then(Value::as_str))?;
    let severity = r.get("severity").and_then(Value::as_str).unwrap_or("INFO");
    let title = r
        .get("rule_description")
        .and_then(Value::as_str)
        .unwrap_or(rule_id)
        .to_owned();
    let description = r
        .get("description")
        .and_then(Value::as_str)
        .or_else(|| r.get("impact").and_then(Value::as_str))
        .unwrap_or("")
        .to_owned();
    let loc = r.get("location");
    let file_path = loc
        .and_then(|l| l.get("filename"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let line = loc
        .and_then(|l| l.get("start_line"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());
    Some(ScannerFinding {
        id: rule_id.to_owned(),
        severity: Severity::from_token(severity),
        title,
        description,
        file_path,
        line,
        rule_id: Some(rule_id.to_owned()),
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
    fn tfsec_scanner_detect_returns_none_when_binary_missing() {
        use crate::scanner::wrappers::detect_in;
        assert!(detect_in("tfsec", "").is_none());
    }

    #[test]
    fn tfsec_scanner_parses_sample_output() {
        let payload = br#"{
          "results": [
            {
              "rule_id": "AVD-AWS-0086",
              "long_id": "aws-s3-no-public-buckets",
              "rule_description": "S3 bucket should not be public",
              "description": "Bucket has public-read ACL.",
              "severity": "HIGH",
              "impact": "Data may leak.",
              "location": {
                "filename": "/tmp/proj/main.tf",
                "start_line": 12,
                "end_line": 18
              }
            },
            {
              "rule_id": "AVD-AWS-0001",
              "rule_description": "open ingress",
              "severity": "CRITICAL",
              "location": {"filename": "/tmp/proj/sg.tf", "start_line": 4}
            }
          ]
        }"#;
        let findings = parse_tfsec_json(payload);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id, "AVD-AWS-0086");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].line, Some(12));
        assert_eq!(findings[1].severity, Severity::Critical);
        assert_eq!(findings[1].file_path.as_deref(), Some("/tmp/proj/sg.tf"));
    }

    #[test]
    fn tfsec_parser_tolerates_garbage() {
        assert!(parse_tfsec_json(b"").is_empty());
        assert!(parse_tfsec_json(b"{}").is_empty());
        assert!(parse_tfsec_json(b"{\"results\":\"x\"}").is_empty());
    }

    #[tokio::test]
    async fn tfsec_scan_rejects_missing_target() {
        let s = TfsecScanner::new(PathBuf::from("/usr/local/bin/tfsec"));
        let err = s
            .scan(Path::new("/does/not/exist/__tf__"))
            .await
            .expect_err("missing target should fail");
        assert!(matches!(err, ScannerError::TargetMissing(_)));
    }

    #[tokio::test]
    #[ignore = "requires tfsec binary"]
    async fn tfsec_scanner_smoke() {
        let Some(scanner) = TfsecScanner::detect() else {
            return;
        };
        let cwd = std::env::current_dir().expect("cwd");
        let _ = scanner.scan(&cwd).await;
    }
}
