//! [Checkov](https://github.com/bridgecrewio/checkov) CLI wrapper.
//!
//! Targets a directory, runs `checkov --output json -d <path>`, and parses
//! the `results.failed_checks` array.
//!
//! # Severity mapping
//!
//! | Checkov  | Normalised             |
//! |----------|------------------------|
//! | `HIGH`   | [`Severity::High`]     |
//! | `MEDIUM` | [`Severity::Medium`]   |
//! | `LOW`    | [`Severity::Low`]      |
//! | absent   | [`Severity::Info`]     |
//!
//! Checkov also emits `CRITICAL` for a subset of cloud checks; it's mapped
//! to [`Severity::Critical`] verbatim.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;

use super::{
    check_binary, check_target, detect_in_path, stderr_excerpt, ScannerError, ScannerFinding,
    Severity, DEFAULT_TIMEOUT,
};

/// Wrapper around the `checkov` CLI.
#[derive(Debug, Clone)]
pub struct CheckovScanner {
    binary: PathBuf,
    timeout: Duration,
}

impl CheckovScanner {
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

    /// Resolve `checkov` from the process `PATH`.
    #[must_use]
    pub fn detect() -> Option<Self> {
        detect_in_path("checkov").map(Self::new)
    }

    /// Scan `target` and return findings.
    pub async fn scan(&self, target: &Path) -> Result<Vec<ScannerFinding>, ScannerError> {
        check_binary(&self.binary)?;
        check_target(target)?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("--output")
            .arg("json")
            .arg("--quiet")
            .arg("--soft-fail")
            .arg("-d")
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
        Ok(parse_checkov_json(&output.stdout))
    }
}

/// Parse `checkov --output json`. Accepts both the single-object and
/// per-framework array shapes.
#[must_use]
pub fn parse_checkov_json(bytes: &[u8]) -> Vec<ScannerFinding> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let mut out: Vec<ScannerFinding> = Vec::new();
    match &root {
        Value::Array(items) => {
            for item in items {
                collect(item, &mut out);
            }
        }
        Value::Object(_) => collect(&root, &mut out),
        _ => {}
    }
    out
}

fn collect(node: &Value, out: &mut Vec<ScannerFinding>) {
    let Some(failed) = node
        .get("results")
        .and_then(|r| r.get("failed_checks"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for c in failed {
        if let Some(f) = parse_failed(c) {
            out.push(f);
        }
    }
}

fn parse_failed(check: &Value) -> Option<ScannerFinding> {
    let check_id = check.get("check_id").and_then(Value::as_str)?;
    let file_path = check.get("file_path").and_then(Value::as_str)?;
    let title = check
        .get("check_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let severity = check
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info");
    let description = check
        .get("guideline")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let line = check
        .get("file_line_range")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());
    Some(ScannerFinding {
        id: check_id.to_owned(),
        severity: Severity::from_token(severity),
        title,
        description,
        file_path: Some(file_path.to_owned()),
        line,
        rule_id: Some(check_id.to_owned()),
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
    fn checkov_scanner_detect_returns_none_when_binary_missing() {
        use crate::scanner::wrappers::detect_in;
        assert!(detect_in("checkov", "").is_none());
    }

    #[test]
    fn checkov_scanner_parses_sample_output() {
        let payload = br#"{
          "results": {
            "failed_checks": [
              {
                "check_id": "CKV_AWS_20",
                "check_name": "Ensure the S3 bucket has access logging enabled",
                "file_path": "./main.tf",
                "file_line_range": [5, 10],
                "severity": "HIGH",
                "guideline": "Enable logging."
              },
              {
                "check_id": "CKV_K8S_8",
                "check_name": "Liveness probe defined",
                "file_path": "k8s/deployment.yaml",
                "file_line_range": [42, 50],
                "severity": "MEDIUM"
              }
            ]
          }
        }"#;
        let findings = parse_checkov_json(payload);
        assert_eq!(findings.len(), 2);
        let high = &findings[0];
        assert_eq!(high.id, "CKV_AWS_20");
        assert_eq!(high.severity, Severity::High);
        assert_eq!(high.line, Some(5));
        assert_eq!(high.file_path.as_deref(), Some("./main.tf"));
        assert!(high.description.contains("Enable"));
    }

    #[test]
    fn checkov_parser_accepts_array_root() {
        let payload = br#"[
          {"results": {"failed_checks": [
            {"check_id": "CKV_AWS_1", "check_name": "x",
             "file_path": "./a.tf", "severity": "low", "file_line_range": [1]}
          ]}}
        ]"#;
        let f = parse_checkov_json(payload);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn checkov_parser_tolerates_garbage() {
        assert!(parse_checkov_json(b"").is_empty());
        assert!(parse_checkov_json(b"null").is_empty());
        assert!(parse_checkov_json(b"{}").is_empty());
        assert!(parse_checkov_json(b"{\"results\":\"oops\"}").is_empty());
    }

    #[tokio::test]
    async fn checkov_scan_rejects_missing_target() {
        let s = CheckovScanner::new(PathBuf::from("/usr/local/bin/checkov"));
        let err = s
            .scan(Path::new("/does/not/exist/abc/__y__"))
            .await
            .expect_err("missing target should fail");
        assert!(matches!(err, ScannerError::TargetMissing(_)));
    }

    #[tokio::test]
    #[ignore = "requires checkov binary"]
    async fn checkov_scanner_smoke() {
        let Some(scanner) = CheckovScanner::detect() else {
            return;
        };
        let cwd = std::env::current_dir().expect("cwd");
        let _ = scanner.scan(&cwd).await;
    }
}
