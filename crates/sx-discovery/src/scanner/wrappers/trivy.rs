//! [Trivy](https://github.com/aquasecurity/trivy) CLI wrapper.
//!
//! Supports the `fs` sub-command, which scans a local directory for both
//! known CVEs in package manifests *and* `IaC` misconfigurations (Terraform,
//! Kubernetes manifests, `Dockerfile`s, …).
//!
//! # Severity mapping
//!
//! | Trivy        | Normalised             |
//! |--------------|------------------------|
//! | `CRITICAL`   | [`Severity::Critical`] |
//! | `HIGH`       | [`Severity::High`]     |
//! | `MEDIUM`     | [`Severity::Medium`]   |
//! | `LOW`        | [`Severity::Low`]      |
//! | `UNKNOWN`/`` | [`Severity::Info`]     |

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;

use super::{
    check_binary, check_target, detect_in_path, stderr_excerpt, ScannerError, ScannerFinding,
    Severity, DEFAULT_TIMEOUT,
};

/// Wrapper around the `trivy` CLI.
#[derive(Debug, Clone)]
pub struct TrivyScanner {
    binary: PathBuf,
    timeout: Duration,
}

impl TrivyScanner {
    /// Build a wrapper from a binary path. The path is **not** verified to
    /// exist here — `scan()` will surface any spawn failure as
    /// [`ScannerError::Spawn`].
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

    /// Resolve `trivy` from the process `PATH`.
    #[must_use]
    pub fn detect() -> Option<Self> {
        detect_in_path("trivy").map(Self::new)
    }

    /// Scan `target` (a directory or single file) and return findings.
    pub async fn scan(&self, target: &Path) -> Result<Vec<ScannerFinding>, ScannerError> {
        check_binary(&self.binary)?;
        check_target(target)?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("fs")
            .arg("--format")
            .arg("json")
            .arg("--quiet")
            .arg("--scanners")
            .arg("vuln,misconfig")
            .arg("--severity")
            .arg("UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
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
        Ok(parse_trivy_json(&output.stdout))
    }
}

/// Parse trivy's `fs --format json` stdout. Tolerates empty / malformed
/// payloads by returning an empty vector.
#[must_use]
pub fn parse_trivy_json(bytes: &[u8]) -> Vec<ScannerFinding> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let Some(results) = root.get("Results").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<ScannerFinding> = Vec::new();
    for result in results {
        let target = result
            .get("Target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if let Some(vulns) = result.get("Vulnerabilities").and_then(Value::as_array) {
            for v in vulns {
                if let Some(f) = parse_vulnerability(v, &target) {
                    out.push(f);
                }
            }
        }
        if let Some(miscs) = result.get("Misconfigurations").and_then(Value::as_array) {
            for m in miscs {
                if let Some(f) = parse_misconfig(m, &target) {
                    out.push(f);
                }
            }
        }
    }
    out
}

fn parse_vulnerability(v: &Value, target: &str) -> Option<ScannerFinding> {
    let id = v.get("VulnerabilityID").and_then(Value::as_str)?;
    let severity = v
        .get("Severity")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    let title = v
        .get("Title")
        .and_then(Value::as_str)
        .unwrap_or(id)
        .to_owned();
    let description = v
        .get("Description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    Some(ScannerFinding {
        id: id.to_owned(),
        severity: Severity::from_token(severity),
        title,
        description,
        file_path: if target.is_empty() {
            None
        } else {
            Some(target.to_owned())
        },
        line: None,
        rule_id: Some(id.to_owned()),
    })
}

fn parse_misconfig(m: &Value, target: &str) -> Option<ScannerFinding> {
    let id = m.get("ID").and_then(Value::as_str)?;
    let severity = m
        .get("Severity")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    let title = m
        .get("Title")
        .and_then(Value::as_str)
        .unwrap_or(id)
        .to_owned();
    let description = m
        .get("Description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let line = m
        .get("CauseMetadata")
        .and_then(|c| c.get("StartLine"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());
    Some(ScannerFinding {
        id: id.to_owned(),
        severity: Severity::from_token(severity),
        title,
        description,
        file_path: if target.is_empty() {
            None
        } else {
            Some(target.to_owned())
        },
        line,
        rule_id: Some(id.to_owned()),
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
    fn trivy_scanner_detect_returns_none_when_binary_missing() {
        // detect_in is the testable cousin of detect_in_path — feed it an
        // empty PATH so we can assert without mutating process env.
        use crate::scanner::wrappers::detect_in;
        assert!(detect_in("trivy", "").is_none());
    }

    #[test]
    fn trivy_scanner_parses_sample_output() {
        let payload = br#"{
          "Results": [
            {
              "Target": "Dockerfile",
              "Class": "config",
              "Misconfigurations": [
                {
                  "ID": "DS002",
                  "Title": "Image user should not be root",
                  "Description": "Running container as root",
                  "Severity": "HIGH",
                  "CauseMetadata": {"StartLine": 3}
                }
              ]
            },
            {
              "Target": "package.json",
              "Class": "lang-pkgs",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-2024-1234",
                  "PkgName": "lodash",
                  "InstalledVersion": "4.17.0",
                  "FixedVersion": "4.17.21",
                  "Severity": "CRITICAL",
                  "Title": "Prototype pollution"
                }
              ]
            }
          ]
        }"#;
        let findings = parse_trivy_json(payload);
        assert!(!findings.is_empty());
        let crit = findings
            .iter()
            .find(|f| f.severity == Severity::Critical)
            .expect("critical present");
        assert_eq!(crit.id, "CVE-2024-1234");
        let misc = findings
            .iter()
            .find(|f| f.id == "DS002")
            .expect("misconfig present");
        assert_eq!(misc.severity, Severity::High);
        assert_eq!(misc.line, Some(3));
        assert_eq!(misc.file_path.as_deref(), Some("Dockerfile"));
    }

    #[test]
    fn trivy_parse_tolerates_garbage() {
        assert!(parse_trivy_json(b"").is_empty());
        assert!(parse_trivy_json(b"not json").is_empty());
        assert!(parse_trivy_json(b"{}").is_empty());
        assert!(parse_trivy_json(b"{\"Results\":\"oops\"}").is_empty());
    }

    #[test]
    fn trivy_with_timeout_sets_budget() {
        let s = TrivyScanner::new(PathBuf::from("/usr/local/bin/trivy"))
            .with_timeout(Duration::from_secs(10));
        assert_eq!(s.timeout, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn trivy_scan_rejects_missing_target() {
        let s = TrivyScanner::new(PathBuf::from("/usr/local/bin/trivy"));
        let err = s
            .scan(Path::new("/does/not/exist/abc/__x__"))
            .await
            .expect_err("missing target should fail");
        assert!(matches!(err, ScannerError::TargetMissing(_)));
    }

    #[tokio::test]
    #[ignore = "requires trivy binary"]
    async fn trivy_scanner_smoke() {
        let Some(scanner) = TrivyScanner::detect() else {
            return;
        };
        let cwd = std::env::current_dir().expect("cwd");
        let _ = scanner.scan(&cwd).await;
    }
}
