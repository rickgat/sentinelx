//! [kube-bench](https://github.com/aquasecurity/kube-bench) CLI wrapper.
//!
//! kube-bench evaluates a Kubernetes cluster against the CIS Kubernetes
//! Benchmark. Unlike most scanners, its `--json` flag is paired with
//! `--outputfile`; the wrapper writes to a scratch file under
//! [`std::env::temp_dir`], reads it back, and parses the report.
//!
//! The `target` parameter is the Kubernetes config directory (or any
//! directory the operator wants logged as the scan context). kube-bench
//! itself reads the live cluster state from environment variables and
//! kubeconfig; the path is *not* passed as a positional argument.
//!
//! # Severity mapping
//!
//! kube-bench reports per-check status (`PASS`, `FAIL`, `WARN`, `INFO`). The
//! wrapper emits findings only for `FAIL` (mapped to [`Severity::High`]) and
//! `WARN` (mapped to [`Severity::Medium`]). Passes and informational
//! results are dropped.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;
use uuid::Uuid;

use super::{
    check_binary, check_target, detect_in_path, stderr_excerpt, ScannerError, ScannerFinding,
    Severity, DEFAULT_TIMEOUT,
};

/// Wrapper around the `kube-bench` CLI.
#[derive(Debug, Clone)]
pub struct KubeBenchScanner {
    binary: PathBuf,
    timeout: Duration,
}

impl KubeBenchScanner {
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

    /// Resolve `kube-bench` from the process `PATH`.
    #[must_use]
    pub fn detect() -> Option<Self> {
        detect_in_path("kube-bench").map(Self::new)
    }

    /// Run kube-bench. `target` is used only for existence-checking and
    /// logging context (kube-bench resolves cluster state from env).
    pub async fn scan(&self, target: &Path) -> Result<Vec<ScannerFinding>, ScannerError> {
        check_binary(&self.binary)?;
        check_target(target)?;

        let outfile = std::env::temp_dir().join(format!("sx-kubebench-{}.json", Uuid::new_v4()));

        let mut cmd = Command::new(&self.binary);
        cmd.arg("--json")
            .arg("--outputfile")
            .arg(&outfile)
            .arg("--noremediations")
            .arg("--noresults");
        cmd.kill_on_drop(true);

        let exec = cmd.output();
        let result = match timeout(self.timeout, exec).await {
            Err(_) => Err(ScannerError::Timeout),
            Ok(Err(e)) => Err(ScannerError::Spawn(e.to_string())),
            Ok(Ok(out)) => match tokio::fs::read(&outfile).await {
                Ok(bytes) => Ok(parse_kubebench_json(&bytes)),
                Err(_) if !out.status.success() => Err(ScannerError::ProcessFailed {
                    exit_code: out.status.code(),
                    stderr_excerpt: stderr_excerpt(&out.stderr, 512),
                }),
                Err(e) => Err(ScannerError::Parse(format!("read outputfile: {e}"))),
            },
        };

        // Best-effort cleanup.
        let _ = tokio::fs::remove_file(&outfile).await;
        result
    }
}

/// Parse kube-bench's JSON report. The shape is
/// `{"Controls":[{"tests":[{"results":[{...}]}]}]}`.
#[must_use]
pub fn parse_kubebench_json(bytes: &[u8]) -> Vec<ScannerFinding> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let controls = root.get("Controls").and_then(Value::as_array);
    let mut out: Vec<ScannerFinding> = Vec::new();
    let Some(controls) = controls else {
        return out;
    };
    for control in controls {
        let Some(tests) = control.get("tests").and_then(Value::as_array) else {
            continue;
        };
        for test in tests {
            let Some(results) = test.get("results").and_then(Value::as_array) else {
                continue;
            };
            for r in results {
                if let Some(f) = parse_check(r) {
                    out.push(f);
                }
            }
        }
    }
    out
}

fn parse_check(r: &Value) -> Option<ScannerFinding> {
    let test_number = r.get("test_number").and_then(Value::as_str)?;
    let status = r.get("status").and_then(Value::as_str).unwrap_or("");
    let severity = match status {
        "FAIL" => Severity::High,
        "WARN" => Severity::Medium,
        _ => return None,
    };
    let title = r
        .get("test_desc")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let description = r
        .get("remediation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    Some(ScannerFinding {
        id: test_number.to_owned(),
        severity,
        title,
        description,
        file_path: None,
        line: None,
        rule_id: Some(test_number.to_owned()),
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
    fn kubebench_scanner_detect_returns_none_when_binary_missing() {
        use crate::scanner::wrappers::detect_in;
        assert!(detect_in("kube-bench", "").is_none());
    }

    #[test]
    fn kubebench_scanner_parses_sample_output() {
        let payload = br#"{
          "Controls": [
            {
              "id": "1",
              "tests": [
                {
                  "section": "1.1",
                  "results": [
                    {
                      "test_number": "1.1.1",
                      "test_desc": "Ensure API server pod spec is owned by root",
                      "status": "FAIL",
                      "remediation": "chown root:root /etc/kubernetes/manifests"
                    },
                    {
                      "test_number": "1.1.2",
                      "test_desc": "Pod spec permissions",
                      "status": "PASS"
                    },
                    {
                      "test_number": "1.1.3",
                      "test_desc": "etcd data dir perms",
                      "status": "WARN",
                      "remediation": "chmod 700 /var/lib/etcd"
                    }
                  ]
                }
              ]
            }
          ]
        }"#;
        let findings = parse_kubebench_json(payload);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id, "1.1.1");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].description.contains("chown"));
        assert_eq!(findings[1].id, "1.1.3");
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn kubebench_parser_tolerates_garbage() {
        assert!(parse_kubebench_json(b"").is_empty());
        assert!(parse_kubebench_json(b"{}").is_empty());
        assert!(parse_kubebench_json(b"{\"Controls\":\"x\"}").is_empty());
    }

    #[test]
    fn kubebench_parser_drops_pass_status() {
        let payload = br#"{"Controls":[{"tests":[{"results":[
          {"test_number":"a","status":"PASS","test_desc":"x"}
        ]}]}]}"#;
        assert!(parse_kubebench_json(payload).is_empty());
    }

    #[tokio::test]
    async fn kubebench_scan_rejects_missing_target() {
        let s = KubeBenchScanner::new(PathBuf::from("/usr/local/bin/kube-bench"));
        let err = s
            .scan(Path::new("/does/not/exist/__kb__"))
            .await
            .expect_err("missing target should fail");
        assert!(matches!(err, ScannerError::TargetMissing(_)));
    }

    #[tokio::test]
    #[ignore = "requires kube-bench binary"]
    async fn kubebench_scanner_smoke() {
        let Some(scanner) = KubeBenchScanner::detect() else {
            return;
        };
        let cwd = std::env::current_dir().expect("cwd");
        let _ = scanner.scan(&cwd).await;
    }
}
