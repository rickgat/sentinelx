//! [testssl.sh](https://github.com/drwetter/testssl.sh) CLI wrapper.
//!
//! testssl.sh scans one or more TLS endpoints. To honour the
//! `Path` target shape, the wrapper invokes it with `--file <target>` —
//! the file must contain one `host:port` per line (testssl's "mass-test"
//! mode). Output is written via `--jsonfile` to a scratch file.
//!
//! # Severity mapping
//!
//! testssl emits `severity` tokens per finding:
//!
//! | testssl    | Normalised             |
//! |------------|------------------------|
//! | `CRITICAL` | [`Severity::Critical`] |
//! | `HIGH`     | [`Severity::High`]     |
//! | `MEDIUM`   | [`Severity::Medium`]   |
//! | `LOW`      | [`Severity::Low`]      |
//! | `WARN`     | [`Severity::Medium`]   |
//! | `INFO`/`OK`| [`Severity::Info`]     |

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

/// Wrapper around the `testssl.sh` CLI.
#[derive(Debug, Clone)]
pub struct TestSslScanner {
    binary: PathBuf,
    timeout: Duration,
}

impl TestSslScanner {
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

    /// Resolve `testssl.sh` from the process `PATH`.
    #[must_use]
    pub fn detect() -> Option<Self> {
        detect_in_path("testssl.sh")
            .or_else(|| detect_in_path("testssl"))
            .map(Self::new)
    }

    /// Scan the host list in `target` (one `host[:port]` per line).
    pub async fn scan(&self, target: &Path) -> Result<Vec<ScannerFinding>, ScannerError> {
        check_binary(&self.binary)?;
        check_target(target)?;

        let outfile = std::env::temp_dir().join(format!("sx-testssl-{}.json", Uuid::new_v4()));

        let mut cmd = Command::new(&self.binary);
        cmd.arg("--quiet")
            .arg("--color")
            .arg("0")
            .arg("--jsonfile")
            .arg(&outfile)
            .arg("--file")
            .arg(target);
        cmd.kill_on_drop(true);

        let exec = cmd.output();
        let result = match timeout(self.timeout, exec).await {
            Err(_) => Err(ScannerError::Timeout),
            Ok(Err(e)) => Err(ScannerError::Spawn(e.to_string())),
            Ok(Ok(out)) => match tokio::fs::read(&outfile).await {
                Ok(bytes) => Ok(parse_testssl_json(&bytes)),
                Err(_) if !out.status.success() => Err(ScannerError::ProcessFailed {
                    exit_code: out.status.code(),
                    stderr_excerpt: stderr_excerpt(&out.stderr, 512),
                }),
                Err(e) => Err(ScannerError::Parse(format!("read jsonfile: {e}"))),
            },
        };

        let _ = tokio::fs::remove_file(&outfile).await;
        result
    }
}

/// Parse testssl's JSON output. The single-host form is an array; the
/// mass-test form is `{"scanResult":[{...}]}`. Both are supported.
#[must_use]
pub fn parse_testssl_json(bytes: &[u8]) -> Vec<ScannerFinding> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let mut out: Vec<ScannerFinding> = Vec::new();
    match &root {
        Value::Array(items) => {
            for item in items {
                if let Some(f) = parse_finding(item) {
                    out.push(f);
                }
            }
        }
        Value::Object(_) => {
            if let Some(scans) = root.get("scanResult").and_then(Value::as_array) {
                for scan in scans {
                    walk_object(scan, &mut out);
                }
            } else {
                walk_object(&root, &mut out);
            }
        }
        _ => {}
    }
    out
}

fn walk_object(node: &Value, out: &mut Vec<ScannerFinding>) {
    // testssl's JSON groups checks by category; each value is either a list
    // of finding objects or a single finding object.
    let Some(map) = node.as_object() else {
        return;
    };
    for (_, v) in map {
        match v {
            Value::Array(arr) => {
                for item in arr {
                    if let Some(f) = parse_finding(item) {
                        out.push(f);
                    }
                }
            }
            Value::Object(_) => {
                if let Some(f) = parse_finding(v) {
                    out.push(f);
                }
            }
            _ => {}
        }
    }
}

fn parse_finding(node: &Value) -> Option<ScannerFinding> {
    let id = node.get("id").and_then(Value::as_str)?;
    let severity = node.get("severity").and_then(Value::as_str)?;
    // Drop OK / informational unless we deliberately want them. We keep them
    // — they round-trip to [`Severity::Info`] and may be useful upstream.
    let finding = node
        .get("finding")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let cve = node.get("cve").and_then(Value::as_str).unwrap_or("");
    let host = node.get("ip").and_then(Value::as_str).unwrap_or("");
    Some(ScannerFinding {
        id: if cve.is_empty() {
            id.to_owned()
        } else {
            cve.to_owned()
        },
        severity: map_testssl_severity(severity),
        title: id.to_owned(),
        description: finding,
        file_path: if host.is_empty() {
            None
        } else {
            Some(host.to_owned())
        },
        line: None,
        rule_id: Some(id.to_owned()),
    })
}

fn map_testssl_severity(sev: &str) -> Severity {
    match sev.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" | "WARN" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
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
    use std::path::PathBuf;

    #[test]
    fn testssl_scanner_detect_returns_none_when_binary_missing() {
        use crate::scanner::wrappers::detect_in;
        assert!(detect_in("testssl.sh", "").is_none());
    }

    #[test]
    fn testssl_scanner_parses_sample_output() {
        let payload = br#"[
          {"id":"heartbleed","severity":"CRITICAL","cve":"CVE-2014-0160",
           "finding":"vulnerable","ip":"1.2.3.4"},
          {"id":"BREACH","severity":"MEDIUM","finding":"potentially vulnerable","ip":"1.2.3.4"},
          {"id":"protocol_negotiated","severity":"INFO","finding":"TLSv1.3","ip":"1.2.3.4"}
        ]"#;
        let findings = parse_testssl_json(payload);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].id, "CVE-2014-0160");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[2].severity, Severity::Info);
    }

    #[test]
    fn testssl_parser_handles_scanresult_envelope() {
        let payload = br#"{"scanResult":[{
          "scanCategory":{"id":"x","severity":"HIGH","finding":"f","ip":"h"}
        }]}"#;
        let f = parse_testssl_json(payload);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn testssl_parser_tolerates_garbage() {
        assert!(parse_testssl_json(b"").is_empty());
        assert!(parse_testssl_json(b"null").is_empty());
        assert!(parse_testssl_json(b"\"oops\"").is_empty());
    }

    #[tokio::test]
    async fn testssl_scan_rejects_missing_target() {
        let s = TestSslScanner::new(PathBuf::from("/usr/local/bin/testssl.sh"));
        let err = s
            .scan(Path::new("/does/not/exist/__t__"))
            .await
            .expect_err("missing target should fail");
        assert!(matches!(err, ScannerError::TargetMissing(_)));
    }

    #[tokio::test]
    #[ignore = "requires testssl binary"]
    async fn testssl_scanner_smoke() {
        let Some(scanner) = TestSslScanner::detect() else {
            return;
        };
        let scratch = std::env::temp_dir().join("sx-testssl-smoke-targets.txt");
        let _ = tokio::fs::write(&scratch, b"example.com:443\n").await;
        let _ = scanner.scan(&scratch).await;
        let _ = tokio::fs::remove_file(&scratch).await;
    }
}
