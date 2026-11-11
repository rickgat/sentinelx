//! [KICS](https://github.com/Checkmarx/kics) CLI wrapper.
//!
//! KICS writes its report to a directory rather than stdout. The wrapper
//! creates a unique scratch directory under [`std::env::temp_dir`], runs
//! `kics scan -p <target> -o <scratch> --report-formats json`, reads the
//! resulting `results.json`, deletes the scratch directory, and parses the
//! payload.
//!
//! # Severity mapping
//!
//! | KICS     | Normalised             |
//! |----------|------------------------|
//! | `HIGH`   | [`Severity::High`]     |
//! | `MEDIUM` | [`Severity::Medium`]   |
//! | `LOW`    | [`Severity::Low`]      |
//! | `INFO`   | [`Severity::Info`]     |
//! | `TRACE`  | [`Severity::Info`]     |

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

/// Wrapper around the `kics` CLI.
#[derive(Debug, Clone)]
pub struct KicsScanner {
    binary: PathBuf,
    timeout: Duration,
}

impl KicsScanner {
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

    /// Resolve `kics` from the process `PATH`.
    #[must_use]
    pub fn detect() -> Option<Self> {
        detect_in_path("kics").map(Self::new)
    }

    /// Scan `target` and return findings.
    pub async fn scan(&self, target: &Path) -> Result<Vec<ScannerFinding>, ScannerError> {
        check_binary(&self.binary)?;
        check_target(target)?;

        let scratch = std::env::temp_dir().join(format!("sx-kics-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&scratch)
            .await
            .map_err(|e| ScannerError::Spawn(format!("scratch dir: {e}")))?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("scan")
            .arg("--no-color")
            .arg("--no-progress")
            .arg("-p")
            .arg(target)
            .arg("-o")
            .arg(&scratch)
            .arg("--report-formats")
            .arg("json");
        cmd.kill_on_drop(true);

        let exec = cmd.output();
        let output = timeout(self.timeout, exec).await;

        // Always read what KICS produced and try to clean up, regardless of
        // exit code (KICS returns non-zero when findings exist).
        let result = match output {
            Err(_) => Err(ScannerError::Timeout),
            Ok(Err(e)) => Err(ScannerError::Spawn(e.to_string())),
            Ok(Ok(out)) => {
                let report = scratch.join("results.json");
                match tokio::fs::read(&report).await {
                    Ok(bytes) => Ok(parse_kics_json(&bytes)),
                    Err(_) if !out.status.success() => Err(ScannerError::ProcessFailed {
                        exit_code: out.status.code(),
                        stderr_excerpt: stderr_excerpt(&out.stderr, 512),
                    }),
                    Err(e) => Err(ScannerError::Parse(format!("read results.json: {e}"))),
                }
            }
        };

        // Best-effort cleanup; ignore failures so we never mask the real error.
        let _ = tokio::fs::remove_dir_all(&scratch).await;
        result
    }
}

/// Parse the `results.json` KICS writes (`{"queries": [{...}]}` shape).
#[must_use]
pub fn parse_kics_json(bytes: &[u8]) -> Vec<ScannerFinding> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let Some(queries) = root.get("queries").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<ScannerFinding> = Vec::new();
    for q in queries {
        let query_id = q.get("query_id").and_then(Value::as_str).unwrap_or("");
        let query_name = q.get("query_name").and_then(Value::as_str).unwrap_or("");
        let severity = q.get("severity").and_then(Value::as_str).unwrap_or("INFO");
        let description = q
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if query_id.is_empty() {
            continue;
        }
        let Some(files) = q.get("files").and_then(Value::as_array) else {
            continue;
        };
        for file in files {
            let file_name = file
                .get("file_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let line = file
                .get("line")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok());
            out.push(ScannerFinding {
                id: query_id.to_owned(),
                severity: Severity::from_token(severity),
                title: query_name.to_owned(),
                description: description.clone(),
                file_path: if file_name.is_empty() {
                    None
                } else {
                    Some(file_name)
                },
                line,
                rule_id: Some(query_id.to_owned()),
            });
        }
    }
    out
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
    fn kics_scanner_detect_returns_none_when_binary_missing() {
        use crate::scanner::wrappers::detect_in;
        assert!(detect_in("kics", "").is_none());
    }

    #[test]
    fn kics_scanner_parses_sample_output() {
        let payload = br#"{
          "queries": [
            {
              "query_id": "a227ec01-f97a-4084-91a4-47b350c1db54",
              "query_name": "Missing TLS",
              "severity": "HIGH",
              "description": "TLS not enforced",
              "files": [
                {"file_name": "ingress.yaml", "line": 17},
                {"file_name": "ingress-v2.yaml", "line": 5}
              ]
            },
            {
              "query_id": "c1d2",
              "query_name": "Resource without tag",
              "severity": "LOW",
              "files": [{"file_name": "main.tf", "line": 1}]
            }
          ]
        }"#;
        let findings = parse_kics_json(payload);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].id, "a227ec01-f97a-4084-91a4-47b350c1db54");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].line, Some(17));
        assert_eq!(findings[2].severity, Severity::Low);
    }

    #[test]
    fn kics_parser_tolerates_garbage() {
        assert!(parse_kics_json(b"").is_empty());
        assert!(parse_kics_json(b"{}").is_empty());
        assert!(parse_kics_json(b"{\"queries\":\"x\"}").is_empty());
    }

    #[test]
    fn kics_parser_skips_entries_without_id() {
        let payload = br#"{"queries":[{"query_name":"x","files":[{"file_name":"a"}]}]}"#;
        assert!(parse_kics_json(payload).is_empty());
    }

    #[tokio::test]
    async fn kics_scan_rejects_missing_target() {
        let s = KicsScanner::new(PathBuf::from("/usr/local/bin/kics"));
        let err = s
            .scan(Path::new("/does/not/exist/__k__"))
            .await
            .expect_err("missing target should fail");
        assert!(matches!(err, ScannerError::TargetMissing(_)));
    }

    #[tokio::test]
    #[ignore = "requires kics binary"]
    async fn kics_scanner_smoke() {
        let Some(scanner) = KicsScanner::detect() else {
            return;
        };
        let cwd = std::env::current_dir().expect("cwd");
        let _ = scanner.scan(&cwd).await;
    }
}
