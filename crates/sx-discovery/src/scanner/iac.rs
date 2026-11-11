//! Infrastructure-as-Code (`IaC`) scanner.
//!
//! Wraps [checkov](https://github.com/bridgecrewio/checkov) as a child
//! process to detect misconfigurations in Terraform, `CloudFormation`,
//! Kubernetes manifests, and other `IaC` formats.
//!
//! The scanner accepts [`ScopeTarget::Url`] targets where the URL scheme is
//! one of:
//!
//! - `dir://path` — local filesystem path (cloned working tree).
//! - `git+https://…` — git repository URL.
//! - `git+ssh://…` — git repository over SSH.
//!
//! Other schemes are rejected before any subprocess is invoked. The scheme
//! prefix is stripped before passing the path to checkov.
//!
//! ## Why subprocess?
//!
//! Checkov's policy rule set is a large Python package updated frequently;
//! embedding it in this crate would couple `SentinelX`'s release cadence
//! to checkov's. A shell-out is the pragmatic choice for Phase 1 and
//! matches the design of [`crate::scanner::sca`].
//!
//! ## Safety
//!
//! - The binary path is taken from configuration; no `PATH` lookups.
//! - The target URL is validated against an allowlist of schemes.
//! - Stdout is parsed as JSON; deserialisation failures degrade to an empty
//!   result set, never a panic.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use time::OffsetDateTime;
use tokio::process::Command;
use tokio::time::timeout;

use crate::contracts::{ScanIntensity, ScopeTarget};
use crate::error::DiscoveryError;
use crate::model::observation::Observation;
use crate::model::scan_result::ScanResult;
use crate::service::scanner::{ScanContext, Scanner, ScannerCapabilities, ScannerId, TargetKind};

/// Stable id used to register / look up this scanner.
pub const IAC_SCANNER_ID: ScannerId = ScannerId::new("iac_checkov_v1");

/// Allowed URL schemes for the `IaC` scanner's targets.
const ALLOWED_SCHEMES: &[&str] = &["dir", "git+https", "git+ssh"];

/// Configuration for [`IacScanner`].
#[derive(Debug, Clone)]
pub struct IacScannerConfig {
    /// Path to the `checkov` binary. Must be absolute — no `PATH` lookup.
    pub checkov_binary: PathBuf,
    /// Wall-clock budget for one invocation.
    pub exec_timeout: Duration,
}

impl IacScannerConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        if !self.checkov_binary.is_absolute() {
            return Err(DiscoveryError::config(
                "iac.checkov_binary must be an absolute path",
            ));
        }
        if self.exec_timeout.is_zero() {
            return Err(DiscoveryError::config("iac.exec_timeout must be > 0"));
        }
        Ok(())
    }
}

/// Checkov-backed `IaC` scanner.
#[derive(Debug)]
pub struct IacScanner {
    cfg: IacScannerConfig,
}

impl IacScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: IacScannerConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        Ok(Self { cfg })
    }

    /// Validate the target and return the path with the scheme prefix
    /// stripped.
    fn validate_target(target: &ScopeTarget) -> Result<String, DiscoveryError> {
        let ScopeTarget::Url(url) = target else {
            return Err(DiscoveryError::config(
                "iac scanner accepts only Url targets (dir:// / git+https / git+ssh)",
            ));
        };
        let scheme = url.scheme();
        if !ALLOWED_SCHEMES.contains(&scheme) {
            return Err(DiscoveryError::config(format!(
                "iac: unsupported scheme '{scheme}' (allowed: {ALLOWED_SCHEMES:?})",
            )));
        }
        let s = url.as_str();
        let prefix = format!("{scheme}://");
        let path = s.strip_prefix(&prefix).unwrap_or(s).to_owned();
        if path.is_empty() {
            return Err(DiscoveryError::config(
                "iac: empty target path after stripping scheme",
            ));
        }
        Ok(path)
    }

    async fn run_checkov(&self, path_arg: &str) -> Result<Vec<u8>, DiscoveryError> {
        let mut cmd = Command::new(&self.cfg.checkov_binary);
        cmd.arg("--output")
            .arg("json")
            .arg("--quiet")
            .arg("-d")
            .arg(path_arg);
        cmd.kill_on_drop(true);

        let exec = cmd.output();
        let output = timeout(self.cfg.exec_timeout, exec)
            .await
            .map_err(|_| DiscoveryError::Timeout)?
            .map_err(|e| DiscoveryError::Io(format!("checkov spawn: {e}")))?;

        // Checkov returns a non-zero exit code when findings exist. Treat the
        // output as authoritative if stdout looks like JSON, and only surface
        // an error if both stdout is empty and the process truly failed.
        if !output.status.success() && output.stdout.is_empty() {
            return Err(DiscoveryError::Io(format!(
                "checkov exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(output.stdout)
    }
}

#[async_trait]
impl Scanner for IacScanner {
    fn id(&self) -> ScannerId {
        IAC_SCANNER_ID
    }

    fn capabilities(&self) -> ScannerCapabilities {
        let mut kinds = std::collections::HashSet::new();
        kinds.insert(TargetKind::Url);
        ScannerCapabilities {
            max_intensity: ScanIntensity::Standard,
            target_kinds: kinds,
            max_throughput_obs_per_sec: 200,
        }
    }

    async fn scan(
        &self,
        ctx: ScanContext,
        target: ScopeTarget,
    ) -> Result<ScanResult, DiscoveryError> {
        let path_arg = Self::validate_target(&target)?;

        let _permit = ctx
            .rate_limiter
            .acquire(&target.canonical_key())
            .await
            .map_err(|_| DiscoveryError::RateLimited)?;

        let started_at = OffsetDateTime::now_utc();
        let stdout = self.run_checkov(&path_arg).await?;
        let ended_at = OffsetDateTime::now_utc();

        let observations = parse_checkov_output(&stdout);
        tracing::info!(
            scanner = %IAC_SCANNER_ID,
            tenant_id = %ctx.tenant_id,
            engagement_id = %ctx.engagement_id,
            target = %path_arg,
            findings = observations.len(),
            "iac.scan.complete",
        );
        Ok(ScanResult {
            scanner_id: IAC_SCANNER_ID,
            target,
            observations,
            started_at,
            ended_at,
        })
    }
}

/// Infer the `IaC` framework from a file path. The heuristics are intentionally
/// conservative and only look at file extension / parent directory tokens.
#[must_use]
pub fn infer_framework(file_path: &str) -> &'static str {
    // Lowercase the path so all comparisons below are case-insensitive.
    let lower = file_path.to_ascii_lowercase();
    // `lower` is already lowercase, so `ends_with` here is effectively
    // case-insensitive over the original input.
    let ends = |suffix: &str| lower.as_bytes().ends_with(suffix.as_bytes());
    if ends(".tf") || ends(".tf.json") {
        return "terraform";
    }
    if ends(".json") || ends(".template") {
        return "cloudformation";
    }
    if (ends(".yaml") || ends(".yml")) && (lower.contains("k8s/") || lower.contains("/k8s/")) {
        return "kubernetes";
    }
    "unknown"
}

/// Parse checkov's JSON output into observations. Unknown / malformed fields
/// are tolerated — only the well-formed `failed_checks` entries contribute
/// observations.
///
/// Checkov sometimes emits a list at the root (one element per framework)
/// and sometimes a single object. Both shapes are accepted.
pub fn parse_checkov_output(bytes: &[u8]) -> Vec<Observation> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let mut out: Vec<Observation> = Vec::new();
    match &root {
        Value::Array(items) => {
            for item in items {
                collect_failed(item, &mut out);
            }
        }
        Value::Object(_) => collect_failed(&root, &mut out),
        _ => {}
    }
    out
}

fn collect_failed(node: &Value, out: &mut Vec<Observation>) {
    let Some(failed) = node
        .get("results")
        .and_then(|r| r.get("failed_checks"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for check in failed {
        if let Some(obs) = parse_failed_check(check) {
            out.push(obs);
        }
    }
}

fn parse_failed_check(check: &Value) -> Option<Observation> {
    let check_id = check.get("check_id").and_then(Value::as_str)?;
    let file_path = check.get("file_path").and_then(Value::as_str)?;
    let check_name = check
        .get("check_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let severity = check
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let line = check
        .get("file_line_range")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());
    Some(Observation::IacMisconfiguration {
        framework: infer_framework(file_path).to_owned(),
        file: file_path.to_owned(),
        line,
        check_id: check_id.to_owned(),
        severity: severity.to_ascii_lowercase(),
        message: check_name.to_owned(),
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
    use url::Url;

    // -------- config validation --------

    #[test]
    fn config_rejects_relative_binary() {
        let cfg = IacScannerConfig {
            checkov_binary: PathBuf::from("checkov"),
            exec_timeout: Duration::from_secs(30),
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let cfg = IacScannerConfig {
            checkov_binary: PathBuf::from("/usr/local/bin/checkov"),
            exec_timeout: Duration::ZERO,
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn config_accepts_valid() {
        let cfg = IacScannerConfig {
            checkov_binary: PathBuf::from("/usr/local/bin/checkov"),
            exec_timeout: Duration::from_secs(60),
        };
        assert!(cfg.check().is_ok());
    }

    #[test]
    fn new_rejects_bad_config() {
        let cfg = IacScannerConfig {
            checkov_binary: PathBuf::from("checkov"),
            exec_timeout: Duration::from_secs(30),
        };
        assert!(matches!(
            IacScanner::new(cfg),
            Err(DiscoveryError::Config(_))
        ));
    }

    // -------- target validation --------

    #[test]
    fn target_validator_accepts_dir() {
        let t = ScopeTarget::Url(Url::parse("dir:///srv/app").unwrap());
        let arg = IacScanner::validate_target(&t).unwrap();
        assert_eq!(arg, "/srv/app");
    }

    #[test]
    fn target_validator_accepts_git_https() {
        let t = ScopeTarget::Url(Url::parse("git+https://github.com/x/y.git").unwrap());
        let arg = IacScanner::validate_target(&t).unwrap();
        assert_eq!(arg, "github.com/x/y.git");
    }

    #[test]
    fn target_validator_rejects_http() {
        let t = ScopeTarget::Url(Url::parse("http://example.com/").unwrap());
        assert!(IacScanner::validate_target(&t).is_err());
    }

    #[test]
    fn target_validator_rejects_oci_scheme() {
        let t = ScopeTarget::Url(Url::parse("oci://docker.io/library/alpine").unwrap());
        assert!(IacScanner::validate_target(&t).is_err());
    }

    #[test]
    fn target_validator_rejects_non_url() {
        let t =
            ScopeTarget::Domain(crate::contracts::Fqdn::new("example.com").expect("static input"));
        assert!(IacScanner::validate_target(&t).is_err());
    }

    // -------- framework inference --------

    #[test]
    fn framework_terraform_for_tf() {
        assert_eq!(infer_framework("./main.tf"), "terraform");
        assert_eq!(infer_framework("/abs/path/network.tf"), "terraform");
        assert_eq!(infer_framework("./bundle.tf.json"), "terraform");
    }

    #[test]
    fn framework_kubernetes_for_yaml_under_k8s() {
        assert_eq!(infer_framework("k8s/deployment.yaml"), "kubernetes");
        assert_eq!(infer_framework("./k8s/svc.yml"), "kubernetes");
        assert_eq!(infer_framework("repo/k8s/manifests/pod.yaml"), "kubernetes");
    }

    #[test]
    fn framework_cloudformation_for_json_and_template() {
        assert_eq!(infer_framework("./stack.json"), "cloudformation");
        assert_eq!(infer_framework("./template.template"), "cloudformation");
    }

    #[test]
    fn framework_unknown_for_other_extensions() {
        assert_eq!(infer_framework("./README.md"), "unknown");
        assert_eq!(infer_framework("./script.sh"), "unknown");
        assert_eq!(infer_framework("./misc/file.yaml"), "unknown");
    }

    // -------- parser --------

    #[test]
    fn parse_extracts_failed_checks_object_shape() {
        let payload = br#"{
          "results": {
            "failed_checks": [
              {
                "check_id": "CKV_AWS_20",
                "check_name": "Ensure the S3 bucket has access logging enabled",
                "file_path": "./main.tf",
                "file_line_range": [5, 10],
                "severity": "HIGH"
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
        let obs = parse_checkov_output(payload);
        assert_eq!(obs.len(), 2);
        match &obs[0] {
            Observation::IacMisconfiguration {
                framework,
                file,
                line,
                check_id,
                severity,
                message,
            } => {
                assert_eq!(framework, "terraform");
                assert_eq!(file, "./main.tf");
                assert_eq!(*line, Some(5));
                assert_eq!(check_id, "CKV_AWS_20");
                assert_eq!(severity, "high");
                assert!(message.contains("S3"));
            }
            other => panic!("unexpected observation: {other:?}"),
        }
        match &obs[1] {
            Observation::IacMisconfiguration {
                framework,
                file,
                check_id,
                ..
            } => {
                assert_eq!(framework, "kubernetes");
                assert_eq!(file, "k8s/deployment.yaml");
                assert_eq!(check_id, "CKV_K8S_8");
            }
            other => panic!("unexpected observation: {other:?}"),
        }
    }

    #[test]
    fn parse_extracts_failed_checks_array_shape() {
        let payload = br#"[
          {
            "results": {
              "failed_checks": [
                {
                  "check_id": "CKV_AWS_1",
                  "check_name": "iam policy",
                  "file_path": "./iam.tf",
                  "file_line_range": [1, 2],
                  "severity": "low"
                }
              ]
            }
          }
        ]"#;
        let obs = parse_checkov_output(payload);
        assert_eq!(obs.len(), 1);
    }

    #[test]
    fn parse_tolerates_empty() {
        assert!(parse_checkov_output(b"").is_empty());
        assert!(parse_checkov_output(b"{}").is_empty());
        assert!(parse_checkov_output(b"[]").is_empty());
        assert!(parse_checkov_output(b"{\"results\":{\"failed_checks\":[]}}").is_empty());
    }

    #[test]
    fn parse_tolerates_garbage() {
        assert!(parse_checkov_output(b"not json").is_empty());
        assert!(parse_checkov_output(b"null").is_empty());
        assert!(parse_checkov_output(b"{\"results\":\"oops\"}").is_empty());
    }

    #[test]
    fn parse_skips_entries_without_required_fields() {
        let payload = br#"{
          "results": {
            "failed_checks": [
              {"check_id": "X"},
              {"file_path": "./y.tf"},
              {
                "check_id": "OK",
                "file_path": "./y.tf",
                "check_name": "ok",
                "severity": "low",
                "file_line_range": [3]
              }
            ]
          }
        }"#;
        let obs = parse_checkov_output(payload);
        assert_eq!(obs.len(), 1);
        match &obs[0] {
            Observation::IacMisconfiguration { check_id, line, .. } => {
                assert_eq!(check_id, "OK");
                assert_eq!(*line, Some(3));
            }
            other => panic!("unexpected observation: {other:?}"),
        }
    }
}
