//! Secret-leak scanner.
//!
//! Wraps [gitleaks](https://github.com/gitleaks/gitleaks) as a child process
//! to detect credentials accidentally committed to source control. The
//! scanner accepts [`ScopeTarget::Url`] targets where the URL scheme is one
//! of:
//!
//! - `git+https://…` — git repository over HTTPS.
//! - `git+ssh://…`   — git repository over SSH.
//! - `dir://…`       — local filesystem path (already-cloned working tree).
//!
//! Any other scheme is rejected before any subprocess is invoked.
//!
//! ## Security: the secret value never leaves this module
//!
//! Gitleaks emits the matched secret string in its JSON output. The parser
//! [`parse_gitleaks_output`] reads that field, immediately computes a
//! SHA-256 hash, hex-encodes it, and drops the original string before
//! constructing the [`Observation::SecretFinding`]. The raw secret is
//! **never** stored, logged, returned, or otherwise propagated outside
//! [`parse_gitleaks_output`]'s stack frame.
//!
//! Subprocess stderr is treated as untrusted text — it is sanitised to a
//! short prefix and never includes the JSON payload, on the assumption
//! that gitleaks may have written secret material to stderr during
//! debug-level builds.
//!
//! ## Why subprocess?
//!
//! `gitleaks`'s detection ruleset is a large embedded TOML file, updated
//! independently of `SentinelX`'s release cadence. A shell-out is the
//! pragmatic choice for Phase 1 and matches the SCA scanner's design.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::process::Command;
use tokio::time::timeout;
use url::Url;

use crate::contracts::{ScanIntensity, ScopeTarget};
use crate::error::DiscoveryError;
use crate::model::observation::Observation;
use crate::model::scan_result::ScanResult;
use crate::service::scanner::{ScanContext, Scanner, ScannerCapabilities, ScannerId, TargetKind};

/// Stable id used to register / look up this scanner.
pub const SECRET_SCANNER_ID: ScannerId = ScannerId::new("secret_gitleaks_v1");

/// Allowed URL schemes for the secret scanner's targets.
const ALLOWED_SCHEMES: &[&str] = &["git+https", "git+ssh", "dir"];

/// Maximum number of stderr bytes copied into a `DiscoveryError::Io`
/// message. Keeps log lines bounded and prevents accidental leak of large
/// debug dumps.
const STDERR_PREVIEW_BYTES: usize = 256;

/// Tag set deemed high-severity. Every other tag set degrades to `medium`.
const HIGH_SEVERITY_TAGS: &[&str] = &["aws", "gcp", "token", "azure", "private-key"];

/// Configuration for [`SecretScanner`].
#[derive(Debug, Clone)]
pub struct SecretScannerConfig {
    /// Path to the `gitleaks` binary. Must be absolute — no `PATH` lookup.
    pub gitleaks_binary: PathBuf,
    /// Wall-clock budget for one invocation.
    pub exec_timeout: Duration,
}

impl SecretScannerConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        if !self.gitleaks_binary.is_absolute() {
            return Err(DiscoveryError::config(
                "secret.gitleaks_binary must be an absolute path",
            ));
        }
        if self.exec_timeout.is_zero() {
            return Err(DiscoveryError::config("secret.exec_timeout must be > 0"));
        }
        Ok(())
    }
}

/// Gitleaks-backed secret-leak scanner.
#[derive(Debug)]
pub struct SecretScanner {
    cfg: SecretScannerConfig,
}

impl SecretScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: SecretScannerConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        Ok(Self { cfg })
    }

    fn validate_target(target: &ScopeTarget) -> Result<String, DiscoveryError> {
        let ScopeTarget::Url(url) = target else {
            return Err(DiscoveryError::config(
                "secret scanner accepts only Url targets (git+https / git+ssh / dir)",
            ));
        };
        let scheme = url.scheme();
        if !ALLOWED_SCHEMES.contains(&scheme) {
            return Err(DiscoveryError::config(format!(
                "secret: unsupported scheme '{scheme}' (allowed: {ALLOWED_SCHEMES:?})",
            )));
        }
        target_to_gitleaks_arg(url)
    }

    async fn run_gitleaks(&self, target_arg: &str) -> Result<Vec<u8>, DiscoveryError> {
        let mut cmd = Command::new(&self.cfg.gitleaks_binary);
        cmd.arg("detect")
            .arg("--no-banner")
            .arg("--report-format")
            .arg("json")
            .arg("--report-path")
            .arg("-")
            .arg("--source")
            .arg(target_arg);
        cmd.kill_on_drop(true);

        let exec = cmd.output();
        let output = timeout(self.cfg.exec_timeout, exec)
            .await
            .map_err(|_| DiscoveryError::Timeout)?
            .map_err(|e| DiscoveryError::Io(format!("gitleaks spawn: {e}")))?;

        if !output.status.success() {
            let stderr_preview = sanitise_stderr(&output.stderr);
            return Err(DiscoveryError::Io(format!(
                "gitleaks exited with {}: {stderr_preview}",
                output.status,
            )));
        }
        Ok(output.stdout)
    }
}

#[async_trait]
impl Scanner for SecretScanner {
    fn id(&self) -> ScannerId {
        SECRET_SCANNER_ID
    }

    fn capabilities(&self) -> ScannerCapabilities {
        let mut target_kinds = std::collections::HashSet::new();
        target_kinds.insert(TargetKind::Url);
        ScannerCapabilities {
            max_intensity: ScanIntensity::Light,
            target_kinds,
            max_throughput_obs_per_sec: 100,
        }
    }

    async fn scan(
        &self,
        ctx: ScanContext,
        target: ScopeTarget,
    ) -> Result<ScanResult, DiscoveryError> {
        let target_arg = Self::validate_target(&target)?;

        // One token per shell-out — gitleaks is a single repo-clone / scan
        // event.
        let _permit = ctx
            .rate_limiter
            .acquire(&target_arg)
            .await
            .map_err(|_| DiscoveryError::RateLimited)?;

        let started = OffsetDateTime::now_utc();
        let stdout = self.run_gitleaks(&target_arg).await?;
        let ended = OffsetDateTime::now_utc();

        let observations = parse_gitleaks_output(&stdout);
        tracing::info!(
            scanner = %SECRET_SCANNER_ID,
            tenant_id = %ctx.tenant_id,
            engagement_id = %ctx.engagement_id,
            target = %target_arg,
            findings = observations.len(),
            "secret.scan.complete",
        );
        Ok(ScanResult {
            scanner_id: SECRET_SCANNER_ID,
            target,
            observations,
            started_at: started,
            ended_at: ended,
        })
    }
}

/// Strip the `git+` / `dir://` prefix to produce the argument gitleaks
/// expects.
///
/// `git+https://x` becomes `https://x`, `dir:///tmp/x` becomes `/tmp/x`.
/// URLs that did not pass [`SecretScanner::validate_target`] produce a
/// [`DiscoveryError::Config`].
pub fn target_to_gitleaks_arg(url: &Url) -> Result<String, DiscoveryError> {
    let scheme = url.scheme();
    let raw = url.as_str();
    match scheme {
        "git+https" | "git+ssh" => raw
            .strip_prefix("git+")
            .map(str::to_owned)
            .ok_or_else(|| DiscoveryError::internal("git+ url missing 'git+' prefix")),
        "dir" => {
            // `dir://` URLs may parse with the path after the authority.
            // Reconstruct the absolute path from the URL components rather
            // than guessing at byte offsets.
            let host = url.host_str().unwrap_or("");
            let path = url.path();
            let combined = if host.is_empty() {
                path.to_owned()
            } else {
                format!("/{host}{path}")
            };
            if combined.is_empty() {
                return Err(DiscoveryError::config("dir:// url has empty path"));
            }
            Ok(combined)
        }
        other => Err(DiscoveryError::config(format!(
            "secret: unsupported scheme '{other}'",
        ))),
    }
}

/// Severity tier inferred from a gitleaks rule's tag list.
///
/// Mapping (documented for reviewers):
/// - `aws`, `gcp`, `azure`, `token`, `private-key` → `"high"`
/// - everything else → `"medium"`
///
/// Tags are matched case-insensitively against [`HIGH_SEVERITY_TAGS`].
#[must_use]
pub fn severity_for_tags(tags: &[&str]) -> &'static str {
    let high = tags
        .iter()
        .any(|t| HIGH_SEVERITY_TAGS.iter().any(|h| h.eq_ignore_ascii_case(t)));
    if high {
        "high"
    } else {
        "medium"
    }
}

/// Minimal projection of a gitleaks finding. Fields we don't need are
/// ignored — `serde` tolerates additional keys by default.
///
/// The `secret` field is **not** retained: it is hashed and dropped inside
/// [`parse_gitleaks_output`] before any [`Observation`] is constructed.
#[derive(Debug, Deserialize)]
struct RawFinding {
    #[serde(rename = "RuleID", default)]
    rule_id: String,
    #[serde(rename = "File", default)]
    file: String,
    #[serde(rename = "StartLine", default)]
    start_line: i64,
    #[serde(rename = "Secret", default)]
    secret: String,
    #[serde(rename = "Tags", default)]
    tags: Vec<String>,
}

/// Parse gitleaks' JSON output into observations.
///
/// The function is the single trust boundary for secret material: it reads
/// each `Secret` field, hashes it with SHA-256, hex-encodes the digest,
/// and drops the original `String` (the field is consumed by `mem::take`).
/// The resulting [`Observation::SecretFinding`] contains only the
/// fingerprint — the raw secret is unreachable from the caller.
///
/// Malformed JSON, an empty array, or unexpected shape all yield
/// `Vec::new()` — never a panic.
#[must_use]
pub fn parse_gitleaks_output(bytes: &[u8]) -> Vec<Observation> {
    let Ok(raw): Result<Vec<RawFinding>, _> = serde_json::from_slice(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(raw.len());
    for mut finding in raw {
        // SECURITY: take the secret out of the struct so no later code can
        // observe it. Hash, hex-encode, then drop.
        let secret = std::mem::take(&mut finding.secret);
        let fingerprint = sha256_hex(secret.as_bytes());
        drop(secret);

        let tags: Vec<&str> = finding.tags.iter().map(String::as_str).collect();
        let severity = severity_for_tags(&tags);
        let line = u32::try_from(finding.start_line.max(0)).unwrap_or(u32::MAX);

        out.push(Observation::SecretFinding {
            rule_id: finding.rule_id,
            severity: severity.to_owned(),
            file: if finding.file.is_empty() {
                None
            } else {
                Some(finding.file)
            },
            line: if line == 0 { None } else { Some(line) },
            fingerprint,
        });
    }
    out
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Truncate untrusted stderr to a fixed byte prefix and strip control
/// characters. Defensive: gitleaks debug builds may emit secret material
/// on stderr; we treat the whole stream as opaque.
fn sanitise_stderr(stderr: &[u8]) -> String {
    let truncated = stderr.get(..STDERR_PREVIEW_BYTES).unwrap_or(stderr);
    String::from_utf8_lossy(truncated)
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect::<String>()
        .trim()
        .to_owned()
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
    fn config_rejects_relative_binary() {
        let cfg = SecretScannerConfig {
            gitleaks_binary: PathBuf::from("gitleaks"),
            exec_timeout: Duration::from_secs(30),
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let cfg = SecretScannerConfig {
            gitleaks_binary: PathBuf::from("/usr/local/bin/gitleaks"),
            exec_timeout: Duration::ZERO,
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn target_accepts_git_https() {
        let t = ScopeTarget::Url(Url::parse("git+https://github.com/example/repo.git").unwrap());
        let arg = SecretScanner::validate_target(&t).unwrap();
        assert_eq!(arg, "https://github.com/example/repo.git");
    }

    #[test]
    fn target_accepts_dir() {
        let t = ScopeTarget::Url(Url::parse("dir:///tmp/checkout").unwrap());
        let arg = SecretScanner::validate_target(&t).unwrap();
        assert_eq!(arg, "/tmp/checkout");
    }

    #[test]
    fn target_rejects_oci() {
        let t = ScopeTarget::Url(Url::parse("oci://docker.io/library/alpine").unwrap());
        assert!(SecretScanner::validate_target(&t).is_err());
    }

    #[test]
    fn severity_aws_token_is_high() {
        assert_eq!(severity_for_tags(&["aws", "key"]), "high");
        assert_eq!(severity_for_tags(&["token"]), "high");
        assert_eq!(severity_for_tags(&["gcp"]), "high");
        assert_eq!(severity_for_tags(&["AWS"]), "high");
    }

    #[test]
    fn severity_generic_is_medium() {
        assert_eq!(severity_for_tags(&[]), "medium");
        assert_eq!(severity_for_tags(&["random"]), "medium");
        assert_eq!(severity_for_tags(&["password-ish"]), "medium");
    }

    #[test]
    fn parse_extracts_two_findings_and_redacts_secret() {
        // Two distinct secret values; we verify the parser hashes them and
        // never lets the raw strings reach the observation set.
        let secret_a = "AKIAIOSFODNN7EXAMPLE";
        let secret_b = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let payload = format!(
            r#"[
              {{
                "RuleID": "aws-access-token",
                "Description": "AWS",
                "File": "src/aws.go",
                "StartLine": 42,
                "Secret": "{secret_a}",
                "Match": "...",
                "Tags": ["aws"]
              }},
              {{
                "RuleID": "github-pat",
                "Description": "GitHub PAT",
                "File": "src/gh.rs",
                "StartLine": 7,
                "Secret": "{secret_b}",
                "Match": "...",
                "Tags": ["github"]
              }}
            ]"#
        );
        let obs = parse_gitleaks_output(payload.as_bytes());
        assert_eq!(obs.len(), 2);

        let expected_a = sha256_hex(secret_a.as_bytes());
        let expected_b = sha256_hex(secret_b.as_bytes());

        match &obs[0] {
            Observation::SecretFinding {
                rule_id,
                severity,
                file,
                line,
                fingerprint,
            } => {
                assert_eq!(rule_id, "aws-access-token");
                assert_eq!(severity, "high");
                assert_eq!(file.as_deref(), Some("src/aws.go"));
                assert_eq!(*line, Some(42));
                assert_eq!(fingerprint, &expected_a);
            }
            other => panic!("unexpected observation: {other:?}"),
        }

        match &obs[1] {
            Observation::SecretFinding {
                rule_id,
                severity,
                file,
                line,
                fingerprint,
            } => {
                assert_eq!(rule_id, "github-pat");
                assert_eq!(severity, "medium");
                assert_eq!(file.as_deref(), Some("src/gh.rs"));
                assert_eq!(*line, Some(7));
                assert_eq!(fingerprint, &expected_b);
            }
            other => panic!("unexpected observation: {other:?}"),
        }

        // SECURITY INVARIANT: no observation may contain the raw secret
        // value. This is the test the security review will read.
        let serialised = serde_json::to_string(&obs).unwrap();
        assert!(
            !serialised.contains(secret_a),
            "raw secret A leaked into observation set",
        );
        assert!(
            !serialised.contains(secret_b),
            "raw secret B leaked into observation set",
        );
    }

    #[test]
    fn parse_tolerates_empty_json_array() {
        let obs = parse_gitleaks_output(b"[]");
        assert!(obs.is_empty());
    }

    #[test]
    fn parse_tolerates_garbage_json() {
        assert!(parse_gitleaks_output(b"not json").is_empty());
        assert!(parse_gitleaks_output(b"").is_empty());
        assert!(parse_gitleaks_output(b"{\"unexpected\":\"shape\"}").is_empty());
    }

    #[test]
    fn gitleaks_arg_for_git_https_strips_prefix() {
        let url = Url::parse("git+https://github.com/example/repo").unwrap();
        let arg = target_to_gitleaks_arg(&url).unwrap();
        assert_eq!(arg, "https://github.com/example/repo");

        let ssh = Url::parse("git+ssh://git@github.com/example/repo").unwrap();
        let arg = target_to_gitleaks_arg(&ssh).unwrap();
        assert_eq!(arg, "ssh://git@github.com/example/repo");
    }

    #[test]
    fn gitleaks_arg_for_dir_strips_prefix() {
        let url = Url::parse("dir:///var/checkout").unwrap();
        let arg = target_to_gitleaks_arg(&url).unwrap();
        assert_eq!(arg, "/var/checkout");
    }

    #[test]
    fn sanitise_stderr_truncates_and_strips_controls() {
        let raw: Vec<u8> = b"hello\x07world\n".to_vec();
        let s = sanitise_stderr(&raw);
        assert!(!s.contains('\x07'));
        assert!(!s.contains('\n'));

        let long = vec![b'a'; STDERR_PREVIEW_BYTES * 4];
        let s = sanitise_stderr(&long);
        assert!(s.len() <= STDERR_PREVIEW_BYTES);
    }

    #[test]
    fn line_overflow_saturates() {
        let payload = br#"[
          {
            "RuleID": "x",
            "File": "f",
            "StartLine": 99999999999,
            "Secret": "s",
            "Tags": []
          }
        ]"#;
        let obs = parse_gitleaks_output(payload);
        assert_eq!(obs.len(), 1);
        match &obs[0] {
            Observation::SecretFinding { line, .. } => assert_eq!(*line, Some(u32::MAX)),
            _ => panic!("expected secret finding"),
        }
    }
}
