//! Cloud Security Posture Management (CSPM) scanner.
//!
//! Wraps [Prowler v4](https://github.com/prowler-cloud/prowler) as a child
//! process to audit a cloud account against the CIS Benchmark. The scanner
//! accepts [`ScopeTarget::Url`] targets where the URL scheme identifies the
//! provider:
//!
//! - `aws://account_id[/region]` — AWS account (12-digit id) and optional
//!   region (e.g. `aws://123456789012/us-east-1`).
//! - `gcp://project-id[/region]` — GCP project id (lowercase letters / digits
//!   / hyphens, 6-30 chars) and optional region.
//! - `azure://subscription-id[/resource-group]` — Azure subscription id
//!   (UUID) and optional resource group.
//!
//! Other schemes are rejected at the validator with a documented
//! [`DiscoveryError::Config`].
//!
//! ## Why subprocess?
//!
//! Prowler is a Python application that maintains a multi-megabyte rule set
//! updated on the upstream's cadence. Re-implementing the CIS Benchmark in
//! Rust would couple `SentinelX`'s release schedule to Prowler's rule
//! revisions. Shelling out is the pragmatic choice for Phase 1.
//!
//! ## Authentication
//!
//! The caller passes credentials via [`CspmScannerConfig::credentials`] as a
//! [`CloudCredentials`] enum. The scanner injects them into the subprocess
//! environment **only at spawn time** — never via stdout/stderr or process
//! arguments — so they are not exposed through tracing or argv.
//!
//! - AWS: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional
//!   `AWS_SESSION_TOKEN`.
//! - GCP: `GOOGLE_APPLICATION_CREDENTIALS_JSON` is written to a per-run
//!   temp file referenced by `GOOGLE_APPLICATION_CREDENTIALS`. The file is
//!   created with restrictive permissions and removed in the cleanup path.
//! - Azure: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`.
//!
//! Credentials are wrapped in [`secrecy::SecretString`] to prevent
//! accidental logging via `Debug`. The crate never calls `expose_secret`
//! except inside `Command::env` and the GCP credential file writer.
//!
//! ## Safety
//!
//! - The binary path is taken from configuration; no `PATH` lookups.
//! - The target URL is validated against the per-provider allowlist before
//!   any subprocess is spawned.
//! - The argument vector never includes shell metacharacters;
//!   [`tokio::process::Command`] uses `execvp`-style execution so there is
//!   no shell interpolation.
//! - The OCSF JSON output is parsed leniently: deserialisation failures or
//!   missing fields degrade to an empty / partial result set, never a panic.
//! - `kill_on_drop(true)` ensures a runaway prowler child is reaped if the
//!   future is cancelled.
//!
//! ## Service mapping
//!
//! The `service` field of an emitted [`Observation::CloudMisconfiguration`]
//! is derived from the OCSF `resources[0].type` value. The mapping is
//! intentionally conservative — unrecognised resource types fall back to
//! `"unknown"`. The AWS table below also documents the Phase-1 baseline; the
//! GCP/Azure CIS Benchmark mapping table is deferred (P1-009 scope).
//!
//! | OCSF resource type                | Service |
//! |-----------------------------------|---------|
//! | `AwsIamUser`, `AwsIamRole`, `AwsIamPolicy`, `AwsIamGroup` | `iam` |
//! | `AwsS3Bucket`                     | `s3` |
//! | `AwsEc2Instance`, `AwsEc2SecurityGroup`, `AwsEc2Volume`, `AwsEc2Vpc` | `ec2` |
//! | `AwsRdsDbInstance`, `AwsRdsDbCluster` | `rds` |
//! | `AwsKmsKey`                       | `kms` |
//! | `AwsCloudTrailTrail`              | `cloudtrail` |
//! | `AwsCloudWatchAlarm`, `AwsCloudWatchLogGroup` | `cloudwatch` |
//! | `AwsLambdaFunction`               | `lambda` |
//! | `AwsEksCluster`                   | `eks` |
//! | `AwsElbLoadBalancer`, `AwsElbv2LoadBalancer` | `elb` |
//! | `AwsConfigRule`                   | `config` |
//! | `AwsGuardDutyDetector`            | `guardduty` |
//! | `AwsSnsTopic`                     | `sns` |
//! | `AwsSqsQueue`                     | `sqs` |
//! | anything else                     | `unknown` |

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use sx_core::reference::cspm_enrichment::{extract_cwe_from_text, parse_prowler_compliance};
use sx_core::value_object::compliance::ComplianceTags;
use sx_core::value_object::cwe::CweId;
use time::OffsetDateTime;
use tokio::process::Command;
use tokio::time::timeout;
use uuid::Uuid;

use crate::contracts::{ScanIntensity, ScopeTarget};
use crate::error::DiscoveryError;
use crate::model::observation::Observation;
use crate::model::scan_result::ScanResult;
use crate::service::scanner::{ScanContext, Scanner, ScannerCapabilities, ScannerId, TargetKind};

/// Stable id used to register / look up this scanner.
pub const CSPM_SCANNER_ID: ScannerId = ScannerId::new("cspm_prowler_v1");

/// URL schemes this scanner accepts, one per supported cloud provider.
const ALLOWED_SCHEMES: &[&str] = &["aws", "gcp", "azure"];

/// AWS account ids are always exactly 12 ASCII digits.
const AWS_ACCOUNT_ID_LEN: usize = 12;

/// GCP project ids are between 6 and 30 chars, lowercase letters / digits /
/// hyphens, and must start with a lowercase letter.
const GCP_PROJECT_ID_MIN_LEN: usize = 6;
const GCP_PROJECT_ID_MAX_LEN: usize = 30;

/// Azure subscription ids are RFC 4122 UUIDs (36 chars including hyphens).
const AZURE_SUBSCRIPTION_ID_LEN: usize = 36;

/// Allowed severity strings (lower-case). Unknown severities are clamped to
/// `medium`.
const ALLOWED_SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];

/// Default severity when the upstream value is missing or unrecognised.
const DEFAULT_SEVERITY: &str = "medium";

/// Cloud-provider credentials supplied by the caller. Spawned into the
/// child's environment, never logged.
///
/// Stored secrets are wrapped in [`SecretString`] which suppresses their
/// contents from `Debug` and zeroises memory on drop.
#[derive(Debug, Clone)]
pub enum CloudCredentials {
    /// AWS IAM access-key pair, optionally a session token.
    Aws {
        /// `AWS_ACCESS_KEY_ID`.
        access_key_id: SecretString,
        /// `AWS_SECRET_ACCESS_KEY`.
        secret_access_key: SecretString,
        /// Optional `AWS_SESSION_TOKEN` for STS-issued credentials.
        session_token: Option<SecretString>,
    },
    /// GCP service-account credentials. The JSON is materialised to a
    /// per-run file pointed to by `GOOGLE_APPLICATION_CREDENTIALS`.
    Gcp {
        /// Raw service-account JSON body.
        service_account_json: SecretString,
    },
    /// Azure service-principal credentials.
    Azure {
        /// `AZURE_CLIENT_ID` (application UUID).
        client_id: SecretString,
        /// `AZURE_CLIENT_SECRET`.
        client_secret: SecretString,
        /// `AZURE_TENANT_ID` (directory UUID).
        tenant_id: SecretString,
    },
}

impl CloudCredentials {
    /// Provider tag used to match credentials to the target's scheme.
    #[must_use]
    pub const fn provider(&self) -> &'static str {
        match self {
            Self::Aws { .. } => "aws",
            Self::Gcp { .. } => "gcp",
            Self::Azure { .. } => "azure",
        }
    }
}

/// Configuration for [`CspmScanner`].
#[derive(Debug, Clone)]
pub struct CspmScannerConfig {
    /// Absolute path to the `prowler` binary. No `PATH` lookup is performed.
    pub prowler_binary: PathBuf,
    /// Wall-clock budget for one invocation.
    pub exec_timeout: Duration,
    /// Per-provider credential bundle. The scanner picks the entry matching
    /// the target's scheme; if no matching entry is configured, the
    /// subprocess is launched without injected credentials (Prowler then
    /// falls back to ambient SDK auth, e.g. instance metadata).
    pub credentials: Vec<CloudCredentials>,
}

impl CspmScannerConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        if !self.prowler_binary.is_absolute() {
            return Err(DiscoveryError::config(
                "cspm.prowler_binary must be an absolute path",
            ));
        }
        if self.exec_timeout.is_zero() {
            return Err(DiscoveryError::config("cspm.exec_timeout must be > 0"));
        }
        // Reject duplicates so caller knows which entry the scanner will
        // pick.
        let mut seen: Vec<&'static str> = Vec::with_capacity(self.credentials.len());
        for c in &self.credentials {
            let p = c.provider();
            if seen.contains(&p) {
                return Err(DiscoveryError::config(format!(
                    "cspm.credentials: duplicate entry for provider '{p}'",
                )));
            }
            seen.push(p);
        }
        Ok(())
    }

    /// Look up the credential entry for `provider` (one of `"aws"`,
    /// `"gcp"`, `"azure"`).
    fn find(&self, provider: &str) -> Option<&CloudCredentials> {
        self.credentials.iter().find(|c| c.provider() == provider)
    }
}

/// Parsed CSPM target, normalised across providers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CspmTarget {
    /// `aws://account_id[/region]`.
    Aws {
        account_id: String,
        region: Option<String>,
    },
    /// `gcp://project-id[/region]`.
    Gcp {
        project_id: String,
        region: Option<String>,
    },
    /// `azure://subscription-id[/resource-group]`.
    Azure {
        subscription_id: String,
        resource_group: Option<String>,
    },
}

impl CspmTarget {
    /// Provider tag for matching credentials and tracing.
    const fn provider(&self) -> &'static str {
        match self {
            Self::Aws { .. } => "aws",
            Self::Gcp { .. } => "gcp",
            Self::Azure { .. } => "azure",
        }
    }

    /// Canonical string form (used as a rate-limit key and as a tracing field).
    fn canonical(&self) -> String {
        match self {
            Self::Aws { account_id, region } => region.as_ref().map_or_else(
                || format!("aws://{account_id}"),
                |r| format!("aws://{account_id}/{r}"),
            ),
            Self::Gcp { project_id, region } => region.as_ref().map_or_else(
                || format!("gcp://{project_id}"),
                |r| format!("gcp://{project_id}/{r}"),
            ),
            Self::Azure {
                subscription_id,
                resource_group,
            } => resource_group.as_ref().map_or_else(
                || format!("azure://{subscription_id}"),
                |g| format!("azure://{subscription_id}/{g}"),
            ),
        }
    }
}

/// Prowler-backed CSPM scanner.
#[derive(Debug)]
pub struct CspmScanner {
    cfg: CspmScannerConfig,
}

impl CspmScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: CspmScannerConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        Ok(Self { cfg })
    }

    /// Parse and validate a target.
    fn validate_target(target: &ScopeTarget) -> Result<CspmTarget, DiscoveryError> {
        let ScopeTarget::Url(url) = target else {
            return Err(DiscoveryError::config(
                "cspm scanner accepts only Url targets \
                 (aws://account_id, gcp://project-id, azure://subscription-id)",
            ));
        };
        let scheme = url.scheme();
        if !ALLOWED_SCHEMES.contains(&scheme) {
            return Err(DiscoveryError::config(format!(
                "cspm: unsupported provider '{scheme}://' \
                 (allowed: aws, gcp, azure)",
            )));
        }
        match scheme {
            "aws" => parse_aws_target(url),
            "gcp" => parse_gcp_target(url),
            "azure" => parse_azure_target(url),
            // Unreachable because the contains() check gates this match.
            other => Err(DiscoveryError::config(format!(
                "cspm: unsupported provider '{other}://'",
            ))),
        }
    }

    /// Build a tempdir under `std::env::temp_dir()` named with a UUID v7.
    /// `tempfile` is intentionally not a workspace dependency — see crate docs.
    fn make_tempdir() -> Result<PathBuf, DiscoveryError> {
        let id = Uuid::now_v7();
        let mut path = std::env::temp_dir();
        path.push(format!("sx-cspm-{id}"));
        std::fs::create_dir_all(&path)
            .map_err(|e| DiscoveryError::io(format!("cspm: tempdir create failed: {e}")))?;
        Ok(path)
    }

    /// Best-effort cleanup. Logs on failure but never bubbles up.
    fn cleanup_tempdir(path: &Path) {
        if let Err(e) = std::fs::remove_dir_all(path) {
            tracing::warn!(
                scanner = %CSPM_SCANNER_ID,
                path = %path.display(),
                error = %e,
                "cspm.tempdir.cleanup_failed",
            );
        }
    }

    /// Run prowler against the parsed target. Output is written to the OCSF
    /// JSON file in `tempdir`, which is then read and returned as bytes.
    async fn run_prowler(
        &self,
        target: &CspmTarget,
        tempdir: &Path,
    ) -> Result<Vec<u8>, DiscoveryError> {
        let mut cmd = Command::new(&self.cfg.prowler_binary);
        // Per-provider argv. Always include `--output-formats json-ocsf`,
        // `--output-directory <tempdir>`, `--no-banner`, `--quiet`.
        match target {
            CspmTarget::Aws { region, .. } => {
                cmd.arg("aws")
                    .arg("--output-formats")
                    .arg("json-ocsf")
                    .arg("--output-directory")
                    .arg(tempdir)
                    .arg("--no-banner")
                    .arg("--quiet");
                if let Some(region) = region {
                    cmd.arg("--region").arg(region);
                }
            }
            CspmTarget::Gcp { project_id, region } => {
                cmd.arg("gcp")
                    .arg("--project-id")
                    .arg(project_id)
                    .arg("--output-formats")
                    .arg("json-ocsf")
                    .arg("--output-directory")
                    .arg(tempdir)
                    .arg("--no-banner")
                    .arg("--quiet");
                if let Some(region) = region {
                    cmd.arg("--region").arg(region);
                }
            }
            CspmTarget::Azure {
                subscription_id,
                resource_group,
            } => {
                cmd.arg("azure")
                    .arg("--sp-env-auth")
                    .arg("--subscription-ids")
                    .arg(subscription_id)
                    .arg("--output-formats")
                    .arg("json-ocsf")
                    .arg("--output-directory")
                    .arg(tempdir)
                    .arg("--no-banner")
                    .arg("--quiet");
                if let Some(rg) = resource_group {
                    cmd.arg("--resource-group").arg(rg);
                }
            }
        }
        // Inject credentials via environment variables. For GCP we write the
        // service-account JSON to a file inside the per-run tempdir.
        let creds = self.cfg.find(target.provider());
        let _gcp_creds_path = match creds {
            Some(CloudCredentials::Aws {
                access_key_id,
                secret_access_key,
                session_token,
            }) => {
                cmd.env("AWS_ACCESS_KEY_ID", access_key_id.expose_secret());
                cmd.env("AWS_SECRET_ACCESS_KEY", secret_access_key.expose_secret());
                if let Some(tok) = session_token {
                    cmd.env("AWS_SESSION_TOKEN", tok.expose_secret());
                }
                None
            }
            Some(CloudCredentials::Gcp {
                service_account_json,
            }) => {
                let path = write_gcp_credentials_file(tempdir, service_account_json)?;
                cmd.env("GOOGLE_APPLICATION_CREDENTIALS", &path);
                Some(path)
            }
            Some(CloudCredentials::Azure {
                client_id,
                client_secret,
                tenant_id,
            }) => {
                cmd.env("AZURE_CLIENT_ID", client_id.expose_secret());
                cmd.env("AZURE_CLIENT_SECRET", client_secret.expose_secret());
                cmd.env("AZURE_TENANT_ID", tenant_id.expose_secret());
                None
            }
            None => None,
        };
        cmd.kill_on_drop(true);

        let output = timeout(self.cfg.exec_timeout, cmd.output())
            .await
            .map_err(|_| DiscoveryError::Timeout)?
            .map_err(|e| DiscoveryError::io(format!("cspm: prowler spawn: {e}")))?;

        if !output.status.success() {
            // Stderr is bounded to a short snippet to limit blast radius if
            // upstream ever decides to echo env contents into errors. We
            // also never include the env vector in the error message.
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DiscoveryError::io(format!(
                "cspm: prowler exited with {}: {}",
                output.status,
                redact_stderr(stderr.trim()),
            )));
        }

        let ocsf_path = find_ocsf_output(tempdir)?;
        std::fs::read(&ocsf_path)
            .map_err(|e| DiscoveryError::io(format!("cspm: read ocsf output: {e}")))
    }
}

#[async_trait]
impl Scanner for CspmScanner {
    fn id(&self) -> ScannerId {
        CSPM_SCANNER_ID
    }

    fn capabilities(&self) -> ScannerCapabilities {
        let mut target_kinds = std::collections::HashSet::new();
        target_kinds.insert(TargetKind::Url);
        ScannerCapabilities {
            max_intensity: ScanIntensity::Standard,
            target_kinds,
            max_throughput_obs_per_sec: 100,
        }
    }

    async fn scan(
        &self,
        ctx: ScanContext,
        target: ScopeTarget,
    ) -> Result<ScanResult, DiscoveryError> {
        let cspm = Self::validate_target(&target)?;
        let canonical = cspm.canonical();
        let provider = cspm.provider();

        // One token per shell-out — prowler is a single multi-API event.
        let _permit = ctx
            .rate_limiter
            .acquire(&canonical)
            .await
            .map_err(|_| DiscoveryError::RateLimited)?;

        let tempdir = Self::make_tempdir()?;

        let started = OffsetDateTime::now_utc();
        let run = self.run_prowler(&cspm, &tempdir).await;
        let ended = OffsetDateTime::now_utc();

        // Cleanup is best-effort and runs in every branch. The tempdir
        // owns any GCP credential file written during run_prowler, so
        // removal here purges those bytes from disk.
        let bytes = match run {
            Ok(b) => {
                Self::cleanup_tempdir(&tempdir);
                b
            }
            Err(e) => {
                Self::cleanup_tempdir(&tempdir);
                return Err(e);
            }
        };

        let observations = parse_prowler_ocsf(&bytes);
        tracing::info!(
            scanner = %CSPM_SCANNER_ID,
            tenant_id = %ctx.tenant_id,
            engagement_id = %ctx.engagement_id,
            provider = %provider,
            target = %canonical,
            findings = observations.len(),
            "cspm.scan.complete",
        );

        Ok(ScanResult {
            scanner_id: CSPM_SCANNER_ID,
            target,
            observations,
            started_at: started,
            ended_at: ended,
        })
    }
}

/// Parse `aws://account_id[/region]`.
fn parse_aws_target(url: &url::Url) -> Result<CspmTarget, DiscoveryError> {
    let account_id = url
        .host_str()
        .ok_or_else(|| DiscoveryError::config("cspm: aws:// target is missing account id"))?
        .to_owned();

    if !is_valid_aws_account_id(&account_id) {
        return Err(DiscoveryError::config(format!(
            "cspm: invalid AWS account id '{account_id}' (must be {AWS_ACCOUNT_ID_LEN} digits)",
        )));
    }

    let path = url.path().trim_matches('/');
    let region = if path.is_empty() {
        None
    } else {
        if path.contains('/') {
            return Err(DiscoveryError::config(format!(
                "cspm: aws:// target path has more than one segment: '{path}'",
            )));
        }
        if !is_valid_region(path) {
            return Err(DiscoveryError::config(format!(
                "cspm: invalid AWS region '{path}'",
            )));
        }
        Some(path.to_owned())
    };

    Ok(CspmTarget::Aws { account_id, region })
}

/// Parse `gcp://project-id[/region]`.
fn parse_gcp_target(url: &url::Url) -> Result<CspmTarget, DiscoveryError> {
    let project_id = url
        .host_str()
        .ok_or_else(|| DiscoveryError::config("cspm: gcp:// target is missing project id"))?
        .to_owned();

    if !is_valid_gcp_project_id(&project_id) {
        return Err(DiscoveryError::config(format!(
            "cspm: invalid GCP project id '{project_id}' (must be \
             {GCP_PROJECT_ID_MIN_LEN}-{GCP_PROJECT_ID_MAX_LEN} chars: \
             lowercase letters, digits, hyphens; starts with a letter)",
        )));
    }

    let path = url.path().trim_matches('/');
    let region = if path.is_empty() {
        None
    } else {
        if path.contains('/') {
            return Err(DiscoveryError::config(format!(
                "cspm: gcp:// target path has more than one segment: '{path}'",
            )));
        }
        if !is_valid_region(path) {
            return Err(DiscoveryError::config(format!(
                "cspm: invalid GCP region '{path}'",
            )));
        }
        Some(path.to_owned())
    };

    Ok(CspmTarget::Gcp { project_id, region })
}

/// Parse `azure://subscription-id[/resource-group]`.
fn parse_azure_target(url: &url::Url) -> Result<CspmTarget, DiscoveryError> {
    let subscription_id = url
        .host_str()
        .ok_or_else(|| DiscoveryError::config("cspm: azure:// target is missing subscription id"))?
        .to_owned();

    if !is_valid_azure_subscription_id(&subscription_id) {
        return Err(DiscoveryError::config(format!(
            "cspm: invalid Azure subscription id '{subscription_id}' \
             (must be a UUID)",
        )));
    }

    let path = url.path().trim_matches('/');
    let resource_group = if path.is_empty() {
        None
    } else {
        if path.contains('/') {
            return Err(DiscoveryError::config(format!(
                "cspm: azure:// target path has more than one segment: '{path}'",
            )));
        }
        if !is_valid_azure_resource_group(path) {
            return Err(DiscoveryError::config(format!(
                "cspm: invalid Azure resource group '{path}'",
            )));
        }
        Some(path.to_owned())
    };

    Ok(CspmTarget::Azure {
        subscription_id,
        resource_group,
    })
}

/// Materialise the GCP service-account JSON to a file inside `tempdir`. The
/// file is overwritten if it already exists and stays inside the per-run
/// tempdir so the standard cleanup path removes it.
fn write_gcp_credentials_file(
    tempdir: &Path,
    json: &SecretString,
) -> Result<PathBuf, DiscoveryError> {
    let path = tempdir.join("gcp-sa.json");
    // Best-effort tightening of permissions on Unix. We write before
    // adjusting because `std::fs::write` does not accept a mode parameter
    // on stable Rust without `unsafe` extensions.
    std::fs::write(&path, json.expose_secret().as_bytes())
        .map_err(|e| DiscoveryError::io(format!("cspm: write gcp credentials: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0o600 — owner read/write only.
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(&path, perms) {
            tracing::warn!(
                scanner = %CSPM_SCANNER_ID,
                path = %path.display(),
                error = %e,
                "cspm.gcp_creds.chmod_failed",
            );
        }
    }
    Ok(path)
}

/// Validate an AWS account id: exactly 12 ASCII digits.
fn is_valid_aws_account_id(s: &str) -> bool {
    s.len() == AWS_ACCOUNT_ID_LEN && s.bytes().all(|b| b.is_ascii_digit())
}

/// Validate a GCP project id: 6-30 chars, lowercase ASCII letters / digits /
/// hyphens, must start with a lowercase letter, must not end with a hyphen.
fn is_valid_gcp_project_id(s: &str) -> bool {
    let len = s.len();
    if !(GCP_PROJECT_ID_MIN_LEN..=GCP_PROJECT_ID_MAX_LEN).contains(&len) {
        return false;
    }
    let bytes = s.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    if bytes.last() == Some(&b'-') {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Positions of the hyphens in a canonical UUID: 8, 13, 18, 23.
const AZURE_UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];

/// Validate an Azure subscription id: a canonical UUID
/// (`8-4-4-4-12` hex groups separated by hyphens).
fn is_valid_azure_subscription_id(s: &str) -> bool {
    if s.len() != AZURE_SUBSCRIPTION_ID_LEN {
        return false;
    }
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if AZURE_UUID_HYPHENS.contains(&i) {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Validate an Azure resource-group name: 1-90 chars, ASCII alphanumeric,
/// hyphens, underscores, periods, and parentheses. Cannot end with a period.
fn is_valid_azure_resource_group(s: &str) -> bool {
    let len = s.len();
    if !(1..=90).contains(&len) {
        return false;
    }
    if s.ends_with('.') {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'(' | b')'))
}

/// Light validation for a region string: 2-30 chars, lowercase ascii letters,
/// digits, and hyphens. Matches every published AWS region (e.g.
/// `us-east-1`, `eu-central-1`, `ap-southeast-2`) and GCP regions
/// (e.g. `us-central1`, `europe-west4`).
fn is_valid_region(s: &str) -> bool {
    (2..=30).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Locate the OCSF JSON file Prowler wrote into `dir`. Prowler names the
/// file `prowler-output-<timestamp>.ocsf.json`; we accept any file whose
/// name ends with `.ocsf.json`.
fn find_ocsf_output(dir: &Path) -> Result<PathBuf, DiscoveryError> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| DiscoveryError::io(format!("cspm: read tempdir: {e}")))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".ocsf.json"))
        {
            return Ok(path);
        }
    }
    Err(DiscoveryError::io(
        "cspm: prowler produced no .ocsf.json output".to_owned(),
    ))
}

/// Redact sensitive-looking substrings from prowler stderr before it flows
/// into a `DiscoveryError`. The list is intentionally conservative:
/// we substring-match the names of the env vars we ever set and drop the
/// remainder of the line in case Prowler echoed back `KEY=value` syntax.
fn redact_stderr(s: &str) -> String {
    // Cap the snippet length so a runaway error stream cannot dominate logs.
    const MAX: usize = 1024;
    let snippet: &str = if s.len() > MAX { &s[..MAX] } else { s };
    let needles = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
    ];
    let mut out = String::with_capacity(snippet.len());
    for line in snippet.lines() {
        if needles.iter().any(|n| line.contains(n)) {
            out.push_str("[redacted: credential env var name appeared in prowler stderr]");
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    // Trim the trailing newline added for the last line.
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Map a raw OCSF severity to the canonical lowercase form. Unknown values
/// fall back to [`DEFAULT_SEVERITY`].
fn normalise_severity(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if ALLOWED_SEVERITIES.contains(&lower.as_str()) {
        lower
    } else {
        DEFAULT_SEVERITY.to_owned()
    }
}

/// Derive a short service identifier from an OCSF resource type string. The
/// mapping is documented in the module-level doc-comment.
fn service_from_resource_type(resource_type: &str) -> &'static str {
    match resource_type {
        "AwsIamUser" | "AwsIamRole" | "AwsIamPolicy" | "AwsIamGroup" => "iam",
        "AwsS3Bucket" => "s3",
        "AwsEc2Instance" | "AwsEc2SecurityGroup" | "AwsEc2Volume" | "AwsEc2Vpc" => "ec2",
        "AwsRdsDbInstance" | "AwsRdsDbCluster" => "rds",
        "AwsKmsKey" => "kms",
        "AwsCloudTrailTrail" => "cloudtrail",
        "AwsCloudWatchAlarm" | "AwsCloudWatchLogGroup" => "cloudwatch",
        "AwsLambdaFunction" => "lambda",
        "AwsEksCluster" => "eks",
        "AwsElbLoadBalancer" | "AwsElbv2LoadBalancer" => "elb",
        "AwsConfigRule" => "config",
        "AwsGuardDutyDetector" => "guardduty",
        "AwsSnsTopic" => "sns",
        "AwsSqsQueue" => "sqs",
        _ => "unknown",
    }
}

/// Parse Prowler's OCSF JSON output into observations. Garbage / partial
/// payloads are tolerated — only well-formed `Fail` entries contribute
/// observations.
#[must_use]
pub fn parse_prowler_ocsf(bytes: &[u8]) -> Vec<Observation> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let Some(items) = root.as_array() else {
        return Vec::new();
    };
    items.iter().filter_map(parse_ocsf_entry).collect()
}

fn parse_ocsf_entry(entry: &Value) -> Option<Observation> {
    let status = entry.get("status_code").and_then(Value::as_str)?;
    if !status.eq_ignore_ascii_case("Fail") {
        return None;
    }
    let check_id = entry.get("uid").and_then(Value::as_str)?.to_owned();

    let severity_raw = entry
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_SEVERITY);
    let severity = normalise_severity(severity_raw);

    let cloud = entry.get("cloud");
    let provider = cloud
        .and_then(|c| c.get("provider"))
        .and_then(Value::as_str)
        .unwrap_or("aws")
        .to_ascii_lowercase();

    let region = cloud
        .and_then(|c| c.get("region"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    let first_resource = entry
        .get("resources")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first());

    let resource = first_resource
        .and_then(|r| r.get("uid"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();

    let resource_type = first_resource
        .and_then(|r| r.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let service = service_from_resource_type(resource_type).to_owned();

    let message = entry
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();

    // TOP5-#3 Phase 2 (P2-006) — project Prowler's own CWE / compliance
    // metadata into the canonical enrichment surface. Prowler emits no
    // CVSS, so `cvss` stays None; no Prowler-id → ATT&CK table exists
    // yet so `mitre_attack` stays empty.
    let (cwe, compliance) = extract_enrichment(entry);

    Some(Observation::CloudMisconfiguration {
        check_id,
        severity,
        provider,
        region,
        service,
        resource,
        message,
        cvss: None,
        cwe,
        mitre_attack: Vec::new(),
        compliance,
    })
}

/// Pull the Prowler enrichment payload out of a single OCSF entry.
///
/// Compliance is read from (in order) `unmapped.compliance`,
/// `compliance`, and `metadata.compliance`. CWE identifiers are
/// regex-extracted from any free-text field Prowler is known to surface
/// (`risk_details`, `risk`, `description`, `remediation.desc`,
/// `unmapped.related_url`).
fn extract_enrichment(entry: &Value) -> (Vec<CweId>, ComplianceTags) {
    let compliance = compliance_value(entry)
        .map(parse_prowler_compliance)
        .unwrap_or_default();
    let cwe = extract_cwe_from_text(&collect_cwe_corpus(entry));
    (cwe, compliance)
}

/// Locate the Prowler `compliance` object across known OCSF shapes.
fn compliance_value(entry: &Value) -> Option<&Value> {
    if let Some(v) = entry.pointer("/unmapped/compliance") {
        if v.is_object() {
            return Some(v);
        }
    }
    if let Some(v) = entry.get("compliance") {
        if v.is_object() {
            return Some(v);
        }
    }
    if let Some(v) = entry.pointer("/metadata/compliance") {
        if v.is_object() {
            return Some(v);
        }
    }
    None
}

/// Concatenate the free-text fields Prowler is known to use for risk
/// summaries; the result is fed to the CWE regex.
fn collect_cwe_corpus(entry: &Value) -> String {
    let mut buf = String::new();
    for path in [
        "/risk",
        "/risk_details",
        "/description",
        "/remediation/desc",
        "/remediation/description",
        "/unmapped/risk",
        "/unmapped/risk_details",
        "/unmapped/related_url",
    ] {
        if let Some(s) = entry.pointer(path).and_then(Value::as_str) {
            buf.push_str(s);
            buf.push(' ');
        }
    }
    buf
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
    use sx_core::value_object::compliance::{IsoControl, NistControl, PciRequirement};
    use url::Url;

    fn url_target(s: &str) -> ScopeTarget {
        ScopeTarget::Url(Url::parse(s).expect("static input"))
    }

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned().into_boxed_str())
    }

    #[test]
    fn config_rejects_relative_binary() {
        let cfg = CspmScannerConfig {
            prowler_binary: PathBuf::from("prowler"),
            exec_timeout: Duration::from_secs(60),
            credentials: vec![],
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let cfg = CspmScannerConfig {
            prowler_binary: PathBuf::from("/usr/local/bin/prowler"),
            exec_timeout: Duration::ZERO,
            credentials: vec![],
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn config_rejects_duplicate_credentials() {
        let cfg = CspmScannerConfig {
            prowler_binary: PathBuf::from("/usr/local/bin/prowler"),
            exec_timeout: Duration::from_secs(60),
            credentials: vec![
                CloudCredentials::Aws {
                    access_key_id: secret("a"),
                    secret_access_key: secret("b"),
                    session_token: None,
                },
                CloudCredentials::Aws {
                    access_key_id: secret("c"),
                    secret_access_key: secret("d"),
                    session_token: None,
                },
            ],
        };
        let err = cfg.check().expect_err("duplicate must reject");
        match err {
            DiscoveryError::Config(msg) => assert!(msg.contains("duplicate")),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn target_accepts_aws_account_only() {
        let t = url_target("aws://123456789012");
        let parsed = CspmScanner::validate_target(&t).expect("valid target");
        assert!(matches!(
            parsed,
            CspmTarget::Aws {
                ref account_id,
                region: None,
            } if account_id == "123456789012",
        ));
    }

    #[test]
    fn target_accepts_aws_with_region() {
        let t = url_target("aws://123456789012/us-east-1");
        let parsed = CspmScanner::validate_target(&t).expect("valid target");
        match parsed {
            CspmTarget::Aws { account_id, region } => {
                assert_eq!(account_id, "123456789012");
                assert_eq!(region.as_deref(), Some("us-east-1"));
            }
            other => panic!("expected Aws target, got {other:?}"),
        }
    }

    #[test]
    fn target_accepts_gcp_project_only() {
        let t = url_target("gcp://my-project-id");
        let parsed = CspmScanner::validate_target(&t).expect("valid target");
        match parsed {
            CspmTarget::Gcp { project_id, region } => {
                assert_eq!(project_id, "my-project-id");
                assert_eq!(region, None);
            }
            other => panic!("expected Gcp target, got {other:?}"),
        }
    }

    #[test]
    fn target_accepts_gcp_with_region() {
        let t = url_target("gcp://my-project/us-central1");
        let parsed = CspmScanner::validate_target(&t).expect("valid target");
        match parsed {
            CspmTarget::Gcp { project_id, region } => {
                assert_eq!(project_id, "my-project");
                assert_eq!(region.as_deref(), Some("us-central1"));
            }
            other => panic!("expected Gcp target, got {other:?}"),
        }
    }

    #[test]
    fn target_rejects_gcp_project_starting_with_digit() {
        let t = url_target("gcp://1bad-start");
        let err = CspmScanner::validate_target(&t).unwrap_err();
        assert!(matches!(err, DiscoveryError::Config(_)));
    }

    #[test]
    fn target_rejects_gcp_project_too_short() {
        let t = url_target("gcp://ab12");
        let err = CspmScanner::validate_target(&t).unwrap_err();
        assert!(matches!(err, DiscoveryError::Config(_)));
    }

    #[test]
    fn target_accepts_azure_subscription_only() {
        let t = url_target("azure://00000000-0000-0000-0000-000000000000");
        let parsed = CspmScanner::validate_target(&t).expect("valid target");
        match parsed {
            CspmTarget::Azure {
                subscription_id,
                resource_group,
            } => {
                assert_eq!(subscription_id, "00000000-0000-0000-0000-000000000000");
                assert_eq!(resource_group, None);
            }
            other => panic!("expected Azure target, got {other:?}"),
        }
    }

    #[test]
    fn target_accepts_azure_with_resource_group() {
        let t = url_target("azure://12345678-1234-1234-1234-123456789abc/my-rg-01");
        let parsed = CspmScanner::validate_target(&t).expect("valid target");
        match parsed {
            CspmTarget::Azure {
                subscription_id,
                resource_group,
            } => {
                assert_eq!(subscription_id, "12345678-1234-1234-1234-123456789abc");
                assert_eq!(resource_group.as_deref(), Some("my-rg-01"));
            }
            other => panic!("expected Azure target, got {other:?}"),
        }
    }

    #[test]
    fn target_rejects_azure_non_uuid() {
        let t = url_target("azure://not-a-uuid");
        let err = CspmScanner::validate_target(&t).unwrap_err();
        assert!(matches!(err, DiscoveryError::Config(_)));
    }

    #[test]
    fn target_rejects_unknown_scheme() {
        // Confirm everything outside the aws/gcp/azure allowlist is rejected.
        for s in ["oci://docker.io/library/alpine", "https://example.com/x"] {
            let t = url_target(s);
            let err = CspmScanner::validate_target(&t).unwrap_err();
            match err {
                DiscoveryError::Config(msg) => {
                    assert!(msg.contains("allowed: aws, gcp, azure"), "got: {msg}");
                }
                other => panic!("expected Config error for {s}, got {other:?}"),
            }
        }
    }

    #[test]
    fn target_rejects_invalid_account_id() {
        // Too short.
        let t = url_target("aws://12345");
        assert!(matches!(
            CspmScanner::validate_target(&t),
            Err(DiscoveryError::Config(_)),
        ));
        // Non-digit.
        let t = url_target("aws://12345678901a");
        assert!(matches!(
            CspmScanner::validate_target(&t),
            Err(DiscoveryError::Config(_)),
        ));
        // Too long.
        let t = url_target("aws://1234567890123");
        assert!(matches!(
            CspmScanner::validate_target(&t),
            Err(DiscoveryError::Config(_)),
        ));
    }

    #[test]
    fn canonical_round_trip_per_provider() {
        let aws = CspmScanner::validate_target(&url_target("aws://123456789012/us-east-1"))
            .expect("aws valid");
        assert_eq!(aws.canonical(), "aws://123456789012/us-east-1");
        assert_eq!(aws.provider(), "aws");

        let gcp = CspmScanner::validate_target(&url_target("gcp://my-project/us-central1"))
            .expect("gcp valid");
        assert_eq!(gcp.canonical(), "gcp://my-project/us-central1");
        assert_eq!(gcp.provider(), "gcp");

        let azure = CspmScanner::validate_target(&url_target(
            "azure://12345678-1234-1234-1234-123456789abc/my-rg",
        ))
        .expect("azure valid");
        assert_eq!(
            azure.canonical(),
            "azure://12345678-1234-1234-1234-123456789abc/my-rg"
        );
        assert_eq!(azure.provider(), "azure");
    }

    #[test]
    fn config_find_matches_provider() {
        let cfg = CspmScannerConfig {
            prowler_binary: PathBuf::from("/usr/local/bin/prowler"),
            exec_timeout: Duration::from_secs(60),
            credentials: vec![
                CloudCredentials::Aws {
                    access_key_id: secret("AKIA"),
                    secret_access_key: secret("S3CRET"),
                    session_token: None,
                },
                CloudCredentials::Gcp {
                    service_account_json: secret("{\"type\":\"service_account\"}"),
                },
                CloudCredentials::Azure {
                    client_id: secret("11111111-1111-1111-1111-111111111111"),
                    client_secret: secret("az-secret"),
                    tenant_id: secret("22222222-2222-2222-2222-222222222222"),
                },
            ],
        };
        cfg.check().expect("config valid");
        assert!(matches!(
            cfg.find("aws"),
            Some(CloudCredentials::Aws { .. })
        ));
        assert!(matches!(
            cfg.find("gcp"),
            Some(CloudCredentials::Gcp { .. })
        ));
        assert!(matches!(
            cfg.find("azure"),
            Some(CloudCredentials::Azure { .. })
        ));
        assert!(cfg.find("oracle").is_none());
    }

    #[test]
    fn cloud_credentials_debug_does_not_leak_secret() {
        let creds = CloudCredentials::Aws {
            access_key_id: secret("AKIA-LEAK-ID"),
            secret_access_key: secret("SUPER-SECRET-VALUE"),
            session_token: Some(secret("STS-SESSION-TOKEN")),
        };
        let dbg = format!("{creds:?}");
        // `secrecy::SecretString` redacts itself in Debug; assert that the
        // raw secret bytes are nowhere in the formatted representation.
        assert!(!dbg.contains("AKIA-LEAK-ID"), "debug leaked: {dbg}");
        assert!(!dbg.contains("SUPER-SECRET-VALUE"), "debug leaked: {dbg}");
        assert!(!dbg.contains("STS-SESSION-TOKEN"), "debug leaked: {dbg}");
    }

    #[test]
    fn cloud_credentials_provider_tag() {
        assert_eq!(
            CloudCredentials::Aws {
                access_key_id: secret("a"),
                secret_access_key: secret("b"),
                session_token: None,
            }
            .provider(),
            "aws",
        );
        assert_eq!(
            CloudCredentials::Gcp {
                service_account_json: secret("{}"),
            }
            .provider(),
            "gcp",
        );
        assert_eq!(
            CloudCredentials::Azure {
                client_id: secret("a"),
                client_secret: secret("b"),
                tenant_id: secret("c"),
            }
            .provider(),
            "azure",
        );
    }

    #[test]
    fn write_gcp_credentials_creates_restricted_file() {
        let dir = std::env::temp_dir().join(format!("sx-cspm-test-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("create tempdir");
        let json = secret("{\"type\":\"service_account\",\"k\":\"v\"}");
        let path = write_gcp_credentials_file(&dir, &json).expect("write creds");
        assert!(path.starts_with(&dir));

        let read_back = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(read_back, "{\"type\":\"service_account\",\"k\":\"v\"}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).expect("metadata");
            // Only the bottom nine permission bits — strip the file-type bits.
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_stderr_masks_credential_env_var_lines() {
        let raw = "INFO: prowler starting\n\
                   ERROR: AWS_SECRET_ACCESS_KEY=AKIAOOPS in environment\n\
                   ERROR: AZURE_CLIENT_SECRET leaked\n\
                   INFO: finished\n";
        let red = redact_stderr(raw);
        assert!(!red.contains("AKIAOOPS"));
        assert!(red.contains("[redacted: credential env var name appeared in prowler stderr]"));
        assert!(red.contains("INFO: prowler starting"));
        assert!(red.contains("INFO: finished"));
    }

    #[test]
    fn parse_extracts_failed_checks_only() {
        let payload = br#"[
          {
            "uid": "iam_root_mfa_enabled",
            "severity": "High",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn:aws:iam::123:user/root", "type": "AwsIamUser" }],
            "message": "Root has no MFA"
          },
          {
            "uid": "s3_bucket_public_access_block",
            "severity": "Medium",
            "status_code": "Pass",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn:aws:s3:::bucket-a", "type": "AwsS3Bucket" }],
            "message": "OK"
          },
          {
            "uid": "s3_bucket_default_encryption",
            "severity": "Critical",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn:aws:s3:::bucket-b", "type": "AwsS3Bucket" }],
            "message": "Bucket lacks default encryption"
          }
        ]"#;
        let obs = parse_prowler_ocsf(payload);
        assert_eq!(obs.len(), 2);
        let ids: Vec<&str> = obs
            .iter()
            .map(|o| match o {
                Observation::CloudMisconfiguration { check_id, .. } => check_id.as_str(),
                _ => panic!("unexpected observation kind"),
            })
            .collect();
        assert_eq!(
            ids,
            vec!["iam_root_mfa_enabled", "s3_bucket_default_encryption"],
        );
    }

    #[test]
    fn parse_maps_service_from_resource_type() {
        let payload = br#"[
          {
            "uid": "iam_check_1",
            "severity": "High",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn:aws:iam::1:user/x", "type": "AwsIamUser" }],
            "message": "iam finding"
          },
          {
            "uid": "s3_check_1",
            "severity": "High",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn:aws:s3:::bucket", "type": "AwsS3Bucket" }],
            "message": "s3 finding"
          },
          {
            "uid": "unknown_check_1",
            "severity": "Low",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn:aws:??", "type": "AwsBrandNewService" }],
            "message": "future finding"
          }
        ]"#;
        let obs = parse_prowler_ocsf(payload);
        assert_eq!(obs.len(), 3);
        let services: Vec<&str> = obs
            .iter()
            .map(|o| match o {
                Observation::CloudMisconfiguration { service, .. } => service.as_str(),
                _ => panic!("unexpected observation kind"),
            })
            .collect();
        assert_eq!(services, vec!["iam", "s3", "unknown"]);

        // Spot-check the direct mapping function too.
        assert_eq!(service_from_resource_type("AwsIamUser"), "iam");
        assert_eq!(service_from_resource_type("AwsS3Bucket"), "s3");
        assert_eq!(service_from_resource_type("AwsEc2Instance"), "ec2");
        assert_eq!(service_from_resource_type("AwsRdsDbInstance"), "rds");
        assert_eq!(service_from_resource_type("AwsKmsKey"), "kms");
        assert_eq!(service_from_resource_type("AwsLambdaFunction"), "lambda");
        assert_eq!(service_from_resource_type("Unrecognised"), "unknown");
    }

    #[test]
    fn parse_severity_normalises_to_lowercase() {
        let payload = br#"[
          {
            "uid": "c1",
            "severity": "CRITICAL",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn", "type": "AwsS3Bucket" }],
            "message": "m"
          },
          {
            "uid": "c2",
            "severity": "Bogus",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn", "type": "AwsS3Bucket" }],
            "message": "m"
          },
          {
            "uid": "c3",
            "severity": "  High  ",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn", "type": "AwsS3Bucket" }],
            "message": "m"
          }
        ]"#;
        let obs = parse_prowler_ocsf(payload);
        assert_eq!(obs.len(), 3);
        let sevs: Vec<&str> = obs
            .iter()
            .map(|o| match o {
                Observation::CloudMisconfiguration { severity, .. } => severity.as_str(),
                _ => panic!("unexpected observation kind"),
            })
            .collect();
        // Bogus -> default `medium`.
        assert_eq!(sevs, vec!["critical", "medium", "high"]);
    }

    #[test]
    fn parse_tolerates_empty_array() {
        assert!(parse_prowler_ocsf(b"[]").is_empty());
    }

    #[test]
    fn parse_tolerates_garbage_json() {
        assert!(parse_prowler_ocsf(b"not json at all").is_empty());
        assert!(parse_prowler_ocsf(b"{}").is_empty());
        assert!(parse_prowler_ocsf(b"null").is_empty());
        // Array of garbage entries — each one is skipped.
        assert!(parse_prowler_ocsf(b"[1, \"str\", null, {}]").is_empty());
    }

    /// TOP5-#3 Phase 2 (P2-006) — verify that Prowler's OCSF compliance
    /// object and any `CWE-xxx` mentions in the risk text are projected
    /// onto the canonical enrichment surface on
    /// [`Observation::CloudMisconfiguration`]. Prowler does not emit
    /// CVSS, so `cvss` stays `None`; no ATT&CK table exists yet so
    /// `mitre_attack` stays empty.
    #[test]
    fn parse_projects_prowler_enrichment_into_observation() {
        let payload = br#"[
          {
            "uid": "iam_password_policy_minimum_length_14",
            "severity": "Medium",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn:aws:iam::1:account-password-policy", "type": "AwsIamPolicy" }],
            "message": "Password policy minimum length is below 14.",
            "risk": "Weak password policies allow brute-forcing (CWE-521); cleartext storage may also apply (CWE-256).",
            "unmapped": {
                "compliance": {
                    "nist_800_53_revision_5": ["AC-7", "IA-5"],
                    "iso_27001_2013": ["A.9.4.3"],
                    "pci_3_2_1": ["8.2.3"],
                    "cis_aws_1_4": ["1.10"]
                }
            }
          }
        ]"#;
        let obs = parse_prowler_ocsf(payload);
        assert_eq!(obs.len(), 1);
        match &obs[0] {
            Observation::CloudMisconfiguration {
                check_id,
                cvss,
                cwe,
                mitre_attack,
                compliance,
                ..
            } => {
                assert_eq!(check_id, "iam_password_policy_minimum_length_14");
                // Prowler does not emit CVSS — confirm we did not invent one.
                assert!(cvss.is_none());
                // No ATT&CK table yet for CSPM.
                assert!(mitre_attack.is_empty());
                // CWE: both ids picked up, dedup-stable, ordered by first
                // appearance in the risk text.
                let cwe_nums: Vec<u32> = cwe.iter().copied().map(CweId::as_u32).collect();
                assert_eq!(cwe_nums, vec![521, 256]);
                // Compliance: known frameworks projected, unknown
                // (`cis_aws_1_4`) silently dropped.
                let nist: Vec<&str> = compliance
                    .nist_800_53
                    .iter()
                    .map(NistControl::as_str)
                    .collect();
                assert_eq!(nist, vec!["AC-7", "IA-5"]);
                let iso: Vec<&str> = compliance
                    .iso_27001
                    .iter()
                    .map(IsoControl::as_str)
                    .collect();
                assert_eq!(iso, vec!["A.9.4.3"]);
                let pci: Vec<&str> = compliance
                    .pci_dss
                    .iter()
                    .map(PciRequirement::as_str)
                    .collect();
                assert_eq!(pci, vec!["8.2.3"]);
                assert!(compliance.soc2.is_empty());
                assert!(compliance.hipaa.is_empty());
            }
            other => panic!("expected CloudMisconfiguration, got {other:?}"),
        }
    }

    /// When Prowler emits no compliance / no risk text the enrichment
    /// surface stays empty and the JSON wire payload omits the keys
    /// (covered by the `#[serde(skip_serializing_if = …)]` attributes).
    #[test]
    fn parse_leaves_enrichment_empty_when_prowler_omits_it() {
        let payload = br#"[
          {
            "uid": "s3_bucket_default_encryption",
            "severity": "High",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn:aws:s3:::b", "type": "AwsS3Bucket" }],
            "message": "Bucket lacks default encryption"
          }
        ]"#;
        let obs = parse_prowler_ocsf(payload);
        assert_eq!(obs.len(), 1);
        match &obs[0] {
            Observation::CloudMisconfiguration {
                cvss,
                cwe,
                mitre_attack,
                compliance,
                ..
            } => {
                assert!(cvss.is_none());
                assert!(cwe.is_empty());
                assert!(mitre_attack.is_empty());
                assert!(compliance.is_empty());
            }
            other => panic!("expected CloudMisconfiguration, got {other:?}"),
        }

        // Serialise: enrichment keys must be absent from the wire form.
        let json = serde_json::to_string(&obs[0]).expect("serialise");
        assert!(!json.contains("\"cvss\""), "cvss key leaked: {json}");
        assert!(!json.contains("\"cwe\""), "cwe key leaked: {json}");
        assert!(
            !json.contains("\"mitre_attack\""),
            "mitre_attack key leaked: {json}",
        );
        assert!(
            !json.contains("\"compliance\""),
            "compliance key leaked: {json}",
        );
    }

    /// Top-level `compliance` key (Prowler v3 shape) is honoured too.
    #[test]
    fn parse_accepts_top_level_compliance_shape() {
        let payload = br#"[
          {
            "uid": "cloudtrail_logs_s3_bucket_access_logging_enabled",
            "severity": "Low",
            "status_code": "Fail",
            "cloud": { "provider": "AWS", "region": "us-east-1" },
            "resources": [{ "uid": "arn:aws:s3:::trail", "type": "AwsS3Bucket" }],
            "message": "Access logging disabled",
            "compliance": {
                "nist_800_53": ["AU-9"],
                "pci_dss": ["10.2.1"]
            }
          }
        ]"#;
        let obs = parse_prowler_ocsf(payload);
        match &obs[0] {
            Observation::CloudMisconfiguration { compliance, .. } => {
                assert_eq!(
                    compliance
                        .nist_800_53
                        .iter()
                        .map(NistControl::as_str)
                        .collect::<Vec<_>>(),
                    vec!["AU-9"],
                );
                assert_eq!(
                    compliance
                        .pci_dss
                        .iter()
                        .map(PciRequirement::as_str)
                        .collect::<Vec<_>>(),
                    vec!["10.2.1"],
                );
            }
            other => panic!("expected CloudMisconfiguration, got {other:?}"),
        }
    }
}
