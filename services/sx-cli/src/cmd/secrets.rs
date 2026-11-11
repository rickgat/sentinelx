//! `sx secrets rotate` — on-demand commercial intel credential rotation
//! (CRIT-005).
//!
//! Usage:
//!
//! ```text
//! sx secrets rotate --tenant <uuid> --secret <secret_id> \
//!                   [--vendor vault-transit|aws-sm|gcp-sm] \
//!                   [--vault-addr URL] [--vault-token-env VAR] \
//!                   [--vault-mount transit]
//! ```
//!
//! The command resolves the rotation provider, runs a single rotation
//! cycle for `(tenant, secret_id)`, persists the new credential into
//! the in-process secrets backend (defaults to an in-memory provider
//! so the CLI exits cleanly in a dev/test environment), and reports
//! the new version + audit event.
//!
//! Production deployments are expected to wire the CLI binary against
//! the same Vault / AWS / GCP backend the running server uses; the
//! defaults below cover the common Vault-Transit case.

use std::sync::Arc;

use anyhow::{anyhow, Context};
use clap::{Args, Subcommand, ValueEnum};
use reqwest::Client;
use secrecy::SecretString;
use uuid::Uuid;

use sx_intel_feeds::{
    CredentialRotationScheduler, InMemoryCredentialAuditSink, InMemoryRotationStateStore,
    RotationStateRow, RotationStateStore, RotationVendor, StaticRotationRegistry,
    DEFAULT_ROTATION_CADENCE,
};
use sx_secrets::{
    dek::TenantId as DekTenantId,
    dek_rotation::{
        DekRotationAuditSink, DekRotationJob, InMemoryDekRotationAuditSink,
        InMemoryRotationPolicyStore, InMemoryRotationProgressStore, ReencryptionVisitor,
        RotationConfig as DekRotConfig, RotationJobStatus, RotationPolicyStore,
        RotationProgressStore, VisitorBatchOutcome,
    },
    AwsSecretsManagerApi, AwsSecretsManagerRotation, DekManager, EnvelopeKeyManager,
    GcpSecretManagerRotation, GcpStaticToken, InMemoryDekStore, InMemoryProvider, RotationError,
    RotationPort, SecretsError, SecretsProvider, VaultTransitRotation,
};

use crate::output::OutputFormat;

/// Top-level `secrets` sub-command dispatcher.
#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// Rotate a single commercial intel credential.
    Rotate(RotateArgs),
    /// Rotate the per-tenant DEK and re-encrypt every tenant-scoped row
    /// (CRIT-003).
    RotateDek(RotateDekArgs),
    /// Report the latest DEK rotation checkpoint for a tenant.
    RotationStatus(RotationStatusArgs),
}

/// Provider selector for `sx secrets rotate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VendorArg {
    /// Vault Transit rewrap + sub-key derivation.
    VaultTransit,
    /// AWS Secrets Manager Lambda rotator.
    AwsSm,
    /// GCP Cloud Secret Manager `addVersion` rotator.
    GcpSm,
}

impl From<VendorArg> for RotationVendor {
    fn from(v: VendorArg) -> Self {
        match v {
            VendorArg::VaultTransit => Self::VaultTransit,
            VendorArg::AwsSm => Self::AwsSecretsManager,
            VendorArg::GcpSm => Self::GcpSecretManager,
        }
    }
}

/// Arguments for `sx secrets rotate`.
#[derive(Debug, Args)]
pub struct RotateArgs {
    /// Tenant UUID (v7 recommended).
    #[arg(long)]
    pub tenant: Uuid,
    /// Provider-opaque secret identifier (Vault key name / AWS ARN /
    /// GCP resource path).
    #[arg(long)]
    pub secret: String,
    /// Which rotation provider to invoke. Defaults to `vault-transit`.
    #[arg(long, value_enum, default_value_t = VendorArg::VaultTransit)]
    pub vendor: VendorArg,
    /// Vault address (e.g. `https://vault.example.com`). Required for
    /// `vault-transit` vendor.
    #[arg(long = "vault-addr")]
    pub vault_addr: Option<String>,
    /// Inline Vault token (avoid in production; prefer the env
    /// variable indirection in real deployments).
    #[arg(long = "vault-token")]
    pub vault_token: Option<String>,
    /// Vault Transit mount path. Defaults to `transit`.
    #[arg(long = "vault-mount", default_value = "transit")]
    pub vault_mount: String,
    /// GCP bearer token (test/dev only).
    #[arg(long = "gcp-token")]
    pub gcp_token: Option<String>,
}

/// Top-level dispatch hook called from `main`.
pub fn run(cmd: &SecretsCommand, fmt: OutputFormat) -> anyhow::Result<i32> {
    match cmd {
        SecretsCommand::Rotate(args) => rotate_run(args),
        SecretsCommand::RotateDek(args) => rotate_dek_run(args, fmt),
        SecretsCommand::RotationStatus(args) => rotation_status_run(args, fmt),
    }
}

fn rotate_run(args: &RotateArgs) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(async move { rotate_async(args).await })
}

async fn rotate_async(args: &RotateArgs) -> anyhow::Result<i32> {
    let vendor: RotationVendor = args.vendor.into();
    let port = build_port(args, vendor)?;

    // Seed an in-memory secrets provider + rotation state so the on-
    // demand flow can complete end-to-end. Production wiring replaces
    // the InMemoryProvider with the configured Vault / AWS / GCP
    // backend at startup.
    let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
    let state = Arc::new(InMemoryRotationStateStore::new());
    state
        .upsert(RotationStateRow::new_due_now(
            args.tenant,
            args.secret.clone(),
            vendor,
            DEFAULT_ROTATION_CADENCE,
        ))
        .await
        .map_err(|e| anyhow!("seed rotation state: {e}"))?;
    let registry = Arc::new(StaticRotationRegistry::new().with(vendor, port));
    let audit = Arc::new(InMemoryCredentialAuditSink::new());
    let scheduler =
        CredentialRotationScheduler::<_, (), _, _>::new(secrets, state, registry, audit.clone());

    match scheduler.rotate_now(args.tenant, &args.secret).await {
        Ok(cred) => {
            tracing::info!(
                tenant_id = %args.tenant,
                secret_id = %args.secret,
                vendor = ?vendor,
                version = %cred.version,
                "credential rotated"
            );
            Ok(0)
        }
        Err(e) => Err(anyhow!("rotation failed: {e}")),
    }
}

fn build_port(args: &RotateArgs, vendor: RotationVendor) -> anyhow::Result<Arc<dyn RotationPort>> {
    let http = Client::new();
    match vendor {
        RotationVendor::VaultTransit => {
            let addr = args
                .vault_addr
                .as_deref()
                .ok_or_else(|| anyhow!("--vault-addr is required for vault-transit"))?;
            let token = args
                .vault_token
                .as_deref()
                .ok_or_else(|| anyhow!("--vault-token is required for vault-transit"))?;
            let secret = SecretString::new(token.to_owned().into_boxed_str());
            Ok(Arc::new(VaultTransitRotation::new(
                http,
                addr,
                secret,
                args.vault_mount.clone(),
            )))
        }
        RotationVendor::AwsSecretsManager => {
            // The CLI ships a deterministic placeholder API stub. Real
            // deployments swap this for the production AWS SDK
            // adapter wired in the monolith.
            Ok(Arc::new(AwsSecretsManagerRotation::new(Arc::new(
                CliAwsStub,
            ))))
        }
        RotationVendor::GcpSecretManager => {
            let token = args
                .gcp_token
                .as_deref()
                .ok_or_else(|| anyhow!("--gcp-token is required for gcp-sm"))?;
            let auth = Arc::new(GcpStaticToken(SecretString::new(
                token.to_owned().into_boxed_str(),
            )));
            Ok(Arc::new(GcpSecretManagerRotation::new(http, auth)))
        }
    }
}

/// Trivial CLI-side AWS Secrets Manager stub. Real production code
/// wires the SDK-backed implementation in `sx-monolith`; the CLI uses
/// this stub purely to demonstrate the trait wiring on a local dev
/// box where AWS credentials are unavailable.
struct CliAwsStub;

#[async_trait::async_trait]
impl AwsSecretsManagerApi for CliAwsStub {
    async fn rotate_secret(&self, _secret_id: &str) -> Result<String, RotationError> {
        Err(RotationError::Unauthorized)
    }

    async fn get_current(&self, _secret_id: &str) -> Result<(String, SecretString), RotationError> {
        Err(RotationError::Unauthorized)
    }

    async fn describe_current_age(
        &self,
        _secret_id: &str,
    ) -> Result<std::time::Duration, RotationError> {
        Err(RotationError::Unauthorized)
    }
}

// =============================================================================
// `sx secrets rotate-dek` / `sx secrets rotation-status` (CRIT-003)
// =============================================================================

/// Arguments for `sx secrets rotate-dek`.
#[derive(Debug, Args)]
pub struct RotateDekArgs {
    /// Tenant UUID (v7 recommended) whose DEK should rotate.
    #[arg(long)]
    pub tenant: Uuid,
    /// Optional explicit target version. Defaults to
    /// `current + 1` (auto-bumps).
    #[arg(long = "target-version")]
    pub target_version: Option<u32>,
    /// Batch size — rows re-encrypted per checkpoint. Defaults to the
    /// orchestrator default (1000).
    #[arg(long = "batch-size")]
    pub batch_size: Option<u32>,
}

/// Arguments for `sx secrets rotation-status`.
#[derive(Debug, Args)]
pub struct RotationStatusArgs {
    /// Tenant UUID to inspect.
    #[arg(long)]
    pub tenant: Uuid,
}

/// `sx secrets rotate-dek` entry point.
///
/// The CLI binary is dev/diagnostic tooling: it stands up an in-process
/// envelope manager with a deterministic in-memory KMS / store / progress
/// / policy stack, runs the rotation, and reports the resulting
/// checkpoint. Production callers invoke the HTTP admin endpoint
/// (`POST /v1/admin/secrets/rotate-dek`) instead.
pub fn rotate_dek_run(args: &RotateDekArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(async move { rotate_dek_async(args, fmt).await })
}

async fn rotate_dek_async(args: &RotateDekArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    let envelope = build_cli_envelope_manager(args.batch_size);
    let tenant = DekTenantId::new(args.tenant);
    // Seed the manager so the resolve-old/new DEK plumbing has a baseline.
    envelope
        .dek_manager()
        .get_or_create(tenant)
        .await
        .map_err(|e| anyhow!("seed DEK: {e}"))?;

    let cp = match args.target_version {
        Some(v) => envelope.rotate_dek_to(tenant, v).await,
        None => envelope.rotate_dek(tenant).await,
    }
    .map_err(|e| anyhow!("rotation failed: {e}"))?;

    render_checkpoint(args.tenant, &cp, fmt);
    Ok(0)
}

/// `sx secrets rotation-status` entry point.
pub fn rotation_status_run(args: &RotationStatusArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(async move {
        let envelope = build_cli_envelope_manager(None);
        let tenant = DekTenantId::new(args.tenant);
        let status = envelope
            .rotation_status(tenant)
            .await
            .map_err(|e| anyhow!("status read failed: {e}"))?;
        match status {
            Some(cp) => render_checkpoint(args.tenant, &cp, fmt),
            None => match fmt {
                OutputFormat::Json => {
                    crate::output::print_line(
                        &serde_json::json!({
                            "tenant_id": args.tenant.to_string(),
                            "status": "no_rotation_recorded"
                        })
                        .to_string(),
                    );
                }
                OutputFormat::Human => {
                    crate::output::print_line(&format!(
                        "tenant {}: no rotation has ever run",
                        args.tenant
                    ));
                }
            },
        }
        Ok::<i32, anyhow::Error>(0)
    })
}

fn render_checkpoint(
    tenant: Uuid,
    cp: &sx_secrets::dek_rotation::RotationCheckpoint,
    fmt: OutputFormat,
) {
    match fmt {
        OutputFormat::Json => {
            let body = serde_json::json!({
                "tenant_id": tenant.to_string(),
                "target_dek_version": cp.target_dek_version,
                "status": match cp.status {
                    RotationJobStatus::Pending => "pending",
                    RotationJobStatus::InProgress => "in_progress",
                    RotationJobStatus::Completed => "completed",
                    RotationJobStatus::Failed => "failed",
                    RotationJobStatus::Cancelled => "cancelled",
                },
                "processed_rows": cp.processed_rows,
                "total_rows": cp.total_rows,
                "started_at": cp.started_at.to_rfc3339(),
                "last_checkpoint_at": cp.last_checkpoint_at.to_rfc3339(),
                "last_error": cp.last_error,
            });
            crate::output::print_line(&body.to_string());
        }
        OutputFormat::Human => {
            crate::output::print_line(&format!(
                "tenant {tenant}: target=v{} status={:?} processed={}/{}",
                cp.target_dek_version, cp.status, cp.processed_rows, cp.total_rows
            ));
        }
    }
}

/// Build the CLI's dev-mode envelope manager.
///
/// Uses [`InMemoryDekStore`], [`InMemoryRotationProgressStore`],
/// [`InMemoryRotationPolicyStore`], and a deterministic
/// [`CliDevKms`] so the CLI exits cleanly on a developer laptop without
/// any Vault / KMS / Postgres connection. Production callers go through
/// the REST admin endpoint backed by the monolith's real DEK stack.
#[must_use]
fn build_cli_envelope_manager(
    batch_size: Option<u32>,
) -> EnvelopeKeyManager<CliDevKms, InMemoryDekStore> {
    let kms = Arc::new(CliDevKms::new());
    let store = Arc::new(InMemoryDekStore::new());
    let manager = Arc::new(DekManager::new(kms, store, "sx-cli-dev-kek"));
    let progress: Arc<dyn RotationProgressStore> = Arc::new(InMemoryRotationProgressStore::new());
    let policy: Arc<dyn RotationPolicyStore> = Arc::new(InMemoryRotationPolicyStore::new());
    let audit: Arc<dyn DekRotationAuditSink> = Arc::new(InMemoryDekRotationAuditSink::new());
    // No visitors are registered in dev mode — the CLI is for triage
    // and smoke-test only. The orchestrator therefore completes
    // immediately with `processed_rows = 0`, which is the expected dev
    // behaviour (a real deployment registers per-table visitors at the
    // composition root).
    let visitors: Vec<Arc<dyn ReencryptionVisitor>> = Vec::new();
    let config = batch_size.map_or_else(DekRotConfig::defaults, |n| {
        DekRotConfig::defaults().with_batch_size(n)
    });
    let job = Arc::new(DekRotationJob::new(
        manager, progress, policy, audit, visitors, config,
    ));
    EnvelopeKeyManager::new(job)
}

/// CLI-only deterministic in-process KMS.
///
/// Implements just enough of [`sx_secrets::KmsKeyProvider`] for the dev
/// rotation flow to round-trip. The plaintexts are NOT secret —
/// production code wires a real KMS backend.
#[derive(Debug, Default)]
pub struct CliDevKms {
    version: std::sync::atomic::AtomicU32,
}

impl CliDevKms {
    fn new() -> Self {
        Self {
            version: std::sync::atomic::AtomicU32::new(1),
        }
    }
}

#[async_trait::async_trait]
impl sx_secrets::KmsKeyProvider for CliDevKms {
    async fn encrypt(
        &self,
        _key_id: &str,
        plaintext: &SecretString,
    ) -> Result<sx_secrets::Ciphertext, SecretsError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use secrecy::ExposeSecret;
        let v = self.version.load(std::sync::atomic::Ordering::SeqCst);
        Ok(sx_secrets::Ciphertext::new(format!(
            "cli:v{v}:{}",
            B64.encode(plaintext.expose_secret().as_bytes())
        )))
    }

    async fn decrypt(
        &self,
        _key_id: &str,
        ciphertext: &sx_secrets::Ciphertext,
    ) -> Result<SecretString, SecretsError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let parts: Vec<&str> = ciphertext.as_str().splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(SecretsError::Format("bad ciphertext shape".to_owned()));
        }
        // INVARIANT: parts.len() == 3 verified above.
        #[allow(clippy::indexing_slicing)]
        let bytes = B64
            .decode(parts[2])
            .map_err(|e| SecretsError::Format(e.to_string()))?;
        let s = String::from_utf8(bytes).map_err(|e| SecretsError::Format(e.to_string()))?;
        Ok(SecretString::new(s.into_boxed_str()))
    }

    async fn generate_dek(&self, key_id: &str) -> Result<sx_secrets::WrappedDek, SecretsError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let v = self.version.load(std::sync::atomic::Ordering::SeqCst);
        let pt = format!("cli-dek-v{v}");
        let wrapped =
            sx_secrets::Ciphertext::new(format!("cli:v{v}:{}", B64.encode(pt.as_bytes())));
        Ok(sx_secrets::WrappedDek::new(
            key_id,
            v,
            SecretString::new(pt.into_boxed_str()),
            wrapped,
        ))
    }

    async fn rotate(&self, _key_id: &str) -> Result<sx_secrets::KeyVersion, SecretsError> {
        let v = self
            .version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        Ok(sx_secrets::KeyVersion::now(v))
    }
}

// `VisitorBatchOutcome` is imported for the dev-mode visitor shape used
// in tests that wire their own visitors against the same orchestrator.
#[allow(dead_code)]
fn _visitor_outcome_marker(_: VisitorBatchOutcome) {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: SecretsCommand,
    }

    #[test]
    fn rotate_args_parse_minimal_invocation() {
        let cli = Cli::try_parse_from([
            "sx",
            "rotate",
            "--tenant",
            "00000000-0000-7000-8000-000000000001",
            "--secret",
            "mandiant/client_secret",
        ])
        .unwrap();
        match cli.cmd {
            SecretsCommand::Rotate(args) => {
                assert_eq!(args.secret, "mandiant/client_secret");
                assert_eq!(args.vendor, VendorArg::VaultTransit);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rotate_args_accept_vendor_override() {
        let cli = Cli::try_parse_from([
            "sx",
            "rotate",
            "--tenant",
            "00000000-0000-7000-8000-000000000001",
            "--secret",
            "projects/p/secrets/mandiant",
            "--vendor",
            "gcp-sm",
            "--gcp-token",
            "fake",
        ])
        .unwrap();
        match cli.cmd {
            SecretsCommand::Rotate(args) => {
                assert_eq!(args.vendor, VendorArg::GcpSm);
                assert_eq!(args.gcp_token.as_deref(), Some("fake"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn vendor_arg_maps_to_rotation_vendor() {
        assert_eq!(
            RotationVendor::from(VendorArg::VaultTransit),
            RotationVendor::VaultTransit
        );
        assert_eq!(
            RotationVendor::from(VendorArg::AwsSm),
            RotationVendor::AwsSecretsManager
        );
        assert_eq!(
            RotationVendor::from(VendorArg::GcpSm),
            RotationVendor::GcpSecretManager
        );
    }

    #[test]
    fn rotate_dek_args_parse() {
        let cli = Cli::try_parse_from([
            "sx",
            "rotate-dek",
            "--tenant",
            "00000000-0000-7000-8000-000000000001",
        ])
        .unwrap();
        match cli.cmd {
            SecretsCommand::RotateDek(args) => {
                assert_eq!(
                    args.tenant.to_string(),
                    "00000000-0000-7000-8000-000000000001"
                );
                assert!(args.target_version.is_none());
                assert!(args.batch_size.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rotate_dek_args_accept_target_version_and_batch_size() {
        let cli = Cli::try_parse_from([
            "sx",
            "rotate-dek",
            "--tenant",
            "00000000-0000-7000-8000-000000000001",
            "--target-version",
            "7",
            "--batch-size",
            "256",
        ])
        .unwrap();
        match cli.cmd {
            SecretsCommand::RotateDek(args) => {
                assert_eq!(args.target_version, Some(7));
                assert_eq!(args.batch_size, Some(256));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rotation_status_args_parse() {
        let cli = Cli::try_parse_from([
            "sx",
            "rotation-status",
            "--tenant",
            "00000000-0000-7000-8000-000000000001",
        ])
        .unwrap();
        match cli.cmd {
            SecretsCommand::RotationStatus(args) => {
                assert_eq!(
                    args.tenant.to_string(),
                    "00000000-0000-7000-8000-000000000001"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rotate_dek_async_completes_for_dev_tenant() {
        let args = RotateDekArgs {
            tenant: Uuid::now_v7(),
            target_version: None,
            batch_size: Some(64),
        };
        let code = rotate_dek_async(&args, OutputFormat::Json).await.unwrap();
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn rotation_status_returns_none_then_some_after_rotate() {
        let tenant_uuid = Uuid::now_v7();
        let envelope = build_cli_envelope_manager(None);
        let tenant = DekTenantId::new(tenant_uuid);
        // Pre-rotation: no checkpoint exists.
        let pre = envelope.rotation_status(tenant).await.unwrap();
        assert!(pre.is_none());
        // Rotate.
        envelope.dek_manager().get_or_create(tenant).await.unwrap();
        let _ = envelope.rotate_dek(tenant).await.unwrap();
        let post = envelope.rotation_status(tenant).await.unwrap();
        assert!(post.is_some());
        assert_eq!(post.as_ref().unwrap().status, RotationJobStatus::Completed);
    }
}
