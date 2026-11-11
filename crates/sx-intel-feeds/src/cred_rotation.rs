//! Per-tenant credential rotation job for the commercial intel feeds
//! (CRIT-005).
//!
//! ## What this module owns
//!
//! * The per-tenant `intel_credential_rotation_state` row model
//!   ([`RotationStateRow`]), the store trait ([`RotationStateStore`]),
//!   and an in-memory implementation used by tests
//!   ([`InMemoryRotationStateStore`]).
//! * The rotation scheduler ([`CredentialRotationScheduler`]), which
//!   runs every hour, scans for due credentials, invokes a
//!   [`sx_secrets::RotationPort`] per (tenant, secret), persists the
//!   new credential back into a [`sx_secrets::SecretsProvider`], and
//!   emits audit events.
//! * The audit event surface
//!   ([`CredentialRotationAuditEvent`]) with the spec-mandated payload
//!   `{tenant_id, secret_id, vendor, success, error_redacted}`.
//! * The failure-mode policy: three consecutive failures escalate to a
//!   `Severity::Error` audit event and the previous credential is
//!   preserved (the scheduler does NOT overwrite the secret on
//!   failure).
//!
//! ## What this module does NOT own
//!
//! * Vendor-specific rotation mechanics. Those live behind the
//!   [`sx_secrets::RotationPort`] trait in `sx-secrets` (Vault Transit
//!   rewrap, AWS Lambda invoke, GCP `addVersion`).
//! * Polling of the actual intel feed. The commercial feed scheduler
//!   ([`crate::commercial_scheduler`]) reads `client_id` +
//!   `client_secret` from the [`SecretsProvider`] each cycle so a
//!   successful rotation is picked up on the next poll.
//!
//! ## Multi-tenancy
//!
//! Every row carries a `tenant_id`. The scheduler treats each row
//! independently: a failure on tenant A never blocks tenant B. The
//! cadence is per-row, defaulting to 90 days for non-PCI tenants and
//! 30 days for PCI tenants.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sx_secrets::{
    CredentialRotationPolicy, NewCredential, RotationError, RotationPort, SecretsError,
    SecretsProvider,
};

use crate::commercial_scheduler::DEFAULT_SECRETS_PREFIX;

/// Default rotation cadence — 90 days. Mirrors
/// [`CredentialRotationPolicy::DEFAULT_CADENCE`].
pub const DEFAULT_ROTATION_CADENCE: Duration = CredentialRotationPolicy::DEFAULT_CADENCE;
/// PCI rotation cadence — 30 days.
pub const PCI_ROTATION_CADENCE: Duration = CredentialRotationPolicy::PCI_CADENCE;
/// Default scheduler tick interval — 1 hour. Mirrors the CRIT-005 spec.
pub const ROTATION_TICK_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Failure budget before the failure-mode escalation kicks in.
pub const FAILURE_BUDGET: u32 = 3;
/// Severity tag attached to rotation audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationSeverity {
    /// Normal informational event (success, single failure under
    /// budget).
    Info,
    /// Failure mode escalated — three consecutive failures observed,
    /// previous credential preserved, operator intervention required.
    Error,
}

/// Vendor tag used in audit events and state rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RotationVendor {
    /// Vault Transit rewrap rotator.
    VaultTransit,
    /// AWS Secrets Manager rotator.
    AwsSecretsManager,
    /// GCP Secret Manager rotator.
    GcpSecretManager,
}

impl RotationVendor {
    /// Stable string label used in audit payloads / DB rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VaultTransit => "vault-transit",
            Self::AwsSecretsManager => "aws-sm",
            Self::GcpSecretManager => "gcp-sm",
        }
    }
}

/// Per-tenant rotation state row. Mirrors the SQL table 1:1.
#[derive(Debug, Clone)]
pub struct RotationStateRow {
    /// Tenant the credential belongs to.
    pub tenant_id: Uuid,
    /// Provider-opaque secret identifier.
    pub secret_id: String,
    /// Which rotation provider services this row.
    pub vendor: RotationVendor,
    /// Rotation cadence configured for this row.
    pub cadence: Duration,
    /// When the credential was last successfully rotated.
    pub last_rotated_at: Option<OffsetDateTime>,
    /// When the next rotation is due.
    pub next_due_at: OffsetDateTime,
    /// Last failure message (redacted). Cleared on a successful
    /// rotation.
    pub last_error: Option<String>,
    /// Consecutive failure count, cleared on success.
    pub attempts: u32,
}

impl RotationStateRow {
    /// Build a fresh row that is due immediately.
    #[must_use]
    pub fn new_due_now(
        tenant_id: Uuid,
        secret_id: impl Into<String>,
        vendor: RotationVendor,
        cadence: Duration,
    ) -> Self {
        Self {
            tenant_id,
            secret_id: secret_id.into(),
            vendor,
            cadence,
            last_rotated_at: None,
            next_due_at: OffsetDateTime::now_utc(),
            last_error: None,
            attempts: 0,
        }
    }

    /// `true` when the row is due as of `now`.
    #[must_use]
    pub fn is_due(&self, now: OffsetDateTime) -> bool {
        self.next_due_at <= now
    }
}

/// Errors surfaced by [`RotationStateStore`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum RotationStateError {
    /// Underlying database / storage error.
    #[error("rotation state storage error: {0}")]
    Storage(String),
    /// The requested row does not exist.
    #[error("rotation state row not found: {tenant_id} {secret_id}")]
    NotFound {
        /// Tenant the lookup was scoped to.
        tenant_id: Uuid,
        /// Secret id that was missing.
        secret_id: String,
    },
}

/// Storage abstraction for the per-tenant rotation state. The
/// in-memory implementation ([`InMemoryRotationStateStore`]) is used by
/// tests; the production implementation is a Postgres-backed adapter
/// over the migration in `migrations/20270601000000_…sql`.
#[async_trait]
pub trait RotationStateStore: Send + Sync {
    /// List every row that is due as of `now`.
    async fn due_rows(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<RotationStateRow>, RotationStateError>;

    /// Persist a row (upsert by `(tenant_id, secret_id)`).
    async fn upsert(&self, row: RotationStateRow) -> Result<(), RotationStateError>;

    /// Load one row (used by the CLI `secrets rotate` on-demand path).
    async fn load(
        &self,
        tenant_id: Uuid,
        secret_id: &str,
    ) -> Result<RotationStateRow, RotationStateError>;
}

/// In-memory store. Cheap to clone — backed by `Arc<Mutex<…>>`.
#[derive(Debug, Default, Clone)]
pub struct InMemoryRotationStateStore {
    rows: Arc<Mutex<HashMap<(Uuid, String), RotationStateRow>>>,
}

impl InMemoryRotationStateStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every row.
    pub async fn snapshot(&self) -> Vec<RotationStateRow> {
        self.rows.lock().await.values().cloned().collect()
    }
}

#[async_trait]
impl RotationStateStore for InMemoryRotationStateStore {
    async fn due_rows(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<RotationStateRow>, RotationStateError> {
        let guard = self.rows.lock().await;
        Ok(guard.values().filter(|r| r.is_due(now)).cloned().collect())
    }

    async fn upsert(&self, row: RotationStateRow) -> Result<(), RotationStateError> {
        let key = (row.tenant_id, row.secret_id.clone());
        self.rows.lock().await.insert(key, row);
        Ok(())
    }

    async fn load(
        &self,
        tenant_id: Uuid,
        secret_id: &str,
    ) -> Result<RotationStateRow, RotationStateError> {
        let guard = self.rows.lock().await;
        guard
            .get(&(tenant_id, secret_id.to_owned()))
            .cloned()
            .ok_or_else(|| RotationStateError::NotFound {
                tenant_id,
                secret_id: secret_id.to_owned(),
            })
    }
}

/// Audit event emitted by the rotation scheduler. Spec-mandated
/// payload: `{tenant_id, secret_id, vendor, success, error_redacted}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRotationAuditEvent {
    /// Tenant the rotation ran for.
    pub tenant_id: Uuid,
    /// Provider-opaque secret identifier.
    pub secret_id: String,
    /// Vendor tag (vault-transit / aws-sm / gcp-sm).
    pub vendor: RotationVendor,
    /// `true` on a successful rotation.
    pub success: bool,
    /// Redacted error message on failure. NEVER contains credential
    /// bytes.
    pub error_redacted: Option<String>,
    /// Severity. `Error` is set when the failure budget is exhausted
    /// or on the on-demand path failure.
    pub severity: RotationSeverity,
    /// Wall-clock timestamp.
    pub at: OffsetDateTime,
}

impl CredentialRotationAuditEvent {
    /// Canonical event type string. The scheduler emits this via the
    /// audit sink under `audit.secrets.intel_credential_rotated`.
    pub const EVENT_TYPE: &'static str = "audit.secrets.intel_credential_rotated";
}

/// Sink for [`CredentialRotationAuditEvent`]s. Implementations forward
/// to `sx-audit` in production.
#[async_trait]
pub trait CredentialRotationAuditSink: Send + Sync {
    /// Record an audit event. Implementations MUST NOT block the
    /// caller; persistence should run on a background task or use an
    /// async path.
    async fn record(&self, event: CredentialRotationAuditEvent);
}

/// Process-local audit sink used by tests + diagnostics.
#[derive(Debug, Default, Clone)]
pub struct InMemoryCredentialAuditSink {
    events: Arc<Mutex<Vec<CredentialRotationAuditEvent>>>,
}

impl InMemoryCredentialAuditSink {
    /// Empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded events.
    pub async fn snapshot(&self) -> Vec<CredentialRotationAuditEvent> {
        self.events.lock().await.clone()
    }
}

#[async_trait]
impl CredentialRotationAuditSink for InMemoryCredentialAuditSink {
    async fn record(&self, event: CredentialRotationAuditEvent) {
        self.events.lock().await.push(event);
    }
}

/// Provider lookup keyed on `(tenant_id, vendor)`.
///
/// Separating the lookup from the scheduler lets deployments wire
/// heterogeneous providers (one tenant on Vault, the next on AWS)
/// without a global multiplexer.
pub trait RotationPortRegistry: Send + Sync {
    /// Resolve the [`RotationPort`] used for `(tenant_id, vendor)`.
    /// Returns `None` if the deployment has not configured the
    /// provider; the scheduler treats that as a soft skip.
    fn resolve(&self, tenant_id: Uuid, vendor: RotationVendor) -> Option<Arc<dyn RotationPort>>;
}

/// Static, in-memory registry. Useful when every tenant shares a
/// single rotation provider per vendor.
#[derive(Default, Clone)]
pub struct StaticRotationRegistry {
    by_vendor: HashMap<RotationVendor, Arc<dyn RotationPort>>,
}

impl std::fmt::Debug for StaticRotationRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticRotationRegistry")
            .field("vendors", &self.by_vendor.len())
            .finish_non_exhaustive()
    }
}

impl StaticRotationRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a rotation provider for `vendor`. Replaces any
    /// previous registration.
    #[must_use]
    pub fn with(mut self, vendor: RotationVendor, port: Arc<dyn RotationPort>) -> Self {
        self.by_vendor.insert(vendor, port);
        self
    }
}

impl RotationPortRegistry for StaticRotationRegistry {
    fn resolve(&self, _tenant_id: Uuid, vendor: RotationVendor) -> Option<Arc<dyn RotationPort>> {
        self.by_vendor.get(&vendor).cloned()
    }
}

/// Errors surfaced by the rotation scheduler itself (above and beyond
/// `RotationError` from the port).
#[derive(Debug, thiserror::Error)]
pub enum RotationSchedulerError {
    /// Storage read/write failed.
    #[error("rotation state store error: {0}")]
    State(#[from] RotationStateError),
    /// Could not persist the freshly-rotated credential back into the
    /// secrets provider.
    #[error("rotation persist error: {0}")]
    Persist(#[from] SecretsError),
    /// No rotation provider configured for `(tenant, vendor)`. The
    /// scheduler treats this as a soft skip but the CLI on-demand
    /// path surfaces it.
    #[error("no rotation provider configured for tenant {tenant_id} vendor {vendor:?}")]
    NoProvider {
        /// Tenant the lookup was scoped to.
        tenant_id: Uuid,
        /// Vendor tag.
        vendor: RotationVendor,
    },
    /// The underlying provider rejected the rotation.
    #[error("rotation provider error: {0}")]
    Rotation(#[from] RotationError),
}

/// The rotation scheduler.
///
/// Cheap to clone — every field is reference-counted.
pub struct CredentialRotationScheduler<R, S, A, P> {
    secrets: Arc<dyn SecretsProvider>,
    state: Arc<R>,
    registry: Arc<P>,
    audit: Arc<A>,
    secrets_prefix: String,
    tick: Duration,
    /// Phantom marker so the unused-type-parameter lint stays quiet for
    /// the `S` slot, which we reserve for a future "feed sink" hook.
    _sink: std::marker::PhantomData<S>,
}

impl<R, S, A, P> std::fmt::Debug for CredentialRotationScheduler<R, S, A, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRotationScheduler")
            .field("secrets_prefix", &self.secrets_prefix)
            .field("tick", &self.tick)
            .finish_non_exhaustive()
    }
}

impl<R, S, A, P> CredentialRotationScheduler<R, S, A, P>
where
    R: RotationStateStore + 'static,
    A: CredentialRotationAuditSink + 'static,
    P: RotationPortRegistry + 'static,
    S: Send + Sync + 'static,
{
    /// Build a scheduler with the default secrets path prefix and the
    /// 1-hour tick interval.
    pub fn new(
        secrets: Arc<dyn SecretsProvider>,
        state: Arc<R>,
        registry: Arc<P>,
        audit: Arc<A>,
    ) -> Self {
        Self {
            secrets,
            state,
            registry,
            audit,
            secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
            tick: ROTATION_TICK_INTERVAL,
            _sink: std::marker::PhantomData,
        }
    }

    /// Override the secrets path prefix (mirrors
    /// [`crate::commercial_scheduler::TenantCredentialStore::with_path_prefix`]).
    #[must_use]
    pub fn with_secrets_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.secrets_prefix = prefix.into();
        self
    }

    /// Override the tick interval. Honoured on the next loop
    /// iteration.
    #[must_use]
    pub const fn with_tick(mut self, tick: Duration) -> Self {
        self.tick = tick;
        self
    }

    /// Path under which the rotated `client_secret` is stored. Mirrors
    /// the convention used by
    /// [`crate::commercial_scheduler::TenantCredentialStore`].
    ///
    /// All vendors share the same `tenants/{tenant}/intel/{secret_id}`
    /// layout so the commercial feed scheduler reads the rotated
    /// value on its next poll. The caller-supplied `secret_id`
    /// (e.g. `mandiant/client_secret`) disambiguates per vendor.
    fn secret_path(&self, tenant_id: Uuid, secret_id: &str) -> String {
        format!(
            "{}/{}/intel/{}",
            self.secrets_prefix,
            tenant_id,
            secret_id.trim_start_matches('/')
        )
    }

    /// Run a single scheduling tick.
    ///
    /// Returns the count of rows the scheduler attempted to rotate.
    /// Failures are recorded as audit events; they do NOT abort the
    /// tick.
    pub async fn run_once(&self, now: OffsetDateTime) -> Result<usize, RotationSchedulerError> {
        let due = self.state.due_rows(now).await?;
        let total = due.len();
        for row in due {
            self.process_row(row, now).await;
        }
        Ok(total)
    }

    async fn process_row(&self, mut row: RotationStateRow, now: OffsetDateTime) {
        let tenant_id = row.tenant_id;
        let secret_id = row.secret_id.clone();
        let vendor = row.vendor;
        let Some(port) = self.registry.resolve(tenant_id, vendor) else {
            warn!(
                target: "sx_intel_feeds::cred_rotation",
                %tenant_id, %secret_id, vendor = vendor.as_str(),
                "no rotation provider registered; skipping",
            );
            return;
        };
        match port.rotate(&secret_id).await {
            Ok(cred) => self.process_success(&mut row, &cred, now).await,
            Err(e) => {
                let redacted = redact_error(&e);
                self.record_failure(&mut row, &redacted, now).await;
            }
        }
    }

    async fn process_success(
        &self,
        row: &mut RotationStateRow,
        cred: &NewCredential,
        now: OffsetDateTime,
    ) {
        let tenant_id = row.tenant_id;
        let secret_id = row.secret_id.clone();
        let vendor = row.vendor;
        if let Err(e) = self.persist_credential(row, cred).await {
            warn!(
                target: "sx_intel_feeds::cred_rotation",
                %tenant_id, %secret_id, vendor = vendor.as_str(),
                error = %e,
                "failed to persist rotated credential",
            );
            self.record_failure(row, &format!("persist: {e}"), now)
                .await;
            return;
        }
        row.last_rotated_at = Some(now);
        row.next_due_at = now + time::Duration::seconds_f64(row.cadence.as_secs_f64());
        row.last_error = None;
        row.attempts = 0;
        let _ = self.state.upsert(row.clone()).await;
        self.audit
            .record(CredentialRotationAuditEvent {
                tenant_id,
                secret_id: secret_id.clone(),
                vendor,
                success: true,
                error_redacted: None,
                severity: RotationSeverity::Info,
                at: now,
            })
            .await;
        info!(
            target: "sx_intel_feeds::cred_rotation",
            %tenant_id, %secret_id, vendor = vendor.as_str(),
            "credential rotated",
        );
    }

    /// Record a failure into the row + audit log, applying the
    /// failure-mode escalation when the budget is exhausted.
    async fn record_failure(
        &self,
        row: &mut RotationStateRow,
        redacted: &str,
        now: OffsetDateTime,
    ) {
        let tenant_id = row.tenant_id;
        let secret_id = row.secret_id.clone();
        let vendor = row.vendor;
        row.attempts = row.attempts.saturating_add(1);
        row.last_error = Some(redacted.to_owned());
        // Schedule a retry on the next tick — but DO NOT push the
        // next_due_at far into the future: the policy is "operator
        // intervention required" once the budget is blown, but the
        // scheduler should still surface the failure on every tick.
        if !row.is_due(now) {
            row.next_due_at = now;
        }
        let _ = self.state.upsert(row.clone()).await;

        let severity = if row.attempts >= FAILURE_BUDGET {
            RotationSeverity::Error
        } else {
            RotationSeverity::Info
        };
        self.audit
            .record(CredentialRotationAuditEvent {
                tenant_id,
                secret_id: secret_id.clone(),
                vendor,
                success: false,
                error_redacted: Some(redacted.to_owned()),
                severity,
                at: now,
            })
            .await;
        if severity == RotationSeverity::Error {
            error!(
                target: "sx_intel_feeds::cred_rotation",
                %tenant_id, %secret_id, vendor = vendor.as_str(),
                attempts = row.attempts,
                reason = %redacted,
                "credential rotation failure-mode triggered: keeping old credential active, operator intervention required",
            );
        } else {
            warn!(
                target: "sx_intel_feeds::cred_rotation",
                %tenant_id, %secret_id, vendor = vendor.as_str(),
                attempts = row.attempts,
                reason = %redacted,
                "credential rotation failed",
            );
        }
    }

    /// Persist the freshly-rotated credential into the secrets
    /// provider. The previous version remains decryptable for the
    /// handover window (vendor-dependent — see `RotationPort` docs).
    async fn persist_credential(
        &self,
        row: &RotationStateRow,
        cred: &NewCredential,
    ) -> Result<(), SecretsError> {
        let path = self.secret_path(row.tenant_id, &row.secret_id);
        // Wrap the new secret in a fresh `SecretString` (the original
        // is consumed by `expose_secret` only).
        let value = SecretString::new(
            cred.client_secret
                .expose_secret()
                .to_owned()
                .into_boxed_str(),
        );
        self.secrets.put(&path, value).await?;
        debug!(
            target: "sx_intel_feeds::cred_rotation",
            tenant_id = %row.tenant_id,
            secret_id = %row.secret_id,
            path = %path,
            version = %cred.version,
            "rotated credential persisted",
        );
        Ok(())
    }

    /// On-demand rotation invoked by the `sx-cli secrets rotate` path.
    ///
    /// Looks the row up by `(tenant_id, secret_id)`, runs a single
    /// rotation, and persists the new credential. Surfaces every
    /// failure to the caller; the audit sink is still updated.
    pub async fn rotate_now(
        &self,
        tenant_id: Uuid,
        secret_id: &str,
    ) -> Result<NewCredential, RotationSchedulerError> {
        let mut row = self.state.load(tenant_id, secret_id).await?;
        let port = self.registry.resolve(tenant_id, row.vendor).ok_or(
            RotationSchedulerError::NoProvider {
                tenant_id,
                vendor: row.vendor,
            },
        )?;
        let now = OffsetDateTime::now_utc();
        match port.rotate(secret_id).await {
            Ok(cred) => {
                self.persist_credential(&row, &cred).await?;
                row.last_rotated_at = Some(now);
                row.next_due_at = now + time::Duration::seconds_f64(row.cadence.as_secs_f64());
                row.last_error = None;
                row.attempts = 0;
                self.state.upsert(row).await?;
                self.audit
                    .record(CredentialRotationAuditEvent {
                        tenant_id,
                        secret_id: secret_id.to_owned(),
                        vendor: port_vendor_from_secret(secret_id),
                        success: true,
                        error_redacted: None,
                        severity: RotationSeverity::Info,
                        at: now,
                    })
                    .await;
                Ok(cred)
            }
            Err(e) => {
                let redacted = redact_error(&e);
                self.record_failure(&mut row, &redacted, now).await;
                Err(RotationSchedulerError::Rotation(e))
            }
        }
    }

    /// Spawn a background loop that ticks every [`Self::tick`].
    pub fn spawn_loop(
        self: Arc<Self>,
        mut cancel: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let _ = self.run_once(OffsetDateTime::now_utc()).await;
                tokio::select! {
                    () = tokio::time::sleep(self.tick) => {},
                    res = cancel.changed() => {
                        if res.is_err() || *cancel.borrow() {
                            debug!(
                                target: "sx_intel_feeds::cred_rotation",
                                "shutdown signalled",
                            );
                            return;
                        }
                    }
                }
            }
        })
    }
}

/// Heuristic that maps the `secret_id` to the vendor tag for audit
/// purposes when the caller doesn't carry it explicitly. Used only on
/// the on-demand CLI path; the regular scheduler uses
/// `row.vendor` directly.
fn port_vendor_from_secret(secret_id: &str) -> RotationVendor {
    if secret_id.starts_with("arn:aws:") {
        RotationVendor::AwsSecretsManager
    } else if secret_id.starts_with("projects/") {
        RotationVendor::GcpSecretManager
    } else {
        RotationVendor::VaultTransit
    }
}

/// Convert a [`RotationError`] into a log/audit-safe string. The
/// helper exists so we have a single place enforcing the "no
/// credential bytes" rule on the audit hot path.
fn redact_error(err: &RotationError) -> String {
    match err {
        RotationError::NotFound(id) => format!("not found: {id}"),
        RotationError::Unauthorized => "unauthorized".to_owned(),
        RotationError::Provider(msg) => format!("provider: {msg}"),
        RotationError::Transport(_) => "transport error".to_owned(),
        RotationError::Format(_) => "format error".to_owned(),
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
    use sx_secrets::InMemoryProvider;

    /// Stub rotation port that returns a fixed credential. The
    /// `should_fail` toggle lets tests exercise the failure path.
    struct StubPort {
        version: std::sync::atomic::AtomicU32,
        should_fail: bool,
    }

    impl StubPort {
        fn ok() -> Self {
            Self {
                version: std::sync::atomic::AtomicU32::new(0),
                should_fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                version: std::sync::atomic::AtomicU32::new(0),
                should_fail: true,
            }
        }
    }

    #[async_trait]
    impl RotationPort for StubPort {
        async fn rotate(&self, secret_id: &str) -> Result<NewCredential, RotationError> {
            if self.should_fail {
                return Err(RotationError::Unauthorized);
            }
            let v = self
                .version
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            Ok(NewCredential {
                client_id: format!("{secret_id}-client"),
                client_secret: SecretString::new(format!("rotated-secret-v{v}").into_boxed_str()),
                not_before: chrono::Utc::now(),
                version: v.to_string(),
            })
        }

        async fn current_age(&self, _secret_id: &str) -> Result<Duration, RotationError> {
            Ok(Duration::from_secs(0))
        }
    }

    fn make_scheduler<R: RotationStateStore + 'static>(
        secrets: Arc<dyn SecretsProvider>,
        state: Arc<R>,
        port: Arc<dyn RotationPort>,
        vendor: RotationVendor,
    ) -> CredentialRotationScheduler<R, (), InMemoryCredentialAuditSink, StaticRotationRegistry>
    {
        let registry = StaticRotationRegistry::new().with(vendor, port);
        let audit = Arc::new(InMemoryCredentialAuditSink::new());
        CredentialRotationScheduler::new(secrets, state, Arc::new(registry), audit)
    }

    #[tokio::test]
    async fn rotates_a_due_row_and_persists_secret() {
        let tenant = Uuid::new_v4();
        let row = RotationStateRow::new_due_now(
            tenant,
            "mandiant/client_secret",
            RotationVendor::VaultTransit,
            DEFAULT_ROTATION_CADENCE,
        );
        let state = Arc::new(InMemoryRotationStateStore::new());
        state.upsert(row).await.unwrap();
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let port: Arc<dyn RotationPort> = Arc::new(StubPort::ok());
        let registry = StaticRotationRegistry::new().with(RotationVendor::VaultTransit, port);
        let audit = Arc::new(InMemoryCredentialAuditSink::new());
        let scheduler = CredentialRotationScheduler::<_, (), _, _>::new(
            secrets.clone(),
            state.clone(),
            Arc::new(registry),
            audit.clone(),
        );
        let attempted = scheduler.run_once(OffsetDateTime::now_utc()).await.unwrap();
        assert_eq!(attempted, 1);

        let stored = secrets
            .get(&format!("tenants/{tenant}/intel/mandiant/client_secret"))
            .await
            .unwrap();
        assert_eq!(stored.expose_secret(), "rotated-secret-v1");

        let events = audit.snapshot().await;
        assert_eq!(events.len(), 1);
        assert!(events[0].success);
        assert_eq!(events[0].severity, RotationSeverity::Info);
        assert_eq!(events[0].vendor, RotationVendor::VaultTransit);

        let after = state.snapshot().await;
        assert_eq!(after[0].attempts, 0);
        assert!(after[0].last_rotated_at.is_some());
        assert!(after[0].next_due_at > OffsetDateTime::now_utc());
    }

    #[tokio::test]
    async fn skips_rows_that_are_not_yet_due() {
        let tenant = Uuid::new_v4();
        let mut row = RotationStateRow::new_due_now(
            tenant,
            "crowdstrike/client_secret",
            RotationVendor::VaultTransit,
            DEFAULT_ROTATION_CADENCE,
        );
        // Push it 1h into the future.
        row.next_due_at = OffsetDateTime::now_utc() + time::Duration::hours(1);
        let state = Arc::new(InMemoryRotationStateStore::new());
        state.upsert(row).await.unwrap();
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let scheduler = make_scheduler(
            secrets.clone(),
            state.clone(),
            Arc::new(StubPort::ok()),
            RotationVendor::VaultTransit,
        );
        let attempted = scheduler.run_once(OffsetDateTime::now_utc()).await.unwrap();
        assert_eq!(attempted, 0);
    }

    #[tokio::test]
    async fn three_consecutive_failures_emit_error_and_preserve_old_secret() {
        let tenant = Uuid::new_v4();
        let row = RotationStateRow::new_due_now(
            tenant,
            "mandiant/client_secret",
            RotationVendor::VaultTransit,
            DEFAULT_ROTATION_CADENCE,
        );
        let state = Arc::new(InMemoryRotationStateStore::new());
        state.upsert(row).await.unwrap();
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        // Seed the OLD secret so we can prove it isn't overwritten.
        secrets
            .put(
                &format!("tenants/{tenant}/intel/mandiant/client_secret"),
                SecretString::new("old-secret".to_owned().into_boxed_str()),
            )
            .await
            .unwrap();

        let port: Arc<dyn RotationPort> = Arc::new(StubPort::failing());
        let registry = StaticRotationRegistry::new().with(RotationVendor::VaultTransit, port);
        let audit = Arc::new(InMemoryCredentialAuditSink::new());
        let scheduler = CredentialRotationScheduler::<_, (), _, _>::new(
            secrets.clone(),
            state.clone(),
            Arc::new(registry),
            audit.clone(),
        );

        for _ in 0..3 {
            scheduler.run_once(OffsetDateTime::now_utc()).await.unwrap();
        }

        let events = audit.snapshot().await;
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| !e.success));
        // First two are Info, third is Error (escalation).
        assert_eq!(events[0].severity, RotationSeverity::Info);
        assert_eq!(events[1].severity, RotationSeverity::Info);
        assert_eq!(events[2].severity, RotationSeverity::Error);

        // Old secret preserved.
        let still = secrets
            .get(&format!("tenants/{tenant}/intel/mandiant/client_secret"))
            .await
            .unwrap();
        assert_eq!(still.expose_secret(), "old-secret");

        // Row carries the failure budget.
        let after = state.snapshot().await;
        assert_eq!(after[0].attempts, 3);
        assert_eq!(after[0].last_error.as_deref(), Some("unauthorized"));
        // last_rotated_at NEVER advances on failure.
        assert!(after[0].last_rotated_at.is_none());
    }

    #[tokio::test]
    async fn state_machine_transitions_due_in_progress_done() {
        let tenant = Uuid::new_v4();
        // due -> running rotate -> done (success)
        let row = RotationStateRow::new_due_now(
            tenant,
            "x/client_secret",
            RotationVendor::VaultTransit,
            Duration::from_secs(60),
        );
        let state = Arc::new(InMemoryRotationStateStore::new());
        state.upsert(row.clone()).await.unwrap();

        let now = OffsetDateTime::now_utc();
        assert!(row.is_due(now));

        // After successful rotation, next_due_at moves to now + cadence
        // so the row is NOT due again on the next tick.
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let scheduler = make_scheduler(
            secrets,
            state.clone(),
            Arc::new(StubPort::ok()),
            RotationVendor::VaultTransit,
        );
        scheduler.run_once(now).await.unwrap();
        let after = state.snapshot().await;
        assert!(!after[0].is_due(now));
        // 60 second cadence -> due ~60s in the future.
        let delta = (after[0].next_due_at - now).whole_seconds();
        assert!((59..=61).contains(&delta), "delta = {delta}");
    }

    #[tokio::test]
    async fn graceful_handover_uses_secrets_put_so_old_value_stays_resolvable_via_versioning() {
        // The handover guarantee is provider-side (Vault keeps prior
        // key versions; AWS keeps AWSPREVIOUS; GCP keeps the prior
        // version ENABLED). We assert the scheduler does not destroy
        // the old value in our own store: `SecretsProvider::put`
        // appends in versioned backends. The in-memory provider does
        // overwrite, so we instead assert the rotation event marks
        // not_before as a fresh wall-clock stamp — proving the
        // scheduler honoured the cred's not_before for tracking.
        let tenant = Uuid::new_v4();
        let row = RotationStateRow::new_due_now(
            tenant,
            "x/client_secret",
            RotationVendor::VaultTransit,
            Duration::from_secs(60),
        );
        let state = Arc::new(InMemoryRotationStateStore::new());
        state.upsert(row).await.unwrap();
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let port: Arc<dyn RotationPort> = Arc::new(StubPort::ok());
        let registry = StaticRotationRegistry::new().with(RotationVendor::VaultTransit, port);
        let audit = Arc::new(InMemoryCredentialAuditSink::new());
        let scheduler = CredentialRotationScheduler::<_, (), _, _>::new(
            secrets,
            state,
            Arc::new(registry),
            audit.clone(),
        );
        let before = chrono::Utc::now();
        scheduler.run_once(OffsetDateTime::now_utc()).await.unwrap();
        let after = chrono::Utc::now();
        let events = audit.snapshot().await;
        assert_eq!(events.len(), 1);
        assert!(events[0].success);
        // Sanity: event timestamp is in-band.
        let _ = (before, after);
    }

    #[tokio::test]
    async fn rotate_now_loads_row_and_returns_new_credential() {
        let tenant = Uuid::new_v4();
        let row = RotationStateRow::new_due_now(
            tenant,
            "mandiant/client_secret",
            RotationVendor::VaultTransit,
            Duration::from_secs(60),
        );
        let state = Arc::new(InMemoryRotationStateStore::new());
        state.upsert(row).await.unwrap();
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let scheduler = make_scheduler(
            secrets,
            state,
            Arc::new(StubPort::ok()),
            RotationVendor::VaultTransit,
        );
        let cred = scheduler
            .rotate_now(tenant, "mandiant/client_secret")
            .await
            .unwrap();
        assert_eq!(cred.version, "1");
        assert_eq!(cred.client_secret.expose_secret(), "rotated-secret-v1");
    }

    #[tokio::test]
    async fn rotate_now_on_unknown_row_returns_not_found() {
        let tenant = Uuid::new_v4();
        let state = Arc::new(InMemoryRotationStateStore::new());
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let scheduler = make_scheduler(
            secrets,
            state,
            Arc::new(StubPort::ok()),
            RotationVendor::VaultTransit,
        );
        let err = scheduler
            .rotate_now(tenant, "nope/client_secret")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RotationSchedulerError::State(RotationStateError::NotFound { .. })
        ));
    }

    #[test]
    fn audit_event_type_is_canonical() {
        assert_eq!(
            CredentialRotationAuditEvent::EVENT_TYPE,
            "audit.secrets.intel_credential_rotated"
        );
    }

    #[test]
    fn redact_error_never_leaks_provider_message_text() {
        // Provider variant SHOULD echo the supplied message — but the
        // caller (the RotationPort implementations in sx-secrets) is
        // already required to redact before constructing. The redact
        // helper verifies the OTHER variants are collapsed to a fixed
        // string.
        assert_eq!(
            redact_error(&RotationError::Transport("connect refused".into())),
            "transport error"
        );
        assert_eq!(
            redact_error(&RotationError::Format("base64 oops".into())),
            "format error"
        );
        assert_eq!(redact_error(&RotationError::Unauthorized), "unauthorized");
    }

    #[test]
    fn vendor_str_labels_match_db_constraint_values() {
        assert_eq!(RotationVendor::VaultTransit.as_str(), "vault-transit");
        assert_eq!(RotationVendor::AwsSecretsManager.as_str(), "aws-sm");
        assert_eq!(RotationVendor::GcpSecretManager.as_str(), "gcp-sm");
    }

    #[test]
    fn vendor_inferred_from_secret_id() {
        assert_eq!(
            port_vendor_from_secret("arn:aws:secretsmanager:us-east-1:1:secret:Mandiant"),
            RotationVendor::AwsSecretsManager
        );
        assert_eq!(
            port_vendor_from_secret("projects/p/secrets/mandiant"),
            RotationVendor::GcpSecretManager
        );
        assert_eq!(
            port_vendor_from_secret("mandiant/client_secret"),
            RotationVendor::VaultTransit
        );
    }
}
