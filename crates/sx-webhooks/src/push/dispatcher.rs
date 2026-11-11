//! Critical-finding push dispatcher.
//!
//! The dispatcher is the only public surface upstream finding
//! pipelines should touch. It enforces three properties on every
//! [`dispatch_finding`](PushDispatcher::dispatch_finding) call:
//!
//! 1. **Severity gate** — only findings of severity `Critical` (or
//!    higher) fan out. Lower-severity findings short-circuit with a
//!    zero-delivery success.
//! 2. **Rate limit** — at most 5 notifications per device per minute.
//!    Excess requests are *dropped*, not retried, and recorded in the
//!    audit trail so operators can see throttle activity.
//! 3. **Dedupe** — identical `(device_id, finding_id)` pairs delivered
//!    within a 60-second window are suppressed. This prevents the
//!    classic "alert storm replays" pathology.
//!
//! The dispatcher also emits a [`PushAuditEvent`] for every accepted,
//! suppressed, or failed delivery so the central audit pipeline can
//! reason about push activity per tenant.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::push::apns::{ApnsAlert, ApnsClient, ApnsPriority};
use crate::push::credentials::TenantPushCredentials;
use crate::push::error::PushError;
use crate::push::fcm::{FcmClient, FcmNotification};
use crate::push::registry::{DeviceId, DeviceRegistry, MobilePlatform};

/// Coarse-grained severity that the dispatcher cares about.
///
/// The mapping from the project's richer
/// `sx_core::finding::Severity` enum should happen at the call site;
/// keeping this enum small lets the dispatcher remain independent of
/// the rest of the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    /// Informational only — no push.
    Info,
    /// Low severity — no push.
    Low,
    /// Medium severity — no push.
    Medium,
    /// High severity — no push (operators check dashboard).
    High,
    /// Critical severity — fan out push to escalation contacts.
    Critical,
}

impl FindingSeverity {
    /// Whether the dispatcher should fan out a push for this severity.
    #[must_use]
    pub fn warrants_push(self) -> bool {
        self >= Self::Critical
    }
}

/// Input shape for a finding that the dispatcher may fan out.
///
/// `finding_id` is the dedupe key — multiple deliveries of the same
/// `finding_id` for a given device within a 60s window collapse into
/// one.
#[derive(Debug, Clone)]
pub struct PushFinding {
    /// Stable id of the finding (UUID, snowflake, …). Used as the
    /// dedupe key.
    pub finding_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Severity at the time the finding was produced.
    pub severity: FindingSeverity,
    /// Short headline shown on the lockscreen.
    pub title: String,
    /// Body text shown under the title.
    pub body: String,
}

/// Configurable knobs for the dispatcher.
#[derive(Debug, Clone, Copy)]
pub struct PushDispatcherConfig {
    /// Maximum sends per device per [`rate_window`]. Defaults to 5.
    pub rate_limit_max: u32,
    /// Length of the rate-limit token bucket window. Defaults to
    /// 60 seconds.
    pub rate_window: Duration,
    /// Dedupe window: identical `(device_id, finding_id)` pairs within
    /// this window are dropped. Defaults to 60 seconds.
    pub dedupe_window: Duration,
}

impl Default for PushDispatcherConfig {
    fn default() -> Self {
        Self {
            rate_limit_max: 5,
            rate_window: Duration::from_secs(60),
            dedupe_window: Duration::from_secs(60),
        }
    }
}

/// Audit event emitted for every delivery attempt.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PushAuditEvent {
    /// Provider accepted the push.
    Delivered {
        /// Tenant scope.
        tenant_id: String,
        /// Finding id that triggered the push.
        finding_id: String,
        /// Destination device.
        device_id: DeviceId,
        /// Provider — `"apns"` or `"fcm"`.
        provider: &'static str,
    },
    /// Dropped because the device exceeded the rate-limit window.
    RateLimited {
        /// Tenant scope.
        tenant_id: String,
        /// Finding id.
        finding_id: String,
        /// Device that hit the rate limit.
        device_id: DeviceId,
    },
    /// Dropped because the dispatcher already delivered the same
    /// `(device, finding)` within the dedupe window.
    Deduped {
        /// Tenant scope.
        tenant_id: String,
        /// Finding id.
        finding_id: String,
        /// Device that was previously notified.
        device_id: DeviceId,
    },
    /// Provider returned an error.
    Failed {
        /// Tenant scope.
        tenant_id: String,
        /// Finding id.
        finding_id: String,
        /// Device.
        device_id: DeviceId,
        /// Provider.
        provider: &'static str,
        /// HTTP status code (or `0` for transport-layer failure).
        status: u16,
    },
}

/// Audit sink the dispatcher emits events to.
#[async_trait]
pub trait PushAuditSink: Send + Sync {
    /// Record a single audit event. Implementations should never
    /// panic; transport / persistence errors should be swallowed and
    /// retried out-of-band.
    async fn record(&self, event: PushAuditEvent);
}

/// In-memory audit sink suitable for tests.
#[derive(Default)]
pub struct InMemoryAuditSink {
    inner: Mutex<Vec<PushAuditEvent>>,
}

impl std::fmt::Debug for InMemoryAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryAuditSink").finish_non_exhaustive()
    }
}

impl InMemoryAuditSink {
    /// Construct an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every event recorded so far.
    pub async fn snapshot(&self) -> Vec<PushAuditEvent> {
        self.inner.lock().await.clone()
    }
}

#[async_trait]
impl PushAuditSink for InMemoryAuditSink {
    async fn record(&self, event: PushAuditEvent) {
        self.inner.lock().await.push(event);
    }
}

/// Monotonic clock the dispatcher uses for rate-limit + dedupe
/// bookkeeping.
///
/// Lifted into a trait so tests can pin time deterministically without
/// `tokio::time::pause` plumbing.
pub trait MonotonicClock: Send + Sync + std::fmt::Debug {
    /// Current monotonic instant.
    fn now(&self) -> Instant;
}

/// Default clock backed by `std::time::Instant::now`.
#[derive(Debug, Default)]
pub struct SystemClock;

impl MonotonicClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Debug, Default)]
struct DeviceState {
    /// Send timestamps within the current rate-limit window.
    sends: Vec<Instant>,
    /// Last successful delivery per `finding_id`. Older entries are
    /// garbage-collected on each access.
    dedupe: HashMap<String, Instant>,
}

/// Critical-finding push dispatcher.
pub struct PushDispatcher {
    registry: Arc<dyn DeviceRegistry>,
    creds: Arc<dyn TenantPushCredentials>,
    audit: Arc<dyn PushAuditSink>,
    apns: ApnsClient,
    fcm: FcmClient,
    cfg: PushDispatcherConfig,
    clock: Box<dyn MonotonicClock>,
    state: Mutex<HashMap<DeviceId, DeviceState>>,
}

impl std::fmt::Debug for PushDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushDispatcher")
            .field("cfg", &self.cfg)
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

impl PushDispatcher {
    /// Build a dispatcher with the default clock and an
    /// already-configured APNs/FCM client pair (tests inject wiremock
    /// hosts here).
    #[must_use]
    pub fn new(
        registry: Arc<dyn DeviceRegistry>,
        creds: Arc<dyn TenantPushCredentials>,
        audit: Arc<dyn PushAuditSink>,
        apns: ApnsClient,
        fcm: FcmClient,
    ) -> Self {
        Self::with_config(
            registry,
            creds,
            audit,
            apns,
            fcm,
            PushDispatcherConfig::default(),
            Box::new(SystemClock),
        )
    }

    /// Build with explicit configuration and clock — used by tests
    /// that want a fake clock to drive rate-limit / dedupe windows.
    pub fn with_config(
        registry: Arc<dyn DeviceRegistry>,
        creds: Arc<dyn TenantPushCredentials>,
        audit: Arc<dyn PushAuditSink>,
        apns: ApnsClient,
        fcm: FcmClient,
        cfg: PushDispatcherConfig,
        clock: Box<dyn MonotonicClock>,
    ) -> Self {
        Self {
            registry,
            creds,
            audit,
            apns,
            fcm,
            cfg,
            clock,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Fan a finding out to every registered device of every
    /// escalation contact for the affected tenant.
    ///
    /// Returns the number of devices to which the dispatcher accepted
    /// the delivery (i.e. neither rate-limited, deduped, nor errored).
    pub async fn dispatch_finding(&self, finding: &PushFinding) -> Result<usize, PushError> {
        if !finding.severity.warrants_push() {
            tracing::debug!(
                tenant = %finding.tenant_id,
                finding = %finding.finding_id,
                severity = ?finding.severity,
                "skipping push: below critical threshold"
            );
            return Ok(0);
        }

        let contacts = self.creds.escalation_contacts(&finding.tenant_id).await?;
        if contacts.is_empty() {
            tracing::debug!(
                tenant = %finding.tenant_id,
                "no escalation contacts configured; skipping push"
            );
            return Ok(0);
        }

        let devices = self
            .registry
            .devices_for_users(&finding.tenant_id, &contacts)
            .await?;
        let mut delivered: usize = 0;
        for device in devices {
            match self.deliver_one(finding, &device).await {
                Outcome::Delivered => delivered = delivered.saturating_add(1),
                Outcome::RateLimited | Outcome::Deduped | Outcome::Failed => {}
            }
        }
        Ok(delivered)
    }

    async fn deliver_one(
        &self,
        finding: &PushFinding,
        device: &crate::push::registry::DeviceRecord,
    ) -> Outcome {
        if !self.admit(device.id, &finding.finding_id).await {
            // admit() emits the right audit event; nothing more to do.
            self.audit
                .record(PushAuditEvent::RateLimited {
                    tenant_id: finding.tenant_id.clone(),
                    finding_id: finding.finding_id.clone(),
                    device_id: device.id,
                })
                .await;
            return Outcome::RateLimited;
        }

        if self.is_duplicate(device.id, &finding.finding_id).await {
            self.audit
                .record(PushAuditEvent::Deduped {
                    tenant_id: finding.tenant_id.clone(),
                    finding_id: finding.finding_id.clone(),
                    device_id: device.id,
                })
                .await;
            return Outcome::Deduped;
        }

        let outcome = match device.platform {
            MobilePlatform::Ios => self.send_apns(finding, device).await,
            MobilePlatform::Android => self.send_fcm(finding, device).await,
        };

        match outcome {
            Ok(provider) => {
                self.note_delivery(device.id, &finding.finding_id).await;
                self.audit
                    .record(PushAuditEvent::Delivered {
                        tenant_id: finding.tenant_id.clone(),
                        finding_id: finding.finding_id.clone(),
                        device_id: device.id,
                        provider,
                    })
                    .await;
                Outcome::Delivered
            }
            Err((provider, status)) => {
                self.audit
                    .record(PushAuditEvent::Failed {
                        tenant_id: finding.tenant_id.clone(),
                        finding_id: finding.finding_id.clone(),
                        device_id: device.id,
                        provider,
                        status,
                    })
                    .await;
                Outcome::Failed
            }
        }
    }

    async fn send_apns(
        &self,
        finding: &PushFinding,
        device: &crate::push::registry::DeviceRecord,
    ) -> Result<&'static str, (&'static str, u16)> {
        let Some(creds) = self
            .creds
            .apns_for(&device.tenant_id)
            .await
            .map_err(|_| ("apns", 0_u16))?
        else {
            return Err(("apns", 0));
        };
        let alert = ApnsAlert {
            title: finding.title.clone(),
            body: finding.body.clone(),
        };
        match self
            .apns
            .send(
                &creds,
                &device.device_token,
                &alert,
                ApnsPriority::Immediate,
            )
            .await
        {
            Ok(()) => Ok("apns"),
            Err(PushError::ProviderRejected { status }) => Err(("apns", status)),
            Err(_) => Err(("apns", 0)),
        }
    }

    async fn send_fcm(
        &self,
        finding: &PushFinding,
        device: &crate::push::registry::DeviceRecord,
    ) -> Result<&'static str, (&'static str, u16)> {
        let Some(creds) = self
            .creds
            .fcm_for(&device.tenant_id)
            .await
            .map_err(|_| ("fcm", 0_u16))?
        else {
            return Err(("fcm", 0));
        };
        let notification = FcmNotification {
            title: finding.title.clone(),
            body: finding.body.clone(),
        };
        match self
            .fcm
            .send(&creds, &device.device_token, &notification)
            .await
        {
            Ok(()) => Ok("fcm"),
            Err(PushError::ProviderRejected { status }) => Err(("fcm", status)),
            Err(_) => Err(("fcm", 0)),
        }
    }

    /// Returns `true` if the device is *under* the rate-limit cap and
    /// the send may proceed (and records the timestamp). Returns
    /// `false` if the device is over the cap.
    async fn admit(&self, device_id: DeviceId, _finding_id: &str) -> bool {
        let now = self.clock.now();
        let window = self.cfg.rate_window;
        let mut guard = self.state.lock().await;
        let entry = guard.entry(device_id).or_default();
        entry.sends.retain(|t| now.duration_since(*t) < window);
        if entry.sends.len() >= self.cfg.rate_limit_max as usize {
            drop(guard);
            return false;
        }
        entry.sends.push(now);
        drop(guard);
        true
    }

    async fn is_duplicate(&self, device_id: DeviceId, finding_id: &str) -> bool {
        let now = self.clock.now();
        let window = self.cfg.dedupe_window;
        let mut guard = self.state.lock().await;
        let entry = guard.entry(device_id).or_default();
        entry
            .dedupe
            .retain(|_, last| now.duration_since(*last) < window);
        let hit = entry
            .dedupe
            .get(finding_id)
            .is_some_and(|last| now.duration_since(*last) < window);
        drop(guard);
        hit
    }

    async fn note_delivery(&self, device_id: DeviceId, finding_id: &str) {
        let now = self.clock.now();
        let mut guard = self.state.lock().await;
        let entry = guard.entry(device_id).or_default();
        entry.dedupe.insert(finding_id.to_owned(), now);
        drop(guard);
    }
}

#[derive(Debug, Clone, Copy)]
enum Outcome {
    Delivered,
    RateLimited,
    Deduped,
    Failed,
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn severity_gate_only_admits_critical() {
        assert!(!FindingSeverity::Info.warrants_push());
        assert!(!FindingSeverity::Low.warrants_push());
        assert!(!FindingSeverity::Medium.warrants_push());
        assert!(!FindingSeverity::High.warrants_push());
        assert!(FindingSeverity::Critical.warrants_push());
    }

    #[test]
    fn config_defaults_to_5_per_minute() {
        let cfg = PushDispatcherConfig::default();
        assert_eq!(cfg.rate_limit_max, 5);
        assert_eq!(cfg.rate_window, Duration::from_secs(60));
        assert_eq!(cfg.dedupe_window, Duration::from_secs(60));
    }
}
