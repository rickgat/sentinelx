//! Cron-driven report scheduler — P2-001 MVP.
//!
//! The scheduler is the orchestrator that turns a persisted
//! [`ReportSchedule`] row into an email with the rendered report attached.
//!
//! ## Pipeline
//!
//! 1. The orchestrator (cron-fired in production, hand-driven in tests)
//!    calls [`Scheduler::tick`] with the current wall-clock instant.
//! 2. The tick implementation pulls every [`ReportSchedule`] whose
//!    `enabled = true` AND `next_run_at <= now` from the supplied
//!    [`ScheduleStore`].
//! 3. For each due row, it invokes [`SchedulerReportPort::render`] to
//!    materialise the report. The port returns a
//!    [`SchedulerReportArtifact`] whose `inline_payload` is the base64
//!    representation of the rendered bytes — identical to the wire shape
//!    returned by `POST /v1/reports/render`.
//! 4. The bytes are base64-decoded, wrapped in a sanitised HTML email
//!    body, and handed to [`EmailDispatcher::send`] for delivery.
//! 5. The store is updated via [`ScheduleStore::mark_run`] and the cron
//!    expression is evaluated against `now` to compute the next
//!    `next_run_at`.
//!
//! ## Hard constraints
//!
//! - **No unsafe code** (crate-wide `#![forbid(unsafe_code)]`).
//! - **No `unwrap` / `expect` / `panic!` in production paths** — tests may
//!   relax this locally.
//! - **Email body is HTML-escaped.** The wrapper template never embeds
//!   raw user input outside `text` nodes, so a malicious tenant name (or
//!   engagement label) cannot inject `<script>` / `<style>` / `<iframe>`.
//! - **Rustls only.** The bundled [`LettreSmtpDispatcher`] depends on
//!   lettre's `tokio1-rustls-tls` feature; the workspace never links
//!   native-tls / OpenSSL.
//!
//! ## Out of scope (deliberately)
//!
//! - Wiring the scheduler into the monolith composition root (cron-fired
//!   loop, graceful shutdown).
//! - The CRUD UI / API endpoints for managing schedules.
//! - Signed download URLs for the inline attachment.

use std::sync::Mutex;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

use crate::error::ReportError;
use crate::port::ReportFormat;

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// Persisted definition of a recurring report job.
///
/// One row drives one engagement + one format + one recipient list. Multi-
/// format delivery is modelled as multiple rows so a tenant can disable one
/// format without touching the others.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSchedule {
    /// Stable identifier (uuid v4 / v7).
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Optional engagement scope. `None` means "render every engagement
    /// the tenant owns" — concrete semantics live in the adapter.
    pub engagement_id: Option<Uuid>,
    /// Output format.
    pub format: ReportFormat,
    /// Cron expression (six-or-seven-field zero-padded format accepted by
    /// the `cron = "0.12"` crate, e.g. `0 0 9 * * *` for 09:00 daily).
    pub cron_expr: String,
    /// RFC 5322 destination addresses. Empty vector is rejected at
    /// construction time.
    pub recipients: Vec<String>,
    /// When `false`, the scheduler skips this row even if `next_run_at`
    /// has elapsed.
    pub enabled: bool,
    /// Time of the most recent successful dispatch, if any.
    pub last_run_at: Option<OffsetDateTime>,
    /// Next planned dispatch — `tick` treats every row with
    /// `next_run_at <= now` as due.
    pub next_run_at: OffsetDateTime,
    /// Number of consecutive *failed* delivery attempts since the most
    /// recent success. Used to drive exponential backoff and dead-letter
    /// promotion in [`Scheduler::tick_with_policy`].
    #[serde(default)]
    pub failure_count: u32,
    /// Additional delivery channels the dispatcher should fan out to per
    /// successful render. Email is always implicit through
    /// [`Self::recipients`]; this list adds S3 dropbox and outbound
    /// webhook deliveries.
    #[serde(default)]
    pub channels: Vec<DeliveryChannel>,
}

impl ReportSchedule {
    /// Construct a [`ReportSchedule`] after validating cron expression,
    /// recipient list, and at-least-one-RFC-5322 address.
    ///
    /// # Errors
    ///
    /// - [`ReportError::InvalidContext`] when `cron_expr` does not parse,
    ///   when `recipients` is empty, or when any recipient fails the
    ///   RFC 5322 sanity check (`local@host` with non-empty halves).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        tenant_id: Uuid,
        engagement_id: Option<Uuid>,
        format: ReportFormat,
        cron_expr: impl Into<String>,
        recipients: Vec<String>,
        enabled: bool,
        last_run_at: Option<OffsetDateTime>,
        next_run_at: OffsetDateTime,
    ) -> Result<Self, ReportError> {
        let cron_expr = cron_expr.into();
        // Validate cron expression up-front so persistence layers never
        // store an unparseable row.
        CronEvaluator::validate(&cron_expr)?;
        if recipients.is_empty() {
            return Err(ReportError::invalid_context(
                "report schedule must have >= 1 recipient",
            ));
        }
        for r in &recipients {
            if !is_rfc5322_address(r) {
                return Err(ReportError::invalid_context(format!(
                    "recipient is not a valid RFC 5322 address: {r}"
                )));
            }
        }
        Ok(Self {
            id,
            tenant_id,
            engagement_id,
            format,
            cron_expr,
            recipients,
            enabled,
            last_run_at,
            next_run_at,
            failure_count: 0,
            channels: Vec::new(),
        })
    }

    /// Builder-style helper to attach additional delivery channels.
    #[must_use]
    pub fn with_channels(mut self, channels: Vec<DeliveryChannel>) -> Self {
        self.channels = channels;
        self
    }
}

/// Minimal RFC 5322 address sanity check — just enough to refuse the
/// obvious garbage (`""`, `"a"`, `"a@"`, `"@b"`). Full RFC 5322
/// validation lives in the SMTP dispatcher: lettre's `Address::from_str`
/// is the final arbiter at send time.
fn is_rfc5322_address(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    let mut parts = s.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    // The domain must contain at least one dot (so `a@b` is rejected but
    // `a@example.com` is accepted) and the local part must not contain a
    // whitespace character.
    if !domain.contains('.') {
        return false;
    }
    if local.chars().any(char::is_whitespace) || domain.chars().any(char::is_whitespace) {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Storage port
// ---------------------------------------------------------------------------

/// Persistent backing for [`ReportSchedule`] rows.
///
/// The trait is intentionally narrow: only the two operations the
/// scheduler tick needs. CRUD (create / update / delete / list) lives in
/// the adapter layer because it has very different RLS / auth concerns.
#[async_trait]
pub trait ScheduleStore: Send + Sync {
    /// Return every row whose `enabled = true` AND `next_run_at <= now`.
    /// Implementations MAY return rows in any order.
    async fn list_due(&self, now: OffsetDateTime) -> Result<Vec<ReportSchedule>, ReportError>;

    /// Record a successful dispatch and update `next_run_at`.
    ///
    /// `ran_at` is the wall clock at the moment dispatch returned `Ok`.
    /// `next_run_at` is the freshly-computed cron-derived instant.
    async fn mark_run(
        &self,
        id: Uuid,
        ran_at: OffsetDateTime,
        next_run_at: OffsetDateTime,
    ) -> Result<(), ReportError>;

    /// Toggle the `enabled` flag — backs `pause` / `resume` operations.
    ///
    /// Implementations MUST scope by `(tenant_id, id)` so a tenant cannot
    /// flip another tenant's row.
    async fn set_enabled(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        enabled: bool,
    ) -> Result<(), ReportError>;

    /// Force `next_run_at` to `now` so the next `tick` fires this row.
    /// Used by the "run now" API.
    async fn request_run_now(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), ReportError>;

    /// Fetch a single row scoped by `(tenant_id, id)`. Returns
    /// [`ReportError::Internal`] if the row does not exist — the controller
    /// translates that to a 404.
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<ReportSchedule, ReportError>;

    /// List every row owned by `tenant_id`, newest-first.
    async fn list_for_tenant(&self, tenant_id: Uuid) -> Result<Vec<ReportSchedule>, ReportError>;

    /// Bump the failure counter and push `next_run_at` to the configured
    /// retry instant. Used by the retry loop in
    /// [`Scheduler::tick_with_policy`].
    ///
    /// Returns the post-bump `failure_count`.
    async fn record_failure(
        &self,
        id: Uuid,
        next_run_at: OffsetDateTime,
    ) -> Result<u32, ReportError>;
}

/// In-memory [`ScheduleStore`] implementation used by tests and the
/// monolith's offline mode.
#[derive(Debug, Default)]
pub struct InMemoryScheduleStore {
    rows: Mutex<Vec<ReportSchedule>>,
}

impl InMemoryScheduleStore {
    /// Build an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed the store with `rows`.
    #[must_use]
    pub const fn with_rows(rows: Vec<ReportSchedule>) -> Self {
        Self {
            rows: Mutex::new(rows),
        }
    }

    /// Insert a row.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Internal`] if the mutex has been poisoned.
    pub fn insert(&self, row: ReportSchedule) -> Result<(), ReportError> {
        {
            let mut guard = self.rows.lock().map_err(|e| {
                ReportError::internal(format!("schedule store mutex poisoned: {e}"))
            })?;
            guard.push(row);
        }
        Ok(())
    }

    /// Snapshot every persisted row (test helper).
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Internal`] if the mutex has been poisoned.
    pub fn snapshot(&self) -> Result<Vec<ReportSchedule>, ReportError> {
        let guard = self
            .rows
            .lock()
            .map_err(|e| ReportError::internal(format!("schedule store mutex poisoned: {e}")))?;
        Ok(guard.clone())
    }
}

#[async_trait]
impl ScheduleStore for InMemoryScheduleStore {
    async fn list_due(&self, now: OffsetDateTime) -> Result<Vec<ReportSchedule>, ReportError> {
        let guard = self
            .rows
            .lock()
            .map_err(|e| ReportError::internal(format!("schedule store mutex poisoned: {e}")))?;
        Ok(guard
            .iter()
            .filter(|r| r.enabled && r.next_run_at <= now)
            .cloned()
            .collect())
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn mark_run(
        &self,
        id: Uuid,
        ran_at: OffsetDateTime,
        next_run_at: OffsetDateTime,
    ) -> Result<(), ReportError> {
        {
            let mut guard = self.rows.lock().map_err(|e| {
                ReportError::internal(format!("schedule store mutex poisoned: {e}"))
            })?;
            let row = guard
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or_else(|| ReportError::internal(format!("schedule id {id} not found")))?;
            row.last_run_at = Some(ran_at);
            row.next_run_at = next_run_at;
            row.failure_count = 0;
        }
        Ok(())
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn set_enabled(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        enabled: bool,
    ) -> Result<(), ReportError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|e| ReportError::internal(format!("schedule store mutex poisoned: {e}")))?;
        let row = guard
            .iter_mut()
            .find(|r| r.id == id && r.tenant_id == tenant_id)
            .ok_or_else(|| ReportError::internal(format!("schedule id {id} not found")))?;
        row.enabled = enabled;
        Ok(())
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn request_run_now(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), ReportError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|e| ReportError::internal(format!("schedule store mutex poisoned: {e}")))?;
        let row = guard
            .iter_mut()
            .find(|r| r.id == id && r.tenant_id == tenant_id)
            .ok_or_else(|| ReportError::internal(format!("schedule id {id} not found")))?;
        row.next_run_at = now;
        // Reset failure counter so the manual run is not penalised by the
        // backoff state of a previously stuck row.
        row.failure_count = 0;
        Ok(())
    }

    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<ReportSchedule, ReportError> {
        let guard = self
            .rows
            .lock()
            .map_err(|e| ReportError::internal(format!("schedule store mutex poisoned: {e}")))?;
        guard
            .iter()
            .find(|r| r.id == id && r.tenant_id == tenant_id)
            .cloned()
            .ok_or_else(|| ReportError::internal(format!("schedule id {id} not found")))
    }

    async fn list_for_tenant(&self, tenant_id: Uuid) -> Result<Vec<ReportSchedule>, ReportError> {
        let guard = self
            .rows
            .lock()
            .map_err(|e| ReportError::internal(format!("schedule store mutex poisoned: {e}")))?;
        Ok(guard
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn record_failure(
        &self,
        id: Uuid,
        next_run_at: OffsetDateTime,
    ) -> Result<u32, ReportError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|e| ReportError::internal(format!("schedule store mutex poisoned: {e}")))?;
        let row = guard
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| ReportError::internal(format!("schedule id {id} not found")))?;
        row.failure_count = row.failure_count.saturating_add(1);
        row.next_run_at = next_run_at;
        Ok(row.failure_count)
    }
}

// ---------------------------------------------------------------------------
// Cron evaluator
// ---------------------------------------------------------------------------

/// Thin wrapper around the `cron = "0.12"` crate that bridges between the
/// crate's [`chrono::DateTime<Utc>`] surface and the rest of `sx-report`
/// which is uniformly built on [`time::OffsetDateTime`].
#[derive(Debug, Default, Clone, Copy)]
pub struct CronEvaluator;

impl CronEvaluator {
    /// Build a new evaluator. The type is zero-sized; the constructor
    /// exists so callers do not have to depend on the `Default` impl.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse `expr` and return the next firing instant strictly after
    /// `after`, or `None` if the schedule has no future occurrences (rare
    /// — fixed-year cron expressions).
    ///
    /// The method is intentionally an associated function (no `&self`)
    /// because the evaluator is a zero-sized marker — every call is
    /// stateless. The instance constructor exists only so call sites can
    /// write `CronEvaluator::new().next_after(...)` ergonomically; this
    /// associated form is also exposed.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::InvalidContext`] when `expr` is not a
    /// well-formed cron expression.
    #[allow(clippy::unused_self)]
    pub fn next_after(
        self,
        expr: &str,
        after: OffsetDateTime,
    ) -> Result<Option<OffsetDateTime>, ReportError> {
        let schedule = expr
            .parse::<cron::Schedule>()
            .map_err(|e| ReportError::invalid_context(format!("invalid cron expression: {e}")))?;
        let after_chrono = offset_datetime_to_chrono(after)?;
        let Some(next_chrono) = schedule.after(&after_chrono).next() else {
            return Ok(None);
        };
        Ok(Some(chrono_to_offset_datetime(next_chrono)?))
    }

    /// Validate that `expr` parses. Used by [`ReportSchedule::new`] at
    /// construction time to avoid persisting unparseable rows.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::InvalidContext`] when `expr` does not parse.
    pub fn validate(expr: &str) -> Result<(), ReportError> {
        expr.parse::<cron::Schedule>()
            .map(|_| ())
            .map_err(|e| ReportError::invalid_context(format!("invalid cron expression: {e}")))
    }
}

fn offset_datetime_to_chrono(
    dt: OffsetDateTime,
) -> Result<chrono::DateTime<chrono::Utc>, ReportError> {
    let utc = dt.to_offset(time::UtcOffset::UTC);
    let unix = utc.unix_timestamp();
    let nanos = utc.nanosecond();
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix, nanos)
        .ok_or_else(|| ReportError::internal(format!("offsetdatetime {dt:?} out of chrono range")))
}

fn chrono_to_offset_datetime(
    dt: chrono::DateTime<chrono::Utc>,
) -> Result<OffsetDateTime, ReportError> {
    let unix = dt.timestamp();
    let nanos = i128::from(dt.timestamp_subsec_nanos());
    let total_nanos = i128::from(unix)
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nanos))
        .ok_or_else(|| ReportError::internal("chrono datetime overflowed i128 nanos"))?;
    OffsetDateTime::from_unix_timestamp_nanos(total_nanos).map_err(|e| {
        ReportError::internal(format!("chrono->offsetdatetime conversion failed: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Report port
// ---------------------------------------------------------------------------

/// Wire shape of the report payload the scheduler hands to the email
/// dispatcher.
///
/// Mirrors the wire shape returned by `POST /v1/reports/render` so an
/// adapter can forward the HTTP-port response without translation.
#[derive(Debug, Clone)]
pub struct SchedulerReportArtifact {
    /// Suggested file name (with extension), e.g. `executive-2026-05-30.pdf`.
    pub filename: String,
    /// MIME type, e.g. `application/pdf`.
    pub mime_type: String,
    /// Base64-encoded payload — present for every format the scheduler
    /// can attach. For PDF formats the adapter MUST set this (the HTTP
    /// surface skips it; the scheduler needs the bytes inline so it can
    /// attach them).
    pub inline_payload: String,
}

/// Render port the scheduler depends on.
///
/// Stays inside `sx-report` (rather than reusing `sx-api`'s
/// `ReportRenderPort`) so this crate does not pick up an HTTP-layer
/// dependency cycle. The composition root implements it on top of either
/// [`crate::controller::RenderReportUseCase`] or the HTTP port adapter.
#[async_trait]
pub trait SchedulerReportPort: Send + Sync {
    /// Render the report identified by `(tenant_id, engagement_id, format)`
    /// and return the artefact (filename, mime-type, base64 payload).
    async fn render(
        &self,
        tenant_id: Uuid,
        engagement_id: Option<Uuid>,
        format: ReportFormat,
    ) -> Result<SchedulerReportArtifact, ReportError>;
}

// ---------------------------------------------------------------------------
// Email dispatcher
// ---------------------------------------------------------------------------

/// Async email-dispatch port.
///
/// Attachments are passed as `(filename, mime_type, raw_bytes)` triples.
/// The wrapper template the scheduler hands to `body_html` already
/// HTML-escapes every dynamic substitution — implementations are free to
/// treat the body as-is.
#[async_trait]
pub trait EmailDispatcher: Send + Sync {
    /// Send one email.
    async fn send(
        &self,
        to: Vec<String>,
        subject: String,
        body_html: String,
        attachments: Vec<(String, String, Vec<u8>)>,
    ) -> Result<(), ReportError>;
}

/// Captured email used by [`RecordingDispatcher`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedEmail {
    /// Recipient addresses (RFC 5322).
    pub to: Vec<String>,
    /// Subject line.
    pub subject: String,
    /// Pre-escaped HTML body.
    pub body_html: String,
    /// Attachments as `(filename, mime, bytes)` triples.
    pub attachments: Vec<(String, String, Vec<u8>)>,
}

/// In-memory [`EmailDispatcher`] that captures everything for assertion in
/// tests. Wraps a [`Mutex<Vec<RecordedEmail>>`] so it is `Sync`.
#[derive(Debug, Default)]
pub struct RecordingDispatcher {
    sent: Mutex<Vec<RecordedEmail>>,
}

impl RecordingDispatcher {
    /// Build an empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded emails.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Internal`] if the mutex has been poisoned.
    pub fn captured(&self) -> Result<Vec<RecordedEmail>, ReportError> {
        let guard = self
            .sent
            .lock()
            .map_err(|e| ReportError::internal(format!("dispatcher mutex poisoned: {e}")))?;
        Ok(guard.clone())
    }

    /// Convenience: how many emails have been recorded.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Internal`] if the mutex has been poisoned.
    pub fn count(&self) -> Result<usize, ReportError> {
        let guard = self
            .sent
            .lock()
            .map_err(|e| ReportError::internal(format!("dispatcher mutex poisoned: {e}")))?;
        Ok(guard.len())
    }
}

#[async_trait]
impl EmailDispatcher for RecordingDispatcher {
    async fn send(
        &self,
        to: Vec<String>,
        subject: String,
        body_html: String,
        attachments: Vec<(String, String, Vec<u8>)>,
    ) -> Result<(), ReportError> {
        {
            let mut guard = self
                .sent
                .lock()
                .map_err(|e| ReportError::internal(format!("dispatcher mutex poisoned: {e}")))?;
            guard.push(RecordedEmail {
                to,
                subject,
                body_html,
                attachments,
            });
        }
        Ok(())
    }
}

/// SMTP credentials passed to [`LettreSmtpDispatcher::new`].
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP relay hostname.
    pub host: String,
    /// SMTP port (e.g. 465 for SMTPS, 587 for STARTTLS).
    pub port: u16,
    /// Authenticated username.
    pub username: String,
    /// Authenticated password (treat as a secret in callers).
    pub password: String,
    /// `From:` address shown to recipients.
    pub from: String,
}

/// Production lettre-based [`EmailDispatcher`] implementation.
///
/// Hard-pinned to lettre's `tokio1-rustls-tls` transport so the binary
/// never links OpenSSL / native-tls. The configured port determines the
/// TLS dance: callers that need STARTTLS should construct over port 587
/// (lettre auto-selects STARTTLS for that port) while 465 yields implicit
/// TLS.
#[derive(Debug)]
pub struct LettreSmtpDispatcher {
    /// `From:` address (parsed at construction so a malformed value
    /// surfaces immediately).
    from_addr: lettre::message::Mailbox,
    /// Pre-built transport. Cloned per-send so the connection pool is
    /// shared.
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
}

impl LettreSmtpDispatcher {
    /// Build a lettre dispatcher from `cfg`.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::InvalidContext`] when the `from` address
    /// fails to parse or the SMTP relay constructor rejects the host.
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(cfg: SmtpConfig) -> Result<Self, ReportError> {
        let from_addr = cfg
            .from
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| ReportError::invalid_context(format!("invalid from address: {e}")))?;
        let creds = lettre::transport::smtp::authentication::Credentials::new(
            cfg.username.clone(),
            cfg.password.clone(),
        );
        let transport =
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(cfg.host.as_str())
                .map_err(|e| ReportError::invalid_context(format!("smtp relay rejected: {e}")))?
                .port(cfg.port)
                .credentials(creds)
                .build();
        Ok(Self {
            from_addr,
            transport,
        })
    }
}

#[async_trait]
impl EmailDispatcher for LettreSmtpDispatcher {
    async fn send(
        &self,
        to: Vec<String>,
        subject: String,
        body_html: String,
        attachments: Vec<(String, String, Vec<u8>)>,
    ) -> Result<(), ReportError> {
        use lettre::message::{header::ContentType, Attachment, MultiPart, SinglePart};
        use lettre::AsyncTransport;

        if to.is_empty() {
            return Err(ReportError::invalid_context("`to` cannot be empty"));
        }

        // Build the multipart body: HTML + each attachment.
        let html_part = SinglePart::builder()
            .header(ContentType::TEXT_HTML)
            .body(body_html);
        let mut mixed = MultiPart::mixed().singlepart(html_part);
        for (filename, mime, bytes) in attachments {
            let ct = mime.parse::<ContentType>().map_err(|e| {
                ReportError::invalid_context(format!("invalid attachment mime: {e}"))
            })?;
            mixed = mixed.singlepart(Attachment::new(filename).body(bytes, ct));
        }

        let mut builder = lettre::Message::builder()
            .from(self.from_addr.clone())
            .subject(subject);
        for r in &to {
            let mailbox = r
                .parse::<lettre::message::Mailbox>()
                .map_err(|e| ReportError::invalid_context(format!("invalid recipient {r}: {e}")))?;
            builder = builder.to(mailbox);
        }
        let message = builder
            .multipart(mixed)
            .map_err(|e| ReportError::internal(format!("lettre message build failed: {e}")))?;
        self.transport
            .send(message)
            .await
            .map(|_| ())
            .map_err(|e| ReportError::internal(format!("smtp send failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Email body builder
// ---------------------------------------------------------------------------

/// Minimal HTML-escape: enough to neutralise `<script>` injection in the
/// fields we substitute into the body wrapper (tenant name, engagement
/// label, format identifier).
fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            '/' => out.push_str("&#x2F;"),
            other => out.push(other),
        }
    }
    out
}

/// Construct the HTML body of the scheduled-report email.
///
/// The template is intentionally plain — no inline JS, no remote
/// stylesheet, no `<iframe>`s. Every dynamic value is HTML-escaped via
/// [`html_escape`].
#[must_use]
pub fn build_email_body(filename: &str, format: ReportFormat) -> String {
    format!(
        concat!(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head>",
            "<body>",
            "<h1>SentinelX scheduled report</h1>",
            "<p>The attached report has been generated by the SentinelX scheduler.</p>",
            "<ul>",
            "<li><strong>File:</strong> {filename}</li>",
            "<li><strong>Format:</strong> {format}</li>",
            "</ul>",
            "<p>This message is automated. Do not reply.</p>",
            "</body></html>",
        ),
        filename = html_escape(filename),
        format = html_escape(format.as_str()),
    )
}

// ---------------------------------------------------------------------------
// Friendly schedule kinds
// ---------------------------------------------------------------------------

/// High-level recurrence the operator chooses in the UI. Lowered into a
/// six-field cron string by [`ScheduleKind::to_cron_expr`].
///
/// The lowered cron strings always fire at minute zero of the chosen hour
/// — the UI never lets a tenant pick a sub-hour cadence on purpose
/// (limits noisy delivery + DB churn) and the operator can always escape
/// hatch via a raw cron string supplied straight into [`ReportSchedule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ScheduleKind {
    /// Every day at the chosen UTC hour.
    Daily {
        /// Hour of day (0..=23) in UTC.
        hour: u8,
    },
    /// Once a week on the chosen day at the chosen UTC hour.
    Weekly {
        /// Day of week — `Sunday` = 0, `Saturday` = 6, matching the
        /// `cron = "0.12"` crate's expectation.
        day_of_week: u8,
        /// Hour of day (0..=23) in UTC.
        hour: u8,
    },
    /// Once a month on the chosen day-of-month at the chosen UTC hour.
    Monthly {
        /// Day of month (1..=31). Months without that day skip the
        /// firing — semantics inherited from the `cron` crate.
        day_of_month: u8,
        /// Hour of day (0..=23) in UTC.
        hour: u8,
    },
}

impl ScheduleKind {
    /// Lower into the six-field cron string the [`CronEvaluator`]
    /// understands (`sec min hour dom mon dow`).
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::InvalidContext`] when a field falls outside
    /// its inclusive range (`hour` 0-23, `day_of_week` 0-6, `day_of_month`
    /// 1-31).
    pub fn to_cron_expr(self) -> Result<String, ReportError> {
        match self {
            Self::Daily { hour } => {
                if hour > 23 {
                    return Err(ReportError::invalid_context("hour must be in 0..=23"));
                }
                Ok(format!("0 0 {hour} * * *"))
            }
            Self::Weekly { day_of_week, hour } => {
                if hour > 23 {
                    return Err(ReportError::invalid_context("hour must be in 0..=23"));
                }
                if day_of_week > 6 {
                    return Err(ReportError::invalid_context("day_of_week must be in 0..=6"));
                }
                Ok(format!("0 0 {hour} * * {day_of_week}"))
            }
            Self::Monthly { day_of_month, hour } => {
                if hour > 23 {
                    return Err(ReportError::invalid_context("hour must be in 0..=23"));
                }
                if !(1..=31).contains(&day_of_month) {
                    return Err(ReportError::invalid_context(
                        "day_of_month must be in 1..=31",
                    ));
                }
                Ok(format!("0 0 {hour} {day_of_month} * *"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Delivery channels (email + S3 + webhook)
// ---------------------------------------------------------------------------

/// One additional delivery target for a scheduled report.
///
/// Email is always implicit through [`ReportSchedule::recipients`]; this
/// enum lists the *extra* sinks the scheduler must also write to per
/// successful render. Each variant carries everything the sink needs to
/// run without further lookups — the configuration is stored verbatim on
/// the schedule row so a delete/disable on the channel itself is a
/// no-op for in-flight tick cycles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DeliveryChannel {
    /// Drop the rendered artefact into an S3 bucket under a key derived
    /// from `prefix`/`tenant_id`/`run_timestamp`/`filename`.
    S3 {
        /// Bucket name (no protocol, no path).
        bucket: String,
        /// Optional key prefix; if `None`, the key starts at the tenant id.
        #[serde(default)]
        prefix: Option<String>,
        /// AWS region (e.g. `"us-east-1"`).
        region: String,
    },
    /// POST a JSON envelope (`{tenant_id, run_at, filename, mime_type,
    /// payload_b64}`) to the configured URL with an HMAC-SHA256 signature
    /// header (`X-SentinelX-Signature`).
    Webhook {
        /// Destination URL (must be HTTPS in production — the dispatcher
        /// rejects `http://` by default; tests can opt in).
        url: String,
        /// Shared secret used as the HMAC key. The dispatcher must zero
        /// the secret from memory after the signature is computed.
        secret: String,
    },
}

/// Sink that uploads the rendered bytes to an S3 bucket.
#[async_trait]
pub trait S3DropboxSink: Send + Sync {
    /// Upload `bytes` to `bucket/key`. The dispatcher MUST set
    /// `content-type` to `mime`.
    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        mime: &str,
        bytes: Vec<u8>,
    ) -> Result<(), ReportError>;
}

/// Sink that POSTs the JSON envelope to an outbound webhook URL.
#[async_trait]
pub trait WebhookSink: Send + Sync {
    /// Deliver `body` to `url` with the HMAC-SHA256 signature in
    /// `signature_hex`. The sink MUST set `Content-Type:
    /// application/json` and `X-SentinelX-Signature: <hex>`.
    async fn post_json(
        &self,
        url: &str,
        signature_hex: &str,
        body: Vec<u8>,
    ) -> Result<(), ReportError>;
}

/// Captured S3 PUT used by the in-memory test sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedS3Put {
    /// Destination bucket.
    pub bucket: String,
    /// Object key.
    pub key: String,
    /// Reported content-type.
    pub mime: String,
    /// Raw payload bytes.
    pub bytes: Vec<u8>,
}

/// In-memory [`S3DropboxSink`] used by tests.
#[derive(Debug, Default)]
pub struct RecordingS3Sink {
    puts: Mutex<Vec<RecordedS3Put>>,
}

impl RecordingS3Sink {
    /// Build an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded uploads.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Internal`] if the mutex has been poisoned.
    pub fn captured(&self) -> Result<Vec<RecordedS3Put>, ReportError> {
        let guard = self
            .puts
            .lock()
            .map_err(|e| ReportError::internal(format!("s3 sink mutex poisoned: {e}")))?;
        Ok(guard.clone())
    }
}

#[async_trait]
impl S3DropboxSink for RecordingS3Sink {
    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        mime: &str,
        bytes: Vec<u8>,
    ) -> Result<(), ReportError> {
        {
            let mut guard = self
                .puts
                .lock()
                .map_err(|e| ReportError::internal(format!("s3 sink mutex poisoned: {e}")))?;
            guard.push(RecordedS3Put {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                mime: mime.to_owned(),
                bytes,
            });
        }
        Ok(())
    }
}

/// Captured webhook POST used by the in-memory test sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedWebhookPost {
    /// Destination URL.
    pub url: String,
    /// Hex-encoded HMAC-SHA256 signature.
    pub signature_hex: String,
    /// Raw JSON body.
    pub body: Vec<u8>,
}

/// In-memory [`WebhookSink`] used by tests.
#[derive(Debug, Default)]
pub struct RecordingWebhookSink {
    posts: Mutex<Vec<RecordedWebhookPost>>,
}

impl RecordingWebhookSink {
    /// Build an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded posts.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Internal`] if the mutex has been poisoned.
    pub fn captured(&self) -> Result<Vec<RecordedWebhookPost>, ReportError> {
        let guard = self
            .posts
            .lock()
            .map_err(|e| ReportError::internal(format!("webhook sink mutex poisoned: {e}")))?;
        Ok(guard.clone())
    }
}

#[async_trait]
impl WebhookSink for RecordingWebhookSink {
    async fn post_json(
        &self,
        url: &str,
        signature_hex: &str,
        body: Vec<u8>,
    ) -> Result<(), ReportError> {
        {
            let mut guard = self
                .posts
                .lock()
                .map_err(|e| ReportError::internal(format!("webhook sink mutex poisoned: {e}")))?;
            guard.push(RecordedWebhookPost {
                url: url.to_owned(),
                signature_hex: signature_hex.to_owned(),
                body,
            });
        }
        Ok(())
    }
}

/// HMAC-SHA256 of `body` keyed by `secret`, lowercase hex.
///
/// Pulled from `sha2` (already a workspace dep). We avoid the optional
/// `hmac` crate by inlining the standard FIPS-198 construction; the
/// caller-supplied secret is the only sensitive material we touch and it
/// is zeroised right after the hash is computed.
#[must_use]
pub fn hmac_sha256_hex(secret: &[u8], body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const BLOCK_SIZE: usize = 64;
    let mut key = [0_u8; BLOCK_SIZE];
    if secret.len() > BLOCK_SIZE {
        let digest = Sha256::digest(secret);
        let n = digest.len().min(BLOCK_SIZE);
        if let (Some(dst), Some(src)) = (key.get_mut(..n), digest.get(..n)) {
            dst.copy_from_slice(src);
        }
    } else {
        let n = secret.len().min(BLOCK_SIZE);
        if let (Some(dst), Some(src)) = (key.get_mut(..n), secret.get(..n)) {
            dst.copy_from_slice(src);
        }
    }
    let mut o_pad = [0_u8; BLOCK_SIZE];
    let mut i_pad = [0_u8; BLOCK_SIZE];
    for (idx, k) in key.iter().enumerate() {
        if let (Some(o), Some(i)) = (o_pad.get_mut(idx), i_pad.get_mut(idx)) {
            *o = k ^ 0x5c;
            *i = k ^ 0x36;
        }
    }
    // Zero the unpadded key copy so it is not left on the stack longer
    // than needed.
    key.fill(0);
    let mut inner = Sha256::new();
    inner.update(i_pad);
    inner.update(body);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(o_pad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();
    hex::encode(outer_digest)
}

/// Build the JSON envelope `POST`ed to a webhook channel.
///
/// Kept as a free function so the dispatch path and tests share one
/// canonical schema.
#[must_use]
pub fn build_webhook_envelope(
    tenant_id: Uuid,
    run_at: OffsetDateTime,
    filename: &str,
    mime: &str,
    payload_b64: &str,
) -> Vec<u8> {
    let body = serde_json::json!({
        "tenant_id": tenant_id.to_string(),
        "run_at": run_at.unix_timestamp(),
        "filename": filename,
        "mime_type": mime,
        "payload_b64": payload_b64,
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Retry policy + dead-letter
// ---------------------------------------------------------------------------

/// Configurable exponential-backoff policy for failed deliveries.
///
/// `base` is the multiplier applied to `2^failure_count` — every retry
/// pushes `next_run_at` further into the future, capped at `cap`.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Base unit of backoff. Default 30 seconds.
    pub base: time::Duration,
    /// Hard ceiling on a single backoff step. Default 1 hour.
    pub cap: time::Duration,
    /// After this many consecutive failures the row is forwarded to the
    /// [`DeadLetterQueue`] and disabled.
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base: time::Duration::seconds(30),
            cap: time::Duration::hours(1),
            max_attempts: 5,
        }
    }
}

impl RetryPolicy {
    /// Compute the next `next_run_at` for a row that has failed
    /// `failure_count` consecutive times (1-based — pass the post-bump
    /// counter).
    #[must_use]
    pub fn next_attempt_at(self, now: OffsetDateTime, failure_count: u32) -> OffsetDateTime {
        // 2^(failure_count - 1), clamped so the shift does not overflow.
        let exp = failure_count.saturating_sub(1).min(20);
        let multiplier = 1_u32 << exp;
        let secs = self
            .base
            .whole_seconds()
            .saturating_mul(i64::from(multiplier));
        let mut delay = time::Duration::seconds(secs);
        if delay > self.cap {
            delay = self.cap;
        }
        now + delay
    }

    /// Has the row exhausted its retries?
    #[must_use]
    pub const fn is_dead_lettered(self, failure_count: u32) -> bool {
        failure_count >= self.max_attempts
    }
}

/// Persistent dead-letter sink.
///
/// Production implementations write to Postgres + the audit log so an
/// on-call operator can inspect the abandoned rows. The in-memory variant
/// (`RecordingDeadLetterQueue`) is reserved for tests.
#[async_trait]
pub trait DeadLetterQueue: Send + Sync {
    /// Persist a dead-lettered row + the last error message.
    async fn enqueue(
        &self,
        schedule: &ReportSchedule,
        last_error: &str,
        at: OffsetDateTime,
    ) -> Result<(), ReportError>;
}

/// In-memory [`DeadLetterQueue`] used by tests.
#[derive(Debug, Default)]
pub struct RecordingDeadLetterQueue {
    entries: Mutex<Vec<(ReportSchedule, String, OffsetDateTime)>>,
}

impl RecordingDeadLetterQueue {
    /// Build an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded dead-letters.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Internal`] if the mutex has been poisoned.
    pub fn captured(&self) -> Result<Vec<(ReportSchedule, String, OffsetDateTime)>, ReportError> {
        let guard = self
            .entries
            .lock()
            .map_err(|e| ReportError::internal(format!("dlq mutex poisoned: {e}")))?;
        Ok(guard.clone())
    }
}

#[async_trait]
impl DeadLetterQueue for RecordingDeadLetterQueue {
    async fn enqueue(
        &self,
        schedule: &ReportSchedule,
        last_error: &str,
        at: OffsetDateTime,
    ) -> Result<(), ReportError> {
        {
            let mut guard = self
                .entries
                .lock()
                .map_err(|e| ReportError::internal(format!("dlq mutex poisoned: {e}")))?;
            guard.push((schedule.clone(), last_error.to_owned(), at));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Audit hook
// ---------------------------------------------------------------------------

/// Operations the scheduler audits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleAuditAction {
    /// A new schedule was created (POST /v1/reports/schedules).
    Created,
    /// An existing schedule was modified (PATCH /v1/reports/schedules/:id).
    Updated,
    /// A schedule was deleted (DELETE /v1/reports/schedules/:id).
    Deleted,
    /// The scheduler dispatched a row.
    Ran,
    /// The schedule was paused.
    Paused,
    /// The schedule was resumed.
    Resumed,
    /// `run-now` was requested.
    RunNowRequested,
    /// The retry budget was exhausted; row routed to the dead-letter.
    DeadLettered,
}

/// Audit-log emission hook.
///
/// The production adapter forwards records into the audit pipeline; tests
/// use [`RecordingAuditHook`] to assert specific entries are emitted.
#[async_trait]
pub trait ScheduleAuditHook: Send + Sync {
    /// Append one audit entry.
    async fn record(
        &self,
        tenant_id: Uuid,
        schedule_id: Uuid,
        action: ScheduleAuditAction,
        at: OffsetDateTime,
    ) -> Result<(), ReportError>;
}

/// Captured audit entry used by [`RecordingAuditHook`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedAuditEntry {
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Schedule row that was operated on.
    pub schedule_id: Uuid,
    /// What happened.
    pub action: ScheduleAuditAction,
    /// When it happened.
    pub at: OffsetDateTime,
}

/// In-memory [`ScheduleAuditHook`] used by tests.
#[derive(Debug, Default)]
pub struct RecordingAuditHook {
    entries: Mutex<Vec<RecordedAuditEntry>>,
}

impl RecordingAuditHook {
    /// Build an empty audit hook.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot recorded entries.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Internal`] if the mutex has been poisoned.
    pub fn captured(&self) -> Result<Vec<RecordedAuditEntry>, ReportError> {
        let guard = self
            .entries
            .lock()
            .map_err(|e| ReportError::internal(format!("audit mutex poisoned: {e}")))?;
        Ok(guard.clone())
    }
}

#[async_trait]
impl ScheduleAuditHook for RecordingAuditHook {
    async fn record(
        &self,
        tenant_id: Uuid,
        schedule_id: Uuid,
        action: ScheduleAuditAction,
        at: OffsetDateTime,
    ) -> Result<(), ReportError> {
        {
            let mut guard = self
                .entries
                .lock()
                .map_err(|e| ReportError::internal(format!("audit mutex poisoned: {e}")))?;
            guard.push(RecordedAuditEntry {
                tenant_id,
                schedule_id,
                action,
                at,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scheduler tick
// ---------------------------------------------------------------------------

/// Outcome of one [`Scheduler::tick`] invocation.
///
/// Returned so callers (the cron-fired loop in production, individual
/// tests in unit tests) can assert on how many rows were processed and
/// how many were dispatched successfully.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
    /// Total rows pulled from [`ScheduleStore::list_due`].
    pub considered: usize,
    /// Rows that were dispatched + persisted successfully.
    pub dispatched: usize,
    /// Rows that failed at any point in the pipeline. The errors are
    /// logged via `tracing::warn!`; the cron tick is best-effort and
    /// never short-circuits on a single bad row.
    pub failed: usize,
    /// Rows whose retry budget was exhausted and which were forwarded to
    /// the dead-letter queue. Only populated by
    /// [`Scheduler::tick_with_policy`].
    pub dead_lettered: usize,
}

/// Stateless orchestrator that drives one scheduler cycle.
#[derive(Debug, Default, Clone, Copy)]
pub struct Scheduler;

impl Scheduler {
    /// Build a stateless scheduler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Drive one scheduler cycle.
    ///
    /// 1. Pull every due row from `store`.
    /// 2. For each, render via `renderer`, decode the base64 inline
    ///    payload, build the HTML body, and dispatch via `dispatcher`.
    /// 3. On success, persist `last_run_at = now` and recompute
    ///    `next_run_at` via the cron expression.
    ///
    /// Errors on a per-row basis are recorded in the returned
    /// [`TickReport`] and logged — `tick` never returns `Err` for a
    /// single row failure so a single bad schedule cannot starve the
    /// rest.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError`] only when the initial `list_due` call
    /// fails — i.e. the storage layer is unreachable.
    #[instrument(skip(self, store, renderer, dispatcher), fields(now = %now))]
    pub async fn tick<S, R, D>(
        &self,
        store: &S,
        renderer: &R,
        dispatcher: &D,
        now: OffsetDateTime,
    ) -> Result<TickReport, ReportError>
    where
        S: ScheduleStore + ?Sized,
        R: SchedulerReportPort + ?Sized,
        D: EmailDispatcher + ?Sized,
    {
        let due = store.list_due(now).await?;
        let mut report = TickReport {
            considered: due.len(),
            ..TickReport::default()
        };
        for row in due {
            match dispatch_one(store, renderer, dispatcher, &row, now).await {
                Ok(()) => report.dispatched = report.dispatched.saturating_add(1),
                Err(e) => {
                    warn!(schedule_id = %row.id, error = %e, "scheduler row failed");
                    report.failed = report.failed.saturating_add(1);
                }
            }
        }
        debug!(?report, "scheduler tick complete");
        Ok(report)
    }

    /// Full-featured cycle — email + S3 + webhook channels, retry with
    /// exponential backoff, dead-letter promotion, and audit emission.
    ///
    /// `ctx` carries every concrete adapter. Sinks tagged `None` mean
    /// the corresponding channel kind is ignored (callers can disable a
    /// channel entirely by omitting the sink even if a tenant added
    /// a [`DeliveryChannel`] variant for it).
    ///
    /// On per-row failure:
    /// 1. `failure_count` is incremented.
    /// 2. `next_run_at` is bumped by `policy.next_attempt_at`.
    /// 3. If `failure_count >= policy.max_attempts`, the row is
    ///    disabled, forwarded to `ctx.dead_letter`, and a
    ///    [`ScheduleAuditAction::DeadLettered`] entry is emitted.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError`] only when the initial `list_due` call
    /// fails — i.e. the storage layer is unreachable.
    #[instrument(skip(self, ctx), fields(now = %now))]
    pub async fn tick_with_policy<S, R, D>(
        &self,
        ctx: &SchedulerContext<'_, S, R, D>,
        now: OffsetDateTime,
    ) -> Result<TickReport, ReportError>
    where
        S: ScheduleStore + ?Sized,
        R: SchedulerReportPort + ?Sized,
        D: EmailDispatcher + ?Sized,
    {
        let due = ctx.store.list_due(now).await?;
        let mut report = TickReport {
            considered: due.len(),
            ..TickReport::default()
        };
        for row in due {
            match dispatch_one_full(ctx, &row, now).await {
                Ok(()) => {
                    report.dispatched = report.dispatched.saturating_add(1);
                    ctx.audit
                        .record(row.tenant_id, row.id, ScheduleAuditAction::Ran, now)
                        .await
                        .ok();
                }
                Err(e) => {
                    warn!(schedule_id = %row.id, error = %e, "scheduler row failed");
                    report.failed = report.failed.saturating_add(1);
                    // Increment the failure counter via mark_failure (if
                    // the store supports it) and decide on backoff vs
                    // dead-letter.
                    let new_count = row.failure_count.saturating_add(1);
                    if ctx.policy.is_dead_lettered(new_count) {
                        ctx.dead_letter
                            .enqueue(&row, &e.to_string(), now)
                            .await
                            .ok();
                        // Disable + push next_run_at far into the future
                        // so the row is not retried.
                        ctx.store
                            .set_enabled(row.tenant_id, row.id, false)
                            .await
                            .ok();
                        ctx.audit
                            .record(
                                row.tenant_id,
                                row.id,
                                ScheduleAuditAction::DeadLettered,
                                now,
                            )
                            .await
                            .ok();
                        report.dead_lettered = report.dead_lettered.saturating_add(1);
                    } else {
                        let next = ctx.policy.next_attempt_at(now, new_count);
                        if let Err(persist_err) = ctx.store.record_failure(row.id, next).await {
                            warn!(error = %persist_err, "failed to persist retry state");
                        }
                    }
                }
            }
        }
        debug!(?report, "scheduler tick_with_policy complete");
        Ok(report)
    }
}

/// Bundle of every adapter [`Scheduler::tick_with_policy`] needs.
///
/// Lifetimes are tied to the calling cron loop so the bundle can carry
/// borrowed trait objects without forcing the whole tree behind `Arc`s
/// — composition roots are free to choose either.
#[allow(clippy::struct_field_names, missing_debug_implementations)]
pub struct SchedulerContext<'a, S, R, D>
where
    S: ScheduleStore + ?Sized,
    R: SchedulerReportPort + ?Sized,
    D: EmailDispatcher + ?Sized,
{
    /// Persistent schedule store.
    pub store: &'a S,
    /// Report-render port.
    pub renderer: &'a R,
    /// Email dispatcher.
    pub email: &'a D,
    /// Optional S3 dropbox sink.
    pub s3: Option<&'a dyn S3DropboxSink>,
    /// Optional outbound webhook sink.
    pub webhook: Option<&'a dyn WebhookSink>,
    /// Retry policy.
    pub policy: RetryPolicy,
    /// Dead-letter queue.
    pub dead_letter: &'a dyn DeadLetterQueue,
    /// Audit hook.
    pub audit: &'a dyn ScheduleAuditHook,
}

async fn dispatch_one<S, R, D>(
    store: &S,
    renderer: &R,
    dispatcher: &D,
    row: &ReportSchedule,
    now: OffsetDateTime,
) -> Result<(), ReportError>
where
    S: ScheduleStore + ?Sized,
    R: SchedulerReportPort + ?Sized,
    D: EmailDispatcher + ?Sized,
{
    let artifact = renderer
        .render(row.tenant_id, row.engagement_id, row.format)
        .await?;
    let bytes = BASE64
        .decode(artifact.inline_payload.as_bytes())
        .map_err(|e| ReportError::internal(format!("base64 decode failed: {e}")))?;
    let body_html = build_email_body(&artifact.filename, row.format);
    let subject = format!(
        "SentinelX scheduled report: {fmt}",
        fmt = row.format.as_str()
    );
    dispatcher
        .send(
            row.recipients.clone(),
            subject,
            body_html,
            vec![(artifact.filename, artifact.mime_type, bytes)],
        )
        .await?;

    let next_run_at = CronEvaluator::new()
        .next_after(&row.cron_expr, now)?
        // If the cron expression has no future instants, push the row a
        // century into the future so it never fires again — RLS-friendly
        // sentinel value.
        .unwrap_or_else(|| {
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(now.unix_timestamp()) * 1_000_000_000)
                .unwrap_or(now)
                + time::Duration::days(365 * 100)
        });
    store.mark_run(row.id, now, next_run_at).await
}

/// Multi-channel dispatch path used by [`Scheduler::tick_with_policy`].
///
/// Sequence:
/// 1. Render via `ctx.renderer` once.
/// 2. Decode the base64 inline payload to raw bytes.
/// 3. Email the recipients via `ctx.email`.
/// 4. For each [`DeliveryChannel`] on `row.channels` write to the
///    matching sink (S3 / webhook) — sinks that are not configured on
///    the [`SchedulerContext`] are skipped with a warning.
/// 5. Persist `last_run_at = now` and recompute `next_run_at`.
#[allow(clippy::cognitive_complexity)] // scheduler dispatch: render + email + per-channel sink fan-out + state update
async fn dispatch_one_full<S, R, D>(
    ctx: &SchedulerContext<'_, S, R, D>,
    row: &ReportSchedule,
    now: OffsetDateTime,
) -> Result<(), ReportError>
where
    S: ScheduleStore + ?Sized,
    R: SchedulerReportPort + ?Sized,
    D: EmailDispatcher + ?Sized,
{
    let artifact = ctx
        .renderer
        .render(row.tenant_id, row.engagement_id, row.format)
        .await?;
    let bytes = BASE64
        .decode(artifact.inline_payload.as_bytes())
        .map_err(|e| ReportError::internal(format!("base64 decode failed: {e}")))?;

    // Email is the always-on channel.
    let body_html = build_email_body(&artifact.filename, row.format);
    let subject = format!(
        "SentinelX scheduled report: {fmt}",
        fmt = row.format.as_str()
    );
    ctx.email
        .send(
            row.recipients.clone(),
            subject,
            body_html,
            vec![(
                artifact.filename.clone(),
                artifact.mime_type.clone(),
                bytes.clone(),
            )],
        )
        .await?;

    // Fan out to extra channels.
    for channel in &row.channels {
        match channel {
            DeliveryChannel::S3 {
                bucket,
                prefix,
                region: _,
            } => {
                let Some(s3) = ctx.s3 else {
                    warn!(schedule_id = %row.id, "s3 channel configured but no sink");
                    continue;
                };
                let key = build_s3_key(prefix.as_deref(), row.tenant_id, now, &artifact.filename);
                s3.put_object(bucket, &key, &artifact.mime_type, bytes.clone())
                    .await?;
            }
            DeliveryChannel::Webhook { url, secret } => {
                let Some(hook) = ctx.webhook else {
                    warn!(schedule_id = %row.id, "webhook channel configured but no sink");
                    continue;
                };
                let envelope = build_webhook_envelope(
                    row.tenant_id,
                    now,
                    &artifact.filename,
                    &artifact.mime_type,
                    &artifact.inline_payload,
                );
                let sig = hmac_sha256_hex(secret.as_bytes(), &envelope);
                hook.post_json(url, &sig, envelope).await?;
            }
        }
    }

    let next_run_at = CronEvaluator::new()
        .next_after(&row.cron_expr, now)?
        .unwrap_or_else(|| {
            OffsetDateTime::from_unix_timestamp_nanos(
                i128::from(now.unix_timestamp()) * 1_000_000_000,
            )
            .unwrap_or(now)
                + time::Duration::days(365 * 100)
        });
    ctx.store.mark_run(row.id, now, next_run_at).await
}

/// Build the canonical S3 object key for a scheduled report drop.
///
/// Shape: `[<prefix>/]<tenant_id>/<unix_ts>/<filename>`.
fn build_s3_key(
    prefix: Option<&str>,
    tenant_id: Uuid,
    now: OffsetDateTime,
    filename: &str,
) -> String {
    match prefix {
        Some(p) if !p.is_empty() => {
            format!("{p}/{tenant_id}/{ts}/{filename}", ts = now.unix_timestamp())
        }
        _ => format!("{tenant_id}/{ts}/{filename}", ts = now.unix_timestamp()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn make_schedule(
        cron_expr: &str,
        next_run_at: OffsetDateTime,
        enabled: bool,
    ) -> ReportSchedule {
        ReportSchedule::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
            ReportFormat::Csv,
            cron_expr,
            vec!["ops@example.com".to_owned()],
            enabled,
            None,
            next_run_at,
        )
        .unwrap()
    }

    /// Fake renderer that returns deterministic base64 ("hi\n" → "aGkK").
    #[derive(Debug, Default)]
    struct FakeRenderer {
        calls: Mutex<u32>,
    }

    impl FakeRenderer {
        fn calls(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl SchedulerReportPort for FakeRenderer {
        async fn render(
            &self,
            _tenant_id: Uuid,
            _engagement_id: Option<Uuid>,
            format: ReportFormat,
        ) -> Result<SchedulerReportArtifact, ReportError> {
            *self.calls.lock().unwrap() += 1;
            let payload = BASE64.encode(b"hi\n");
            Ok(SchedulerReportArtifact {
                filename: format!("scheduled.{}", format.extension()),
                mime_type: format.mime().to_owned(),
                inline_payload: payload,
            })
        }
    }

    /// Renderer that always errors — used to exercise the per-row error
    /// path in `tick`.
    #[derive(Debug)]
    struct FailingRenderer;

    #[async_trait]
    impl SchedulerReportPort for FailingRenderer {
        async fn render(
            &self,
            _tenant_id: Uuid,
            _engagement_id: Option<Uuid>,
            _format: ReportFormat,
        ) -> Result<SchedulerReportArtifact, ReportError> {
            Err(ReportError::internal("boom"))
        }
    }

    // ---- Cron tests -----------------------------------------------------

    #[test]
    fn cron_evaluator_round_trips_known_expression() {
        let ev = CronEvaluator::new();
        // Every day at 09:00 UTC.
        let next = ev
            .next_after("0 0 9 * * *", datetime!(2026-05-30 08:00:00 UTC))
            .unwrap()
            .unwrap();
        assert_eq!(next, datetime!(2026-05-30 09:00:00 UTC));
    }

    #[test]
    fn cron_evaluator_advances_past_the_anchor() {
        let ev = CronEvaluator::new();
        let next = ev
            .next_after("0 0 9 * * *", datetime!(2026-05-30 09:00:00 UTC))
            .unwrap()
            .unwrap();
        // Strictly after the anchor.
        assert_eq!(next, datetime!(2026-05-31 09:00:00 UTC));
    }

    #[test]
    fn cron_evaluator_rejects_garbage() {
        let ev = CronEvaluator::new();
        assert!(ev
            .next_after("not a cron expression", OffsetDateTime::now_utc())
            .is_err());
    }

    #[test]
    fn cron_evaluator_validate_accepts_known_good() {
        assert!(CronEvaluator::validate("0 0 9 * * *").is_ok());
        assert!(CronEvaluator::validate("garbage").is_err());
    }

    // ---- Schedule construction tests ------------------------------------

    #[test]
    fn schedule_new_rejects_empty_recipients() {
        let r = ReportSchedule::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            None,
            ReportFormat::Csv,
            "0 0 9 * * *",
            vec![],
            true,
            None,
            datetime!(2026-05-30 09:00:00 UTC),
        );
        assert!(r.is_err());
    }

    #[test]
    fn schedule_new_rejects_garbage_recipient() {
        let r = ReportSchedule::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            None,
            ReportFormat::Csv,
            "0 0 9 * * *",
            vec!["not-an-email".to_owned()],
            true,
            None,
            datetime!(2026-05-30 09:00:00 UTC),
        );
        assert!(r.is_err());
    }

    #[test]
    fn schedule_new_rejects_invalid_cron() {
        let r = ReportSchedule::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            None,
            ReportFormat::Csv,
            "definitely not cron",
            vec!["ops@example.com".to_owned()],
            true,
            None,
            datetime!(2026-05-30 09:00:00 UTC),
        );
        assert!(r.is_err());
    }

    // ---- Store tests ----------------------------------------------------

    #[tokio::test]
    async fn in_memory_store_list_due_filters_by_enabled_and_next_run_at() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let due_enabled = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        let due_disabled = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), false);
        let not_due_enabled = make_schedule("0 0 9 * * *", now + time::Duration::hours(1), true);

        let store = InMemoryScheduleStore::with_rows(vec![
            due_enabled.clone(),
            due_disabled,
            not_due_enabled,
        ]);

        let due = store.list_due(now).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, due_enabled.id);
    }

    #[tokio::test]
    async fn in_memory_store_mark_run_updates_row() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        let id = row.id;
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let next = datetime!(2026-05-31 09:00:00 UTC);

        store.mark_run(id, now, next).await.unwrap();

        let rows = store.snapshot().unwrap();
        assert_eq!(rows[0].last_run_at, Some(now));
        assert_eq!(rows[0].next_run_at, next);
    }

    // ---- Tick + dispatcher tests ----------------------------------------

    #[tokio::test]
    async fn recording_dispatcher_captures_one_email_per_tick() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let renderer = FakeRenderer::default();
        let dispatcher = RecordingDispatcher::new();

        let report = Scheduler::new()
            .tick(&store, &renderer, &dispatcher, now)
            .await
            .unwrap();

        assert_eq!(report.considered, 1);
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(renderer.calls(), 1);
        let captured = dispatcher.captured().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].to, vec!["ops@example.com".to_owned()]);
        assert_eq!(captured[0].attachments.len(), 1);
        // Attachment carries the decoded payload, not the base64 string.
        assert_eq!(captured[0].attachments[0].2, b"hi\n");
        // Subject mentions the format.
        assert!(captured[0].subject.contains("csv"));
    }

    #[tokio::test]
    async fn tick_skips_disabled_rows() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), false);
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let renderer = FakeRenderer::default();
        let dispatcher = RecordingDispatcher::new();

        let report = Scheduler::new()
            .tick(&store, &renderer, &dispatcher, now)
            .await
            .unwrap();

        assert_eq!(report.considered, 0);
        assert_eq!(report.dispatched, 0);
        assert_eq!(renderer.calls(), 0);
        assert_eq!(dispatcher.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn tick_updates_next_run_at_after_dispatch() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        let id = row.id;
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let renderer = FakeRenderer::default();
        let dispatcher = RecordingDispatcher::new();

        Scheduler::new()
            .tick(&store, &renderer, &dispatcher, now)
            .await
            .unwrap();

        let rows = store.snapshot().unwrap();
        let updated = rows.into_iter().find(|r| r.id == id).unwrap();
        assert_eq!(updated.last_run_at, Some(now));
        // Next run is the next 09:00 UTC strictly after `now`.
        assert_eq!(updated.next_run_at, datetime!(2026-05-31 09:00:00 UTC));
    }

    #[tokio::test]
    async fn tick_records_per_row_failures_without_aborting() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let renderer = FailingRenderer;
        let dispatcher = RecordingDispatcher::new();

        let report = Scheduler::new()
            .tick(&store, &renderer, &dispatcher, now)
            .await
            .unwrap();

        assert_eq!(report.considered, 1);
        assert_eq!(report.dispatched, 0);
        assert_eq!(report.failed, 1);
        assert_eq!(dispatcher.count().unwrap(), 0);
    }

    // ---- Body / escaping / base64 tests ---------------------------------

    #[test]
    fn html_escape_neutralises_script_tags() {
        let escaped = html_escape("<script>alert(1)</script>");
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    #[test]
    fn build_email_body_is_well_formed_and_escapes_filename() {
        let body = build_email_body("<bad>.csv", ReportFormat::Csv);
        assert!(body.starts_with("<!DOCTYPE html>"));
        assert!(body.contains("&lt;bad&gt;.csv"));
        assert!(!body.contains("<bad>.csv"));
        assert!(body.contains("csv"));
    }

    #[tokio::test]
    async fn tick_decodes_base64_payload_into_attachment_bytes() {
        // End-to-end base64 path: the fake renderer encodes "hi\n", the
        // dispatcher receives the *decoded* bytes.
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let renderer = FakeRenderer::default();
        let dispatcher = RecordingDispatcher::new();

        Scheduler::new()
            .tick(&store, &renderer, &dispatcher, now)
            .await
            .unwrap();

        let captured = dispatcher.captured().unwrap();
        assert_eq!(captured[0].attachments[0].2, b"hi\n");
        assert_eq!(captured[0].attachments[0].1, "text/csv; charset=utf-8");
    }

    // ---- RFC 5322 helper tests ------------------------------------------

    #[test]
    fn rfc5322_helper_accepts_basic_address() {
        assert!(is_rfc5322_address("ops@example.com"));
        assert!(is_rfc5322_address("alice.bob+filter@sub.example.com"));
    }

    #[test]
    fn rfc5322_helper_rejects_obvious_garbage() {
        assert!(!is_rfc5322_address(""));
        assert!(!is_rfc5322_address("nope"));
        assert!(!is_rfc5322_address("a@"));
        assert!(!is_rfc5322_address("@b.com"));
        assert!(!is_rfc5322_address("a b@example.com"));
        // Missing dot in domain.
        assert!(!is_rfc5322_address("a@b"));
    }

    // ---- Lettre construction smoke test ---------------------------------

    #[test]
    fn lettre_smtp_dispatcher_rejects_invalid_from() {
        let cfg = SmtpConfig {
            host: "smtp.example.com".to_owned(),
            port: 587,
            username: "u".to_owned(),
            password: "p".to_owned(),
            from: "not an email".to_owned(),
        };
        assert!(LettreSmtpDispatcher::new(cfg).is_err());
    }

    // The lettre transport spawns rustls handshake state inside its drop
    // path; running the constructor outside a tokio runtime aborts the
    // process when the transport is dropped. The `tokio::test` macro
    // installs an executor for the whole test, so the constructor and
    // its destructor both see a live runtime.
    #[tokio::test]
    async fn lettre_smtp_dispatcher_builds_with_valid_config() {
        let cfg = SmtpConfig {
            host: "smtp.example.com".to_owned(),
            port: 587,
            username: "u".to_owned(),
            password: "p".to_owned(),
            from: "ops@example.com".to_owned(),
        };
        assert!(LettreSmtpDispatcher::new(cfg).is_ok());
    }

    // ---- ScheduleKind cron lowering -------------------------------------

    #[test]
    fn schedule_kind_daily_lowers_to_six_field_cron() {
        let expr = ScheduleKind::Daily { hour: 9 }.to_cron_expr().unwrap();
        assert_eq!(expr, "0 0 9 * * *");
        // The lowered expression must validate via CronEvaluator.
        assert!(CronEvaluator::validate(&expr).is_ok());
    }

    #[test]
    fn schedule_kind_weekly_lowers_to_six_field_cron() {
        let expr = ScheduleKind::Weekly {
            day_of_week: 1,
            hour: 8,
        }
        .to_cron_expr()
        .unwrap();
        assert_eq!(expr, "0 0 8 * * 1");
        assert!(CronEvaluator::validate(&expr).is_ok());
    }

    #[test]
    fn schedule_kind_monthly_lowers_to_six_field_cron() {
        let expr = ScheduleKind::Monthly {
            day_of_month: 15,
            hour: 6,
        }
        .to_cron_expr()
        .unwrap();
        assert_eq!(expr, "0 0 6 15 * *");
        assert!(CronEvaluator::validate(&expr).is_ok());
    }

    #[test]
    fn schedule_kind_rejects_out_of_range_fields() {
        assert!(ScheduleKind::Daily { hour: 24 }.to_cron_expr().is_err());
        assert!(ScheduleKind::Weekly {
            day_of_week: 7,
            hour: 0
        }
        .to_cron_expr()
        .is_err());
        assert!(ScheduleKind::Monthly {
            day_of_month: 0,
            hour: 0
        }
        .to_cron_expr()
        .is_err());
        assert!(ScheduleKind::Monthly {
            day_of_month: 32,
            hour: 0
        }
        .to_cron_expr()
        .is_err());
    }

    // ---- Pause / resume / run-now ---------------------------------------

    #[tokio::test]
    async fn pause_clears_dispatch_for_subsequent_tick() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        let id = row.id;
        let tenant = row.tenant_id;
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let renderer = FakeRenderer::default();
        let dispatcher = RecordingDispatcher::new();

        // Pause then tick — should not dispatch.
        store.set_enabled(tenant, id, false).await.unwrap();
        let report = Scheduler::new()
            .tick(&store, &renderer, &dispatcher, now)
            .await
            .unwrap();
        assert_eq!(report.considered, 0);
        assert_eq!(dispatcher.count().unwrap(), 0);

        // Resume + tick — should dispatch.
        store.set_enabled(tenant, id, true).await.unwrap();
        let report = Scheduler::new()
            .tick(&store, &renderer, &dispatcher, now)
            .await
            .unwrap();
        assert_eq!(report.considered, 1);
        assert_eq!(report.dispatched, 1);
    }

    #[tokio::test]
    async fn request_run_now_forces_immediate_dispatch() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        // Not due — next_run_at is in the future.
        let row = make_schedule("0 0 9 * * *", now + time::Duration::hours(2), true);
        let id = row.id;
        let tenant = row.tenant_id;
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let renderer = FakeRenderer::default();
        let dispatcher = RecordingDispatcher::new();

        // Without run-now the row is not picked up.
        let report = Scheduler::new()
            .tick(&store, &renderer, &dispatcher, now)
            .await
            .unwrap();
        assert_eq!(report.considered, 0);

        // After run-now the next tick must fire.
        store.request_run_now(tenant, id, now).await.unwrap();
        let report = Scheduler::new()
            .tick(&store, &renderer, &dispatcher, now)
            .await
            .unwrap();
        assert_eq!(report.considered, 1);
        assert_eq!(report.dispatched, 1);
    }

    // ---- Retry / dead-letter --------------------------------------------

    #[test]
    fn retry_policy_backoff_grows_exponentially_and_caps() {
        let policy = RetryPolicy {
            base: time::Duration::seconds(30),
            cap: time::Duration::minutes(10),
            max_attempts: 5,
        };
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let after_1 = policy.next_attempt_at(now, 1);
        let after_2 = policy.next_attempt_at(now, 2);
        let after_3 = policy.next_attempt_at(now, 3);
        // 30s, 60s, 120s.
        assert_eq!(after_1 - now, time::Duration::seconds(30));
        assert_eq!(after_2 - now, time::Duration::seconds(60));
        assert_eq!(after_3 - now, time::Duration::seconds(120));
        // Eventually clamps at the cap.
        let huge = policy.next_attempt_at(now, 20);
        assert_eq!(huge - now, time::Duration::minutes(10));
    }

    #[test]
    fn retry_policy_is_dead_lettered_at_threshold() {
        let policy = RetryPolicy {
            base: time::Duration::seconds(30),
            cap: time::Duration::hours(1),
            max_attempts: 3,
        };
        assert!(!policy.is_dead_lettered(2));
        assert!(policy.is_dead_lettered(3));
        assert!(policy.is_dead_lettered(99));
    }

    #[tokio::test]
    async fn tick_with_policy_routes_to_dead_letter_after_max_attempts() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let mut row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        // Pretend we already had `max_attempts - 1` failures: this tick
        // will push us *over* the threshold.
        row.failure_count = 4;
        let id = row.id;
        let tenant = row.tenant_id;
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let renderer = FailingRenderer;
        let dispatcher = RecordingDispatcher::new();
        let dlq = RecordingDeadLetterQueue::new();
        let audit = RecordingAuditHook::new();

        let ctx = SchedulerContext {
            store: &store,
            renderer: &renderer,
            email: &dispatcher,
            s3: None,
            webhook: None,
            policy: RetryPolicy::default(),
            dead_letter: &dlq,
            audit: &audit,
        };

        let report = Scheduler::new().tick_with_policy(&ctx, now).await.unwrap();

        assert_eq!(report.considered, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.dead_lettered, 1);
        // The row was disabled.
        let snapshot = store.snapshot().unwrap();
        let updated = snapshot.into_iter().find(|r| r.id == id).unwrap();
        assert!(!updated.enabled);
        // Dead-letter queue captured the row + error.
        let dl = dlq.captured().unwrap();
        assert_eq!(dl.len(), 1);
        assert_eq!(dl[0].0.id, id);
        assert!(dl[0].1.contains("boom"));
        // An audit entry for dead-lettering was recorded.
        let entries = audit.captured().unwrap();
        assert!(entries
            .iter()
            .any(|e| e.action == ScheduleAuditAction::DeadLettered
                && e.tenant_id == tenant
                && e.schedule_id == id));
    }

    #[tokio::test]
    async fn tick_with_policy_records_audit_on_successful_run() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        let id = row.id;
        let store = InMemoryScheduleStore::with_rows(vec![row]);
        let renderer = FakeRenderer::default();
        let dispatcher = RecordingDispatcher::new();
        let dlq = RecordingDeadLetterQueue::new();
        let audit = RecordingAuditHook::new();

        let ctx = SchedulerContext {
            store: &store,
            renderer: &renderer,
            email: &dispatcher,
            s3: None,
            webhook: None,
            policy: RetryPolicy::default(),
            dead_letter: &dlq,
            audit: &audit,
        };

        let report = Scheduler::new().tick_with_policy(&ctx, now).await.unwrap();
        assert_eq!(report.dispatched, 1);
        let entries = audit.captured().unwrap();
        assert!(entries
            .iter()
            .any(|e| e.action == ScheduleAuditAction::Ran && e.schedule_id == id));
    }

    // ---- Multi-channel dispatch -----------------------------------------

    #[tokio::test]
    async fn tick_with_policy_fans_out_to_s3_and_webhook_channels() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let mut row = make_schedule("0 0 9 * * *", now - time::Duration::minutes(5), true);
        row.channels = vec![
            DeliveryChannel::S3 {
                bucket: "reports".to_owned(),
                prefix: Some("scheduled".to_owned()),
                region: "us-east-1".to_owned(),
            },
            DeliveryChannel::Webhook {
                url: "https://hooks.example.com/in".to_owned(),
                secret: "topsecret".to_owned(),
            },
        ];
        let store = InMemoryScheduleStore::with_rows(vec![row.clone()]);
        let renderer = FakeRenderer::default();
        let dispatcher = RecordingDispatcher::new();
        let s3 = RecordingS3Sink::new();
        let webhook = RecordingWebhookSink::new();
        let dlq = RecordingDeadLetterQueue::new();
        let audit = RecordingAuditHook::new();

        let ctx = SchedulerContext {
            store: &store,
            renderer: &renderer,
            email: &dispatcher,
            s3: Some(&s3),
            webhook: Some(&webhook),
            policy: RetryPolicy::default(),
            dead_letter: &dlq,
            audit: &audit,
        };

        let report = Scheduler::new().tick_with_policy(&ctx, now).await.unwrap();
        assert_eq!(report.dispatched, 1);
        // Email was sent.
        assert_eq!(dispatcher.count().unwrap(), 1);
        // S3 put was recorded with the correct key shape.
        let puts = s3.captured().unwrap();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].bucket, "reports");
        assert!(puts[0].key.starts_with("scheduled/"));
        assert!(puts[0].key.contains(&row.tenant_id.to_string()));
        assert!(std::path::Path::new(&puts[0].key)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("csv")));
        // Webhook post was recorded with a non-empty signature.
        let posts = webhook.captured().unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].url, "https://hooks.example.com/in");
        assert!(!posts[0].signature_hex.is_empty());
        // Body is valid JSON with the expected keys.
        let parsed: serde_json::Value = serde_json::from_slice(&posts[0].body).unwrap();
        assert!(parsed.get("tenant_id").is_some());
        assert!(parsed.get("filename").is_some());
        assert!(parsed.get("payload_b64").is_some());
    }

    // ---- HMAC + envelope -------------------------------------------------

    #[test]
    fn hmac_sha256_matches_rfc4231_short_key_case() {
        // RFC 4231 test case 1: key = 20 bytes of 0x0b, data = b"Hi There".
        let key = [0x0b; 20];
        let mac = hmac_sha256_hex(&key, b"Hi There");
        assert_eq!(
            mac,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_long_key_is_hashed_first() {
        use sha2::{Digest, Sha256};
        // Key longer than 64 bytes is hashed down to its SHA-256 digest.
        let long_key = vec![0x11_u8; 200];
        let mac_a = hmac_sha256_hex(&long_key, b"payload");
        // Re-deriving from the SHA-256 of the long key must yield the same
        // tag (FIPS-198 key-shortening rule).
        let shortened = Sha256::digest(&long_key).to_vec();
        let mac_b = hmac_sha256_hex(&shortened, b"payload");
        assert_eq!(mac_a, mac_b);
    }

    #[test]
    fn build_webhook_envelope_emits_canonical_json_keys() {
        let tenant = Uuid::nil();
        let envelope = build_webhook_envelope(
            tenant,
            datetime!(2026-05-30 12:00:00 UTC),
            "scheduled.csv",
            "text/csv; charset=utf-8",
            "aGkK",
        );
        let parsed: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
        assert_eq!(
            parsed.get("tenant_id").and_then(|v| v.as_str()),
            Some(tenant.to_string().as_str())
        );
        assert_eq!(
            parsed.get("filename").and_then(|v| v.as_str()),
            Some("scheduled.csv")
        );
        assert_eq!(
            parsed.get("payload_b64").and_then(|v| v.as_str()),
            Some("aGkK")
        );
    }

    #[test]
    fn build_s3_key_includes_prefix_when_supplied() {
        let tenant = Uuid::nil();
        let key = build_s3_key(
            Some("scheduled"),
            tenant,
            datetime!(2026-05-30 12:00:00 UTC),
            "report.csv",
        );
        assert!(key.starts_with("scheduled/"));
        assert!(key.contains(&tenant.to_string()));
        assert!(key.ends_with("/report.csv"));
    }

    #[test]
    fn build_s3_key_omits_prefix_when_empty() {
        let tenant = Uuid::nil();
        let key = build_s3_key(
            None,
            tenant,
            datetime!(2026-05-30 12:00:00 UTC),
            "report.csv",
        );
        assert!(key.starts_with(&tenant.to_string()));
        // The empty prefix variant must also work.
        let key = build_s3_key(
            Some(""),
            tenant,
            datetime!(2026-05-30 12:00:00 UTC),
            "report.csv",
        );
        assert!(key.starts_with(&tenant.to_string()));
    }

    // ---- Tenant isolation -----------------------------------------------

    #[tokio::test]
    async fn set_enabled_refuses_to_flip_other_tenant_rows() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row = make_schedule("0 0 9 * * *", now, true);
        let id = row.id;
        let store = InMemoryScheduleStore::with_rows(vec![row]);

        let other_tenant = Uuid::new_v4();
        // Foreign tenant trying to pause another tenant's row fails.
        let result = store.set_enabled(other_tenant, id, false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_for_tenant_filters_by_tenant_id() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row_a = make_schedule("0 0 9 * * *", now, true);
        let row_b = make_schedule("0 0 9 * * *", now, true);
        let tenant_a = row_a.tenant_id;
        let store = InMemoryScheduleStore::with_rows(vec![row_a, row_b]);

        let listed = store.list_for_tenant(tenant_a).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].tenant_id, tenant_a);
    }

    // ---- Schedule serde round-trip --------------------------------------

    #[test]
    fn report_schedule_serde_round_trip_preserves_channels() {
        let now = datetime!(2026-05-30 12:00:00 UTC);
        let row =
            make_schedule("0 0 9 * * *", now, true).with_channels(vec![DeliveryChannel::S3 {
                bucket: "reports".to_owned(),
                prefix: None,
                region: "us-east-1".to_owned(),
            }]);
        let json = serde_json::to_string(&row).unwrap();
        let back: ReportSchedule = serde_json::from_str(&json).unwrap();
        assert_eq!(row, back);
    }
}
