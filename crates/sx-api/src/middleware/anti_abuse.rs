//! Anti-abuse detection middleware.
//!
//! Sits between the authentication middleware and the route handlers,
//! observing request metadata and flagging three classes of suspicious
//! behaviour:
//!
//! 1. **Replay** — the same JWT `jti` is presented twice within the
//!    replay window (default 5 minutes). Even when individual tokens are
//!    still inside their `exp` deadline, a re-used `jti` is treated as a
//!    classical replay attempt because legitimate clients never issue the
//!    same `jti` twice from the same session.
//! 2. **Rate anomaly** — the request rate from a single source IP exceeds
//!    `3x` the rolling median across all observed IPs. The median is a
//!    cheap proxy for "what does normal traffic look like right now?" and
//!    avoids hand-tuned thresholds that age poorly.
//! 3. **Agent rotation** — more than 5 distinct `User-Agent` values are
//!    observed for the same source IP within a 10-minute window. This is
//!    a high-precision signal for credential-stuffing botnets and naïve
//!    scrapers that rotate UAs but not IPs.
//!
//! ## Trust boundary
//!
//! This middleware runs **after** authentication when authentication
//! succeeded, and **before** route handlers in all cases. It never
//! refuses the request — that is the rate-limit middleware's job. Its
//! single output is an audit-shaped `tracing` event emitted at
//! `target = "abuse"` whenever a detector fires.
//!
//! ## Audit event shape
//!
//! ```text
//! event!(
//!     target: "abuse",
//!     Level::WARN,
//!     audit = true,
//!     action = "<replay|rate_anomaly|agent_rotation>",
//!     severity = "<low|medium|high>",
//!     ip_prefix = "1.2.3.0/24",   // /24 redacted source IP
//!     user_agent = "<truncated>",  // first 120 chars only
//!     jti = "<jti>",               // present for replay only
//!     request_id = "<request_id>", // when available
//! );
//! ```
//!
//! The event is consumed by the audit pipeline (`sx-audit`) which
//! re-shapes it into a tamper-evident chain entry. This middleware does
//! **not** call `sx-audit` directly — that would couple the HTTP layer
//! to the storage layer and break the layering the rest of the crate
//! enforces.
//!
//! ## Determinism in tests
//!
//! All time arithmetic uses [`std::time::Instant`] in production, but the
//! [`Detector`] state machine accepts an injectable [`Clock`] so unit
//! tests can advance time without `tokio::time::sleep`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, Response};
use axum::middleware::Next;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::request_id::RequestId;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Tunable thresholds for [`AntiAbuseLayer`].
///
/// Every field has a defensible default; production overrides come from
/// `sx-config`.
#[derive(Debug, Clone)]
pub struct AntiAbuseConfig {
    /// Sliding window over which a `jti` is considered "recently seen".
    pub replay_window: Duration,
    /// Per-IP rate sample window.
    pub rate_window: Duration,
    /// Multiplier applied to the rolling median IP rate to decide whether
    /// a single IP is anomalous. Default: `3.0`.
    pub rate_anomaly_multiplier: f64,
    /// Minimum number of requests an IP must contribute in `rate_window`
    /// before the anomaly detector is willing to flag it. Prevents new
    /// IPs from being flagged on their very first request.
    pub rate_min_samples: u32,
    /// Sliding window over which distinct UAs per IP are counted.
    pub agent_window: Duration,
    /// Maximum number of distinct UAs per IP within `agent_window`
    /// before the detector flags `AgentRotation`. Default: `5`.
    pub agent_threshold: u32,
    /// Whether the detector is engaged at all. When `false` every flag
    /// path is a no-op; useful for local development and for emergency
    /// disablement via config push.
    pub enabled: bool,
}

impl Default for AntiAbuseConfig {
    fn default() -> Self {
        Self {
            replay_window: Duration::from_secs(5 * 60),
            rate_window: Duration::from_secs(60),
            rate_anomaly_multiplier: 3.0,
            rate_min_samples: 4,
            agent_window: Duration::from_secs(10 * 60),
            agent_threshold: 5,
            enabled: true,
        }
    }
}

/// Bridge the loader-side [`sx_config::AntiAbuseConfig`] into the runtime
/// [`AntiAbuseConfig`] consumed by the middleware. The loader-side struct
/// only carries plain scalars (`u64` second-windows, etc.) because the
/// figment `Env` provider emits string-typed values; this `From` impl
/// promotes them to [`Duration`] without any further validation — the
/// loader has already guaranteed every window is non-zero when `enabled`.
impl From<sx_config::AntiAbuseConfig> for AntiAbuseConfig {
    fn from(cfg: sx_config::AntiAbuseConfig) -> Self {
        Self::from(&cfg)
    }
}

impl From<&sx_config::AntiAbuseConfig> for AntiAbuseConfig {
    fn from(cfg: &sx_config::AntiAbuseConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            replay_window: Duration::from_secs(cfg.replay_window_secs),
            rate_window: Duration::from_secs(cfg.rate_window_secs),
            rate_anomaly_multiplier: cfg.rate_anomaly_multiplier,
            rate_min_samples: cfg.rate_min_samples,
            agent_window: Duration::from_secs(cfg.agent_window_secs),
            agent_threshold: cfg.agent_threshold,
        }
    }
}

/// Free-function alias of [`From::from`] kept for call-sites that prefer
/// an explicit `from_config` name (e.g. the router builder, where the
/// `From` import would shadow other `From` impls in scope).
#[must_use]
pub fn from_config(cfg: &sx_config::AntiAbuseConfig) -> AntiAbuseConfig {
    AntiAbuseConfig::from(cfg)
}

// ---------------------------------------------------------------------------
// Public flags
// ---------------------------------------------------------------------------

/// Discriminator returned by [`Detector::observe`] when a request matches
/// one of the abuse patterns. Used both as a tracing field and as a test
/// assertion target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseFlag {
    /// Same `jti` re-presented within [`AntiAbuseConfig::replay_window`].
    Replay,
    /// IP rate > `multiplier * rolling median`.
    RateAnomaly,
    /// More than `agent_threshold` distinct UAs from the same IP in
    /// [`AntiAbuseConfig::agent_window`].
    AgentRotation,
}

impl AbuseFlag {
    /// Stable machine-readable code for the flag.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::RateAnomaly => "rate_anomaly",
            Self::AgentRotation => "agent_rotation",
        }
    }

    /// Severity tag for the audit pipeline.
    #[must_use]
    pub const fn severity(self) -> &'static str {
        match self {
            Self::Replay => "high",
            Self::RateAnomaly | Self::AgentRotation => "medium",
        }
    }
}

// ---------------------------------------------------------------------------
// Clock abstraction (for deterministic tests)
// ---------------------------------------------------------------------------

/// Monotonic clock abstraction the detector can be parameterised on.
///
/// Production uses [`SystemClock`]; tests use [`FakeClock`] (in the test
/// module) so they can advance time without sleeping.
pub trait Clock: Send + Sync + std::fmt::Debug + 'static {
    /// Return the current monotonic instant.
    fn now(&self) -> Instant;
}

/// The default production clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

// ---------------------------------------------------------------------------
// Detector core
// ---------------------------------------------------------------------------

/// Per-IP rolling state used by the rate-anomaly and agent-rotation
/// detectors.
#[derive(Debug, Default)]
struct IpState {
    /// Sliding window of request timestamps (for rate).
    rate_samples: VecDeque<Instant>,
    /// Sliding window of (timestamp, user_agent) pairs (for diversity).
    ua_samples: VecDeque<(Instant, String)>,
}

/// Owned state shared across all in-flight requests.
#[derive(Debug, Default)]
pub struct DetectorState {
    /// `jti -> first seen Instant` (only kept while inside the replay
    /// window).
    jtis: HashMap<String, Instant>,
    /// Per-IP rolling counters.
    ips: HashMap<String, IpState>,
}

/// The detector itself. `Send + Sync` so it can live in an
/// `axum::extract::State` slot.
pub struct Detector {
    cfg: AntiAbuseConfig,
    state: Mutex<DetectorState>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl Detector {
    /// Build a detector with the production [`SystemClock`].
    #[must_use]
    pub fn new(cfg: AntiAbuseConfig) -> Self {
        Self::with_clock(cfg, Arc::new(SystemClock))
    }

    /// Build a detector with an arbitrary clock. Public for tests in
    /// other crates; the in-file tests use the [`FakeClock`] helper.
    #[must_use]
    pub fn with_clock(cfg: AntiAbuseConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            cfg,
            state: Mutex::new(DetectorState::default()),
            clock,
        }
    }

    /// Snapshot of the current configuration.
    #[must_use]
    pub fn config(&self) -> &AntiAbuseConfig {
        &self.cfg
    }

    /// Observe one request and return every abuse pattern it matched.
    ///
    /// The return is a `Vec` because a single request can legitimately
    /// trip multiple detectors (e.g. an attacker re-using a `jti` from a
    /// new UA on the same IP).
    pub fn observe(&self, sample: &RequestSample<'_>) -> Vec<AbuseFlag> {
        if !self.cfg.enabled {
            return Vec::new();
        }
        let now = self.clock.now();
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        let mut flags = Vec::new();

        // Replay detection.
        if let Some(jti) = sample.jti {
            if !jti.is_empty() {
                self.prune_jtis(&mut state, now);
                if state.jtis.contains_key(jti) {
                    flags.push(AbuseFlag::Replay);
                } else {
                    state.jtis.insert(jti.to_owned(), now);
                }
            }
        }

        // IP-keyed detectors.
        if let Some(ip) = sample.ip {
            if !ip.is_empty() {
                if self.observe_rate(&mut state, ip, now) {
                    flags.push(AbuseFlag::RateAnomaly);
                }
                if let Some(ua) = sample.user_agent {
                    if self.observe_agent(&mut state, ip, ua, now) {
                        flags.push(AbuseFlag::AgentRotation);
                    }
                }
            }
        }

        flags
    }

    fn prune_jtis(&self, state: &mut DetectorState, now: Instant) {
        let window = self.cfg.replay_window;
        state
            .jtis
            .retain(|_, seen| now.duration_since(*seen) < window);
    }

    fn observe_rate(&self, state: &mut DetectorState, ip: &str, now: Instant) -> bool {
        let window = self.cfg.rate_window;

        // Stage 1: insert current sample and prune all IPs for the rate
        // window. We must mutate `ips` in two passes because we need to
        // hand out a mutable reference to the focal IP and then read
        // counts from every other IP.
        let entry = state.ips.entry(ip.to_owned()).or_default();
        entry.rate_samples.push_back(now);
        while let Some(front) = entry.rate_samples.front() {
            if now.duration_since(*front) >= window {
                entry.rate_samples.pop_front();
            } else {
                break;
            }
        }
        let this_count = u32::try_from(entry.rate_samples.len()).unwrap_or(u32::MAX);

        // Stage 2: collect counts across all other IPs in the same
        // window and compute the median.
        let counts = Self::collect_counts(state, ip, now, window);
        let median = median_u32(&counts);

        // Decision: flag only when we have enough evidence and the focal
        // IP is comfortably above the multiplier.
        if this_count < self.cfg.rate_min_samples {
            return false;
        }
        // If median is zero or one we still want to flag flagrant
        // outliers (e.g. 10 vs 1). Use `max(1.0, median)` to avoid
        // divide-by-zero corner cases.
        let baseline = f64::from(median).max(1.0);
        let threshold = baseline * self.cfg.rate_anomaly_multiplier;
        f64::from(this_count) > threshold
    }

    fn collect_counts(
        state: &mut DetectorState,
        focal: &str,
        now: Instant,
        window: Duration,
    ) -> Vec<u32> {
        let mut counts: Vec<u32> = Vec::with_capacity(state.ips.len());
        for (other, ip_state) in &mut state.ips {
            if other == focal {
                continue;
            }
            while let Some(front) = ip_state.rate_samples.front() {
                if now.duration_since(*front) >= window {
                    ip_state.rate_samples.pop_front();
                } else {
                    break;
                }
            }
            let len = u32::try_from(ip_state.rate_samples.len()).unwrap_or(u32::MAX);
            if len > 0 {
                counts.push(len);
            }
        }
        counts
    }

    fn observe_agent(&self, state: &mut DetectorState, ip: &str, ua: &str, now: Instant) -> bool {
        let window = self.cfg.agent_window;
        let entry = state.ips.entry(ip.to_owned()).or_default();
        entry.ua_samples.push_back((now, ua.to_owned()));
        while let Some((ts, _)) = entry.ua_samples.front() {
            if now.duration_since(*ts) >= window {
                entry.ua_samples.pop_front();
            } else {
                break;
            }
        }
        let distinct = {
            let mut seen: Vec<&str> = Vec::with_capacity(entry.ua_samples.len());
            for (_, u) in &entry.ua_samples {
                let s = u.as_str();
                if !seen.contains(&s) {
                    seen.push(s);
                }
            }
            u32::try_from(seen.len()).unwrap_or(u32::MAX)
        };
        distinct > self.cfg.agent_threshold
    }
}

// ---------------------------------------------------------------------------
// Sample type — what we feed the detector
// ---------------------------------------------------------------------------

/// One observation of a single request. Lifetimes are explicit so the
/// caller can pass borrowed header values without allocation.
#[derive(Debug, Clone, Copy)]
pub struct RequestSample<'a> {
    /// Source IP after `X-Forwarded-For` normalisation. Empty means
    /// "unknown".
    pub ip: Option<&'a str>,
    /// `User-Agent` header, truncated to a sensible length by the
    /// caller.
    pub user_agent: Option<&'a str>,
    /// JWT identifier from the authenticated user, if any.
    pub jti: Option<&'a str>,
    /// Correlation id for audit emission.
    pub request_id: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Layer wiring
// ---------------------------------------------------------------------------

/// Public façade exposed to the router builder.
#[derive(Clone)]
pub struct AntiAbuseLayer {
    /// Shared detector. `Arc` so the layer can be cloned cheaply per
    /// request.
    pub detector: Arc<Detector>,
}

impl AntiAbuseLayer {
    /// Build a layer with the default production clock.
    #[must_use]
    pub fn new(cfg: AntiAbuseConfig) -> Self {
        Self {
            detector: Arc::new(Detector::new(cfg)),
        }
    }

    /// Build a layer wrapping an existing detector. Used by callers that
    /// want to share detector state across multiple sub-routers or that
    /// need a custom clock for tests.
    #[must_use]
    pub fn from_detector(detector: Arc<Detector>) -> Self {
        Self { detector }
    }
}

impl std::fmt::Debug for AntiAbuseLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AntiAbuseLayer")
            .field("detector", &self.detector)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Helpers (IP / UA redaction)
// ---------------------------------------------------------------------------

/// Reduce an IPv4 address to its `/24` prefix and an IPv6 to its `/48` prefix.
///
/// Anything that does not parse as either is returned verbatim so test
/// fixtures with `"unknown"` are preserved. Empty input is returned as
/// `"unknown"` so downstream consumers never see a blank field.
#[must_use]
pub fn redact_ip(ip: &str) -> String {
    if ip.is_empty() {
        return "unknown".to_owned();
    }
    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        let oct = addr.octets();
        return format!("{}.{}.{}.0/24", oct[0], oct[1], oct[2]);
    }
    if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
        let seg = addr.segments();
        return format!("{:x}:{:x}:{:x}::/48", seg[0], seg[1], seg[2]);
    }
    ip.to_owned()
}

/// Truncate a `User-Agent` so it fits in a structured log field
/// without bloating audit storage.
#[must_use]
pub fn truncate_ua(ua: &str) -> String {
    const MAX: usize = 120;
    if ua.len() <= MAX {
        return ua.to_owned();
    }
    // Find the largest char boundary `<= MAX`.
    let mut end = MAX;
    while end > 0 && !ua.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = ua[..end].to_owned();
    out.push('\u{2026}');
    out
}

/// Pull the first non-empty `X-Forwarded-For` hop, falling back to
/// `X-Real-IP` or the empty string.
fn source_ip(req: &Request) -> Option<&str> {
    if let Some(v) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let first = v.split(',').next().unwrap_or("").trim();
        if !first.is_empty() {
            return Some(first);
        }
    }
    if let Some(v) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
}

fn user_agent(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
}

fn median_u32(counts: &[u32]) -> u32 {
    if counts.is_empty() {
        return 0;
    }
    let mut sorted: Vec<u32> = counts.to_vec();
    sorted.sort_unstable();
    let len = sorted.len();
    let mid = len.div_euclid(2);
    if len.rem_euclid(2) == 0 {
        // Even count: average the two middle samples via the overflow-
        // safe midpoint helper. Rounding down is intentional — we want
        // the more lenient interpretation.
        let lo = sorted.get(mid.saturating_sub(1)).copied().unwrap_or(0);
        let hi = sorted.get(mid).copied().unwrap_or(0);
        u32::midpoint(lo, hi)
    } else {
        sorted.get(mid).copied().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Audit emission
// ---------------------------------------------------------------------------

fn emit_audit(flag: AbuseFlag, sample: &RequestSample<'_>) {
    let ip_prefix = redact_ip(sample.ip.unwrap_or(""));
    let ua = sample.user_agent.map(truncate_ua).unwrap_or_default();
    let jti = sample.jti.unwrap_or_default();
    let rid = sample.request_id.unwrap_or_default();
    // The `target` and `audit` fields are how the audit pipeline picks
    // this event out of the global trace stream.
    tracing::event!(
        target: "abuse",
        tracing::Level::WARN,
        audit = true,
        action = flag.action(),
        severity = flag.severity(),
        ip_prefix = %ip_prefix,
        user_agent = %ua,
        jti = %jti,
        request_id = %rid,
        "anti-abuse detector fired"
    );
}

// ---------------------------------------------------------------------------
// axum middleware fn
// ---------------------------------------------------------------------------

/// `axum::middleware::from_fn_with_state` callback paired with
/// [`AntiAbuseLayer`].
#[allow(clippy::needless_pass_by_value)]
pub async fn anti_abuse_middleware(
    State(layer): State<AntiAbuseLayer>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let ip = source_ip(&req).map(str::to_owned);
    let ua = user_agent(&req).map(str::to_owned);
    let jti = req
        .extensions()
        .get::<AuthenticatedUser>()
        .map(|u| u.claims.jti.clone());
    let rid = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.as_str().to_owned());

    let sample = RequestSample {
        ip: ip.as_deref(),
        user_agent: ua.as_deref(),
        jti: jti.as_deref(),
        request_id: rid.as_deref(),
    };

    for flag in layer.detector.observe(&sample) {
        emit_audit(flag, &sample);
    }

    next.run(req).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Test clock the unit tests can advance manually.
    #[derive(Debug)]
    struct FakeClock {
        inner: StdMutex<Instant>,
    }

    impl FakeClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: StdMutex::new(Instant::now()),
            })
        }
        fn advance(&self, d: Duration) {
            let mut g = self.inner.lock().unwrap();
            *g += d;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.inner.lock().unwrap()
        }
    }

    fn detector_with(cfg: AntiAbuseConfig) -> (Detector, Arc<FakeClock>) {
        let clock = FakeClock::new();
        let det = Detector::with_clock(cfg, clock.clone());
        (det, clock)
    }

    fn sample<'a>(
        ip: Option<&'a str>,
        ua: Option<&'a str>,
        jti: Option<&'a str>,
    ) -> RequestSample<'a> {
        RequestSample {
            ip,
            user_agent: ua,
            jti,
            request_id: Some("req-1"),
        }
    }

    // -------------------- Replay --------------------

    #[test]
    fn replay_same_jti_within_window_is_flagged() {
        let (det, _clk) = detector_with(AntiAbuseConfig::default());
        let s = sample(Some("10.0.0.1"), Some("ua"), Some("jti-1"));
        assert!(det.observe(&s).is_empty());
        let flags = det.observe(&s);
        assert!(flags.contains(&AbuseFlag::Replay));
    }

    #[test]
    fn replay_same_jti_outside_window_is_not_flagged() {
        let cfg = AntiAbuseConfig {
            replay_window: Duration::from_secs(60),
            ..AntiAbuseConfig::default()
        };
        let (det, clk) = detector_with(cfg);
        let s = sample(Some("10.0.0.1"), Some("ua"), Some("jti-1"));
        assert!(det.observe(&s).is_empty());
        clk.advance(Duration::from_secs(61));
        let flags = det.observe(&s);
        assert!(
            !flags.contains(&AbuseFlag::Replay),
            "stale jti should not flag"
        );
    }

    // -------------------- Rate anomaly --------------------

    #[test]
    fn rate_small_burst_against_steady_baseline_is_not_flagged() {
        // 4 requests from focal IP against a steady 1 req from a peer
        // IP in the same window. 4 vs median(1) * 3 = 3 -> 4 > 3, but we
        // also require min_samples=4, so this is right at the edge.
        // The test asserts no flag is raised in the steady regime by
        // configuring min_samples=5 so 4 requests is below evidence
        // threshold.
        let cfg = AntiAbuseConfig {
            rate_min_samples: 5,
            ..AntiAbuseConfig::default()
        };
        let (det, _clk) = detector_with(cfg);
        // Seed peer IPs.
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"] {
            assert!(!det
                .observe(&sample(Some(ip), Some("ua"), None))
                .contains(&AbuseFlag::RateAnomaly));
        }
        // 4 requests from focal IP.
        let mut flagged = false;
        for _ in 0..4 {
            if det
                .observe(&sample(Some("9.9.9.9"), Some("ua"), None))
                .contains(&AbuseFlag::RateAnomaly)
            {
                flagged = true;
            }
        }
        assert!(!flagged, "small burst should not trip the detector");
    }

    #[test]
    fn rate_large_burst_against_steady_baseline_is_flagged() {
        let cfg = AntiAbuseConfig {
            rate_min_samples: 4,
            ..AntiAbuseConfig::default()
        };
        let (det, _clk) = detector_with(cfg);
        // Establish a baseline median of 1 across several peers.
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"] {
            let _ = det.observe(&sample(Some(ip), Some("ua"), None));
        }
        // Focal IP issues 10 requests; threshold = max(1.0, 1) * 3 = 3,
        // and 10 > 3 -> RateAnomaly.
        let mut flagged = false;
        for _ in 0..10 {
            if det
                .observe(&sample(Some("9.9.9.9"), Some("ua"), None))
                .contains(&AbuseFlag::RateAnomaly)
            {
                flagged = true;
            }
        }
        assert!(flagged, "10x baseline should trip the detector");
    }

    // -------------------- Agent rotation --------------------

    #[test]
    fn agent_rotation_six_uas_in_window_is_flagged() {
        let (det, _clk) = detector_with(AntiAbuseConfig::default());
        let ip = "10.0.0.5";
        let mut flagged = false;
        for i in 0..6 {
            let ua = format!("ua-{i}");
            if det
                .observe(&sample(Some(ip), Some(&ua), None))
                .contains(&AbuseFlag::AgentRotation)
            {
                flagged = true;
            }
        }
        assert!(flagged, "6 distinct UAs in window should fire");
    }

    #[test]
    fn agent_rotation_one_ua_many_requests_is_not_flagged() {
        let (det, _clk) = detector_with(AntiAbuseConfig::default());
        for _ in 0..50 {
            let flags = det.observe(&sample(Some("10.0.0.6"), Some("only-ua"), None));
            assert!(
                !flags.contains(&AbuseFlag::AgentRotation),
                "single UA must never fire"
            );
        }
    }

    // -------------------- Audit emission --------------------

    #[test]
    fn audit_event_is_emitted_for_flagged_request() {
        use std::sync::Arc as StdArc;
        use tracing::subscriber::with_default;
        use tracing::{Event, Subscriber};
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Layer;

        #[derive(Default)]
        struct Captured {
            actions: StdMutex<Vec<String>>,
            ip_prefixes: StdMutex<Vec<String>>,
        }

        struct CaptureLayer {
            captured: StdArc<Captured>,
        }

        struct ActionVisitor<'a> {
            action: &'a mut Option<String>,
            ip_prefix: &'a mut Option<String>,
        }

        impl tracing::field::Visit for ActionVisitor<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                match field.name() {
                    "action" => *self.action = Some(value.to_owned()),
                    "ip_prefix" => *self.ip_prefix = Some(value.to_owned()),
                    _ => {}
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                let s = format!("{value:?}");
                let s = s.trim_matches('"').to_owned();
                match field.name() {
                    "action" => {
                        if self.action.is_none() {
                            *self.action = Some(s);
                        }
                    }
                    "ip_prefix" => {
                        if self.ip_prefix.is_none() {
                            *self.ip_prefix = Some(s);
                        }
                    }
                    _ => {}
                }
            }
        }

        impl<S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>> Layer<S>
            for CaptureLayer
        {
            fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
                if event.metadata().target() != "abuse" {
                    return;
                }
                let mut action: Option<String> = None;
                let mut ip_prefix: Option<String> = None;
                let mut v = ActionVisitor {
                    action: &mut action,
                    ip_prefix: &mut ip_prefix,
                };
                event.record(&mut v);
                if let Some(a) = action {
                    self.captured.actions.lock().unwrap().push(a);
                }
                if let Some(p) = ip_prefix {
                    self.captured.ip_prefixes.lock().unwrap().push(p);
                }
            }
        }

        let captured = StdArc::new(Captured::default());
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            captured: captured.clone(),
        });

        with_default(subscriber, || {
            let (det, _clk) = detector_with(AntiAbuseConfig::default());
            let s = sample(Some("1.2.3.4"), Some("ua"), Some("jti-x"));
            let _ = det.observe(&s);
            // Trip the replay detector deterministically.
            let flags = det.observe(&s);
            for f in flags {
                emit_audit(f, &s);
            }
        });

        let actions = captured.actions.lock().unwrap().clone();
        let prefixes = captured.ip_prefixes.lock().unwrap().clone();
        assert!(
            actions.iter().any(|a| a == "replay"),
            "expected replay action emitted, got {actions:?}"
        );
        assert!(
            prefixes.iter().any(|p| p == "1.2.3.0/24"),
            "expected /24-redacted ip_prefix, got {prefixes:?}"
        );
    }

    // -------------------- Redaction --------------------

    #[test]
    fn redact_ip_zeros_the_last_octet() {
        assert_eq!(redact_ip("203.0.113.42"), "203.0.113.0/24");
        assert_eq!(redact_ip("10.0.0.1"), "10.0.0.0/24");
    }

    #[test]
    fn redact_ip_collapses_ipv6_to_48() {
        let r = redact_ip("2001:db8:abcd:1234::1");
        assert_eq!(r, "2001:db8:abcd::/48");
    }

    #[test]
    fn redact_ip_empty_is_unknown() {
        assert_eq!(redact_ip(""), "unknown");
    }

    // -------------------- Configurability --------------------

    #[test]
    fn threshold_is_configurable_via_config() {
        // Default agent_threshold=5. Override to 2 and trip on 3 UAs.
        let cfg = AntiAbuseConfig {
            agent_threshold: 2,
            ..AntiAbuseConfig::default()
        };
        let (det, _clk) = detector_with(cfg);
        let mut flagged = false;
        for i in 0..3 {
            let ua = format!("ua-{i}");
            if det
                .observe(&sample(Some("10.0.0.9"), Some(&ua), None))
                .contains(&AbuseFlag::AgentRotation)
            {
                flagged = true;
            }
        }
        assert!(
            flagged,
            "lowered agent_threshold should fire on 3 distinct UAs"
        );
    }

    #[test]
    fn disabled_config_never_flags() {
        let cfg = AntiAbuseConfig {
            enabled: false,
            ..AntiAbuseConfig::default()
        };
        let (det, _clk) = detector_with(cfg);
        let s = sample(Some("10.0.0.1"), Some("ua"), Some("jti-1"));
        // Even a textbook replay must not fire.
        assert!(det.observe(&s).is_empty());
        assert!(det.observe(&s).is_empty());
    }

    // -------------------- Helpers --------------------

    // -------------------- From<sx_config::AntiAbuseConfig> --------------------

    #[test]
    fn from_config_maps_every_field_one_to_one() {
        let src = sx_config::AntiAbuseConfig {
            enabled: true,
            replay_window_secs: 123,
            rate_window_secs: 45,
            rate_anomaly_multiplier: 4.5,
            rate_min_samples: 7,
            agent_window_secs: 240,
            agent_threshold: 9,
        };
        let dst = super::from_config(&src);
        assert!(dst.enabled);
        assert_eq!(dst.replay_window, Duration::from_secs(123));
        assert_eq!(dst.rate_window, Duration::from_secs(45));
        assert!((dst.rate_anomaly_multiplier - 4.5).abs() < f64::EPSILON);
        assert_eq!(dst.rate_min_samples, 7);
        assert_eq!(dst.agent_window, Duration::from_secs(240));
        assert_eq!(dst.agent_threshold, 9);
    }

    #[test]
    fn from_config_via_from_trait_matches_runtime_defaults_when_fed_matching_values() {
        // The loader-side default ships `enabled: false`, but the runtime
        // numeric defaults must match the middleware's own defaults so
        // that flipping `enabled: true` alone produces identical behavior
        // to `AntiAbuseConfig::default()` (modulo the `enabled` flag).
        let src = sx_config::AntiAbuseConfig {
            enabled: true,
            ..sx_config::AntiAbuseConfig::default()
        };
        let dst: AntiAbuseConfig = src.into();
        let baseline = AntiAbuseConfig::default();
        assert_eq!(dst.replay_window, baseline.replay_window);
        assert_eq!(dst.rate_window, baseline.rate_window);
        assert!(
            (dst.rate_anomaly_multiplier - baseline.rate_anomaly_multiplier).abs() < f64::EPSILON
        );
        assert_eq!(dst.rate_min_samples, baseline.rate_min_samples);
        assert_eq!(dst.agent_window, baseline.agent_window);
        assert_eq!(dst.agent_threshold, baseline.agent_threshold);
        assert_eq!(dst.enabled, baseline.enabled);
    }

    #[test]
    fn truncate_ua_caps_at_120_with_ellipsis() {
        let long = "x".repeat(200);
        let t = truncate_ua(&long);
        assert!(t.ends_with('\u{2026}'));
        assert!(t.chars().count() <= 121);
    }
}
