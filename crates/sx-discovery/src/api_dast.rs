//! API DAST — Postman Collection v2.1 replay engine (P2-013).
//!
//! Parses a Postman v2.1 collection, materialises the requests against a
//! caller-supplied base URL (the `{{baseUrl}}` substitution every Postman
//! collection ends up using), replays each request once with the supplied
//! bearer credential, and runs a fixed catalogue of signal-class detections
//! over the responses:
//!
//! 1. **Auth bypass** — the request is replayed without the
//!    `Authorization` header. If the un-authenticated call returns `200`
//!    instead of `401/403`, an `auth-bypass` finding is emitted.
//! 2. **IDOR signals** — if a request path contains a Postman
//!    `:resourceId` style segment (or the substituted variable matches
//!    one of the caller-supplied known-other-tenant ids), the scanner
//!    replays the request with that id swapped in. If the alternative
//!    id returns `200` instead of `403/404`, an `idor` finding is
//!    emitted.
//! 3. **Missing rate limits** — the scanner sends a small burst of
//!    100 requests to the *first* `GET` it encounters. If the server
//!    never returns a `429`, a `rate-limit-missing` finding is emitted.
//! 4. **Verbose errors** — any response whose status is 5xx and whose
//!    body contains a stack-trace marker (`Traceback`, `at java.`,
//!    `Exception in thread`, …) emits a `verbose-error` finding.
//! 5. **Insecure CORS** — when a response surfaces
//!    `Access-Control-Allow-Origin: *` combined with
//!    `Access-Control-Allow-Credentials: true`, an `insecure-cors`
//!    finding is emitted.
//!
//! The `Authorization` header is **never** logged or surfaced in the
//! finding evidence; we redact it to `Bearer <redacted>` (or
//! `Basic <redacted>`) before emitting any structured log line.
//!
//! ## What we do **not** do
//!
//! The MVP intentionally avoids full Postman feature-parity:
//!
//! - Pre-request scripts are accepted but only the subset
//!   `pm.environment.set("key", "value")` (single-quote variants
//!   accepted) is evaluated; everything else is ignored. No JS engine
//!   ever runs.
//! - Form-data bodies are flattened to `application/x-www-form-urlencoded`.
//! - File uploads, `OAuth1`, AWS sigv4, Hawk and Digest auth schemes are
//!   not replayed.
//!
//! The engine is `tokio`-async, single-tenant per invocation, and emits
//! one [`ApiDastFinding`] per detection. Callers persist findings under
//! their own tenant scope.

use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use reqwest::{Client, Method, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use tracing::{debug, info, warn};
use url::Url;

use crate::error::DiscoveryError;

/// Hard upper bound on the response body bytes inspected by the verbose
/// error detector. Anything beyond this is ignored.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Hard upper bound on the number of requests we will replay from a
/// single collection — protects against pathologically large uploads.
pub const MAX_REQUESTS_PER_COLLECTION: usize = 500;

/// Number of requests we send in the rate-limit burst.
pub const RATE_LIMIT_BURST_COUNT: usize = 100;

/// Wall-clock window the burst must complete within.
pub const RATE_LIMIT_BURST_WINDOW: Duration = Duration::from_secs(10);

/// Stack-trace markers used by the verbose-error detector.
const STACK_TRACE_MARKERS: &[&str] = &[
    "Traceback (most recent call last)",
    "Exception in thread",
    "at java.",
    "at net.",
    "at com.",
    "stack trace:",
    "SQLSTATE",
    "panicked at",
];

/// A single signal-class finding emitted by the API DAST engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiDastFinding {
    /// Stable check identifier.
    pub check_id: String,
    /// Severity tag (`info`, `low`, `medium`, `high`, `critical`).
    pub severity: String,
    /// HTTP method that triggered the detection.
    pub method: String,
    /// Replayed URL (resolved against the caller-supplied base URL).
    pub url: String,
    /// Human-readable description.
    pub message: String,
    /// Optional remediation hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Postman item name the finding traces back to, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_item: Option<String>,
}

impl ApiDastFinding {
    fn new(
        check_id: &str,
        severity: &str,
        method: &str,
        url: &str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            check_id: check_id.into(),
            severity: severity.into(),
            method: method.into(),
            url: url.into(),
            message: message.into(),
            remediation: None,
            source_item: None,
        }
    }

    fn with_remediation(mut self, hint: impl Into<String>) -> Self {
        self.remediation = Some(hint.into());
        self
    }

    fn with_source(mut self, item: impl Into<String>) -> Self {
        self.source_item = Some(item.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Postman v2.1 wire model
// ---------------------------------------------------------------------------

/// Top-level Postman v2.1 collection (the minimum subset we need).
#[derive(Debug, Clone, Deserialize)]
pub struct PostmanCollection {
    #[serde(default)]
    info: PostmanInfo,
    #[serde(default)]
    item: Vec<PostmanItem>,
    #[serde(default)]
    variable: Vec<PostmanVariable>,
    #[serde(default)]
    auth: Option<PostmanAuth>,
}

impl PostmanCollection {
    /// Deserialise a collection from bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        serde_json::from_slice::<Self>(bytes)
            .map_err(|e| DiscoveryError::config(format!("postman collection parse failed: {e}")))
    }

    /// Name as advertised in the collection metadata.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.info.name
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct PostmanInfo {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanItem {
    #[serde(default)]
    name: String,
    /// Folders nest items recursively.
    #[serde(default)]
    item: Vec<Self>,
    /// Concrete request entry. Mutually exclusive with `item` per the
    /// Postman schema.
    #[serde(default)]
    request: Option<PostmanRequest>,
    /// Pre-request scripts (subset evaluated).
    #[serde(default)]
    event: Vec<PostmanEvent>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanRequest {
    #[serde(default)]
    method: Option<String>,
    /// `url` may be either a raw string or a nested object.
    #[serde(default)]
    url: Option<PostmanUrl>,
    #[serde(default)]
    header: Vec<PostmanHeader>,
    #[serde(default)]
    body: Option<PostmanBody>,
    #[serde(default)]
    auth: Option<PostmanAuth>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum PostmanUrl {
    Raw(String),
    Object(PostmanUrlObject),
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanUrlObject {
    #[serde(default)]
    raw: Option<String>,
    #[serde(default)]
    host: Option<Value>,
    #[serde(default)]
    path: Option<Value>,
    #[serde(default)]
    query: Vec<PostmanQuery>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanQuery {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanHeader {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanBody {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    raw: Option<String>,
    #[serde(default)]
    urlencoded: Vec<PostmanUrlencoded>,
    #[serde(default)]
    formdata: Vec<PostmanUrlencoded>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanUrlencoded {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanVariable {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanAuth {
    #[serde(default, rename = "type")]
    auth_type: Option<String>,
    #[serde(default)]
    bearer: Vec<PostmanAuthKv>,
    #[serde(default)]
    basic: Vec<PostmanAuthKv>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanAuthKv {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanEvent {
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    script: Option<PostmanScript>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostmanScript {
    /// The script body may be either a single string or an array of
    /// strings (Postman lets users line-break their scripts in the
    /// editor; the wire form is then a JSON array of lines).
    #[serde(default)]
    exec: Option<Value>,
}

// ---------------------------------------------------------------------------
// Replay configuration
// ---------------------------------------------------------------------------

/// Inputs to a single API DAST scan.
#[derive(Debug, Clone)]
pub struct ApiDastConfig {
    /// Base URL substituted for `{{baseUrl}}` and used to resolve relative
    /// paths. Must be `http(s)://...`.
    pub base_url: Url,
    /// Bearer token applied to every replay (and stripped for the
    /// auth-bypass shadow request). When `None`, requests are sent
    /// unauthenticated.
    pub bearer: Option<String>,
    /// Per-request timeout.
    pub request_timeout: Duration,
    /// Maximum body bytes captured per response.
    pub max_body_bytes: usize,
    /// Known other-tenant resource ids the scanner is allowed to try in
    /// IDOR probes. Only the *first* entry is used per item; we never
    /// fan out aggressively.
    pub idor_probe_ids: Vec<String>,
}

impl ApiDastConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        let scheme = self.base_url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(DiscoveryError::config(format!(
                "api dast base_url must be http(s), got '{scheme}'"
            )));
        }
        if self.request_timeout.is_zero() {
            return Err(DiscoveryError::config(
                "api dast request_timeout must be > 0",
            ));
        }
        if self.max_body_bytes == 0 {
            return Err(DiscoveryError::config(
                "api dast max_body_bytes must be > 0",
            ));
        }
        Ok(())
    }

    /// Default config builder.
    pub fn new(base_url: Url) -> Result<Self, DiscoveryError> {
        let cfg = Self {
            base_url,
            bearer: None,
            request_timeout: Duration::from_secs(5),
            max_body_bytes: MAX_BODY_BYTES,
            idor_probe_ids: Vec::new(),
        };
        cfg.check()?;
        Ok(cfg)
    }
}

/// Summary returned by [`run_dast`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiDastReport {
    /// Wall-clock start.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// Wall-clock end.
    #[serde(with = "time::serde::rfc3339")]
    pub ended_at: OffsetDateTime,
    /// Total HTTP requests issued (replay + auth-bypass probes + IDOR
    /// probes + rate-limit burst).
    pub requests_sent: u32,
    /// Findings collected, deduplicated by (`check_id`, `url`).
    pub findings: Vec<ApiDastFinding>,
}

// ---------------------------------------------------------------------------
// Scan entry point
// ---------------------------------------------------------------------------

/// Run an API DAST scan over `collection` using `cfg`.
///
/// The function consumes `collection` by reference and returns a fully
/// materialised report. Any per-request failure (DNS, TLS, timeout) is
/// recorded as a warning on the structured log; we *do not* fail the
/// whole scan on a single unreachable request.
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
pub async fn run_dast(
    client: &Client,
    collection: &PostmanCollection,
    cfg: &ApiDastConfig,
) -> Result<ApiDastReport, DiscoveryError> {
    cfg.check()?;
    let started_at = OffsetDateTime::now_utc();
    let mut env = build_initial_env(collection, cfg);

    let items = flatten_items(collection);
    let request_cap = items.len().min(MAX_REQUESTS_PER_COLLECTION);

    let mut requests_sent: u32 = 0;
    let mut findings: Vec<ApiDastFinding> = Vec::new();
    let mut burst_done = false;

    for item in items.into_iter().take(request_cap) {
        apply_pre_request_scripts(&item.events, &mut env);
        let Some(req) = item.request else {
            continue;
        };
        let Some(materialised) = materialise(&item.name, &req, cfg, &env, collection.auth.as_ref())
        else {
            continue;
        };

        info!(
            target: "api_dast",
            item = %item.name,
            method = %materialised.method,
            url = %materialised.url,
            "replaying postman item",
        );

        let primary = match dispatch(client, &materialised, cfg).await {
            Ok(r) => r,
            Err(e) => {
                warn!(target: "api_dast", error = %e, "primary replay failed; skipping item");
                continue;
            }
        };
        requests_sent = requests_sent.saturating_add(1);

        analyse_response(&materialised, &primary, &mut findings);

        // Auth-bypass: only attempt when the original request carried an
        // Authorization header (either from the bearer config or from
        // the collection's own auth block).
        if materialised.authorization.is_some() {
            let mut shadow = materialised.clone();
            shadow.authorization = None;
            match dispatch(client, &shadow, cfg).await {
                Ok(resp) => {
                    requests_sent = requests_sent.saturating_add(1);
                    if resp.status >= 200 && resp.status < 300 {
                        findings.push(
                            ApiDastFinding::new(
                                "auth-bypass",
                                "high",
                                &shadow.method,
                                &shadow.url,
                                format!(
                                    "request returned {} without an Authorization header",
                                    resp.status,
                                ),
                            )
                            .with_remediation(
                                "require authentication on every endpoint; reject anonymous requests with 401",
                            )
                            .with_source(&item.name),
                        );
                    }
                }
                Err(e) => warn!(target: "api_dast", error = %e, "auth-bypass probe failed"),
            }
        }

        // IDOR probe: only when the path looks like it carries a
        // resource id segment AND the operator handed us alternative
        // ids to try.
        if let Some(probe_id) = cfg.idor_probe_ids.first() {
            if let Some(probe) = build_idor_probe(&materialised, probe_id) {
                match dispatch(client, &probe, cfg).await {
                    Ok(resp) => {
                        requests_sent = requests_sent.saturating_add(1);
                        if resp.status >= 200 && resp.status < 300 {
                            findings.push(
                                ApiDastFinding::new(
                                    "idor",
                                    "high",
                                    &probe.method,
                                    &probe.url,
                                    format!(
                                        "swapped resource id returned {} (expected 403/404)",
                                        resp.status,
                                    ),
                                )
                                .with_remediation(
                                    "authorise per-resource: reject requests whose subject does not own the addressed object",
                                )
                                .with_source(&item.name),
                            );
                        }
                    }
                    Err(e) => warn!(target: "api_dast", error = %e, "idor probe failed"),
                }
            }
        }

        // Rate-limit burst: applied once, to the first GET we replay
        // successfully.
        if !burst_done && materialised.method.eq_ignore_ascii_case("GET") {
            burst_done = true;
            match rate_limit_burst(client, &materialised, cfg).await {
                Ok((sent, hit_429)) => {
                    requests_sent = requests_sent.saturating_add(sent);
                    if !hit_429 {
                        findings.push(
                            ApiDastFinding::new(
                                "rate-limit-missing",
                                "medium",
                                &materialised.method,
                                &materialised.url,
                                format!(
                                    "{RATE_LIMIT_BURST_COUNT} requests in <{}s never returned 429",
                                    RATE_LIMIT_BURST_WINDOW.as_secs(),
                                ),
                            )
                            .with_remediation(
                                "deploy a token-bucket / sliding-window limiter and return 429 once exceeded",
                            )
                            .with_source(&item.name),
                        );
                    }
                }
                Err(e) => warn!(target: "api_dast", error = %e, "rate-limit burst failed"),
            }
        }
    }

    dedup_findings(&mut findings);
    let ended_at = OffsetDateTime::now_utc();
    Ok(ApiDastReport {
        started_at,
        ended_at,
        requests_sent,
        findings,
    })
}

// ---------------------------------------------------------------------------
// Materialisation: turn Postman items into concrete HTTP requests
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct MaterialisedRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    /// Authorization header value (kept separate so we can redact it).
    authorization: Option<String>,
    body: Option<MaterialisedBody>,
}

#[derive(Debug, Clone)]
enum MaterialisedBody {
    Raw(String, Option<String>), // (body, content-type override)
    Form(Vec<(String, String)>),
}

#[derive(Debug, Clone)]
struct FlatItem {
    name: String,
    request: Option<PostmanRequest>,
    events: Vec<PostmanEvent>,
}

fn flatten_items(c: &PostmanCollection) -> Vec<FlatItem> {
    fn walk(items: &[PostmanItem], out: &mut Vec<FlatItem>, prefix: &str) {
        for it in items {
            let name = if prefix.is_empty() {
                it.name.clone()
            } else {
                format!("{prefix}/{}", it.name)
            };
            if !it.item.is_empty() {
                walk(&it.item, out, &name);
            }
            if it.request.is_some() {
                out.push(FlatItem {
                    name,
                    request: it.request.clone(),
                    events: it.event.clone(),
                });
            }
        }
    }
    let mut out = Vec::new();
    walk(&c.item, &mut out, "");
    out
}

fn build_initial_env(c: &PostmanCollection, cfg: &ApiDastConfig) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for v in &c.variable {
        if let (Some(k), Some(val)) = (v.key.clone(), v.value.clone()) {
            env.insert(k, val);
        }
    }
    // Always overlay baseUrl from the caller — the operator's target
    // wins over whatever the collection author baked in. Trim any
    // trailing slash so `{{baseUrl}}/path` materialises as `host/path`,
    // not `host//path` (`Url::to_string` appends `/` to bare hosts).
    let base_str = cfg.base_url.to_string();
    let base_trimmed = base_str.trim_end_matches('/').to_string();
    env.insert("baseUrl".to_string(), base_trimmed);
    env
}

fn apply_pre_request_scripts(events: &[PostmanEvent], env: &mut BTreeMap<String, String>) {
    for ev in events {
        if ev.listen.as_deref() != Some("prerequest") {
            continue;
        }
        let Some(script) = &ev.script else { continue };
        let Some(exec) = &script.exec else { continue };
        let lines = collect_script_lines(exec);
        for line in lines {
            apply_env_set_line(&line, env);
        }
    }
}

fn collect_script_lines(exec: &Value) -> Vec<String> {
    match exec {
        Value::String(s) => s.lines().map(ToOwned::to_owned).collect(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Pure parser for the `pm.environment.set("k", "v")` subset. Single or
/// double quotes; trailing semicolon optional. Anything else is ignored.
fn apply_env_set_line(line: &str, env: &mut BTreeMap<String, String>) {
    let trimmed = line.trim();
    let Some(rest) = trimmed.strip_prefix("pm.environment.set(") else {
        return;
    };
    let Some(args) = rest.split(')').next() else {
        return;
    };
    let mut parts = args.splitn(2, ',');
    let Some(k_raw) = parts.next() else { return };
    let Some(v_raw) = parts.next() else { return };
    let k = strip_quotes(k_raw.trim());
    let v = strip_quotes(v_raw.trim());
    if let (Some(k), Some(v)) = (k, v) {
        env.insert(k, v);
    }
}

fn strip_quotes(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let first = *bytes.first()?;
    let last = *bytes.last()?;
    if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
        Some(s.get(1..s.len() - 1)?.to_string())
    } else {
        None
    }
}

fn materialise(
    name: &str,
    req: &PostmanRequest,
    cfg: &ApiDastConfig,
    env: &BTreeMap<String, String>,
    collection_auth: Option<&PostmanAuth>,
) -> Option<MaterialisedRequest> {
    let method = req
        .method
        .clone()
        .unwrap_or_else(|| "GET".to_string())
        .to_ascii_uppercase();
    let url_raw = build_url_raw(req.url.as_ref())?;
    let url_subst = substitute(&url_raw, env);
    let url = resolve_url(&url_subst, &cfg.base_url).ok()?;

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut authorization: Option<String> = None;

    for h in &req.header {
        if h.disabled.unwrap_or(false) {
            continue;
        }
        let (Some(key), Some(val)) = (h.key.clone(), h.value.clone()) else {
            continue;
        };
        let val = substitute(&val, env);
        if key.eq_ignore_ascii_case("authorization") {
            authorization = Some(val);
        } else {
            headers.push((key, val));
        }
    }

    // Auth precedence: per-item auth > collection auth > cfg.bearer.
    if authorization.is_none() {
        let auth_src = req.auth.as_ref().or(collection_auth);
        if let Some(a) = auth_src {
            authorization = derive_auth_header(a, env);
        }
    }
    if authorization.is_none() {
        if let Some(t) = &cfg.bearer {
            authorization = Some(format!("Bearer {t}"));
        }
    }

    let body = materialise_body(req.body.as_ref(), env);

    debug!(target: "api_dast", item = %name, method = %method, url = %url, "materialised request");
    Some(MaterialisedRequest {
        method,
        url,
        headers,
        authorization,
        body,
    })
}

fn build_url_raw(url: Option<&PostmanUrl>) -> Option<String> {
    match url? {
        PostmanUrl::Raw(s) => Some(s.clone()),
        PostmanUrl::Object(o) => o.raw.clone().or_else(|| reconstruct_url(o)),
    }
}

fn reconstruct_url(o: &PostmanUrlObject) -> Option<String> {
    let host_part = value_to_string_segments(o.host.as_ref()).join(".");
    let path_part = value_to_string_segments(o.path.as_ref()).join("/");
    let q: Vec<String> = o
        .query
        .iter()
        .filter(|q| !q.disabled.unwrap_or(false))
        .filter_map(|q| Some(format!("{}={}", q.key.as_deref()?, q.value.as_deref()?)))
        .collect();
    let mut s = String::new();
    if !host_part.is_empty() {
        s.push_str(&host_part);
    }
    if !path_part.is_empty() {
        if !host_part.is_empty() {
            s.push('/');
        }
        s.push_str(&path_part);
    }
    if !q.is_empty() {
        s.push('?');
        s.push_str(&q.join("&"));
    }
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn value_to_string_segments(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => s
            .split(['/', '.'])
            .filter(|p| !p.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Substitute `{{var}}` occurrences using `env`.
fn substitute(input: &str, env: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{{") {
        let Some(before) = rest.get(..start) else {
            break;
        };
        out.push_str(before);
        let Some(after_open) = rest.get(start + 2..) else {
            out.push_str(rest);
            return out;
        };
        if let Some(end) = after_open.find("}}") {
            let Some(key) = after_open.get(..end) else {
                out.push_str(rest);
                return out;
            };
            if let Some(value) = env.get(key.trim()) {
                out.push_str(value);
            } else {
                out.push_str("{{");
                out.push_str(key);
                out.push_str("}}");
            }
            rest = after_open.get(end + 2..).unwrap_or("");
        } else {
            out.push_str(rest);
            return out;
        }
    }
    out.push_str(rest);
    out
}

/// Resolve a possibly-relative URL against `base`.
fn resolve_url(s: &str, base: &Url) -> Result<String, DiscoveryError> {
    if let Ok(u) = Url::parse(s) {
        if u.scheme() == "http" || u.scheme() == "https" {
            return Ok(u.to_string());
        }
    }
    // Treat as path relative to base. Strip any leading slash so
    // `base.join` does not nuke the base's path.
    let normalised = s.strip_prefix('/').unwrap_or(s);
    let joined = base.join(normalised).map_err(|e| {
        DiscoveryError::config(format!("could not resolve `{s}` against base: {e}"))
    })?;
    Ok(joined.to_string())
}

fn derive_auth_header(a: &PostmanAuth, env: &BTreeMap<String, String>) -> Option<String> {
    let kind = a.auth_type.as_deref()?.to_ascii_lowercase();
    match kind.as_str() {
        "bearer" => {
            let token = a
                .bearer
                .iter()
                .find(|kv| kv.key.as_deref() == Some("token"))
                .and_then(|kv| kv.value.clone())?;
            Some(format!("Bearer {}", substitute(&token, env)))
        }
        "basic" => {
            let user = a
                .basic
                .iter()
                .find(|kv| kv.key.as_deref() == Some("username"))
                .and_then(|kv| kv.value.clone())
                .unwrap_or_default();
            let pass = a
                .basic
                .iter()
                .find(|kv| kv.key.as_deref() == Some("password"))
                .and_then(|kv| kv.value.clone())
                .unwrap_or_default();
            let user = substitute(&user, env);
            let pass = substitute(&pass, env);
            let creds = format!("{user}:{pass}");
            let encoded = base64_encode(creds.as_bytes()).unwrap_or_else(|()| String::new());
            Some(format!("Basic {encoded}"))
        }
        _ => None,
    }
}

/// Minimal base64 encoder using the standard alphabet — avoids pulling
/// the full `base64` crate dependency into `sx-discovery`.
fn base64_encode(bytes: &[u8]) -> Result<String, ()> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let b0 = *chunk.first().ok_or(())?;
        let b1 = *chunk.get(1).ok_or(())?;
        let b2 = *chunk.get(2).ok_or(())?;
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for shift in [18u32, 12, 6, 0] {
            let idx = ((n >> shift) & 0x3F) as usize;
            out.push(*ALPHABET.get(idx).ok_or(())? as char);
        }
    }
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let b0 = *rem.first().ok_or(())?;
            let n = u32::from(b0) << 16;
            for shift in [18u32, 12] {
                let idx = ((n >> shift) & 0x3F) as usize;
                out.push(*ALPHABET.get(idx).ok_or(())? as char);
            }
            out.push('=');
            out.push('=');
        }
        2 => {
            let b0 = *rem.first().ok_or(())?;
            let b1 = *rem.get(1).ok_or(())?;
            let n = (u32::from(b0) << 16) | (u32::from(b1) << 8);
            for shift in [18u32, 12, 6] {
                let idx = ((n >> shift) & 0x3F) as usize;
                out.push(*ALPHABET.get(idx).ok_or(())? as char);
            }
            out.push('=');
        }
        _ => return Err(()),
    }
    Ok(out)
}

fn materialise_body(
    body: Option<&PostmanBody>,
    env: &BTreeMap<String, String>,
) -> Option<MaterialisedBody> {
    let b = body?;
    match b.mode.as_deref() {
        Some("raw") => b
            .raw
            .as_ref()
            .map(|r| MaterialisedBody::Raw(substitute(r, env), None)),
        Some("urlencoded") => {
            let pairs: Vec<(String, String)> = b
                .urlencoded
                .iter()
                .filter(|kv| !kv.disabled.unwrap_or(false))
                .filter_map(|kv| {
                    Some((
                        kv.key.clone()?,
                        substitute(&kv.value.clone().unwrap_or_default(), env),
                    ))
                })
                .collect();
            if pairs.is_empty() {
                None
            } else {
                Some(MaterialisedBody::Form(pairs))
            }
        }
        Some("formdata") => {
            let pairs: Vec<(String, String)> = b
                .formdata
                .iter()
                .filter(|kv| !kv.disabled.unwrap_or(false))
                .filter_map(|kv| {
                    Some((
                        kv.key.clone()?,
                        substitute(&kv.value.clone().unwrap_or_default(), env),
                    ))
                })
                .collect();
            if pairs.is_empty() {
                None
            } else {
                Some(MaterialisedBody::Form(pairs))
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Dispatch + response capture
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CapturedResponse {
    status: u16,
    headers: HeaderMap,
    body: String,
}

async fn dispatch(
    client: &Client,
    req: &MaterialisedRequest,
    cfg: &ApiDastConfig,
) -> Result<CapturedResponse, DiscoveryError> {
    let method = Method::from_bytes(req.method.as_bytes())
        .map_err(|e| DiscoveryError::config(format!("invalid method `{}`: {e}", req.method)))?;
    let mut builder: RequestBuilder = client.request(method, &req.url);

    for (k, v) in &req.headers {
        if let (Ok(name), Ok(value)) = (HeaderName::try_from(k.as_str()), HeaderValue::try_from(v))
        {
            builder = builder.header(name, value);
        }
    }
    if let Some(auth) = &req.authorization {
        if let Ok(value) = HeaderValue::try_from(auth.as_str()) {
            builder = builder.header(AUTHORIZATION, value);
        }
    }
    builder = match &req.body {
        Some(MaterialisedBody::Raw(body, ct)) => {
            let mut b = builder.body(body.clone());
            if let Some(ct) = ct {
                b = b.header("content-type", ct.as_str());
            }
            b
        }
        Some(MaterialisedBody::Form(pairs)) => builder.form(pairs),
        None => builder,
    };
    builder = builder.timeout(cfg.request_timeout);

    let resp: Response = match tokio::time::timeout(cfg.request_timeout, builder.send()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) if e.is_timeout() => return Err(DiscoveryError::Timeout),
        Ok(Err(e)) => return Err(DiscoveryError::io(e.to_string())),
        Err(_) => return Err(DiscoveryError::Timeout),
    };
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let bytes = match tokio::time::timeout(cfg.request_timeout, resp.bytes()).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return Err(DiscoveryError::io(e.to_string())),
        Err(_) => return Err(DiscoveryError::Timeout),
    };
    let slice_len = bytes.len().min(cfg.max_body_bytes);
    let body = String::from_utf8_lossy(bytes.get(..slice_len).unwrap_or(&[])).into_owned();
    Ok(CapturedResponse {
        status,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------

fn analyse_response(
    req: &MaterialisedRequest,
    resp: &CapturedResponse,
    findings: &mut Vec<ApiDastFinding>,
) {
    if resp.status >= 500 && contains_stack_trace(&resp.body) {
        findings.push(
            ApiDastFinding::new(
                "verbose-error",
                "medium",
                &req.method,
                &req.url,
                format!(
                    "{} response body contains a stack-trace marker",
                    resp.status
                ),
            )
            .with_remediation(
                "return generic error pages to clients; log stack traces server-side only",
            ),
        );
    }
    if cors_is_insecure(&resp.headers) {
        findings.push(
            ApiDastFinding::new(
                "insecure-cors",
                "high",
                &req.method,
                &req.url,
                "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true",
            )
            .with_remediation(
                "either restrict ACAO to an allow-list of origins, or disable credentials on cross-origin responses",
            ),
        );
    }
}

fn contains_stack_trace(body: &str) -> bool {
    STACK_TRACE_MARKERS.iter().any(|m| body.contains(m))
}

fn cors_is_insecure(h: &HeaderMap) -> bool {
    let allow_origin = h
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let allow_creds = h
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    matches!(allow_origin, Some("*"))
        && matches!(allow_creds, Some(v) if v.eq_ignore_ascii_case("true"))
}

fn build_idor_probe(req: &MaterialisedRequest, probe_id: &str) -> Option<MaterialisedRequest> {
    let parsed = Url::parse(&req.url).ok()?;
    let original_path = parsed.path();
    let segments: Vec<&str> = original_path.split('/').collect();
    let last_idx = segments.iter().rposition(|s| !s.is_empty())?;
    let last = segments.get(last_idx)?;
    if !is_resource_id_like(last) {
        return None;
    }
    if *last == probe_id {
        return None;
    }
    let mut owned: Vec<String> = segments.iter().map(|s| (*s).to_string()).collect();
    if let Some(slot) = owned.get_mut(last_idx) {
        *slot = probe_id.to_string();
    }
    let new_path = owned.join("/");
    let mut new_url = parsed.clone();
    new_url.set_path(&new_path);
    Some(MaterialisedRequest {
        method: req.method.clone(),
        url: new_url.to_string(),
        headers: req.headers.clone(),
        authorization: req.authorization.clone(),
        body: req.body.clone(),
    })
}

fn is_resource_id_like(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // numeric ids
    if s.chars().all(|c| c.is_ascii_digit()) && s.len() <= 24 {
        return true;
    }
    // hex / uuid-ish (≥8 chars, hex + dashes)
    if s.len() >= 8
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
    {
        return true;
    }
    false
}

async fn rate_limit_burst(
    client: &Client,
    req: &MaterialisedRequest,
    cfg: &ApiDastConfig,
) -> Result<(u32, bool), DiscoveryError> {
    let mut hit_429 = false;
    let mut sent: u32 = 0;
    let deadline = tokio::time::Instant::now() + RATE_LIMIT_BURST_WINDOW;
    for _ in 0..RATE_LIMIT_BURST_COUNT {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        match dispatch(client, req, cfg).await {
            Ok(r) => {
                sent = sent.saturating_add(1);
                if r.status == 429 {
                    hit_429 = true;
                    break;
                }
            }
            Err(_) => {
                // Don't fail the whole burst on a single error — the
                // target may already be rejecting us. Treat as 'not
                // 429' and stop.
                break;
            }
        }
    }
    Ok((sent, hit_429))
}

fn dedup_findings(findings: &mut Vec<ApiDastFinding>) {
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    findings.retain(|f| seen.insert((f.check_id.clone(), f.url.clone())));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture_collection(server: &str) -> String {
        format!(
            r#"{{
"info": {{ "name": "demo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" }},
"variable": [{{ "key": "baseUrl", "value": "{server}" }}],
"item": [
  {{
    "name": "get-user",
    "request": {{
      "method": "GET",
      "url": "{{{{baseUrl}}}}/users/42",
      "header": [{{ "key": "Accept", "value": "application/json" }}]
    }}
  }},
  {{
    "name": "get-tenant",
    "request": {{
      "method": "GET",
      "url": "{{{{baseUrl}}}}/tenants/abcd1234"
    }}
  }},
  {{
    "name": "boom",
    "request": {{
      "method": "GET",
      "url": "{{{{baseUrl}}}}/boom"
    }}
  }},
  {{
    "name": "cors",
    "request": {{
      "method": "GET",
      "url": "{{{{baseUrl}}}}/cors"
    }}
  }},
  {{
    "name": "burst",
    "request": {{
      "method": "GET",
      "url": "{{{{baseUrl}}}}/free"
    }}
  }}
]
}}"#
        )
    }

    #[test]
    fn substitute_replaces_known_vars_only() {
        let mut env = BTreeMap::new();
        env.insert("baseUrl".into(), "http://h/api".into());
        assert_eq!(
            substitute("{{baseUrl}}/x/{{missing}}", &env),
            "http://h/api/x/{{missing}}"
        );
    }

    #[test]
    fn pre_request_script_sets_env() {
        let mut env = BTreeMap::new();
        apply_env_set_line(r#"pm.environment.set("token", "abc");"#, &mut env);
        apply_env_set_line(r"  pm.environment.set('uid', 'xyz') ", &mut env);
        assert_eq!(env.get("token"), Some(&"abc".to_string()));
        assert_eq!(env.get("uid"), Some(&"xyz".to_string()));
    }

    #[test]
    fn idor_probe_swaps_terminal_id_segment() {
        let req = MaterialisedRequest {
            method: "GET".into(),
            url: "http://h/users/42".into(),
            headers: vec![],
            authorization: Some("Bearer x".into()),
            body: None,
        };
        let p = build_idor_probe(&req, "999").unwrap();
        assert_eq!(p.url, "http://h/users/999");
        assert_eq!(p.authorization.as_deref(), Some("Bearer x"));
    }

    #[test]
    fn idor_probe_declines_when_no_id_segment() {
        let req = MaterialisedRequest {
            method: "GET".into(),
            url: "http://h/healthz".into(),
            headers: vec![],
            authorization: None,
            body: None,
        };
        assert!(build_idor_probe(&req, "999").is_none());
    }

    #[test]
    fn cors_detector_requires_wildcard_and_credentials() {
        let mut h = HeaderMap::new();
        h.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        h.insert(
            "access-control-allow-credentials",
            HeaderValue::from_static("true"),
        );
        assert!(cors_is_insecure(&h));

        let mut h2 = HeaderMap::new();
        h2.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        assert!(!cors_is_insecure(&h2));
    }

    #[test]
    fn verbose_error_detector_spots_traceback() {
        assert!(contains_stack_trace(
            "Internal Server Error\nTraceback (most recent call last):\n at line 1"
        ));
        assert!(!contains_stack_trace("oops"));
    }

    #[test]
    fn base64_encode_known_vectors() {
        assert_eq!(base64_encode(b"foo:bar").unwrap(), "Zm9vOmJhcg==");
        assert_eq!(base64_encode(b"u:p").unwrap(), "dTpw");
        assert_eq!(base64_encode(b"abcd").unwrap(), "YWJjZA==");
    }

    #[test]
    fn parses_minimal_collection() {
        let s = r#"{ "info": { "name": "t" }, "item": [ { "name": "x", "request": { "method": "GET", "url": "https://h/a" } } ] }"#;
        let c = PostmanCollection::parse(s.as_bytes()).unwrap();
        assert_eq!(c.name(), "t");
        let flat = flatten_items(&c);
        assert_eq!(flat.len(), 1);
        assert_eq!(flat.first().map(|f| f.name.as_str()), Some("x"));
    }

    #[tokio::test]
    async fn detects_auth_bypass() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let raw = fixture_collection(&server.uri());
        let collection = PostmanCollection::parse(raw.as_bytes()).unwrap();
        let mut cfg = ApiDastConfig::new(Url::parse(&server.uri()).unwrap()).unwrap();
        cfg.bearer = Some("test-token".into());
        cfg.idor_probe_ids.clear();

        let client = Client::builder().build().unwrap();
        let report = run_dast(&client, &collection, &cfg).await.unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.check_id == "auth-bypass" && f.url.ends_with("/users/42")));
    }

    #[tokio::test]
    async fn detects_idor_signal() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/users/999"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let raw = fixture_collection(&server.uri());
        let collection = PostmanCollection::parse(raw.as_bytes()).unwrap();
        let mut cfg = ApiDastConfig::new(Url::parse(&server.uri()).unwrap()).unwrap();
        cfg.bearer = Some("test-token".into());
        cfg.idor_probe_ids = vec!["999".into()];

        let client = Client::builder().build().unwrap();
        let report = run_dast(&client, &collection, &cfg).await.unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.check_id == "idor" && f.url.ends_with("/users/999")));
    }

    #[tokio::test]
    async fn detects_verbose_error_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/boom"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_string("Traceback (most recent call last):\n  File \"x.py\""),
            )
            .mount(&server)
            .await;
        // Make every other endpoint quietly 200 so they don't trip the
        // detector.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let raw = fixture_collection(&server.uri());
        let collection = PostmanCollection::parse(raw.as_bytes()).unwrap();
        let mut cfg = ApiDastConfig::new(Url::parse(&server.uri()).unwrap()).unwrap();
        cfg.bearer = None;
        cfg.idor_probe_ids.clear();

        let client = Client::builder().build().unwrap();
        let report = run_dast(&client, &collection, &cfg).await.unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.check_id == "verbose-error" && f.url.ends_with("/boom")));
    }

    #[tokio::test]
    async fn detects_insecure_cors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cors"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Access-Control-Allow-Origin", "*")
                    .insert_header("Access-Control-Allow-Credentials", "true"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let raw = fixture_collection(&server.uri());
        let collection = PostmanCollection::parse(raw.as_bytes()).unwrap();
        let mut cfg = ApiDastConfig::new(Url::parse(&server.uri()).unwrap()).unwrap();
        cfg.bearer = None;
        cfg.idor_probe_ids.clear();

        let client = Client::builder().build().unwrap();
        let report = run_dast(&client, &collection, &cfg).await.unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.check_id == "insecure-cors" && f.url.ends_with("/cors")));
    }

    #[tokio::test]
    async fn detects_missing_rate_limit() {
        let server = MockServer::start().await;
        // Every GET to /free returns 200 — the burst never sees a 429.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        // Trim the collection to a single GET so the burst hits /free.
        let raw = format!(
            r#"{{
"info": {{ "name": "t" }},
"variable": [{{ "key": "baseUrl", "value": "{srv}" }}],
"item": [{{ "name": "g", "request": {{ "method": "GET", "url": "{{{{baseUrl}}}}/free" }} }}]
}}"#,
            srv = server.uri()
        );
        let collection = PostmanCollection::parse(raw.as_bytes()).unwrap();
        let mut cfg = ApiDastConfig::new(Url::parse(&server.uri()).unwrap()).unwrap();
        cfg.bearer = None;
        cfg.idor_probe_ids.clear();
        cfg.request_timeout = Duration::from_secs(2);

        let client = Client::builder().build().unwrap();
        let report = run_dast(&client, &collection, &cfg).await.unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.check_id == "rate-limit-missing"));
    }
}
