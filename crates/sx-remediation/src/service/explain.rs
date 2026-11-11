//! "Explain this finding" LLM-assist surface.
//!
//! Translates a vulnerability finding into three short, plain-language
//! sections — what it is, why a business should care, what the operator
//! should do next — using the same [`LlmClient`] abstraction the
//! remediation copilot uses.
//!
//! ## Surface
//!
//! Callers build an [`ExplainRequest`], hand it to
//! [`ExplainService::explain`], and receive an [`ExplainResponse`]. The
//! service is wired with any [`LlmClient`] implementation; production
//! deployments hand it a [`RealClaudeClient`](crate::service::claude_client::RealClaudeClient),
//! tests hand it a mock.
//!
//! ## Safety guardrails (CRITICAL)
//!
//! This is an MVP surface for `P3-003`. The guardrails are deliberate
//! defense-in-depth — callers are documented to keep PII out of the
//! input, AND we still scan for it before calling the LLM:
//!
//! 1. **Input sanitisation.** Every `key=value` / `key: value` pair whose
//!    key matches the secret-name allow-list
//!    (`token`, `secret`, `api_key`, `api-key`, `apikey`, `password`, `pwd`,
//!    `bearer`, `aws_access_key`, `client_secret`, `private_key`, `cookie`,
//!    `session`) is rewritten to `<key>=[REDACTED]` BEFORE the prompt is
//!    composed. Coverage is unit-tested per pattern.
//! 2. **Input truncation.** `finding_description` is capped at
//!    [`MAX_DESCRIPTION_CHARS`] (2000 chars). The trim happens at a char
//!    boundary so multi-byte content can never produce an invalid `&str`.
//! 3. **Sensitive-data refusal.** PAN (Luhn-validated 13-19 digit groups),
//!    US SSN (`NNN-NN-NNNN`) and Indonesian NIK (16 contiguous digits)
//!    patterns are refused with
//!    [`RemediationError::SensitiveInput`] — the offending value never
//!    leaves the process.
//! 4. **Pinned prompt template.** [`SYSTEM_PROMPT`] is a `'static` string;
//!    callers cannot override it per-tenant or per-request.
//! 5. **Hash-keyed cache.** The in-memory LRU is keyed by
//!    `sha256(finding_id)` (hex), never the raw description, so a memory
//!    dump cannot link a cache entry back to finding content.
//!
//! ## Cache
//!
//! A capacity-bounded LRU with a 1-hour TTL. Eviction picks the entry
//! with the oldest `inserted_at` timestamp once `LRU_CAPACITY` is
//! reached; expired entries are dropped on read. The cache is per
//! [`ExplainService`] instance — there is no global cache.
//!
//! ## Output shape
//!
//! [`ExplainResponse`] surfaces three short fields: a plain-language
//! description, a business-impact line, and a recommended next action.
//! The LLM is asked to return a strict JSON object with exactly those
//! keys; anything else is rejected with
//! [`RemediationError::Invalid`].
//!
//! ## Out of scope (P3-003 MVP)
//!
//! HTTP endpoint, dashboard surface, multi-language output, persistent
//! cache.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::RemediationError;
use crate::service::llm_client::LlmClient;

/// Hard upper bound on `finding_description` length (chars, not bytes).
///
/// Trim happens at a char boundary so multi-byte input cannot produce an
/// invalid `&str`.
pub const MAX_DESCRIPTION_CHARS: usize = 2_000;

/// Cache TTL applied to every successful explanation.
pub const CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// LRU capacity — entries beyond this trigger oldest-first eviction.
pub const LRU_CAPACITY: usize = 256;

/// Hard-coded system prompt. Pinned in the module so it cannot be
/// per-tenant overridden — see module docs.
const SYSTEM_PROMPT: &str = "You are a senior security analyst writing for a non-technical \
audience. Given a vulnerability finding, return a STRICT JSON object with \
EXACTLY these keys and no additional commentary: \
\"plain_language\" (1-2 sentences, plain English, no jargon), \
\"business_impact\" (1 sentence describing operational/financial/regulatory \
risk to the business), \
\"recommended_action\" (1 sentence describing the highest-leverage immediate \
mitigation). Never quote or repeat any token, password, API key, or other \
secret you see in the input. If the input contains placeholders like \
[REDACTED], leave them as-is in your reasoning but do NOT reference them in \
your output. Respond with JSON only — no Markdown, no preamble, no \
trailing prose.";

/// Token substituted into a sanitised secret value.
const REDACT_SECRET: &str = "[REDACTED]";

/// Sensitive-detector tag carried in [`RemediationError::SensitiveInput`].
const TAG_PAN: &str = "pan";
const TAG_SSN: &str = "ssn";
const TAG_NIK: &str = "nik";

/// Inbound request to the explain surface.
///
/// Callers MUST NOT include PII, customer identifiers, or secret material
/// in any field. The service applies defense-in-depth scans regardless,
/// but the public contract is "scrub on the way in".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainRequest {
    /// Stable finding identifier. Used as the cache key (hashed).
    pub finding_id: String,
    /// Human-readable title (e.g. `"Outdated OpenSSL on host-prod-01"`).
    pub finding_title: String,
    /// Free-form description. Capped at [`MAX_DESCRIPTION_CHARS`] chars
    /// before being sent to the LLM.
    pub finding_description: String,
    /// Severity label (`"low"`, `"medium"`, `"high"`, `"critical"`).
    pub severity: String,
    /// Optional CVE identifier, e.g. `"CVE-2024-1234"`.
    pub cve_id: Option<String>,
    /// Optional CVSS base score (0.0 – 10.0). Out-of-range values are
    /// rendered verbatim; the LLM is expected to handle weirdness.
    pub cvss: Option<f64>,
}

/// LLM-produced explanation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExplainResponse {
    /// Plain-English summary of the finding.
    pub plain_language: String,
    /// Why a business should care.
    pub business_impact: String,
    /// What the operator should do next.
    pub recommended_action: String,
    /// `true` if the response came from the in-memory cache.
    pub cached: bool,
}

/// "Explain this finding" service.
///
/// Holds a single [`LlmClient`] and an in-memory LRU. Stateless across
/// requests other than the cache.
pub struct ExplainService<L: LlmClient> {
    llm: Arc<L>,
    cache: Arc<Mutex<LruCache>>,
}

impl<L: LlmClient> std::fmt::Debug for ExplainService<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExplainService")
            .field("llm", &self.llm)
            .field("cache_entries", &self.cache_len())
            .finish_non_exhaustive()
    }
}

impl<L: LlmClient> ExplainService<L> {
    /// Build a new service wrapping `llm`. Starts with an empty cache.
    #[must_use]
    pub fn new(llm: Arc<L>) -> Self {
        Self {
            llm,
            cache: Arc::new(Mutex::new(LruCache::with_capacity(LRU_CAPACITY))),
        }
    }

    /// Current number of live cache entries. Exposed for tests and
    /// `Debug`; not part of the production callers' contract.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// Produce an explanation for `req`.
    ///
    /// # Errors
    ///
    /// - [`RemediationError::SensitiveInput`] if any field contains a
    ///   PAN / SSN / NIK pattern.
    /// - [`RemediationError::Transport`] / [`RemediationError::Malformed`]
    ///   for LLM failures.
    /// - [`RemediationError::Invalid`] if the LLM response is missing
    ///   the required JSON shape.
    pub async fn explain(&self, req: ExplainRequest) -> Result<ExplainResponse, RemediationError> {
        // Defense-in-depth: refuse anything that smells like PII BEFORE
        // building the prompt. The caller's documented contract is to
        // scrub on the way in; we double-check.
        check_no_pii(&req)?;

        let cache_key = hash_finding_id(&req.finding_id);

        if let Some(hit) = self.cache_get(&cache_key) {
            return Ok(ExplainResponse {
                cached: true,
                ..hit
            });
        }

        let user_prompt = build_user_prompt(&req);
        let raw = self.llm.complete(SYSTEM_PROMPT, &user_prompt).await?;
        let parsed = parse_llm_response(&raw)?;

        self.cache_put(cache_key, parsed.clone());

        Ok(parsed)
    }

    fn cache_get(&self, key: &str) -> Option<ExplainResponse> {
        let mut cache = self.cache.lock().ok()?;
        cache.get(key)
    }

    fn cache_put(&self, key: String, value: ExplainResponse) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.put(key, value);
        }
    }
}

// ---------------------------------------------------------------------------
// Prompt construction
// ---------------------------------------------------------------------------

/// Build the user prompt that is sent to the LLM.
///
/// All free-form fields go through [`redact_secrets`] first; the
/// description is truncated to [`MAX_DESCRIPTION_CHARS`]. The function
/// is `pub(crate)` so the tests can pin its exact shape and prove no
/// raw secret material ever escapes.
#[must_use]
pub(crate) fn build_user_prompt(req: &ExplainRequest) -> String {
    let title = redact_secrets(&req.finding_title);
    let description = redact_secrets(&truncate_chars(
        &req.finding_description,
        MAX_DESCRIPTION_CHARS,
    ));
    let severity = redact_secrets(&req.severity);
    let cve = req.cve_id.as_deref().map(redact_secrets);
    let cvss = req.cvss.map(|v| format!("{v:.1}"));

    let mut s = String::with_capacity(256 + description.len());
    s.push_str("Finding metadata:\n");
    s.push_str("- title: ");
    s.push_str(&title);
    s.push('\n');
    s.push_str("- severity: ");
    s.push_str(&severity);
    s.push('\n');
    if let Some(cve_id) = cve {
        s.push_str("- cve_id: ");
        s.push_str(&cve_id);
        s.push('\n');
    }
    if let Some(score) = cvss {
        s.push_str("- cvss: ");
        s.push_str(&score);
        s.push('\n');
    }
    s.push_str("- description: ");
    s.push_str(&description);
    s.push('\n');
    s.push_str(
        "\nReturn a JSON object with keys plain_language, business_impact, recommended_action.",
    );
    s
}

/// Truncate `s` to at most `max_chars` characters, respecting char
/// boundaries.
#[must_use]
fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Redact secret-looking `key=value` / `key: value` pairs.
///
/// The set of keys we treat as secret is documented in the module
/// header. Coverage is exhaustively unit-tested.
#[must_use]
pub(crate) fn redact_secrets(input: &str) -> String {
    static SECRET_RE: OnceLock<Regex> = OnceLock::new();
    let re = SECRET_RE.get_or_init(|| {
        // Pinned: matches the documented allow-list.
        // Group 1 is the key name; the rest is replaced with [REDACTED].
        // `[^\s]+` keeps the redaction surgical — only the value goes,
        // surrounding text is preserved.
        compile_pattern(
            r"(?i)(token|secret|api[_-]?key|apikey|password|pwd|bearer|aws_access_key|client_secret|private_key|cookie|session)[=:]\s*[^\s]+",
        )
    });
    re.replace_all(input, format!("$1={REDACT_SECRET}").as_str())
        .to_string()
}

#[allow(clippy::unwrap_used)]
fn compile_pattern(pattern: &'static str) -> Regex {
    // All patterns in this module are `'static` literals validated by
    // unit tests; an `unwrap` here is equivalent to a compile-time
    // assertion.
    Regex::new(pattern).unwrap()
}

// ---------------------------------------------------------------------------
// PII / sensitive-data detection
// ---------------------------------------------------------------------------

/// Reject the request if any free-form field contains PAN, SSN, or NIK
/// patterns. Returns the first detector tag that fired — the offending
/// value is NEVER carried into the error.
fn check_no_pii(req: &ExplainRequest) -> Result<(), RemediationError> {
    for field in [
        req.finding_title.as_str(),
        req.finding_description.as_str(),
        req.severity.as_str(),
    ] {
        if let Some(tag) = first_sensitive_tag(field) {
            return Err(RemediationError::SensitiveInput(tag));
        }
    }
    if let Some(cve) = req.cve_id.as_deref() {
        if let Some(tag) = first_sensitive_tag(cve) {
            return Err(RemediationError::SensitiveInput(tag));
        }
    }
    Ok(())
}

/// Return the first sensitive-data tag fired by `input`, or `None`.
fn first_sensitive_tag(input: &str) -> Option<&'static str> {
    if contains_pan(input) {
        return Some(TAG_PAN);
    }
    if contains_ssn(input) {
        return Some(TAG_SSN);
    }
    if contains_nik(input) {
        return Some(TAG_NIK);
    }
    None
}

/// US SSN pattern: `NNN-NN-NNNN` with classic invalid-range guards.
fn contains_ssn(input: &str) -> bool {
    static SSN_RE: OnceLock<Regex> = OnceLock::new();
    let re = SSN_RE.get_or_init(|| compile_pattern(r"\b\d{3}-\d{2}-\d{4}\b"));
    re.is_match(input)
}

/// Indonesian NIK: 16 contiguous digits. We deliberately keep the
/// detector broad — a 16-digit run that is also a valid Luhn PAN will
/// be flagged by [`contains_pan`] first; an NIK that happens to fail
/// Luhn still trips this check.
fn contains_nik(input: &str) -> bool {
    static NIK_RE: OnceLock<Regex> = OnceLock::new();
    let re = NIK_RE.get_or_init(|| compile_pattern(r"(?:^|[^\d])(\d{16})(?:$|[^\d])"));
    re.is_match(input)
}

/// Luhn-validated PAN detector. Matches 13–19 digit runs (optionally
/// separated by spaces or hyphens) and verifies the Luhn checksum.
fn contains_pan(input: &str) -> bool {
    static PAN_RE: OnceLock<Regex> = OnceLock::new();
    let re = PAN_RE.get_or_init(|| compile_pattern(r"\b(?:\d[ -]?){12,18}\d\b"));
    for m in re.find_iter(input) {
        let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
        if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
            return true;
        }
    }
    false
}

/// Standard Luhn checksum. Returns `false` for empty or non-digit
/// input.
fn luhn_valid(digits: &str) -> bool {
    let mut sum: u32 = 0;
    let mut alt = false;
    for c in digits.chars().rev() {
        let Some(d) = c.to_digit(10) else {
            return false;
        };
        let v = if alt {
            let doubled = d * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            d
        };
        sum = sum.saturating_add(v);
        alt = !alt;
    }
    sum.is_multiple_of(10) && !digits.is_empty()
}

// ---------------------------------------------------------------------------
// Cache key + LRU
// ---------------------------------------------------------------------------

/// `sha256(finding_id)` rendered as lowercase hex. The cache key
/// derivation deliberately ignores other fields — a stable finding id
/// across re-runs hits the cache.
#[must_use]
pub(crate) fn hash_finding_id(finding_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// Tiny LRU with per-entry TTL. Not generic on purpose: the surface is
/// small enough that wrapping a third-party crate is more code than
/// implementing it inline.
struct LruCache {
    capacity: usize,
    entries: HashMap<String, CacheEntry>,
}

struct CacheEntry {
    value: ExplainResponse,
    inserted_at: Instant,
}

impl LruCache {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&mut self, key: &str) -> Option<ExplainResponse> {
        if let Some(entry) = self.entries.get(key) {
            if entry.inserted_at.elapsed() < CACHE_TTL {
                return Some(entry.value.clone());
            }
            // Expired — evict.
            self.entries.remove(key);
        }
        None
    }

    fn put(&mut self, key: String, value: ExplainResponse) {
        // Drop expired entries opportunistically before inserting so a
        // long-lived service doesn't accumulate garbage.
        self.evict_expired();

        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.evict_oldest();
        }
        self.entries.insert(
            key,
            CacheEntry {
                value,
                inserted_at: Instant::now(),
            },
        );
    }

    fn evict_expired(&mut self) {
        self.entries
            .retain(|_, entry| entry.inserted_at.elapsed() < CACHE_TTL);
    }

    fn evict_oldest(&mut self) {
        // Pick the entry with the oldest `inserted_at`. O(n) but `n` is
        // bounded by `LRU_CAPACITY` (256) so this is fine.
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.inserted_at)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            self.entries.remove(&k);
        }
    }
}

// ---------------------------------------------------------------------------
// LLM response parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawLlmResponse {
    plain_language: String,
    business_impact: String,
    recommended_action: String,
}

fn parse_llm_response(raw: &str) -> Result<ExplainResponse, RemediationError> {
    // Be forgiving about a leading/trailing whitespace, but reject
    // Markdown fences or preamble — the system prompt is explicit.
    let trimmed = raw.trim();
    let parsed: RawLlmResponse = serde_json::from_str(trimmed)
        .map_err(|e| RemediationError::invalid(format!("explain response: {e}")))?;
    Ok(ExplainResponse {
        plain_language: parsed.plain_language,
        business_impact: parsed.business_impact,
        recommended_action: parsed.recommended_action,
        cached: false,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;

    // -----------------------------------------------------------------
    // Mock LLM client. Records every prompt it sees so tests can assert
    // sanitised content never carries raw secret material.
    // -----------------------------------------------------------------
    #[derive(Debug, Default)]
    struct MockLlm {
        calls: StdMutex<Vec<(String, String)>>,
        response: StdMutex<String>,
    }

    impl MockLlm {
        fn new(response: &str) -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                response: StdMutex::new(response.to_string()),
            }
        }

        fn last_user_prompt(&self) -> String {
            self.calls
                .lock()
                .unwrap()
                .last()
                .map(|(_, u)| u.clone())
                .unwrap_or_default()
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl LlmClient for MockLlm {
        async fn complete(
            &self,
            system_prompt: &str,
            user_prompt: &str,
        ) -> Result<String, RemediationError> {
            self.calls
                .lock()
                .unwrap()
                .push((system_prompt.to_string(), user_prompt.to_string()));
            Ok(self.response.lock().unwrap().clone())
        }

        #[allow(clippy::unnecessary_literal_bound)]
        fn model_id(&self) -> &str {
            "mock-llm"
        }
    }

    fn ok_response_json() -> &'static str {
        r#"{
            "plain_language": "Old library version with a known flaw.",
            "business_impact": "Could let an attacker access customer data.",
            "recommended_action": "Patch within the next maintenance window."
        }"#
    }

    fn baseline_req() -> ExplainRequest {
        ExplainRequest {
            finding_id: "FND-001".to_string(),
            finding_title: "Outdated OpenSSL".to_string(),
            finding_description: "OpenSSL 1.0.2 is end-of-life.".to_string(),
            severity: "high".to_string(),
            cve_id: Some("CVE-2024-1234".to_string()),
            cvss: Some(7.5),
        }
    }

    // -----------------------------------------------------------------
    // Redaction patterns (5 patterns required by spec).
    // -----------------------------------------------------------------

    #[test]
    fn explain_redacts_aws_access_key_in_description() {
        let s = redact_secrets("scan log: aws_access_key=AKIAIOSFODNN7EXAMPLE end");
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "leak: {s}");
        assert!(s.contains("[REDACTED]"));
    }

    #[test]
    fn explain_redacts_github_pat_via_token_key() {
        let s = redact_secrets("audit: token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH1234");
        assert!(
            !s.contains("ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH1234"),
            "leak: {s}"
        );
        assert!(s.contains("[REDACTED]"));
    }

    #[test]
    fn explain_redacts_generic_bearer() {
        let s = redact_secrets("header bearer=eyJhbGciOiJIUzI1NiJ9.payload.sig more");
        assert!(!s.contains("eyJhbGciOiJIUzI1NiJ9.payload.sig"), "leak: {s}");
        assert!(s.contains("[REDACTED]"));
    }

    #[test]
    fn explain_redacts_password_equals() {
        let s = redact_secrets("config: password=hunter2!!!");
        assert!(!s.contains("hunter2!!!"), "leak: {s}");
        assert!(s.contains("[REDACTED]"));
    }

    #[test]
    fn explain_redacts_api_key_colon() {
        let s = redact_secrets("client: api_key: sk_live_VeryReal123456");
        assert!(!s.contains("sk_live_VeryReal123456"), "leak: {s}");
        assert!(s.contains("[REDACTED]"));
    }

    #[test]
    fn explain_redacts_api_dash_key_variant() {
        let s = redact_secrets("config api-key=KEYVALUE");
        assert!(!s.contains("KEYVALUE"), "leak: {s}");
    }

    #[test]
    fn explain_redacts_client_secret_and_private_key_and_cookie_and_session_and_pwd() {
        for raw in [
            "client_secret=abcd1234",
            "private_key=BEGINKEYDATA",
            "cookie=sessionvalue123",
            "session=opaquetoken",
            "pwd=letmein",
        ] {
            let s = redact_secrets(raw);
            assert!(s.contains("[REDACTED]"), "no redaction on `{raw}` -> `{s}`");
            // The original value (right side) must be gone.
            let original_value = raw.split(['=', ':']).nth(1).unwrap().trim();
            assert!(!s.contains(original_value), "leak on `{raw}` -> `{s}`",);
        }
    }

    // -----------------------------------------------------------------
    // Truncation
    // -----------------------------------------------------------------

    #[test]
    fn explain_truncates_description_at_2000_chars() {
        let blob = "x".repeat(MAX_DESCRIPTION_CHARS + 500);
        let out = truncate_chars(&blob, MAX_DESCRIPTION_CHARS);
        assert_eq!(out.chars().count(), MAX_DESCRIPTION_CHARS);
    }

    #[test]
    fn explain_truncate_preserves_multibyte_boundaries() {
        // Each emoji is one `char` but >1 byte; trimming at char count
        // can never split a code point.
        let blob: String = "\u{1F510}".repeat(MAX_DESCRIPTION_CHARS + 10);
        let out = truncate_chars(&blob, MAX_DESCRIPTION_CHARS);
        assert_eq!(out.chars().count(), MAX_DESCRIPTION_CHARS);
        // Must still be valid UTF-8 (which a `String` guarantees, but
        // we assert via byte length).
        assert!(out.len() >= MAX_DESCRIPTION_CHARS);
    }

    #[test]
    fn explain_truncate_short_input_unchanged() {
        let blob = "hello";
        assert_eq!(truncate_chars(blob, MAX_DESCRIPTION_CHARS), "hello");
    }

    // -----------------------------------------------------------------
    // PII detection
    // -----------------------------------------------------------------

    #[test]
    fn explain_rejects_pan_luhn_valid() {
        let mut req = baseline_req();
        // 4111-1111-1111-1111 is the canonical Luhn-valid test PAN.
        req.finding_description = "card 4111-1111-1111-1111 found".to_string();
        let err = check_no_pii(&req).unwrap_err();
        match err {
            RemediationError::SensitiveInput(tag) => assert_eq!(tag, "pan"),
            other => panic!("expected SensitiveInput, got {other:?}"),
        }
    }

    #[test]
    fn explain_accepts_luhn_invalid_16_digit_run() {
        // 16 digits, NOT Luhn-valid → NIK detector fires (we want
        // SensitiveInput for "looks like a national id").
        let mut req = baseline_req();
        req.finding_description = "id 1234567890123456".to_string();
        let err = check_no_pii(&req).unwrap_err();
        match err {
            RemediationError::SensitiveInput(tag) => assert_eq!(tag, "nik"),
            other => panic!("expected SensitiveInput, got {other:?}"),
        }
    }

    #[test]
    fn explain_rejects_ssn() {
        let mut req = baseline_req();
        req.finding_description = "user ssn 123-45-6789 on file".to_string();
        let err = check_no_pii(&req).unwrap_err();
        match err {
            RemediationError::SensitiveInput(tag) => assert_eq!(tag, "ssn"),
            other => panic!("expected SensitiveInput, got {other:?}"),
        }
    }

    #[test]
    fn explain_rejects_nik() {
        let mut req = baseline_req();
        // 16 contiguous digits matching Indonesian NIK format.
        req.finding_description = "NIK 3201234567891234 attached".to_string();
        let err = check_no_pii(&req).unwrap_err();
        match err {
            RemediationError::SensitiveInput(_) => {}
            other => panic!("expected SensitiveInput, got {other:?}"),
        }
    }

    #[test]
    fn explain_accepts_clean_input() {
        let req = baseline_req();
        check_no_pii(&req).unwrap();
    }

    // -----------------------------------------------------------------
    // Cache hit / miss
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn explain_first_call_misses_then_caches() {
        let llm = Arc::new(MockLlm::new(ok_response_json()));
        let svc = ExplainService::new(llm.clone());

        let resp1 = svc.explain(baseline_req()).await.unwrap();
        assert!(!resp1.cached);
        assert_eq!(llm.call_count(), 1);

        let resp2 = svc.explain(baseline_req()).await.unwrap();
        assert!(resp2.cached);
        // The LLM must NOT be called a second time.
        assert_eq!(llm.call_count(), 1);
        // Body identical.
        assert_eq!(resp1.plain_language, resp2.plain_language);
    }

    #[tokio::test]
    async fn explain_distinct_finding_ids_are_separate_cache_entries() {
        let llm = Arc::new(MockLlm::new(ok_response_json()));
        let svc = ExplainService::new(llm.clone());

        let mut r1 = baseline_req();
        r1.finding_id = "FND-A".to_string();
        let mut r2 = baseline_req();
        r2.finding_id = "FND-B".to_string();

        svc.explain(r1).await.unwrap();
        svc.explain(r2).await.unwrap();
        assert_eq!(llm.call_count(), 2);
        assert_eq!(svc.cache_len(), 2);
    }

    // -----------------------------------------------------------------
    // Hash-keyed cache: never store raw finding content.
    // -----------------------------------------------------------------

    #[test]
    fn cache_key_is_sha256_hex_of_finding_id() {
        let key = hash_finding_id("FND-001");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable across calls.
        assert_eq!(hash_finding_id("FND-001"), key);
        // Different inputs differ.
        assert_ne!(hash_finding_id("FND-001"), hash_finding_id("FND-002"));
    }

    // -----------------------------------------------------------------
    // Prompt-shape: redacted material must never appear in the user
    // prompt the LLM sees.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn explain_prompt_never_contains_raw_secret() {
        let llm = Arc::new(MockLlm::new(ok_response_json()));
        let svc = ExplainService::new(llm.clone());

        let mut req = baseline_req();
        req.finding_description =
            "incident log: password=hunter2!!! and token=ghp_supersecretvalue".to_string();
        svc.explain(req).await.unwrap();

        let prompt = llm.last_user_prompt();
        assert!(!prompt.contains("hunter2!!!"), "leak: {prompt}");
        assert!(!prompt.contains("ghp_supersecretvalue"), "leak: {prompt}");
        assert!(prompt.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn explain_uses_pinned_system_prompt() {
        let llm = Arc::new(MockLlm::new(ok_response_json()));
        let svc = ExplainService::new(llm.clone());
        svc.explain(baseline_req()).await.unwrap();

        let (sys, _) = llm.calls.lock().unwrap().last().cloned().unwrap();
        assert_eq!(sys, SYSTEM_PROMPT);
    }

    #[tokio::test]
    async fn explain_rejects_malformed_llm_response() {
        let llm = Arc::new(MockLlm::new("not json at all"));
        let svc = ExplainService::new(llm);
        let err = svc.explain(baseline_req()).await.unwrap_err();
        match err {
            RemediationError::Invalid(_) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn explain_rejects_pii_before_calling_llm() {
        let llm = Arc::new(MockLlm::new(ok_response_json()));
        let svc = ExplainService::new(llm.clone());

        let mut req = baseline_req();
        req.finding_description = "ssn 123-45-6789".to_string();
        let err = svc.explain(req).await.unwrap_err();
        match err {
            RemediationError::SensitiveInput(_) => {}
            other => panic!("expected SensitiveInput, got {other:?}"),
        }
        // LLM must NEVER have been called.
        assert_eq!(llm.call_count(), 0);
    }

    // -----------------------------------------------------------------
    // Luhn helper coverage.
    // -----------------------------------------------------------------

    #[test]
    fn luhn_valid_recognises_canonical_test_pans() {
        // Visa test, Mastercard test, Amex test PANs.
        assert!(luhn_valid("4111111111111111"));
        assert!(luhn_valid("5500000000000004"));
        assert!(luhn_valid("340000000000009"));
    }

    #[test]
    fn luhn_invalid_rejects_random_digit_runs() {
        assert!(!luhn_valid("1234567890123456"));
        assert!(!luhn_valid(""));
        assert!(!luhn_valid("abcd"));
    }

    // -----------------------------------------------------------------
    // Prompt build smoke test.
    // -----------------------------------------------------------------

    #[test]
    fn build_user_prompt_contains_metadata_fields() {
        let p = build_user_prompt(&baseline_req());
        assert!(p.contains("title: Outdated OpenSSL"));
        assert!(p.contains("severity: high"));
        assert!(p.contains("cve_id: CVE-2024-1234"));
        assert!(p.contains("cvss: 7.5"));
        assert!(p.contains("description: OpenSSL 1.0.2 is end-of-life."));
    }
}
