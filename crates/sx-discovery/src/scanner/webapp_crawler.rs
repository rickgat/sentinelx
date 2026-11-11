//! Same-origin asynchronous web-application crawler.
//!
//! Performs a BFS from a starting URL, fetching each page once, extracting
//! anchor `href`, `<form>` actions+methods, and `<script src>` URLs. The
//! crawler is deliberately conservative:
//!
//! * **same-origin only** — links that resolve to a different scheme,
//!   host, or port are pushed to `queued_outside_scope` and never fetched;
//! * **robots.txt-respecting** — when `respect_robots == true`, a
//!   `robots.txt` is fetched once per origin and `Disallow` rules for the
//!   `*` user-agent group are obeyed;
//! * **rate-limited** — at most 4 requests / second / host (token bucket
//!   stored on the crawler instance);
//! * **bounded** — `max_depth` and `max_urls` are both honoured; the
//!   crawl additionally aborts after a 5-minute total wall clock and a
//!   10-second per-request timeout.
//!
//! The HTML extractor is intentionally lightweight and dependency-free:
//! it scans the byte stream for `<a`, `<form`, `<script` tags and pulls
//! the relevant attributes. This is sufficient for asset enumeration
//! (the use case here) without dragging in a full HTML5 parser.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use tokio::sync::Mutex;
use tokio::time::{timeout as tokio_timeout, Instant as TokioInstant};
use url::Url;

use crate::error::DiscoveryError;

/// Default per-request timeout (10 s).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default total budget for one crawl (5 min).
pub const DEFAULT_CRAWL_BUDGET: Duration = Duration::from_secs(5 * 60);

/// Default per-host request rate (4 req / s).
pub const DEFAULT_RATE_PER_SEC: u32 = 4;

/// A single form discovered on a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormSpec {
    /// `method` attribute, uppercased; defaults to `"GET"`.
    pub method: String,
    /// `action` attribute resolved against the page URL. `None` when the
    /// form had no `action` (interpreted by browsers as "POST to self";
    /// we record the absence so callers can decide).
    pub action: Option<Url>,
}

/// A single page that was successfully fetched.
#[derive(Debug, Clone)]
pub struct VisitedPage {
    /// URL that was actually fetched (post-redirect canonicalisation by
    /// `reqwest`'s default policy is not applied — we use the request URL).
    pub url: Url,
    /// HTTP status code returned by the server.
    pub status: u16,
    /// Same-origin links discovered in `<a href>` attributes.
    pub links: Vec<Url>,
    /// Forms discovered on the page.
    pub forms: Vec<FormSpec>,
    /// Script `src` URLs (same-origin only).
    pub scripts: Vec<Url>,
}

/// Aggregated crawl output.
#[derive(Debug, Clone, Default)]
pub struct CrawlReport {
    /// Pages fetched, in BFS visit order.
    pub visited: Vec<VisitedPage>,
    /// Off-origin URLs (or URLs blocked by `robots.txt` / depth / cap)
    /// recorded but never fetched.
    pub queued_outside_scope: Vec<Url>,
}

/// Per-host rate-limit state.
#[derive(Debug, Default)]
struct HostBucket {
    /// Last time a token was consumed for this host.
    last_consumed: Option<TokioInstant>,
}

/// Same-origin web-application crawler.
#[derive(Debug, Clone)]
pub struct WebappCrawler {
    /// HTTP client used for every fetch (caller-built).
    pub http: Client,
    /// Maximum link depth from the start URL (0 = only fetch the seed).
    pub max_depth: u32,
    /// Hard cap on the number of pages fetched.
    pub max_urls: usize,
    /// Whether `robots.txt` should be honoured.
    pub respect_robots: bool,
    /// Per-request timeout — defaults to [`DEFAULT_REQUEST_TIMEOUT`].
    pub request_timeout: Duration,
    /// Total crawl budget — defaults to [`DEFAULT_CRAWL_BUDGET`].
    pub crawl_budget: Duration,
    /// Per-host request rate — defaults to [`DEFAULT_RATE_PER_SEC`].
    pub rate_per_sec: u32,
}

impl WebappCrawler {
    /// Build a new crawler with sane defaults for timeout / budget / rate.
    #[must_use]
    pub const fn new(http: Client, max_depth: u32, max_urls: usize, respect_robots: bool) -> Self {
        Self {
            http,
            max_depth,
            max_urls,
            respect_robots,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            crawl_budget: DEFAULT_CRAWL_BUDGET,
            rate_per_sec: DEFAULT_RATE_PER_SEC,
        }
    }

    /// Run the crawl from `start`.
    ///
    /// # Errors
    ///
    /// * [`DiscoveryError::Config`]  — `start` is not http(s) or has no host.
    /// * [`DiscoveryError::Timeout`] — the total crawl budget was exhausted.
    /// * [`DiscoveryError::Io`]      — the seed page itself could not be
    ///   fetched (transient errors on follow-up pages are logged and the
    ///   URL is recorded in `queued_outside_scope`).
    pub async fn crawl(&self, start: Url) -> Result<CrawlReport, DiscoveryError> {
        let origin = Origin::from_url(&start)?;
        let started_at = Instant::now();

        let robots = if self.respect_robots {
            Some(self.fetch_robots(&origin).await)
        } else {
            None
        };

        let buckets: Arc<Mutex<HashMap<String, HostBucket>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut report = CrawlReport::default();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(Url, u32)> = VecDeque::new();
        queue.push_back((start.clone(), 0));

        let mut seed_attempted = false;
        while let Some((url, depth)) = queue.pop_front() {
            if started_at.elapsed() > self.crawl_budget {
                return Err(DiscoveryError::Timeout);
            }
            if report.visited.len() >= self.max_urls {
                report.queued_outside_scope.push(url);
                continue;
            }
            if !visited.insert(url.as_str().to_owned()) {
                continue;
            }
            if !origin.matches(&url) {
                report.queued_outside_scope.push(url);
                continue;
            }
            if let Some(rb) = robots.as_ref() {
                if !rb.allowed(url.path()) {
                    report.queued_outside_scope.push(url);
                    continue;
                }
            }

            self.wait_for_token(&buckets, &origin.host).await;

            let is_seed = !seed_attempted;
            seed_attempted = true;
            let fetched = match self.fetch_html(&url).await {
                Ok(p) => p,
                Err(e) if is_seed => return Err(e),
                Err(_) => {
                    report.queued_outside_scope.push(url);
                    continue;
                }
            };

            let page = extract_page(&url, fetched.status, &fetched.body, &origin);
            let next_links: Vec<Url> = page.links.clone();
            report.visited.push(page);

            if depth < self.max_depth {
                for link in next_links {
                    queue.push_back((link, depth + 1));
                }
            }
        }

        Ok(report)
    }

    /// Acquire a token for the given host. Blocks until the per-host
    /// rate limit allows a new request.
    async fn wait_for_token(&self, buckets: &Mutex<HashMap<String, HostBucket>>, host: &str) {
        let min_gap = Duration::from_secs_f64(1.0 / f64::from(self.rate_per_sec.max(1)));
        loop {
            let wait = compute_wait(buckets, host, min_gap).await;
            if wait.is_zero() {
                return;
            }
            tokio::time::sleep(wait).await;
        }
    }

    /// Fetch `robots.txt` for `origin`. Network failures yield a
    /// permissive parser (everything allowed).
    async fn fetch_robots(&self, origin: &Origin) -> RobotsRules {
        let Ok(mut url) = Url::parse(&format!("{}://{}", origin.scheme, origin.host_with_port()))
        else {
            return RobotsRules::allow_all();
        };
        url.set_path("/robots.txt");
        match tokio_timeout(self.request_timeout, self.http.get(url).send()).await {
            Ok(Ok(resp)) if resp.status().is_success() => resp.text().await.map_or_else(
                |_| RobotsRules::allow_all(),
                |body| RobotsRules::parse(&body),
            ),
            _ => RobotsRules::allow_all(),
        }
    }

    /// Fetch a URL and return the body as a UTF-8 string (lossy on bad
    /// bytes — extraction is permissive).
    async fn fetch_html(&self, url: &Url) -> Result<FetchedPage, DiscoveryError> {
        let send = self.http.get(url.clone()).send();
        let resp = match tokio_timeout(self.request_timeout, send).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.is_timeout() => return Err(DiscoveryError::Timeout),
            Ok(Err(e)) => return Err(DiscoveryError::io(format!("crawler: fetch: {e}"))),
            Err(_) => return Err(DiscoveryError::Timeout),
        };
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| DiscoveryError::io(format!("crawler: read body: {e}")))?;
        let body = String::from_utf8_lossy(&bytes).into_owned();
        Ok(FetchedPage { status, body })
    }
}

/// Read or update the per-host bucket and return how long the caller
/// still has to wait before sending the next request. Returning
/// [`Duration::ZERO`] means the token has been consumed.
async fn compute_wait(
    buckets: &Mutex<HashMap<String, HostBucket>>,
    host: &str,
    min_gap: Duration,
) -> Duration {
    let now = TokioInstant::now();
    let mut guard = buckets.lock().await;
    let bucket = guard.entry(host.to_owned()).or_default();
    let wait = match bucket.last_consumed {
        None => {
            bucket.last_consumed = Some(now);
            Duration::ZERO
        }
        Some(prev) => {
            let elapsed = now.duration_since(prev);
            if elapsed >= min_gap {
                bucket.last_consumed = Some(now);
                Duration::ZERO
            } else {
                // `elapsed < min_gap` was checked above so this
                // subtraction is well-defined. Use `saturating_sub`
                // because rustc 1.92 clippy promotes raw `Duration -`
                // to `unchecked_time_subtraction` deny.
                min_gap.saturating_sub(elapsed)
            }
        }
    };
    drop(guard);
    wait
}

/// Internal: a fetched page prior to HTML extraction.
struct FetchedPage {
    status: u16,
    body: String,
}

/// Same-origin descriptor used to guard cross-origin links.
#[derive(Debug, Clone)]
struct Origin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Origin {
    fn from_url(u: &Url) -> Result<Self, DiscoveryError> {
        let scheme = u.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(DiscoveryError::config(format!(
                "webapp crawler requires http(s) URL, got '{scheme}'",
            )));
        }
        let host = u
            .host_str()
            .ok_or_else(|| DiscoveryError::config("webapp crawler: start URL has no host"))?
            .to_owned();
        Ok(Self {
            scheme: scheme.to_owned(),
            host,
            port: u.port(),
        })
    }

    fn matches(&self, other: &Url) -> bool {
        other.scheme() == self.scheme
            && other.host_str() == Some(self.host.as_str())
            && other.port() == self.port
    }

    fn host_with_port(&self) -> String {
        self.port
            .map_or_else(|| self.host.clone(), |p| format!("{}:{p}", self.host))
    }
}

/// Extract links, forms, and scripts from a single HTML page.
fn extract_page(base: &Url, status: u16, html: &str, origin: &Origin) -> VisitedPage {
    let mut links = Vec::new();
    let mut scripts = Vec::new();
    let mut forms = Vec::new();

    for tag in iter_tags(html) {
        match tag.name {
            "a" => {
                if let Some(href) = tag.attr("href") {
                    if let Some(u) = resolve(base, href) {
                        if origin.matches(&u) {
                            links.push(u);
                        }
                    }
                }
            }
            "script" => {
                if let Some(src) = tag.attr("src") {
                    if let Some(u) = resolve(base, src) {
                        if origin.matches(&u) {
                            scripts.push(u);
                        }
                    }
                }
            }
            "form" => {
                let method = tag
                    .attr("method")
                    .map_or_else(|| "GET".to_owned(), str::to_ascii_uppercase);
                let action = tag.attr("action").and_then(|a| resolve(base, a));
                forms.push(FormSpec { method, action });
            }
            _ => {}
        }
    }

    VisitedPage {
        url: base.clone(),
        status,
        links,
        forms,
        scripts,
    }
}

/// Resolve a possibly-relative URL against `base`. Returns `None` on
/// parse failure or for fragment-only / `javascript:` / `mailto:` hrefs.
fn resolve(base: &Url, href: &str) -> Option<Url> {
    let trimmed = href.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("javascript:")
        || lower.starts_with("mailto:")
        || lower.starts_with("tel:")
        || lower.starts_with("data:")
    {
        return None;
    }
    base.join(trimmed).ok()
}

/// A single tag extracted from the page byte-stream.
struct ParsedTag<'a> {
    name: &'a str,
    attrs: Vec<(String, String)>,
}

impl ParsedTag<'_> {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Iterate over `<a>`, `<form>`, `<script>` open-tags in `html`. The
/// returned iterator is single-pass and does **not** match closing tags
/// or maintain element nesting — sufficient for href / action / src
/// extraction.
const fn iter_tags(html: &str) -> TagIter<'_> {
    TagIter { rest: html }
}

struct TagIter<'a> {
    rest: &'a str,
}

impl<'a> Iterator for TagIter<'a> {
    type Item = ParsedTag<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let lt = self.rest.find('<')?;
            // Skip the '<' and try to read a tag name.
            let after_lt = self.rest.get(lt + 1..)?;
            self.rest = after_lt;
            if after_lt.starts_with('/') || after_lt.starts_with('!') {
                continue;
            }
            let (name_end, _) = after_lt
                .char_indices()
                .find(|(_, c)| !c.is_ascii_alphanumeric() && *c != '-')
                .unwrap_or((after_lt.len(), ' '));
            if name_end == 0 {
                continue;
            }
            let name = after_lt.get(..name_end)?;
            let lname = name.to_ascii_lowercase();
            let interesting = matches!(lname.as_str(), "a" | "form" | "script");
            // Advance past the name to scan attributes (or skip).
            let after_name = after_lt.get(name_end..)?;
            // Find the end of this tag — a '>' that isn't inside a
            // quoted attribute. Track quote state to be safe.
            let tag_end = find_tag_end(after_name)?;
            let attrs_raw = after_name.get(..tag_end)?;
            self.rest = after_name.get(tag_end + 1..).unwrap_or("");
            if !interesting {
                continue;
            }
            let attrs = parse_attrs(attrs_raw);
            // SAFETY: we never store references that outlive `'a`; the
            // tag name slice points into the original `html`.
            return Some(ParsedTag {
                name: name_to_static_lower(name),
                attrs,
            });
        }
    }
}

/// Return the byte index of the `'>'` that closes the current open tag,
/// honouring single / double quoted attribute values.
fn find_tag_end(s: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'>' if !in_single && !in_double => return Some(i),
            _ => {}
        }
    }
    None
}

/// Project a tag name to one of the three lowercase literals we care
/// about so the returned `&str` has the same lifetime as the source HTML.
fn name_to_static_lower(name: &str) -> &'static str {
    match name.to_ascii_lowercase().as_str() {
        "a" => "a",
        "form" => "form",
        "script" => "script",
        _ => "",
    }
}

/// Parse `key="value"` / `key='value'` / `key=value` / bare-`key`
/// attribute pairs out of an open-tag body.
fn parse_attrs(raw: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut chars = raw.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        if c.is_whitespace() || c == '/' {
            continue;
        }
        // Collect attribute name.
        let mut name = String::new();
        name.push(c);
        while let Some(&(_, n)) = chars.peek() {
            if n == '=' || n.is_whitespace() || n == '>' || n == '/' {
                break;
            }
            name.push(n);
            chars.next();
        }
        // Skip whitespace.
        while let Some(&(_, n)) = chars.peek() {
            if n.is_whitespace() {
                chars.next();
            } else {
                break;
            }
        }
        // If the next char is '=', read a value.
        let value = match chars.peek().copied() {
            Some((_, '=')) => {
                chars.next();
                while let Some(&(_, n)) = chars.peek() {
                    if n.is_whitespace() {
                        chars.next();
                    } else {
                        break;
                    }
                }
                read_value(&mut chars)
            }
            _ => String::new(),
        };
        if !name.is_empty() {
            out.push((name, value));
        }
    }
    out
}

/// Read a quoted or bare attribute value, advancing `chars` past it.
fn read_value<I>(chars: &mut std::iter::Peekable<I>) -> String
where
    I: Iterator<Item = (usize, char)>,
{
    let quote = match chars.peek().copied() {
        Some((_, '"')) => {
            chars.next();
            Some('"')
        }
        Some((_, '\'')) => {
            chars.next();
            Some('\'')
        }
        _ => None,
    };
    let mut out = String::new();
    for (_, c) in chars.by_ref() {
        match quote {
            Some(q) if c == q => return out,
            None if c.is_whitespace() || c == '>' => return out,
            _ => out.push(c),
        }
    }
    out
}

/// Minimal `robots.txt` parser — honours `Disallow` rules under the
/// `User-agent: *` group. Other agents and `Allow` rules are ignored.
#[derive(Debug, Clone, Default)]
struct RobotsRules {
    disallow: Vec<String>,
}

impl RobotsRules {
    fn allow_all() -> Self {
        Self::default()
    }

    fn parse(body: &str) -> Self {
        let mut in_star_group = false;
        let mut disallow: Vec<String> = Vec::new();
        for raw in body.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut split = line.splitn(2, ':');
            let key = split.next().unwrap_or("").trim().to_ascii_lowercase();
            let val = split.next().unwrap_or("").trim();
            match key.as_str() {
                "user-agent" => {
                    // A new group starts here. Switch context.
                    in_star_group = val == "*";
                }
                "disallow" if in_star_group => {
                    if !val.is_empty() {
                        disallow.push(val.to_owned());
                    }
                }
                _ => {}
            }
        }
        Self { disallow }
    }

    fn allowed(&self, path: &str) -> bool {
        !self.disallow.iter().any(|rule| path.starts_with(rule))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client() -> Client {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    fn crawler(max_depth: u32, max_urls: usize, respect_robots: bool) -> WebappCrawler {
        let mut c = WebappCrawler::new(client(), max_depth, max_urls, respect_robots);
        // Tests want immediate progress — squash the rate limiter.
        c.rate_per_sec = 1000;
        c.request_timeout = Duration::from_secs(2);
        c
    }

    const FIVE_LINKS: &str = r#"<html><body>
        <a href="/a">A</a>
        <a href="/b">B</a>
        <a href="/c">C</a>
        <a href="/d">D</a>
        <a href="/e">E</a>
    </body></html>"#;

    #[tokio::test]
    async fn extracts_five_links() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(FIVE_LINKS))
            .mount(&server)
            .await;
        // robots is fetched but absent → 404; treat as allow-all.
        Mock::given(method("GET"))
            .and(path("/robots.txt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        // Stub the child pages so we don't fall over on follow-ups.
        for p in ["a", "b", "c", "d", "e"] {
            Mock::given(method("GET"))
                .and(path(format!("/{p}")))
                .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
                .mount(&server)
                .await;
        }

        let start = Url::parse(&server.uri()).unwrap();
        let report = crawler(0, 50, true).crawl(start).await.unwrap();
        // depth=0 — only seed page fetched.
        assert_eq!(report.visited.len(), 1);
        let page = &report.visited[0];
        assert_eq!(page.links.len(), 5);
    }

    #[tokio::test]
    async fn extracts_form_action_and_method() {
        let body = r#"<form action="/login" method="post"><input name="x"/></form>"#;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/robots.txt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let start = Url::parse(&server.uri()).unwrap();
        let report = crawler(0, 10, true).crawl(start.clone()).await.unwrap();
        let page = &report.visited[0];
        assert_eq!(page.forms.len(), 1);
        assert_eq!(page.forms[0].method, "POST");
        assert_eq!(page.forms[0].action.as_ref().map(Url::path), Some("/login"),);
    }

    #[tokio::test]
    async fn off_origin_links_go_to_queued_outside_scope() {
        let body = r#"
            <a href="/local">local</a>
            <a href="https://evil.example/x">offsite</a>
        "#;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/robots.txt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/local"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
            .mount(&server)
            .await;

        let start = Url::parse(&server.uri()).unwrap();
        let report = crawler(2, 50, true).crawl(start).await.unwrap();
        // Only same-origin link is in `page.links`; the off-origin URL is
        // never enqueued at all (filtered at extract time).
        let page = &report.visited[0];
        assert_eq!(page.links.len(), 1);
        assert!(page
            .links
            .iter()
            .all(|u| u.host_str() != Some("evil.example")));
        // None of the visited URLs leave the origin.
        for v in &report.visited {
            assert_ne!(v.url.host_str(), Some("evil.example"));
        }
    }

    #[tokio::test]
    async fn robots_disallow_obeyed() {
        let server = MockServer::start().await;
        let robots = "User-agent: *\nDisallow: /admin\n";
        Mock::given(method("GET"))
            .and(path("/robots.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_string(robots))
            .mount(&server)
            .await;
        let body = r#"
            <a href="/public">ok</a>
            <a href="/admin/secret">no</a>
        "#;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/public"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
            .mount(&server)
            .await;
        // We expect this NOT to be hit — but we still mount a response
        // because wiremock would otherwise return 404 (which our crawler
        // would tolerate either way).
        Mock::given(method("GET"))
            .and(path("/admin/secret"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
            .mount(&server)
            .await;

        let start = Url::parse(&server.uri()).unwrap();
        let report = crawler(2, 50, true).crawl(start).await.unwrap();
        let fetched_paths: Vec<&str> = report.visited.iter().map(|p| p.url.path()).collect();
        assert!(fetched_paths.contains(&"/"));
        assert!(fetched_paths.contains(&"/public"));
        assert!(!fetched_paths.contains(&"/admin/secret"));
        assert!(report
            .queued_outside_scope
            .iter()
            .any(|u| u.path() == "/admin/secret"));
    }

    #[tokio::test]
    async fn max_depth_one_only_follows_initial_page() {
        let server = MockServer::start().await;
        let body = r#"<a href="/child">child</a>"#;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let child = r#"<a href="/grand">grand</a>"#;
        Mock::given(method("GET"))
            .and(path("/child"))
            .respond_with(ResponseTemplate::new(200).set_body_string(child))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/grand"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/robots.txt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let start = Url::parse(&server.uri()).unwrap();
        // max_depth=1 → fetch seed + its direct links, but not their links.
        let report = crawler(1, 50, true).crawl(start).await.unwrap();
        let paths: Vec<&str> = report.visited.iter().map(|p| p.url.path()).collect();
        assert!(paths.contains(&"/"));
        assert!(paths.contains(&"/child"));
        assert!(!paths.contains(&"/grand"));
    }

    #[tokio::test]
    async fn max_urls_cap_stops_crawl() {
        let server = MockServer::start().await;
        // Seed page links to 5 children, but we cap at 2 fetched URLs.
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(FIVE_LINKS))
            .mount(&server)
            .await;
        for p in ["a", "b", "c", "d", "e"] {
            Mock::given(method("GET"))
                .and(path(format!("/{p}")))
                .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/robots.txt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let start = Url::parse(&server.uri()).unwrap();
        let report = crawler(2, 2, true).crawl(start).await.unwrap();
        assert_eq!(report.visited.len(), 2);
        // Remaining children are recorded as out-of-scope (capped).
        assert!(!report.queued_outside_scope.is_empty());
    }

    #[tokio::test]
    async fn script_src_collected_when_same_origin() {
        let server = MockServer::start().await;
        let body = r#"
            <script src="/app.js"></script>
            <script src="https://cdn.example/x.js"></script>
        "#;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/robots.txt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let start = Url::parse(&server.uri()).unwrap();
        let report = crawler(0, 10, true).crawl(start).await.unwrap();
        let page = &report.visited[0];
        assert_eq!(page.scripts.len(), 1);
        assert!(page.scripts[0].path().ends_with("/app.js"));
    }

    #[test]
    fn robots_parser_user_agent_star_only() {
        let body = "User-agent: googlebot\nDisallow: /\nUser-agent: *\nDisallow: /admin\n";
        let r = RobotsRules::parse(body);
        assert!(r.allowed("/index"));
        assert!(!r.allowed("/admin/x"));
        // googlebot rules ignored — we only honour `*`.
        assert!(r.allowed("/something-googlebot-only-blocks"));
    }

    #[test]
    fn extract_resolves_relative_and_skips_schemes() {
        let base = Url::parse("https://h.test/a/").unwrap();
        let origin = Origin::from_url(&base).unwrap();
        let html = r##"
            <a href="x">x</a>
            <a href="/y">y</a>
            <a href="#frag">f</a>
            <a href="javascript:alert(1)">js</a>
            <a href="mailto:a@b">m</a>
        "##;
        let page = extract_page(&base, 200, html, &origin);
        let paths: Vec<&str> = page.links.iter().map(Url::path).collect();
        assert_eq!(paths, vec!["/a/x", "/y"]);
    }

    #[test]
    fn off_scheme_seed_rejected() {
        let c = WebappCrawler::new(client(), 1, 1, false);
        let bad = Url::parse("ftp://example.com/").unwrap();
        // Use a blocking-style runtime invocation via tokio::test would
        // require async; the validation happens synchronously inside the
        // future — drive it with a current-thread runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(c.crawl(bad)).unwrap_err();
        assert!(matches!(err, DiscoveryError::Config(_)));
    }
}
