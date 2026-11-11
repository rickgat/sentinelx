//! `ScopeTarget` — the discriminated union of things that can sit either
//! in an engagement scope OR be the subject of a scan request.
//!
//! Matching rules (scope contains target):
//! - `Cidr(IpNet)` matches `Cidr(IpNet)` / `IpV4(Ipv4Addr)` / `IpV6(Ipv6Addr)`
//!   when the scope CIDR contains the target's network or address.
//! - `Domain(String)` may be exact (`example.com`) or a single-level wildcard
//!   (`*.example.com`). A wildcard matches one OR more labels to the left.
//! - `Url(Url)` matches when host equals scope host AND the scope path is a
//!   prefix of the target path.
//! - `Arn(String)` is a regex pattern matched against a target ARN string.
//! - `RepoUrl(String)` is an exact (case-sensitive) string match.
//!
//! The same `ScopeTarget` variant family is used on both sides of the
//! match — but matching is intentionally asymmetric (e.g. a CIDR scope can
//! contain an IPv4 target, but not vice-versa).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::EngagementError;

/// Any concrete thing that can be authorized for scanning, or be the target
/// of a probe.
///
/// Variants are deliberately broad; matching is the source of truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ScopeTarget {
    /// A CIDR block.
    Cidr(IpNet),
    /// A bare IPv4 address.
    IpV4(Ipv4Addr),
    /// A bare IPv6 address.
    IpV6(Ipv6Addr),
    /// A domain name. Wildcards (`*.example.com`) are allowed.
    Domain(String),
    /// A URL — host + path are both significant.
    Url(Url),
    /// An ARN-like identifier (interpreted as a regex when used as a scope).
    Arn(String),
    /// A git repository URL.
    RepoUrl(String),
}

impl ScopeTarget {
    /// Returns `true` when `self` (interpreted as scope) authorises `target`
    /// (interpreted as request).
    ///
    /// This is the canonical scope-match algorithm. It is intentionally
    /// total — no panics, no `unwrap`s, all variant pairs covered.
    #[must_use]
    pub fn matches(&self, target: &Self) -> bool {
        match (self, target) {
            // CIDR contains another CIDR.
            (Self::Cidr(net), Self::Cidr(other)) => cidr_contains_cidr(net, other),
            // CIDR contains an IP.
            (Self::Cidr(net), Self::IpV4(ip)) => net.contains(&IpAddr::V4(*ip)),
            (Self::Cidr(net), Self::IpV6(ip)) => net.contains(&IpAddr::V6(*ip)),

            // Exact IP equality.
            (Self::IpV4(a), Self::IpV4(b)) => a == b,
            (Self::IpV6(a), Self::IpV6(b)) => a == b,

            // Domain matching: exact or single wildcard.
            (Self::Domain(scope), Self::Domain(target)) => domain_matches(scope, target),

            // URL matching.
            (Self::Url(scope), Self::Url(target)) => url_contains(scope, target),

            // ARN: scope side interpreted as regex.
            (Self::Arn(pat), Self::Arn(target)) => arn_matches(pat, target),

            // Repo URLs are exact string equality.
            (Self::RepoUrl(a), Self::RepoUrl(b)) => a == b,

            // Heterogeneous comparisons never match.
            _ => false,
        }
    }

    /// Returns a short, structured label suitable for `tracing` fields
    /// (no PII, no secrets).
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Cidr(_) => "cidr",
            Self::IpV4(_) => "ipv4",
            Self::IpV6(_) => "ipv6",
            Self::Domain(_) => "domain",
            Self::Url(_) => "url",
            Self::Arn(_) => "arn",
            Self::RepoUrl(_) => "repo_url",
        }
    }

    /// Construct a `Domain` variant after light validation.
    pub fn domain(input: impl Into<String>) -> Result<Self, EngagementError> {
        let raw = input.into();
        let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if trimmed.is_empty() {
            return Err(EngagementError::invalid_input("empty domain"));
        }
        if trimmed.contains(char::is_whitespace) {
            return Err(EngagementError::invalid_input("domain contains whitespace"));
        }
        let labels: Vec<&str> = trimmed.split('.').collect();
        if labels.len() < 2 {
            return Err(EngagementError::invalid_input(
                "domain must have at least two labels",
            ));
        }
        // Allow a single leading wildcard, otherwise labels must be plain.
        for (i, label) in labels.iter().enumerate() {
            if label.is_empty() {
                return Err(EngagementError::invalid_input("empty label"));
            }
            if i == 0 && label == &"*" {
                continue;
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(EngagementError::invalid_input(format!(
                    "illegal label: {label}"
                )));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(EngagementError::invalid_input(format!(
                    "label cannot start or end with '-': {label}"
                )));
            }
        }
        Ok(Self::Domain(trimmed))
    }

    /// Best-effort classifier for a free-form input string.
    ///
    /// 1. If `s` parses as a [`Url`] with a non-empty host, return
    ///    [`ScopeTarget::Url`].
    /// 2. Otherwise, if `s` parses as an [`Ipv4Addr`] / [`Ipv6Addr`] /
    ///    [`IpNet`], return the matching variant.
    /// 3. Otherwise, attempt [`ScopeTarget::domain`]; on success return
    ///    [`ScopeTarget::Domain`], on failure return `None`.
    ///
    /// This function is intentionally **total** (never panics) so it can be
    /// safely driven by fuzz / property test inputs.
    #[must_use]
    pub fn parse_url_or_domain(s: &str) -> Option<Self> {
        // 1. Try URL first; URLs that lack a host (e.g. `mailto:`) are not
        //    valid scope URL targets, so we fall through to other parsers.
        if let Ok(url) = Url::parse(s) {
            if url.host_str().is_some() {
                return Some(Self::Url(url));
            }
        }
        // 2. Try CIDR, then bare IPs.
        if let Ok(net) = s.parse::<IpNet>() {
            return Some(Self::Cidr(net));
        }
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            return Some(Self::IpV4(ip));
        }
        if let Ok(ip) = s.parse::<Ipv6Addr>() {
            return Some(Self::IpV6(ip));
        }
        // 3. Fall back to a domain — light validation only.
        Self::domain(s).ok()
    }
}

impl fmt::Display for ScopeTarget {
    /// Format a target as its stable, lossless textual form.
    ///
    /// The output of `Display` is what a Domain value's underlying string
    /// already is — a `Domain` constructed via [`ScopeTarget::domain`]
    /// round-trips through this `Display`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cidr(net) => write!(f, "{net}"),
            Self::IpV4(ip) => write!(f, "{ip}"),
            Self::IpV6(ip) => write!(f, "{ip}"),
            Self::Domain(d) | Self::Arn(d) | Self::RepoUrl(d) => f.write_str(d),
            Self::Url(u) => write!(f, "{u}"),
        }
    }
}

/// Does CIDR `outer` contain every address in CIDR `inner`?
fn cidr_contains_cidr(outer: &IpNet, inner: &IpNet) -> bool {
    if outer.prefix_len() > inner.prefix_len() {
        return false;
    }
    match (outer, inner) {
        (IpNet::V4(o), IpNet::V4(i)) => o.contains(&i.network()),
        (IpNet::V6(o), IpNet::V6(i)) => o.contains(&i.network()),
        _ => false,
    }
}

/// Matches `target` against a scope `pattern` (exact or `*.example.com`).
fn domain_matches(pattern: &str, target: &str) -> bool {
    let pat = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let tgt = target.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pat.strip_prefix("*.") {
        if suffix.is_empty() {
            return false;
        }
        // `*.example.com` matches `example.com` and any deeper subdomain.
        if tgt == suffix {
            return true;
        }
        // Subdomain must end with `.<suffix>` so we don't false-positive on
        // suffix-only string match (e.g. `evilexample.com`).
        return tgt.len() > suffix.len() && tgt.ends_with(&format!(".{suffix}"));
    }
    pat == tgt
}

/// URL containment: same host, scope path is a strict prefix.
fn url_contains(scope: &Url, target: &Url) -> bool {
    if scope.host_str() != target.host_str() {
        return false;
    }
    // If scope and target differ in port, treat as mismatch.
    if scope.port_or_known_default() != target.port_or_known_default() {
        return false;
    }
    let scope_path = scope.path();
    let target_path = target.path();
    // Treat trailing-slash-equivalent paths consistently.
    if target_path == scope_path {
        return true;
    }
    // Path-segment-aware prefix: avoid `/foo` matching `/foobar`.
    let normalized = if scope_path.ends_with('/') {
        scope_path.to_string()
    } else {
        format!("{scope_path}/")
    };
    target_path.starts_with(&normalized)
}

/// ARN match: scope is a regex; target is the literal ARN.
fn arn_matches(pattern: &str, target: &str) -> bool {
    Regex::new(pattern).is_ok_and(|re| re.is_match(target))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn cidr(s: &str) -> ScopeTarget {
        ScopeTarget::Cidr(IpNet::from_str(s).unwrap())
    }

    fn ipv4(s: &str) -> ScopeTarget {
        ScopeTarget::IpV4(s.parse().unwrap())
    }

    fn ipv6(s: &str) -> ScopeTarget {
        ScopeTarget::IpV6(s.parse().unwrap())
    }

    #[test]
    fn cidr_contains_ipv4() {
        let scope = cidr("10.0.0.0/8");
        assert!(scope.matches(&ipv4("10.0.1.5")));
        assert!(!scope.matches(&ipv4("11.0.0.1")));
    }

    #[test]
    fn cidr_contains_ipv6() {
        let scope = cidr("2001:db8::/32");
        assert!(scope.matches(&ipv6("2001:db8::1")));
        assert!(!scope.matches(&ipv6("2001:db9::1")));
    }

    #[test]
    fn cidr_contains_subcidr() {
        let scope = cidr("10.0.0.0/8");
        let inner = cidr("10.1.0.0/16");
        assert!(scope.matches(&inner));
        let outer = cidr("10.0.0.0/7");
        assert!(!scope.matches(&outer));
    }

    #[test]
    fn heterogeneous_pairs_do_not_match() {
        let scope = cidr("10.0.0.0/8");
        let target = ScopeTarget::Domain("example.com".into());
        assert!(!scope.matches(&target));
    }

    #[test]
    fn domain_exact_match() {
        let scope = ScopeTarget::Domain("example.com".into());
        let target = ScopeTarget::Domain("example.com".into());
        assert!(scope.matches(&target));
    }

    #[test]
    fn domain_exact_rejects_subdomain() {
        let scope = ScopeTarget::Domain("example.com".into());
        let target = ScopeTarget::Domain("api.example.com".into());
        assert!(!scope.matches(&target));
    }

    #[test]
    fn domain_wildcard_matches_subdomains() {
        let scope = ScopeTarget::Domain("*.example.com".into());
        assert!(scope.matches(&ScopeTarget::Domain("example.com".into())));
        assert!(scope.matches(&ScopeTarget::Domain("api.example.com".into())));
        assert!(scope.matches(&ScopeTarget::Domain("a.b.example.com".into())));
    }

    #[test]
    fn domain_wildcard_does_not_match_unrelated() {
        let scope = ScopeTarget::Domain("*.example.com".into());
        assert!(!scope.matches(&ScopeTarget::Domain("evilexample.com".into())));
        assert!(!scope.matches(&ScopeTarget::Domain("example.org".into())));
    }

    #[test]
    fn url_host_and_path_prefix() {
        let scope = ScopeTarget::Url(Url::parse("https://example.com/api").unwrap());
        let in_scope = ScopeTarget::Url(Url::parse("https://example.com/api/v1/items").unwrap());
        let same = ScopeTarget::Url(Url::parse("https://example.com/api").unwrap());
        let other_host = ScopeTarget::Url(Url::parse("https://other.com/api/v1").unwrap());
        let path_outside = ScopeTarget::Url(Url::parse("https://example.com/other").unwrap());
        let prefix_trap = ScopeTarget::Url(Url::parse("https://example.com/apifoo").unwrap());
        assert!(scope.matches(&in_scope));
        assert!(scope.matches(&same));
        assert!(!scope.matches(&other_host));
        assert!(!scope.matches(&path_outside));
        assert!(!scope.matches(&prefix_trap));
    }

    #[test]
    fn arn_regex_matches() {
        let scope = ScopeTarget::Arn(r"^arn:aws:s3:::prod-.*$".into());
        let in_scope = ScopeTarget::Arn("arn:aws:s3:::prod-data".into());
        let out_scope = ScopeTarget::Arn("arn:aws:s3:::dev-data".into());
        assert!(scope.matches(&in_scope));
        assert!(!scope.matches(&out_scope));
    }

    #[test]
    fn arn_invalid_regex_does_not_panic_and_does_not_match() {
        let scope = ScopeTarget::Arn("[".into());
        let target = ScopeTarget::Arn("anything".into());
        assert!(!scope.matches(&target));
    }

    #[test]
    fn repo_url_exact_match() {
        let scope = ScopeTarget::RepoUrl("https://github.com/org/repo.git".into());
        let same = ScopeTarget::RepoUrl("https://github.com/org/repo.git".into());
        let diff = ScopeTarget::RepoUrl("https://github.com/org/other.git".into());
        assert!(scope.matches(&same));
        assert!(!scope.matches(&diff));
    }

    #[test]
    fn domain_constructor_rejects_invalid() {
        assert!(ScopeTarget::domain("").is_err());
        assert!(ScopeTarget::domain("nodot").is_err());
        assert!(ScopeTarget::domain("under_score.com").is_err());
        assert!(ScopeTarget::domain("-leading.com").is_err());
        assert!(ScopeTarget::domain("trailing-.com").is_err());
        assert!(ScopeTarget::domain("contains space.com").is_err());
    }

    #[test]
    fn domain_constructor_accepts_valid() {
        assert!(ScopeTarget::domain("example.com").is_ok());
        assert!(ScopeTarget::domain("*.example.com").is_ok());
        assert!(ScopeTarget::domain("EXAMPLE.com").is_ok());
        assert!(ScopeTarget::domain("a.b.example.com").is_ok());
    }

    #[test]
    fn kind_label_is_stable() {
        assert_eq!(cidr("10.0.0.0/8").kind_label(), "cidr");
        assert_eq!(ipv4("10.0.0.1").kind_label(), "ipv4");
        assert_eq!(ipv6("::1").kind_label(), "ipv6");
        assert_eq!(ScopeTarget::Domain("a.b".into()).kind_label(), "domain");
    }
}
