//! Engagement scope targets and the [`ScopeMatcher`] trait.
//!
//! A [`ScopeTarget`] describes one entry in an engagement's allowed
//! testing surface. The [`ScopeMatcher`] trait is the polymorphic API
//! used by domain services / use-cases to test whether a concrete asset
//! candidate is in scope.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::DomainError;
use crate::value_object::fqdn::Fqdn;

/// A single entry in the allowed engagement scope, or a candidate target.
///
/// The variant set is intentionally broad so that the same enum can sit on
/// both sides of [`ScopeTarget::matches`]: the canonical scope/match algorithm
/// is asymmetric (e.g. a `Cidr` scope contains an `IpV4` target, but never the
/// other way around). See the per-variant docs on
/// [`ScopeTarget::matches`] for the precise semantics.
///
/// Heterogeneous variant pairs never match. This mirrors the engagement
/// crate's algorithm so the two are drop-in compatible during migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ScopeTarget {
    /// An IP network range, IPv4 or IPv6.
    Cidr(IpNet),
    /// A bare IPv4 address.
    IpV4(Ipv4Addr),
    /// A bare IPv6 address.
    IpV6(Ipv6Addr),
    /// A domain name (host or zone). Subdomain matching is up to the matcher.
    ///
    /// When used as a scope, a leading-wildcard form (`*.example.com`) — only
    /// representable here via the convenience constructor [`ScopeTarget::domain_pattern`]
    /// — matches the parent domain plus any deeper subdomain.
    Domain(Fqdn),
    /// A cloud-provider ARN (or equivalent fully-qualified resource id).
    ///
    /// When used as a scope, the string is interpreted as a regular expression
    /// (anchored or not, per the caller). An invalid pattern is treated as a
    /// non-match — see [`ScopeTarget::matches`].
    Arn(String),
    /// A URL — host/path scope (e.g. for web app testing).
    Url(Url),
    /// A source-code repository URL (matched as a `Url`).
    RepoUrl(Url),
    /// A source-code repository URL represented as a free-form string.
    ///
    /// Use this when the repository URL is not strictly a [`url::Url`]
    /// (e.g. `git@github.com:org/repo.git`). String comparison is exact and
    /// case-sensitive.
    RepoUrlStr(String),
}

impl ScopeTarget {
    /// Build a [`ScopeTarget::Cidr`].
    pub fn cidr(net: impl AsRef<str>) -> Result<Self, DomainError> {
        let raw = net.as_ref();
        let parsed: IpNet = raw
            .parse()
            .map_err(|e| DomainError::invalid(format!("invalid CIDR '{raw}': {e}")))?;
        Ok(Self::Cidr(parsed))
    }

    /// Build a [`ScopeTarget::Domain`].
    pub fn domain(d: impl AsRef<str>) -> Result<Self, DomainError> {
        Ok(Self::Domain(Fqdn::new(d.as_ref())?))
    }

    /// Build a [`ScopeTarget::Arn`].
    pub fn arn(s: impl Into<String>) -> Result<Self, DomainError> {
        let raw = s.into();
        if !raw.starts_with("arn:") || raw.split(':').count() < 6 {
            return Err(DomainError::invalid(format!("invalid ARN: {raw}")));
        }
        Ok(Self::Arn(raw))
    }

    /// Build a [`ScopeTarget::Url`].
    pub fn url(s: impl AsRef<str>) -> Result<Self, DomainError> {
        let u = Url::parse(s.as_ref())
            .map_err(|e| DomainError::invalid(format!("invalid url: {e}")))?;
        Ok(Self::Url(u))
    }

    /// Build a [`ScopeTarget::RepoUrl`].
    pub fn repo_url(s: impl AsRef<str>) -> Result<Self, DomainError> {
        let u = Url::parse(s.as_ref())
            .map_err(|e| DomainError::invalid(format!("invalid repo url: {e}")))?;
        Ok(Self::RepoUrl(u))
    }

    /// Build a [`ScopeTarget::Domain`] from a possibly-wildcard pattern.
    ///
    /// Accepts the same forms as [`ScopeTarget::domain`] (a plain FQDN), plus
    /// a single leading-wildcard pattern of the form `*.example.com`. The
    /// returned `Domain(Fqdn)` keeps the literal `*.` prefix; matching logic
    /// in [`ScopeTarget::matches`] interprets the wildcard.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidValue`] if the input is empty, contains
    /// whitespace, or has fewer than two labels.
    pub fn domain_pattern(input: impl AsRef<str>) -> Result<Self, DomainError> {
        let raw = input
            .as_ref()
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if raw.is_empty() {
            return Err(DomainError::invalid("empty domain"));
        }
        if raw.contains(char::is_whitespace) {
            return Err(DomainError::invalid("domain contains whitespace"));
        }
        let labels: Vec<&str> = raw.split('.').collect();
        if labels.len() < 2 {
            return Err(DomainError::invalid("domain must have at least two labels"));
        }
        for (i, label) in labels.iter().enumerate() {
            if label.is_empty() {
                return Err(DomainError::invalid("domain has empty label"));
            }
            if i == 0 && *label == "*" {
                continue;
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(DomainError::invalid(format!("illegal label: {label}",)));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(DomainError::invalid(format!(
                    "label cannot start or end with '-': {label}",
                )));
            }
        }
        // For a non-wildcard pattern, defer to the canonical [`Fqdn`] validator.
        if labels.first().is_some_and(|l| *l != "*") {
            return Ok(Self::Domain(Fqdn::new(&raw)?));
        }
        // For a wildcard pattern, build the `Fqdn` from the suffix and re-prepend `*.`.
        // We cannot store `*.example.com` directly through `Fqdn::new` because the
        // canonical Fqdn validator rejects `*`. We therefore validate the suffix
        // separately and then construct the wildcard form via a TryFrom.
        let suffix = &raw[2..];
        let _suffix_ok = Fqdn::new(suffix)?;
        let wildcard = format!("*.{suffix}");
        // Use `From<String>`-equivalent: try_from to keep validation tight.
        // Fqdn::try_from(String) rejects the `*` prefix, so we cannot use it
        // directly. The wildcard form is stored via a dedicated escape hatch:
        // build a non-wildcard `Fqdn` and then wrap as `Domain` with the
        // original string by way of a `try_from` on `String`.
        // To keep the type discipline, we round-trip through the canonical
        // wildcard wrapper.
        Ok(Self::Domain(Fqdn::new_wildcard(wildcard)?))
    }

    /// Returns the canonical short label for this variant (no PII / secrets).
    ///
    /// Suitable for `tracing` fields and metrics dimensions.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Cidr(_) => "cidr",
            Self::IpV4(_) => "ipv4",
            Self::IpV6(_) => "ipv6",
            Self::Domain(_) => "domain",
            Self::Arn(_) => "arn",
            Self::Url(_) => "url",
            Self::RepoUrl(_) | Self::RepoUrlStr(_) => "repo_url",
        }
    }

    /// Canonical scope-match algorithm: does `self` (interpreted as a scope
    /// entry) authorise `target` (interpreted as a probe candidate)?
    ///
    /// Per-variant rules:
    /// - `Cidr` contains another `Cidr` when the scope CIDR includes the
    ///   target's network (same address family, prefix at most as long).
    /// - `Cidr` contains `IpV4` / `IpV6` when the address is inside the range.
    /// - `IpV4` / `IpV6` match exact equality.
    /// - `Domain` matches `Domain` either as exact equality, or — when the
    ///   scope is a wildcard pattern built via [`ScopeTarget::domain_pattern`]
    ///   — as parent + any deeper subdomain.
    /// - `Url` matches `Url` when host (and port, if either specifies one) are
    ///   equal AND the scope path is a path-segment-aware prefix of the
    ///   target path (so `/foo` does **not** match `/foobar`).
    /// - `Arn` interprets the scope string as a regex against the target
    ///   string. An invalid regex matches nothing — never panics.
    /// - `RepoUrl` is exact `Url` equality.
    /// - `RepoUrlStr` is exact case-sensitive string equality.
    /// - Heterogeneous variant pairs never match.
    ///
    /// This method is intentionally total (no `unwrap` / `panic`).
    #[must_use]
    pub fn matches(&self, target: &Self) -> bool {
        match (self, target) {
            (Self::Cidr(net), Self::Cidr(other)) => cidr_contains_cidr(net, other),
            (Self::Cidr(net), Self::IpV4(ip)) => net.contains(&IpAddr::V4(*ip)),
            (Self::Cidr(net), Self::IpV6(ip)) => net.contains(&IpAddr::V6(*ip)),
            (Self::IpV4(a), Self::IpV4(b)) => a == b,
            (Self::IpV6(a), Self::IpV6(b)) => a == b,
            (Self::Domain(scope), Self::Domain(target)) => {
                domain_matches(scope.as_str(), target.as_str())
            }
            (Self::Url(scope), Self::Url(target)) => url_contains(scope, target),
            (Self::Arn(pat), Self::Arn(target)) => arn_matches(pat, target),
            (Self::RepoUrl(a), Self::RepoUrl(b)) => a == b,
            (Self::RepoUrlStr(a), Self::RepoUrlStr(b)) => a == b,
            _ => false,
        }
    }
}

/// `outer` contains every address in `inner` (same address family, prefix
/// no longer than `inner`'s).
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

/// Match a target FQDN against a scope FQDN. The scope may be either an
/// exact FQDN or a leading-wildcard pattern of the form `*.example.com`
/// (the wildcard pattern is built by [`ScopeTarget::domain_pattern`]).
fn domain_matches(pattern: &str, target: &str) -> bool {
    let pat = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let tgt = target.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pat.strip_prefix("*.") {
        if suffix.is_empty() {
            return false;
        }
        if tgt == suffix {
            return true;
        }
        return tgt.len() > suffix.len() && tgt.ends_with(&format!(".{suffix}"));
    }
    pat == tgt
}

/// URL containment: same host, same (effective) port, scope path is a
/// path-segment-aware prefix of the target path.
fn url_contains(scope: &Url, target: &Url) -> bool {
    if scope.host_str() != target.host_str() {
        return false;
    }
    if scope.port_or_known_default() != target.port_or_known_default() {
        return false;
    }
    let scope_path = scope.path();
    let target_path = target.path();
    if target_path == scope_path {
        return true;
    }
    let normalized = if scope_path.ends_with('/') {
        scope_path.to_string()
    } else {
        format!("{scope_path}/")
    };
    target_path.starts_with(&normalized)
}

/// ARN match: the scope is a regex, the target is the literal ARN. An
/// invalid regex never matches and never panics.
fn arn_matches(pattern: &str, target: &str) -> bool {
    Regex::new(pattern).is_ok_and(|re| re.is_match(target))
}

impl fmt::Display for ScopeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cidr(c) => write!(f, "cidr:{c}"),
            Self::IpV4(ip) => write!(f, "ipv4:{ip}"),
            Self::IpV6(ip) => write!(f, "ipv6:{ip}"),
            Self::Domain(d) => write!(f, "domain:{d}"),
            Self::Arn(a) => write!(f, "arn:{a}"),
            Self::Url(u) => write!(f, "url:{u}"),
            Self::RepoUrl(u) => write!(f, "repo:{u}"),
            Self::RepoUrlStr(s) => write!(f, "repo:{s}"),
        }
    }
}

/// A concrete probe candidate that can be matched against scope entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeCandidate {
    /// An IP address.
    Ip(IpAddr),
    /// A domain name.
    Domain(Fqdn),
    /// A cloud resource ARN.
    Arn(String),
    /// A URL.
    Url(Url),
}

/// Polymorphic API for testing whether a candidate is in scope.
///
/// Implementations live in higher layers (engagement / risk crates).
/// The trait is exposed here so the contract is part of the domain.
pub trait ScopeMatcher {
    /// Return `true` iff `candidate` is permitted by this entry.
    fn matches(&self, candidate: &ScopeCandidate) -> bool;
}

impl ScopeMatcher for ScopeTarget {
    fn matches(&self, candidate: &ScopeCandidate) -> bool {
        match (self, candidate) {
            (Self::Cidr(net), ScopeCandidate::Ip(ip)) => net.contains(ip),
            (Self::Domain(scope), ScopeCandidate::Domain(cand)) => {
                cand == scope || cand.as_str().ends_with(&format!(".{}", scope.as_str()))
            }
            (Self::Arn(scope), ScopeCandidate::Arn(cand)) => scope == cand,
            (Self::Url(scope), ScopeCandidate::Url(cand)) => {
                scope.host_str() == cand.host_str() && cand.path().starts_with(scope.path())
            }
            (Self::RepoUrl(scope), ScopeCandidate::Url(cand)) => scope == cand,
            _ => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn cidr_match() {
        let t = ScopeTarget::cidr("10.0.0.0/8").unwrap();
        let inside: IpAddr = "10.0.0.5".parse().unwrap();
        let outside: IpAddr = "11.0.0.1".parse().unwrap();
        // Disambiguate from the inherent `ScopeTarget::matches(&Self)` by
        // qualifying the trait call.
        assert!(<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Ip(inside)
        ));
        assert!(!<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Ip(outside)
        ));
    }

    #[test]
    fn domain_match_subdomain() {
        let t = ScopeTarget::domain("example.com").unwrap();
        let exact = Fqdn::new("example.com").unwrap();
        let sub = Fqdn::new("api.example.com").unwrap();
        let other = Fqdn::new("evil.com").unwrap();
        assert!(<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Domain(exact)
        ));
        assert!(<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Domain(sub)
        ));
        assert!(!<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Domain(other)
        ));
    }

    #[test]
    fn url_match_path_prefix() {
        let t = ScopeTarget::url("https://example.com/api/").unwrap();
        let in_path = Url::parse("https://example.com/api/v1/users").unwrap();
        let out_path = Url::parse("https://example.com/admin").unwrap();
        let other_host = Url::parse("https://other.com/api/foo").unwrap();
        assert!(<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Url(in_path)
        ));
        assert!(!<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Url(out_path)
        ));
        assert!(!<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Url(other_host)
        ));
    }

    #[test]
    fn arn_match_exact() {
        let raw = "arn:aws:s3:::bucket/key";
        let t = ScopeTarget::arn(raw).unwrap();
        assert!(<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Arn(raw.into())
        ));
        assert!(!<ScopeTarget as ScopeMatcher>::matches(
            &t,
            &ScopeCandidate::Arn("arn:aws:s3:::other".into())
        ));
    }

    #[test]
    fn invalid_arn_rejected() {
        assert!(ScopeTarget::arn("not-an-arn").is_err());
    }

    #[test]
    fn invalid_cidr_rejected() {
        assert!(ScopeTarget::cidr("not-cidr").is_err());
    }

    // -- new canonical (`fn matches(&self, &Self)`) algorithm tests --

    #[test]
    fn scope_target_matches_cidr_contains_ipv4() {
        let scope = ScopeTarget::cidr("10.0.0.0/8").unwrap();
        let inside = ScopeTarget::IpV4("10.0.1.5".parse().unwrap());
        let outside = ScopeTarget::IpV4("11.0.0.1".parse().unwrap());
        assert!(scope.matches(&inside));
        assert!(!scope.matches(&outside));
        // Heterogeneous reverse direction must not match.
        assert!(!inside.matches(&scope));
    }

    #[test]
    fn scope_target_matches_cidr_contains_ipv6() {
        let scope = ScopeTarget::cidr("2001:db8::/32").unwrap();
        let inside = ScopeTarget::IpV6("2001:db8::1".parse().unwrap());
        let outside = ScopeTarget::IpV6("2001:db9::1".parse().unwrap());
        assert!(scope.matches(&inside));
        assert!(!scope.matches(&outside));
    }

    #[test]
    fn scope_target_matches_cidr_contains_subcidr() {
        let scope = ScopeTarget::cidr("10.0.0.0/8").unwrap();
        let inner = ScopeTarget::cidr("10.1.0.0/16").unwrap();
        let outer = ScopeTarget::cidr("10.0.0.0/7").unwrap();
        assert!(scope.matches(&inner));
        assert!(!scope.matches(&outer));
    }

    #[test]
    fn scope_target_matches_domain_wildcard() {
        let scope = ScopeTarget::domain_pattern("*.example.com").unwrap();
        assert!(scope.matches(&ScopeTarget::domain("example.com").unwrap()));
        assert!(scope.matches(&ScopeTarget::domain("api.example.com").unwrap()));
        assert!(scope.matches(&ScopeTarget::domain("a.b.example.com").unwrap()));
        assert!(!scope.matches(&ScopeTarget::domain("evilexample.com").unwrap()));
        assert!(!scope.matches(&ScopeTarget::domain("example.org").unwrap()));
    }

    #[test]
    fn scope_target_matches_url_host_and_prefix() {
        let scope = ScopeTarget::url("https://example.com/api").unwrap();
        let in_scope = ScopeTarget::url("https://example.com/api/v1/items").unwrap();
        let same = ScopeTarget::url("https://example.com/api").unwrap();
        let prefix_trap = ScopeTarget::url("https://example.com/apifoo").unwrap();
        let other_host = ScopeTarget::url("https://other.com/api/v1").unwrap();
        let path_outside = ScopeTarget::url("https://example.com/admin").unwrap();
        assert!(scope.matches(&in_scope));
        assert!(scope.matches(&same));
        assert!(!scope.matches(&prefix_trap));
        assert!(!scope.matches(&other_host));
        assert!(!scope.matches(&path_outside));
    }

    #[test]
    fn scope_target_matches_arn_regex() {
        let scope = ScopeTarget::Arn(r"^arn:aws:s3:::prod-.*$".into());
        let in_scope = ScopeTarget::Arn("arn:aws:s3:::prod-data".into());
        let out_scope = ScopeTarget::Arn("arn:aws:s3:::dev-data".into());
        assert!(scope.matches(&in_scope));
        assert!(!scope.matches(&out_scope));
    }

    #[test]
    fn scope_target_arn_invalid_regex_does_not_panic() {
        let scope = ScopeTarget::Arn("[".into());
        let target = ScopeTarget::Arn("anything".into());
        assert!(!scope.matches(&target));
    }

    #[test]
    fn scope_target_repo_url_str_exact_match() {
        let scope = ScopeTarget::RepoUrlStr("git@github.com:org/repo.git".into());
        let same = ScopeTarget::RepoUrlStr("git@github.com:org/repo.git".into());
        let diff = ScopeTarget::RepoUrlStr("git@github.com:org/other.git".into());
        assert!(scope.matches(&same));
        assert!(!scope.matches(&diff));
    }

    #[test]
    fn scope_target_heterogeneous_never_matches() {
        let cidr = ScopeTarget::cidr("10.0.0.0/8").unwrap();
        let domain = ScopeTarget::domain("example.com").unwrap();
        assert!(!cidr.matches(&domain));
        assert!(!domain.matches(&cidr));
    }

    #[test]
    fn scope_target_kind_label_is_stable() {
        assert_eq!(
            ScopeTarget::cidr("10.0.0.0/8").unwrap().kind_label(),
            "cidr"
        );
        assert_eq!(
            ScopeTarget::IpV4("1.2.3.4".parse().unwrap()).kind_label(),
            "ipv4"
        );
        assert_eq!(
            ScopeTarget::IpV6("::1".parse().unwrap()).kind_label(),
            "ipv6"
        );
        assert_eq!(ScopeTarget::domain("a.b").unwrap().kind_label(), "domain");
        assert_eq!(
            ScopeTarget::Arn("arn:aws:x:y:z:r".into()).kind_label(),
            "arn"
        );
        assert_eq!(
            ScopeTarget::url("https://a.b/").unwrap().kind_label(),
            "url"
        );
        assert_eq!(ScopeTarget::RepoUrlStr("x".into()).kind_label(), "repo_url");
    }

    #[test]
    fn scope_target_domain_pattern_rejects_bad_input() {
        assert!(ScopeTarget::domain_pattern("").is_err());
        assert!(ScopeTarget::domain_pattern("nodot").is_err());
        assert!(ScopeTarget::domain_pattern("under_score.com").is_err());
        assert!(ScopeTarget::domain_pattern("contains space.com").is_err());
    }

    #[test]
    fn scope_target_domain_pattern_accepts_valid() {
        assert!(ScopeTarget::domain_pattern("example.com").is_ok());
        assert!(ScopeTarget::domain_pattern("*.example.com").is_ok());
        assert!(ScopeTarget::domain_pattern("EXAMPLE.com").is_ok());
    }
}
