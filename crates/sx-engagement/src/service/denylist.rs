//! `DenylistChecker` — applies the global denylist *before* any scope check.
//!
//! The denylist is the highest-priority safety control. If a target matches
//! a denylist entry, the request is refused regardless of the engagement's
//! authorized scope. There is no override.
//!
//! Entries are compiled once at construction:
//! * `Cidr` entries parse to `IpNet`.
//! * `Domain` entries compile to lower-cased FQDN literals with optional
//!   `*.` wildcard.
//! * `Regex` entries compile to a `regex::Regex`.
//!
//! Invalid entries (those that fail to parse) are silently dropped *after*
//! a `tracing::error!` — this guarantees that a malformed config never
//! opens a hole. Callers should treat the parser as authoritative at boot.

use std::net::IpAddr;

use ipnet::IpNet;
use regex::Regex;
use sx_config::schema::engagement::{DenylistEntry, DenylistKind, EngagementConfig};
use tracing::error;

use crate::model::scope_target::ScopeTarget;

/// A compiled denylist match.
#[derive(Debug, Clone)]
enum Compiled {
    Cidr {
        net: IpNet,
        raw: String,
        reason: String,
    },
    Domain {
        pattern: String,
        reason: String,
    },
    Regex {
        re: Regex,
        raw: String,
        reason: String,
    },
}

impl Compiled {
    fn raw(&self) -> &str {
        match self {
            Self::Cidr { raw, .. } | Self::Regex { raw, .. } => raw,
            Self::Domain { pattern, .. } => pattern,
        }
    }

    fn reason(&self) -> &str {
        match self {
            Self::Cidr { reason, .. }
            | Self::Domain { reason, .. }
            | Self::Regex { reason, .. } => reason,
        }
    }
}

/// A hit returned by [`DenylistChecker::contains`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenylistHit {
    /// The raw entry text that matched.
    pub pattern: String,
    /// Human-readable reason (from config).
    pub reason: String,
}

/// Pre-compiled, immutable denylist.
///
/// Cheap to share across threads (`Arc` it if you need shared ownership).
#[derive(Debug, Clone)]
pub struct DenylistChecker {
    entries: Vec<Compiled>,
}

impl DenylistChecker {
    /// Build the checker from an `EngagementConfig`. Invalid entries are
    /// skipped (and logged) rather than panicking — the production loader
    /// already validates entries via `check_invariants`, so any failure here
    /// indicates a programmer bypass and is treated as fail-closed (the bad
    /// entry just doesn't apply; everything else still does).
    #[must_use]
    pub fn from_config(cfg: &EngagementConfig) -> Self {
        Self::from_entries(&cfg.global_denylist)
    }

    /// Build the checker from a slice of `DenylistEntry`.
    #[must_use]
    #[allow(clippy::cognitive_complexity)] // dispatch over DenylistEntry variants; each arm trivial
    pub fn from_entries(entries: &[DenylistEntry]) -> Self {
        let mut compiled = Vec::with_capacity(entries.len());
        for entry in entries {
            match entry.kind {
                DenylistKind::Cidr => match entry.value.parse::<IpNet>() {
                    Ok(net) => compiled.push(Compiled::Cidr {
                        net,
                        raw: entry.value.clone(),
                        reason: entry.reason.clone(),
                    }),
                    Err(e) => {
                        error!(
                            target = "sx_engagement::denylist",
                            kind = "cidr",
                            value = %entry.value,
                            error = %e,
                            "denylist entry failed to compile; skipping",
                        );
                    }
                },
                DenylistKind::Domain => {
                    let pattern = entry.value.trim().to_ascii_lowercase();
                    if pattern.is_empty() {
                        error!(
                            target = "sx_engagement::denylist",
                            kind = "domain",
                            "empty domain denylist entry; skipping",
                        );
                    } else {
                        compiled.push(Compiled::Domain {
                            pattern,
                            reason: entry.reason.clone(),
                        });
                    }
                }
                DenylistKind::Regex => match Regex::new(&entry.value) {
                    Ok(re) => compiled.push(Compiled::Regex {
                        re,
                        raw: entry.value.clone(),
                        reason: entry.reason.clone(),
                    }),
                    Err(e) => {
                        error!(
                            target = "sx_engagement::denylist",
                            kind = "regex",
                            value = %entry.value,
                            error = %e,
                            "denylist regex failed to compile; skipping",
                        );
                    }
                },
            }
        }
        Self { entries: compiled }
    }

    /// Number of compiled (i.e. usable) entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the checker has any compiled entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the first matching entry, if any.
    #[must_use]
    pub fn contains(&self, target: &ScopeTarget) -> Option<DenylistHit> {
        for entry in &self.entries {
            if entry_matches(entry, target) {
                return Some(DenylistHit {
                    pattern: entry.raw().to_string(),
                    reason: entry.reason().to_string(),
                });
            }
        }
        None
    }
}

fn entry_matches(entry: &Compiled, target: &ScopeTarget) -> bool {
    match (entry, target) {
        (Compiled::Cidr { net, .. }, ScopeTarget::Cidr(t)) => match (net, t) {
            (IpNet::V4(a), IpNet::V4(b)) => a.contains(&b.network()),
            (IpNet::V6(a), IpNet::V6(b)) => a.contains(&b.network()),
            _ => false,
        },
        (Compiled::Cidr { net, .. }, ScopeTarget::IpV4(ip)) => net.contains(&IpAddr::V4(*ip)),
        (Compiled::Cidr { net, .. }, ScopeTarget::IpV6(ip)) => net.contains(&IpAddr::V6(*ip)),

        (Compiled::Domain { pattern, .. }, ScopeTarget::Domain(host)) => {
            domain_pattern_matches(pattern, host)
        }
        (Compiled::Domain { pattern, .. }, ScopeTarget::Url(u)) => u
            .host_str()
            .is_some_and(|host| domain_pattern_matches(pattern, host)),
        (Compiled::Regex { re, .. }, ScopeTarget::Domain(host)) => re.is_match(host),
        (Compiled::Regex { re, .. }, ScopeTarget::Url(u)) => {
            u.host_str().is_some_and(|host| re.is_match(host))
        }
        (Compiled::Regex { re, .. }, ScopeTarget::Arn(arn)) => re.is_match(arn),
        (Compiled::Regex { re, .. }, ScopeTarget::RepoUrl(s)) => re.is_match(s),
        _ => false,
    }
}

fn domain_pattern_matches(pattern: &str, host: &str) -> bool {
    let pat = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pat.strip_prefix("*.") {
        if suffix.is_empty() {
            return false;
        }
        if host == suffix {
            return true;
        }
        return host.len() > suffix.len() && host.ends_with(&format!(".{suffix}"));
    }
    // For domain denylist entries, treat the value as a suffix match if it
    // begins with `.` (e.g. `.gov`), exact otherwise. The leading dot is
    // strict: `.gov` matches `base.gov` but NOT `gov` on its own — a bare
    // TLD without children is not a deployment target.
    if let Some(suffix) = pat.strip_prefix('.') {
        if suffix.is_empty() {
            return false;
        }
        return host.ends_with(&format!(".{suffix}"));
    }
    pat == host
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::str::FromStr;

    fn entry(kind: DenylistKind, value: &str, reason: &str) -> DenylistEntry {
        DenylistEntry {
            kind,
            value: value.into(),
            reason: reason.into(),
        }
    }

    #[test]
    fn cidr_blocks_ipv4_target() {
        let chk =
            DenylistChecker::from_entries(&[entry(DenylistKind::Cidr, "10.0.0.0/8", "rfc1918")]);
        let hit = chk.contains(&ScopeTarget::IpV4("10.1.2.3".parse().unwrap()));
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().pattern, "10.0.0.0/8");
    }

    #[test]
    fn cidr_blocks_ipv6_target() {
        let chk = DenylistChecker::from_entries(&[entry(
            DenylistKind::Cidr,
            "2001:db8::/32",
            "doc range",
        )]);
        let hit = chk.contains(&ScopeTarget::IpV6("2001:db8::1".parse().unwrap()));
        assert!(hit.is_some());
    }

    #[test]
    fn cidr_blocks_sub_cidr_target() {
        let chk =
            DenylistChecker::from_entries(&[entry(DenylistKind::Cidr, "10.0.0.0/8", "rfc1918")]);
        let target = ScopeTarget::Cidr(IpNet::from_str("10.1.0.0/16").unwrap());
        assert!(chk.contains(&target).is_some());
    }

    #[test]
    fn domain_exact_blocks_host() {
        let chk = DenylistChecker::from_entries(&[entry(
            DenylistKind::Domain,
            "example.gov",
            "government",
        )]);
        assert!(chk
            .contains(&ScopeTarget::Domain("example.gov".into()))
            .is_some());
        assert!(chk
            .contains(&ScopeTarget::Domain("example.com".into()))
            .is_none());
    }

    #[test]
    fn domain_wildcard_blocks_subdomains() {
        let chk =
            DenylistChecker::from_entries(&[entry(DenylistKind::Domain, "*.gov", "government")]);
        assert!(chk
            .contains(&ScopeTarget::Domain("foo.gov".into()))
            .is_some());
        assert!(chk
            .contains(&ScopeTarget::Domain("a.b.gov".into()))
            .is_some());
        assert!(chk
            .contains(&ScopeTarget::Domain("example.com".into()))
            .is_none());
    }

    #[test]
    fn dot_prefix_treated_as_suffix_match() {
        let chk = DenylistChecker::from_entries(&[entry(DenylistKind::Domain, ".mil", "military")]);
        assert!(chk
            .contains(&ScopeTarget::Domain("base.mil".into()))
            .is_some());
        assert!(chk.contains(&ScopeTarget::Domain("mil".into())).is_none());
    }

    #[test]
    fn regex_blocks_arn() {
        let chk = DenylistChecker::from_entries(&[entry(
            DenylistKind::Regex,
            r"^arn:aws:s3:::gov-.*$",
            "gov bucket",
        )]);
        assert!(chk
            .contains(&ScopeTarget::Arn("arn:aws:s3:::gov-secret".into()))
            .is_some());
        assert!(chk
            .contains(&ScopeTarget::Arn("arn:aws:s3:::prod-data".into()))
            .is_none());
    }

    #[test]
    fn invalid_entry_is_skipped_not_panicked() {
        let chk = DenylistChecker::from_entries(&[entry(DenylistKind::Regex, "(", "bad regex")]);
        assert!(chk.is_empty());
    }

    #[test]
    fn no_match_returns_none() {
        let chk =
            DenylistChecker::from_entries(&[entry(DenylistKind::Cidr, "10.0.0.0/8", "rfc1918")]);
        assert!(chk
            .contains(&ScopeTarget::IpV4("8.8.8.8".parse().unwrap()))
            .is_none());
    }

    #[test]
    fn url_blocked_by_domain_pattern() {
        let chk =
            DenylistChecker::from_entries(&[entry(DenylistKind::Domain, "*.gov", "government")]);
        let url = url::Url::parse("https://example.gov/foo").unwrap();
        assert!(chk.contains(&ScopeTarget::Url(url)).is_some());
    }
}
