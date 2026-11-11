//! Property-based tests for `ScopeTarget` parsing and round-tripping.
//!
//! Covers:
//!
//! 1. Any well-formed `Domain` string round-trips through `Display`.
//! 2. Any `IpNet` CIDR round-trips through `Display` → `parse::<IpNet>`.
//! 3. Random free-form strings classified via `parse_url_or_domain` never
//!    panic; when they parse, they yield a `Url`, `Cidr`, `IpV4`, `IpV6`,
//!    or `Domain` variant.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::items_after_statements
)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use proptest::prelude::*;
use url::Url;

use sx_engagement::model::ScopeTarget;

/// Strategy for a syntactically-valid hostname label (no leading/trailing
/// hyphen, ASCII alphanumeric + `-`, length 1..=20).
fn label_strategy() -> impl Strategy<Value = String> {
    // First char must not be `-`. Middle chars may be alnum or `-`. Last
    // char must not be `-`.
    "[a-z0-9][a-z0-9-]{0,18}[a-z0-9]".prop_filter("no trailing hyphen", |s| {
        !s.starts_with('-') && !s.ends_with('-')
    })
}

/// Strategy for a valid 2-3-label domain like `foo.example`, `a.b.c`.
fn domain_strategy() -> impl Strategy<Value = String> {
    (2usize..=3, label_strategy()).prop_flat_map(|(n, _)| {
        prop::collection::vec(label_strategy(), n).prop_map(|labels| labels.join("."))
    })
}

/// Strategy for an arbitrary IPv4 CIDR.
fn ipv4_net_strategy() -> impl Strategy<Value = IpNet> {
    (any::<u32>(), 0u8..=32u8).prop_map(|(addr, prefix)| {
        let ip = Ipv4Addr::from(addr);
        let net = Ipv4Net::new(ip, prefix).unwrap_or_else(|_| Ipv4Net::new(ip, 32).unwrap());
        IpNet::V4(net.trunc())
    })
}

/// Strategy for an arbitrary IPv6 CIDR.
fn ipv6_net_strategy() -> impl Strategy<Value = IpNet> {
    (any::<u128>(), 0u8..=128u8).prop_map(|(addr, prefix)| {
        let ip = Ipv6Addr::from(addr);
        let net = Ipv6Net::new(ip, prefix).unwrap_or_else(|_| Ipv6Net::new(ip, 128).unwrap());
        IpNet::V6(net.trunc())
    })
}

fn ipnet_strategy() -> impl Strategy<Value = IpNet> {
    prop_oneof![ipv4_net_strategy(), ipv6_net_strategy()]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any syntactically valid domain string round-trips through `Display`.
    ///
    /// Construction lowercases and trims the input, so we feed the
    /// generator pre-normalised lowercase strings; the round-trip is on the
    /// *constructed* `ScopeTarget::Domain` value.
    #[test]
    fn domain_round_trips_through_display(s in domain_strategy()) {
        let target = ScopeTarget::domain(s).expect("valid generated domain");
        let displayed = target.to_string();
        // Reparse the displayed form: must succeed and re-equal `target`.
        let reparsed = ScopeTarget::domain(&displayed).expect("display round-trip");
        prop_assert_eq!(&displayed, &reparsed.to_string());
        prop_assert_eq!(target, reparsed);
    }

    /// Any `IpNet` CIDR round-trips through `Display` → `parse::<IpNet>`.
    ///
    /// We compare against the *trunc'd* form because `IpNet::Display`
    /// emits the network address (not the original host bits), so the
    /// reparsed value equals the truncated CIDR.
    #[test]
    fn ip_cidr_round_trips_through_display(net in ipnet_strategy()) {
        let target = ScopeTarget::Cidr(net);
        let displayed = target.to_string();
        let reparsed_net = IpNet::from_str(&displayed).expect("CIDR round-trip");
        prop_assert_eq!(reparsed_net, net.trunc());
        let reparsed = ScopeTarget::Cidr(reparsed_net);
        // The Display of the reparsed value matches the original Display.
        prop_assert_eq!(reparsed.to_string(), displayed);
    }

    /// `parse_url_or_domain` is total — it never panics on arbitrary input.
    /// When it returns `Some`, the resulting variant must be one of the
    /// supported classifications.
    #[test]
    fn random_string_classifies_to_url_or_domain_without_panic(
        s in "\\PC{0,128}",
    ) {
        let result = ScopeTarget::parse_url_or_domain(&s);
        if let Some(target) = result {
            // Sanity: every variant is reachable through this path.
            match target {
                ScopeTarget::Url(_)
                | ScopeTarget::Cidr(_)
                | ScopeTarget::IpV4(_)
                | ScopeTarget::IpV6(_)
                | ScopeTarget::Domain(_) => {}
                ScopeTarget::Arn(_) | ScopeTarget::RepoUrl(_) => {
                    prop_assert!(
                        false,
                        "parse_url_or_domain must never produce Arn/RepoUrl"
                    );
                }
            }
        }
    }

    /// A well-formed http(s) URL string classifies to `Url`.
    #[test]
    fn http_url_classifies_to_url_variant(host in domain_strategy(), path in "[a-z0-9/]{0,16}") {
        let raw = format!("https://{host}/{path}");
        // Some randomly-generated hosts (e.g. `aa.00`) are rejected by the
        // URL parser because the trailing label looks like a partial IPv4
        // address. Skip those — they're not the cases we're testing.
        let Ok(url) = Url::parse(&raw) else {
            return Ok(());
        };
        let target = ScopeTarget::parse_url_or_domain(url.as_str())
            .expect("https URL must classify");
        prop_assert!(matches!(target, ScopeTarget::Url(_)));
    }

    /// A bare domain string falls back to `Domain`.
    ///
    /// Some randomly generated hostnames are also valid bare IPv4 / IPv6
    /// addresses (e.g. `1.2.3.4` is both an "IPv4" and a 4-label domain);
    /// `parse_url_or_domain` prefers the more-specific IP classification,
    /// which is correct. We assert the result is *one of* the
    /// expected variants and that the function never returns `None` for a
    /// generated valid domain.
    #[test]
    fn bare_domain_falls_back_to_domain_variant(host in domain_strategy()) {
        let target = ScopeTarget::parse_url_or_domain(&host)
            .expect("bare domain must classify");
        prop_assert!(matches!(
            target,
            ScopeTarget::Domain(_) | ScopeTarget::IpV4(_) | ScopeTarget::IpV6(_) | ScopeTarget::Cidr(_)
        ));
    }
}
