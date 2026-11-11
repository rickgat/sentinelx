//! SSRF / scan-target guard (QC-SCAN-2026-06-25 fix for gaps a + b).
//!
//! Centralises the validation any "scan a URL" endpoint must perform
//! before reaching out over the network. The same checks are required by
//! every external probe surface in the workspace —
//! `POST /v1/scans/http-headers`, `POST /v1/discovery/dast/scan`,
//! `sx-discovery` web/API DAST scanners — so the policy lives in
//! `sx-core` as the single source of truth.
//!
//! ## What this guard blocks
//!
//! 1. **Non-http(s) schemes**: `file://`, `gopher://`, `ftp://`, `data:`,
//!    `javascript:`, … all rejected. The historical
//!    [`scanner_http::normalise_target`] check only string-prefix-matched
//!    `http://` / `https://` and silently prepended `https://` for
//!    anything else, which turned `file:///etc/passwd` into the
//!    nonsense `https://file:///etc/passwd` and surfaced as a 200-OK
//!    "scan error" rather than a 400 reject (QC-SCAN-2026-06-25 gap a).
//! 2. **Loopback** (`127.0.0.0/8`, `::1`, `localhost`): would let a
//!    caller turn the monolith into an authenticated proxy onto itself
//!    (self-scan circularity + bypass of any localhost-only
//!    admin sockets).
//! 3. **Link-local** (`169.254.0.0/16`, `fe80::/10`): includes cloud
//!    metadata range and stale DHCP fallbacks; never legitimate scan
//!    targets.
//! 4. **Cloud instance-metadata IPs** explicitly: `169.254.169.254`
//!    (AWS / GCP / Azure / Oracle), `fd00:ec2::254` (AWS IPv6),
//!    `100.100.100.200` (Alibaba). Even if a future metadata service
//!    moves OFF the link-local range, the explicit list keeps the
//!    leak path closed.
//!
//! ## What this guard ALLOWS (deliberately)
//!
//! - **RFC 1918 private networks** (`10/8`, `172.16/12`, `192.168/16`):
//!   internal-network scanning IS a documented engagement use case
//!   (red-team workshop labs, intranet vuln sweeps). Blocking them
//!   would force the operator to disable the guard wholesale.
//! - **Carrier-grade NAT** (`100.64.0.0/10`): same rationale.
//! - **Public IPv4 / IPv6 addresses**: the entire point.
//!
//! ## Why this module lives in `sx-core`
//!
//! `sx-core`'s "zero I/O" rule (see crate-level `lib.rs` docstring) is
//! relaxed here as a deliberate exception: `validate_scan_target` is the
//! only guard that needs DNS resolution AND is consumed by multiple
//! downstream crates (`sx-api`, `sx-monolith`, `sx-discovery`). Pushing
//! it into any one consumer would either duplicate the rule table or
//! create a fan-in dependency back into a consumer crate. The async
//! signature (rather than `std::net::ToSocketAddrs`) keeps it stack-
//! compatible with the surrounding `reqwest` + `tokio` runtime each
//! caller already lives in.

use std::net::IpAddr;

use thiserror::Error;
use url::Url;

/// Outcome of [`validate_scan_target`] when the target fails policy.
///
/// Each variant is wire-stable: the public REST envelope surfaces these
/// `Display` strings as the `message` field of a 400 error so a CLI /
/// dashboard caller can branch on the failure mode without re-parsing
/// the underlying URL.
#[derive(Debug, Error)]
pub enum ScanTargetError {
    /// The string passed in was not a parseable URL even after the
    /// `https://` UX-friendly fallback was applied.
    #[error("invalid URL: {0}")]
    Malformed(String),

    /// The URL parsed but its scheme is outside the `{http, https}`
    /// allow-list. Surfaced for `file://`, `gopher://`, `ftp://`, etc.
    #[error("scheme `{0}` is not allowed; only http and https are supported")]
    DisallowedScheme(String),

    /// Host (literal or DNS-resolved) lies in the loopback range:
    /// `127.0.0.0/8` for IPv4, `::1` for IPv6.
    #[error("loopback addresses are not allowed as scan targets")]
    Loopback,

    /// Host lies in the link-local range: `169.254.0.0/16` for IPv4,
    /// `fe80::/10` for IPv6.
    #[error("link-local addresses are not allowed as scan targets")]
    LinkLocal,

    /// Host resolves to a known cloud-metadata IP (AWS / GCP / Azure /
    /// Alibaba / Oracle). Distinct from [`Self::LinkLocal`] so the
    /// audit log can flag the explicit credential-leakage pattern.
    #[error("cloud-metadata IPs ({0}) are blocked to prevent credential leakage")]
    CloudMetadata(IpAddr),

    /// The hostname does not resolve via the system resolver.
    #[error("hostname `{0}` failed DNS resolution")]
    UnresolvableHost(String),
}

/// Hard-coded cloud-instance-metadata addresses.
///
/// Kept as a static slice (not behind a `HashSet`) because:
/// - the list is small enough that linear scan is faster than hashing;
/// - it ships in compiled form so adding entries is a code change with
///   review, not a runtime config toggle.
const CLOUD_METADATA_IPS: &[IpAddr] = &[
    // AWS / GCP / Azure / Oracle / DigitalOcean IPv4 metadata — the
    // canonical link-local 169.254.169.254 endpoint every major cloud
    // exposes. Also caught by `is_link_local`, but listed explicitly so
    // the audit log records `CloudMetadata` rather than `LinkLocal`.
    IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 254)),
    // AWS IPv6 instance metadata (RFC 8415-style allocation).
    IpAddr::V6(std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)),
    // Alibaba Cloud secondary metadata endpoint.
    IpAddr::V4(std::net::Ipv4Addr::new(100, 100, 100, 200)),
];

/// Validate `raw` as a scan target.
///
/// Returns the parsed [`Url`] on success (normalised to `https://` when
/// the caller omitted a scheme — keeping the legacy "operator can type
/// `example.com`" UX). On failure returns a [`ScanTargetError`] whose
/// `Display` string is the wire-facing message.
///
/// ## Resolution strategy
///
/// 1. Parse with `url::Url::parse`. If that fails AND the input does not
///    already contain `://`, prepend `https://` and retry once. Failing
///    twice → [`ScanTargetError::Malformed`].
/// 2. Reject any scheme outside `{http, https}` → [`ScanTargetError::DisallowedScheme`].
/// 3. Extract the host. IP-literal hosts (v4 or v6) skip DNS entirely
///    and check the literal directly. Hostnames are resolved via
///    `tokio::net::lookup_host` — EVERY returned address must pass.
/// 4. Per resolved address: reject loopback, link-local, and the
///    explicit cloud-metadata list. RFC 1918 private space is allowed.
///
/// ## Why async
///
/// DNS resolution is I/O. Every consumer of this guard runs inside a
/// tokio runtime (axum, reqwest), so an async signature avoids forcing
/// a blocking-thread hop. The pure-validation branches (malformed
/// scheme, IP literal) complete without ever yielding.
pub async fn validate_scan_target(raw: &str) -> Result<Url, ScanTargetError> {
    let parsed = parse_with_https_fallback(raw)?;
    enforce_scheme(&parsed)?;

    let host = parsed
        .host_str()
        .ok_or_else(|| ScanTargetError::Malformed(format!("`{raw}` has no host component")))?;

    // IP literal? Skip DNS, check the literal directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        enforce_ip_policy(ip)?;
        return Ok(parsed);
    }

    // Hostname → DNS resolution. We need at least one returned address;
    // we then validate EVERY address (an attacker controlling DNS could
    // round-robin a benign + malicious answer to bypass first-hit checks).
    let port = parsed.port_or_known_default().unwrap_or(443);
    let lookup_target = format!("{host}:{port}");
    let mut iter = tokio::net::lookup_host(&lookup_target)
        .await
        .map_err(|_| ScanTargetError::UnresolvableHost(host.to_owned()))?;

    let first = iter
        .next()
        .ok_or_else(|| ScanTargetError::UnresolvableHost(host.to_owned()))?;
    enforce_ip_policy(first.ip())?;
    for socket in iter {
        enforce_ip_policy(socket.ip())?;
    }
    Ok(parsed)
}

/// Parse `raw` directly; on failure retry with an `https://` prefix
/// when the input has no `://` marker. This preserves the legacy
/// "operator can type `example.com`" UX without bypassing the scheme
/// guard — a `file:` input is parseable as-is and gets rejected on
/// scheme, not on parse.
fn parse_with_https_fallback(raw: &str) -> Result<Url, ScanTargetError> {
    if let Ok(u) = Url::parse(raw) {
        return Ok(u);
    }
    if !raw.contains("://") {
        if let Ok(u) = Url::parse(&format!("https://{raw}")) {
            return Ok(u);
        }
    }
    Err(ScanTargetError::Malformed(raw.to_owned()))
}

fn enforce_scheme(url: &Url) -> Result<(), ScanTargetError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(ScanTargetError::DisallowedScheme(other.to_owned())),
    }
}

/// Apply the IP-level policy to a single resolved address.
///
/// Ordered so the most-specific reject path (`CloudMetadata`) fires
/// before the more-general `LinkLocal` arm, even though
/// `169.254.169.254` matches both — the explicit variant gives the
/// audit log a sharper signal.
fn enforce_ip_policy(ip: IpAddr) -> Result<(), ScanTargetError> {
    if CLOUD_METADATA_IPS.contains(&ip) {
        return Err(ScanTargetError::CloudMetadata(ip));
    }
    if ip.is_loopback() {
        return Err(ScanTargetError::Loopback);
    }
    if is_link_local(ip) {
        return Err(ScanTargetError::LinkLocal);
    }
    Ok(())
}

/// Stable link-local predicate.
///
/// `std::net::Ipv4Addr::is_link_local` is stable; the IPv6 equivalent
/// (`Ipv6Addr::is_unicast_link_local`) is `#[unstable]` on the
/// pinned toolchain, so we bit-test the prefix manually.
const fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        // fe80::/10 — the top 10 bits are 1111 1110 10, so the leading
        // u16 segment masks to `0xffc0 == 0xfe80`.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ---- positive cases ----------------------------------------------

    #[tokio::test]
    async fn accepts_public_https_url() {
        // scanme.nmap.org is the canonical pentest target the upstream
        // project explicitly invites traffic to. The test only checks
        // resolution + policy; we never hit the server.
        let res = validate_scan_target("https://scanme.nmap.org/").await;
        assert!(res.is_ok(), "expected scanme.nmap.org to pass; got {res:?}");
    }

    #[tokio::test]
    async fn accepts_example_dot_com() {
        let res = validate_scan_target("https://example.com").await;
        assert!(res.is_ok(), "expected example.com to pass; got {res:?}");
    }

    #[tokio::test]
    async fn accepts_rfc1918_private_ipv4() {
        let url = validate_scan_target("http://10.0.0.1/").await.unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("10.0.0.1"));
    }

    #[tokio::test]
    async fn bare_hostname_is_normalised_to_https() {
        let url = validate_scan_target("example.com").await.unwrap();
        assert_eq!(
            url.scheme(),
            "https",
            "bare hostname should be normalised to https"
        );
    }

    // ---- negative cases ----------------------------------------------

    #[tokio::test]
    async fn rejects_file_scheme() {
        let err = validate_scan_target("file:///etc/passwd")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ScanTargetError::DisallowedScheme(ref s) if s == "file"),
            "expected DisallowedScheme(file); got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_gopher_scheme() {
        let err = validate_scan_target("gopher://anything").await.unwrap_err();
        assert!(
            matches!(err, ScanTargetError::DisallowedScheme(ref s) if s == "gopher"),
            "expected DisallowedScheme(gopher); got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_ftp_scheme() {
        let err = validate_scan_target("ftp://example.com").await.unwrap_err();
        assert!(
            matches!(err, ScanTargetError::DisallowedScheme(ref s) if s == "ftp"),
            "expected DisallowedScheme(ftp); got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_loopback_ipv4_literal() {
        let err = validate_scan_target("http://127.0.0.1").await.unwrap_err();
        assert!(
            matches!(err, ScanTargetError::Loopback),
            "expected Loopback; got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_loopback_ipv6_literal() {
        let err = validate_scan_target("http://[::1]").await.unwrap_err();
        assert!(
            matches!(err, ScanTargetError::Loopback),
            "expected Loopback; got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_localhost_via_dns() {
        // `localhost` resolves to 127.0.0.1 / ::1 on every supported
        // host, so the IP-policy check fires after DNS.
        let err = validate_scan_target("http://localhost").await.unwrap_err();
        assert!(
            matches!(err, ScanTargetError::Loopback),
            "expected Loopback for localhost; got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_aws_metadata_ip() {
        let err = validate_scan_target("http://169.254.169.254")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ScanTargetError::CloudMetadata(_)),
            "expected CloudMetadata; got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_link_local_non_metadata() {
        let err = validate_scan_target("http://169.254.0.1")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ScanTargetError::LinkLocal),
            "expected LinkLocal; got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_unresolvable_host() {
        // `.invalid` is reserved by RFC 2606 to never resolve. Belt and
        // suspenders: extremely unlikely 64-char random label below.
        let err = validate_scan_target("http://nonexistent-domain-xyz-test-12345.invalid")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ScanTargetError::UnresolvableHost(_)),
            "expected UnresolvableHost; got {err:?}"
        );
    }

    // ---- predicate sanity -------------------------------------------

    #[test]
    fn link_local_predicate_matches_canonical_prefixes() {
        assert!(is_link_local(IpAddr::V4(
            "169.254.169.254".parse().unwrap()
        )));
        assert!(is_link_local(IpAddr::V4("169.254.0.1".parse().unwrap())));
        assert!(!is_link_local(IpAddr::V4("10.0.0.1".parse().unwrap())));
        assert!(is_link_local(IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(!is_link_local(IpAddr::V6("2001:db8::1".parse().unwrap())));
    }
}
