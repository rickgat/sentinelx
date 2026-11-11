# ADR 0024 — SSRF guard for scan-target URLs (`sx-core::reference::url_guard`)

Status: Accepted
Date: 2026-06-25
Deciders: Principal Security Engineer, Principal Platform Engineer, PO
Supersedes: None
Superseded by: None

## Context

`SentinelX` exposes several endpoints that accept an operator-supplied
URL and reach out to it over the network from inside the monolith
process:

- `POST /v1/scans/http-headers` — passive security-headers probe.
- `POST /v1/discovery/dast/scan` — webapp DAST runner.
- `sx-discovery` web / API DAST scanners called by background jobs.

Without an SSRF guard, the same controller surface that lets a
red-team operator probe a partner's hostname *also* lets a stolen
JWT pivot into:

- the cloud instance-metadata service (`169.254.169.254` and family),
  leaking the monolith's own IAM-role credentials;
- the loopback interface, reaching admin sockets bound to
  `127.0.0.1` (Vault dev-mode, the Postgres exporter, the Prometheus
  scrape port);
- the link-local range, which on cloud guests aliases the metadata
  range and on stale-DHCP hosts aliases stranded internal services.

QC-SCAN-2026-06-25 §a / §b also flagged a second bug: the original
`normalise_target` helper string-prefix-matched `http://` /
`https://` and silently prepended `https://` to anything else, which
turned `file:///etc/passwd` into the nonsense `https://file:///etc/passwd`
and surfaced as a 200-OK "scan error" rather than a 400 reject. Any
SSRF guard had to also fix the scheme-handling so non-`http(s)` URLs
fail-closed.

The two existing layers — `validate_target` (the `validator::custom`
function on `HttpHeaderScanRequest`) and the controller body — were
both cheap allow-list checks that fired before any DNS resolution.
Neither could detect the case where a hostile DNS server resolved
`evil.example.com` to `169.254.169.254`, which is the canonical
DNS-rebinding shape.

## Decision

Introduce a single SSRF guard module at `crates/sx-core/src/reference/url_guard.rs`
exposing `validate_scan_target(raw: &str) -> Result<Url, ScanTargetError>`,
called by every controller that accepts a scan target. The guard is
**layered**, runs **AFTER** the cheap validator allow-list, and is
deliberately **opinionated about RFC 1918 / RFC 4193**:

1. **Layer 1 — cheap allow-list.** The view-layer `validate_target`
   (`crates/sx-api/src/view/scan_view.rs`) keeps the existing
   RFC 3986 character-set check and rejects obviously malformed
   strings without doing I/O. This stays as a fast 400-reject before
   the controller is even invoked.
2. **Layer 2 — scheme allow-list.** `validate_scan_target` rejects
   any URL whose scheme is not `http` or `https`. `file://`,
   `gopher://`, `ftp://`, `data:`, `javascript:`, etc., all fail
   with `ScanTargetError::DisallowedScheme`. When the operator
   omits a scheme entirely (`example.com`), the guard prepends
   `https://` — the legacy UX — but does so **before** scheme
   validation, so the prepend cannot smuggle a bad scheme through.
3. **Layer 3 — DNS resolve + per-IP policy.** The guard resolves the
   hostname via the system resolver, then applies a deny-list to
   *each resolved IP*:
   - loopback (`127.0.0.0/8`, `::1`) → `ScanTargetError::Loopback`;
   - link-local (`169.254.0.0/16`, `fe80::/10`) →
     `ScanTargetError::LinkLocal`;
   - cloud-metadata IPs explicitly (`169.254.169.254`,
     `fd00:ec2::254`, `100.100.100.200`) → `ScanTargetError::CloudMetadata`
     even when they fall in the link-local range, so the audit row
     records the explicit credential-leak pattern.

4. **RFC 1918 / RFC 4193 are ALLOWED.** Internal-network scanning IS
   a documented engagement use case (red-team workshop labs,
   intranet vuln sweeps). Blocking the private ranges would force
   operators to disable the guard wholesale, which is worse than
   the current default. The guard's docstring records this as a
   deliberate exception.

5. **DNS-rebinding mitigation.** Because Layer 3 resolves the
   hostname inside the guard and the controller hands the *resolved
   `Url`* (now carrying the same hostname plus the policy decision)
   to the scanner port, the scanner adapter must re-resolve before
   the TCP connect. Today's scanner uses `reqwest`, which re-resolves
   per connection; an adapter that wanted stricter binding would
   pin to the resolved IP at connect time. This is documented in
   the module-level comment.

The module sits in `sx-core` (the shared kernel) as a deliberate
exception to the crate's "zero I/O" rule, because:

- the rule is consumed by `sx-api`, `sx-monolith`, and
  `sx-discovery`;
- pushing it into any one consumer would either duplicate the rule
  table or create a fan-in dependency back into a consumer crate.

## Consequences

### Operational

- Every controller that takes a URL must call `validate_scan_target`
  before the scanner port. The controllers in question
  (`crates/sx-api/src/controller/scan.rs`,
  `crates/sx-api/src/controller/dast.rs`) do; the call site is
  grep-detectable.
- DNS resolution is async (`tokio::net::lookup_host`), so the
  guard's signature is `async fn`. Controllers `await` it before
  invoking the scanner.
- Error message strings are wire-stable: the `Display` impl on
  each `ScanTargetError` variant is the wire-facing `message`
  field of a 400 envelope, so a CLI / dashboard can branch on
  failure mode.

### Security

- Cloud-metadata leak vector closed (`CloudMetadata` distinct from
  `LinkLocal` so the audit log records the explicit pattern).
- Loopback admin-socket pivot closed.
- Scheme-confusion 200-OK bug from QC-SCAN-2026-06-25 §a closed —
  non-http(s) URLs now 400-reject loudly.
- DNS-rebinding partially mitigated: the resolved IP is checked
  before the scan kicks off. Full mitigation (pin-to-IP) is a
  scanner-adapter concern.

### Maintenance

- The metadata-IP list is a hard-coded `const &[IpAddr]`. Adding
  an entry is a code change with review, not a runtime config
  toggle — deliberate, because the list governs a credential-leak
  surface.
- The guard does not depend on `ipnet` or any other dep beyond
  `url` and `thiserror`, both of which `sx-core` already pulls.

## Alternatives Considered

- **Block RFC 1918 + RFC 4193** — would close intranet-pivot risk
  but break the documented internal-engagement use case. Rejected
  in favour of the deliberate-allow stance, with operator-level
  network policy as the second line of defence.
- **Validator-only (no DNS resolve)** — keeps everything synchronous
  and cheap but cannot catch DNS-rebinding or hostnames that
  resolve to the metadata IPs. Rejected — these are the exact
  shapes the threat model called out.
- **Per-tenant allow-list of target IPs / CIDRs** — overkill for
  Phase 1; the engagement-scope mechanism already lets operators
  restrict targets at the engagement level. Tracked as future work
  if a customer asks.
- **Push the guard into the scanner adapters** — each adapter would
  need its own copy, drift would happen, and we would lose the
  per-controller error wiring. Rejected; the shared-kernel
  exception is the explicit price.

## References

- `crates/sx-core/src/reference/url_guard.rs` — the guard itself,
  with the policy table and rationale inline.
- `crates/sx-api/src/controller/scan.rs`,
  `crates/sx-api/src/controller/dast.rs` — call sites.
- `crates/sx-api/src/view/scan_view.rs::validate_target` — Layer 1
  cheap allow-list.
- QC-SCAN-2026-06-25 §a + §b — bug report that triggered the
  guard.
- [ADR-0023](0023-finding-repository-insert.md) — the
  service-internal write seam emitters use; unrelated to the
  guard but cross-referenced by readers walking recent ADRs.
