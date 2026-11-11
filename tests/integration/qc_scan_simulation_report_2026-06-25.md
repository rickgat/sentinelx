# QC scan simulation report — 2026-06-25

Live `tests/integration/qc_scan_simulation.sh` walkthrough of the
operator-facing scan surface (`/v1/scans/*` and `/v1/discovery/dast/*`).
Three gaps surfaced. All three are closed by branch
`feat/scan-ssrf-guard-and-detail-route` (QC-SCAN-2026-06-25-FIX).

## Gaps

### (a) [closed] SSRF — non-http schemes accepted

`POST /v1/scans/http-headers` previously accepted `file:///etc/passwd`
and other non-`http(s)` schemes. The validator at
`services/sx-monolith/src/adapters/scanner_http.rs::normalise_target`
only string-prefix-matched `http://` / `https://` and silently
prepended `https://` for anything else, turning `file:///etc/passwd`
into the nonsense `https://file:///etc/passwd` which then surfaced as a
200 OK with `status: error` rather than a structured 400 reject.

**Fix:** new `sx_core::reference::url_guard::validate_scan_target`
ships a scheme allow-list (`{http, https}`) and rejects everything
else with `ScanTargetError::DisallowedScheme`. Wired into both
`POST /v1/scans/http-headers` and `POST /v1/discovery/dast/scan` at
the controller layer (returns HTTP 400) and at the
`scanner_http::normalise_target` adapter (defense-in-depth, returns
`Phase3PortError::Invalid`).

### (b) [closed] Loopback / cloud metadata accepted

Same endpoint previously accepted `http://127.0.0.1:8080/...` (self-
scan loopback) and `http://169.254.169.254/...` (AWS / GCP / Azure /
Oracle instance-metadata service). Self-scans are circular and
metadata IPs leak instance credentials when the scanner attaches a
bearer token.

**Fix:** `validate_scan_target` resolves the host (IP literal or via
`tokio::net::lookup_host`) and per address rejects:
- `is_loopback()` → `ScanTargetError::Loopback`
- `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200` →
  `ScanTargetError::CloudMetadata(ip)`
- `is_link_local()` (v4 169.254.0.0/16, v6 fe80::/10) →
  `ScanTargetError::LinkLocal`

RFC 1918 private networks (10/8, 172.16/12, 192.168/16) and CGNAT
(100.64.0.0/10) remain ALLOWED — internal-network scanning is a
documented engagement use case.

### (c) [closed] No bare `GET /v1/scans/{id}` JSON detail

The SARIF route added at TOP5-#3-P2-SARIF-API registered
`/v1/scans/:id_sarif` because axum 0.7 / matchit 0.7 cannot bind
`:id.sarif` in a single path segment. As a side-effect, a bare
`GET /v1/scans/{any-id}` returned 404 — operators could list and
SARIF-export but not JSON-detail-fetch a single scan.

**Fix:** collapsed both routes into a single capture
`/v1/scans/:any_id` served by a new `get_scan_dispatch` handler. The
handler inspects the trailing `.sarif` suffix; with it → SARIF
exporter, without it → new `build_json_detail_response` helper that
returns the standard `ApiResponse<ScanRecord>` envelope.

## Tests

- 14 url-guard unit tests (`crates/sx-core/src/reference/url_guard.rs::tests`).
- 3 dispatcher integration tests (`crates/sx-api/tests/scan_detail_endpoint.rs`).
- 2 new adapter tests (`scanner_http.rs::normalise_target_rejects_*`).
- Existing wiremock test refactored to drive the header-evaluation path
  directly so the SSRF guard's loopback reject does not break the
  enrichment regression net.

`cargo test -p sx-core -p sx-api -p sx-monolith` green (1695 tests).
`cargo clippy -p sx-core -p sx-api -p sx-monolith --all-targets -- -D warnings` clean.
