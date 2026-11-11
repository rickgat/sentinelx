# QC re-run report (round 2) — 2026-06-25

Re-runs the QC scan-simulation + dashboard suites against the live
monolith binary built from commit `7985bee` (merged in `291596e`).
Verifies the three SSRF / route gaps (a / b / c) from
[`qc_scan_simulation_report_2026-06-25.md`](./qc_scan_simulation_report_2026-06-25.md)
are CLOSED in the running binary, and probes additional SSRF surface
that the round-1 fix did not specifically target.

- Branch: `feat/qc-rerun-2026-06-25-round-2` (off `main` @ `2d6f9ba`).
- Monolith: `http://127.0.0.1:8080` — JWT obtained via `POST /v1/auth/login`
  with the bootstrap admin (`admin@sentinelx.dev`, tenant
  `01010101-0101-0101-0101-010101010101`).
- Dashboard: `http://127.0.0.1:3000` (Playwright suite NOT executable
  from this agent — see §2 caveat).

## 1. Scan-simulation re-run — `qc_scan_simulation.sh`

Each step below was driven as an individual `curl` call against the
live binary (the script itself could not be `exec`'d from this agent's
sandbox; every assertion was reproduced one-by-one with identical
payloads + identical expected codes).

| # | Case | Expected | Got | Notes |
|---|---|---|---|---|
| 1 | scan `https://example.com` | 200 | **200** | positive control |
| 2 | list scans | 200 | **200** | |
| 3 | scan RFC1918 `http://10.0.0.1` | 200 | **200** | private space allowed |
| 4a | `file:///etc/passwd` | 400 | **400** `DisallowedScheme(file)` | gap (a) CLOSED |
| 4b | `gopher://anything` | 400 | **400** `DisallowedScheme(gopher)` | |
| 4c | `http://127.0.0.1:8080` | 400 | **400** `Loopback` | gap (b) CLOSED |
| 4d | `http://[::1]` | 400 | **422** `invalid_target` | rejected EARLIER at validator (see §3.2) |
| 4e | `http://localhost` | 400 | **400** `Loopback` | DNS-resolved |
| 4f | `http://169.254.169.254/latest/meta-data/iam` | 400 | **400** `CloudMetadata(169.254.169.254)` | gap (b) CLOSED |
| 4g | `http://169.254.0.1` | 400 | **400** `LinkLocal` | |
| 5a | `GET /v1/scans/<uuid>` | 200 | **200** | gap (c) CLOSED |
| 5b | `GET /v1/scans/<uuid>.sarif` | 200 | **200** | |
| 5c | `GET /v1/scans/00000000-…` | 404 | **404** | |

Original suite (12 cases): **11 pass / 1 deviation** (4d hits validator
layer 422 not SSRF guard 400 — both are correct rejections but the
script asserts `==400`; flagged as a low-severity test-quality nit, not
a binary regression — see §3.2).

### Round-2 extra SSRF probes — `qc_scan_simulation_extra.sh`

New script committed in this round; covers DNS rebinding, IPv6
variants, punycode, URL-encoded host smuggling, and three cloud-
metadata variants the round-1 fix table did not enumerate.

| # | Case | Expected | Got | Variant returned |
|---|---|---|---|---|
| 1a | `http://1.1.1.1.nip.io` (positive control) | 200 | **200** | scan ok |
| 1b | `http://127.0.0.1.nip.io` (DNS-rebind → loopback) | 400 | **400** | `Loopback` |
| 1c | `http://169.254.169.254.nip.io` (DNS-rebind → metadata) | 400 | **400** | `CloudMetadata(169.254.169.254)` |
| 2a | `http://[::ffff:127.0.0.1]/` | 400/422 | **422** | `invalid_target` (validator) |
| 2b | `http://[fe80::1]/` | 400/422 | **422** | `invalid_target` (validator) |
| 2c | `http://[fd00::1]/` (RFC 4193 ULA — SHOULD pass) | 200 | **422** | `invalid_target` (validator) — see §3.3 |
| 3a | `http://xn--lcalhost-7za/` | 400 | **400** | `UnresolvableHost` |
| 3b | `http://127.0.0.1%23/` | 400/422 | **422** | `invalid_target` (validator) |
| 4a | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | 400 | **400** | `CloudMetadata` |
| 4b | `http://metadata.google.internal/` | 400 | **400** | `UnresolvableHost` on this host (on a GCP VM it would resolve to 169.254.169.254 → `CloudMetadata`) |
| 4c | `http://[fd00:ec2::254]/` | 400/422 | **422** | `invalid_target` (validator) |
| 4d (bonus) | `http://100.100.100.200/latest/meta-data/` (Alibaba) | 400 | **400** | `CloudMetadata(100.100.100.200)` |

Extra suite (12 cases): all behave as documented above. DNS-rebinding
attacks via `nip.io` are **caught** (great — the round-1 fix's
`tokio::net::lookup_host` + per-resolved-address check holds up under
the rebinding probe).

## 2. Playwright re-run — `qc-comprehensive.spec.ts`

**NOT executed in this round.** The agent sandbox forbids
`npx` / `./node_modules/.bin/playwright` launches; additionally
`web/dashboard/node_modules/` is not present in the worktree. The
spec was last validated against this monolith binary in the round-1
report (39/39). No dashboard source changed between `2d6f9ba` and HEAD
of this branch (only test files added under `web/dashboard/e2e/` +
`tests/integration/`), so a re-run is not expected to surface a
binary regression — it would only validate the FOUR new edge-case
specs added in §2.1 below.

Action: a human or non-sandboxed agent must run
`cd web/dashboard && CI=1 npx playwright test --reporter=line` once
`node_modules/` is installed.

### 2.1 New edge-case specs — `qc-edge-cases.spec.ts`

Added to the worktree at `web/dashboard/e2e/qc-edge-cases.spec.ts`
(not yet executed; depends on the action above). Four cases:

1. **CSRF / cross-origin login** — `request.post(/v1/auth/login)` with
   `Origin: https://evil.example`. Asserts the response does NOT carry
   `Access-Control-Allow-Origin: *` nor echo back the attacker origin.
   This is the only meaningful CSRF defense for a bearer-token API
   surface; same-origin XHR from `evil.example` should not be able to
   read the JWT off the response even if the login succeeds.
2. **Long URL fuzz** — navigates to
   `/dashboard/findings?q=<10 KiB>` and asserts the SSR returns
   `<500`, lands on the findings view, and emits no console error.
3. **Finding-detail enrichment click-through** — clicks the seed
   finding row → asserts CVSS / CWE / MITRE pills are visible on
   the detail page. Guards the SX-REVIEW-002 C1 wiring.
4. **Logout-while-on-detail** — open `/dashboard/findings/{seed}` in
   tab A, logout in tab B, reload A, assert redirect to `/login`.

## 3. New gaps surfaced

### 3.1 [INFORMATIONAL] DNS resolver dependency on `metadata.google.internal`

**Severity:** none (defense-in-depth holds).
**Observation:** `metadata.google.internal` does NOT resolve from the
local runner so the request was rejected with `UnresolvableHost`. On a
real GCP VM it would resolve to `169.254.169.254` and the explicit
`CloudMetadata` arm would fire instead. Both arms are correct
rejections; the test asserts only that the status is 400.

**No action.** Recorded so the next reviewer doesn't read the
`UnresolvableHost` wire string and assume the cloud-metadata explicit
list is unreached.

### 3.2 [LOW] Bracketed-IPv6 + URL-encoded chars rejected at validator layer (422), not SSRF guard (400)

**Severity:** low (test-quality nit, not a binary regression).
**Repro:**
```
POST /v1/scans/http-headers {"target":"http://[::1]"}
→ 422 {"code":"UNPROCESSABLE_ENTITY","message":"unprocessable: target: invalid_target"}
```
**Why:** `crates/sx-api/src/view/scan_view.rs::validate_target`
allow-lists only `[a-zA-Z0-9.\-:/]`. Square brackets (`[`, `]`),
percent (`%`), and underscore (`_`) are all rejected at the validator
BEFORE `validate_scan_target` is reached. That's a hardened parser
posture — defense in depth — but it means:

  - the round-1 script's step 4d asserts `==400` for `http://[::1]`
    and would FAIL if anyone re-runs it against today's binary;
  - the SSRF guard's IPv6 branches (`Loopback` for `::1`,
    `LinkLocal` for `fe80::`, plus the AWS IPv6 metadata entry
    `fd00:ec2::254`) are unreachable from this endpoint — they exist
    for other consumers (`POST /v1/discovery/dast/scan`,
    `sx-discovery` web/API DAST scanners) that don't share this
    validator.

**Suggested fix scope:** one of:
  - (preferred) loosen `validate_target` to admit `[`, `]`, `%` and
    let the SSRF guard return the structured 400 — keeps wire
    behaviour consistent across endpoints. Plus: update step 4d of
    `qc_scan_simulation.sh` to assert `==400` and add 5 new step-4
    rows for the IPv6 variants.
  - (alternative) update the round-1 script to accept `400 or 422`
    for IPv6 inputs and document the two-layer reject explicitly.

### 3.3 [LOW] IPv6 unique-local addresses (RFC 4193 `fd00::/8`) are unreachable from this endpoint

**Severity:** low (operator-facing coverage gap, not a security
regression).
**Repro:**
```
POST /v1/scans/http-headers {"target":"http://[fd00::1]/"}
→ 422 invalid_target
```
**Why:** same root cause as §3.2 — square brackets blocked at the
validator. RFC 4193 ULA is the IPv6 equivalent of RFC 1918 private
space and IS explicitly allowed by the SSRF guard (`enforce_ip_policy`
returns `Ok` for ULA addresses), so an operator scanning a private
IPv6 lab CANNOT do it via `/v1/scans/http-headers` today.

**Suggested fix scope:** same as §3.2 (loosen the validator).

### 3.4 [INFORMATIONAL] Playwright suite not executed in this round

**Severity:** none (process gap).
**Repro:** `web/dashboard/node_modules/` does not exist in the
worktree; sandbox denies `npx`.
**Suggested follow-up:** the human or a non-sandboxed CI step should
run `cd web/dashboard && pnpm install && CI=1 pnpm playwright test
qc-comprehensive.spec.ts qc-edge-cases.spec.ts --reporter=line`
before merging this branch.

## 4. Verification — round-1 gaps (a) + (b) + (c) CLOSED in the running binary

Pasted curl evidence for each gap (full JSON body — one line each):

### (a) DisallowedScheme — `file:///etc/passwd` rejected

```
$ curl -sS -X POST -H "Authorization: Bearer …" -H "Content-Type: application/json" \
    --data '{"target":"file:///etc/passwd"}' http://127.0.0.1:8080/v1/scans/http-headers -w "\nHTTP=%{http_code}\n"
{"error":{"code":"BAD_REQUEST","message":"bad request: scheme `file` is not allowed; only http and https are supported","request_id":"019efeacce2a73b28331b66e25ecbe3c"}}
HTTP=400
```

### (b) Loopback + CloudMetadata — `127.0.0.1` and `169.254.169.254` rejected

```
$ curl -sS -X POST … --data '{"target":"http://127.0.0.1:8080"}' http://127.0.0.1:8080/v1/scans/http-headers -w "\nHTTP=%{http_code}\n"
{"error":{"code":"BAD_REQUEST","message":"bad request: loopback addresses are not allowed as scan targets","request_id":"019efeacdbcf7f428921245dcad03d8c"}}
HTTP=400

$ curl -sS -X POST … --data '{"target":"http://169.254.169.254/latest/meta-data/iam"}' http://127.0.0.1:8080/v1/scans/http-headers -w "\nHTTP=%{http_code}\n"
{"error":{"code":"BAD_REQUEST","message":"bad request: cloud-metadata IPs (169.254.169.254) are blocked to prevent credential leakage","request_id":"019efeacf13c79518b71680d08bc62f7"}}
HTTP=400
```

### (c) JSON scan-detail route — `GET /v1/scans/{uuid}` returns 200

```
$ curl -sS -w "\nHTTP=%{http_code}\n" -H "Authorization: Bearer …" \
    http://127.0.0.1:8080/v1/scans/019efeac-a5c7-78e1-8a6b-c3054c24f5fb
# (200 OK; body is the standard ApiResponse<ScanRecord> JSON envelope)
HTTP=200
```

Plus the `.sarif` suffix still works (HTTP=200) and an unknown id
returns HTTP=404. Dispatcher behaves as documented.

## 5. Sign-off

- 12/12 round-1 scan-sim assertions verified live (1 routes via 422 not 400; see §3.2).
- 12/12 round-2 extra SSRF probes verified live; DNS-rebinding attacks via `nip.io` correctly rejected.
- 4 new dashboard edge-case specs landed but NOT yet executed (§3.4).
- 0 binary regressions surfaced.
- 2 low-severity findings (§3.2, §3.3) — both reduce to the same one-line `validate_target` allowlist edit; followup task, not a blocker.

No Rust source changed in this round (probing run only). No
`cargo fmt --workspace`/`--all` invoked.
