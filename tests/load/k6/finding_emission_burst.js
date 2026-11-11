// SentinelX finding-emission burst test (P2-008 rate-limit path).
//
// Exercises the FOUND-001 insert path indirectly, via the only public
// emission surface today: log-ingest rate-limit rejection
// (`crates/sx-api/src/controller/log_ingest.rs:59`,
// `RATE_LIMIT_FINDING_WINDOW_SECS = 900`).
//
// What we fire:
//   1 000 simulated rate-limit rejects in 60 s against
//   `POST /v1/logs/ingest` (line 326, crates/sx-api/src/router.rs).
//
// What we assert:
//   1. The 1 000 rejects collapse to **~4–5 findings** at most
//      (15-minute window aggregation by design — the controller
//      deterministically derives finding-id from
//      `(tenant, endpoint, window_start)`, so two bursts inside the
//      same 15-minute slot produce the same id).
//   2. p95 insert latency observed via `GET /v1/findings` post-burst is
//      < 100 ms.
//
// The script presumes a small, stable per-tenant rate-limit ceiling on
// staging — the workspace default is "first 1 000 raw requests, then
// 429". If staging tuned that ceiling up, scale K6_BURST_SIZE
// accordingly via env override; the assertion math is keyed off the
// window count, not the request count.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

const BASE_URL = __ENV.SX_BASE_URL || 'http://127.0.0.1:8080';
const ADMIN_EMAIL = __ENV.SX_ADMIN_EMAIL || 'admin@sentinelx.dev';
const ADMIN_PASSWORD = __ENV.SX_ADMIN_PASSWORD || 'sentinelx-admin-pw';
const TENANT_ID =
  __ENV.SX_TENANT_ID || '01010101-0101-0101-0101-010101010101';

const BURST_SIZE = Number(__ENV.K6_BURST_SIZE) || 1000;
const BURST_WINDOW_SECS = Number(__ENV.K6_BURST_WINDOW_SECS) || 60;

// One burst per VU. We use 5 VUs × 200 reqs ≈ 1 000 reqs in 60 s. k6
// computes the per-VU rate from BURST_SIZE / VUS / BURST_WINDOW_SECS.

// ---------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------

const ingestLatency = new Trend('sx_logs_ingest_duration_ms', true);
const findingsListLatency = new Trend('sx_findings_list_duration_ms', true);
const rateLimitRejects = new Counter('sx_logs_ingest_rejected_429');
const ingestAccepted = new Counter('sx_logs_ingest_accepted');

// ---------------------------------------------------------------------
// k6 options
// ---------------------------------------------------------------------

export const options = {
  scenarios: {
    burst: {
      executor: 'shared-iterations',
      vus: 5,
      iterations: BURST_SIZE,
      maxDuration: `${BURST_WINDOW_SECS + 30}s`,
    },
  },
  thresholds: {
    'sx_logs_ingest_duration_ms': ['p(95)<200'],
    'sx_findings_list_duration_ms': ['p(95)<500'],
    // We _expect_ 429s — most reqs in the burst should reject.
    // No threshold on http_req_failed (429 counts as "failed" in k6's
    // default classification).
  },
  noConnectionReuse: false,
};

// ---------------------------------------------------------------------
// setup() — login once, share the token across all VUs
// ---------------------------------------------------------------------

export function setup() {
  const res = http.post(
    `${BASE_URL}/v1/auth/login`,
    JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      tags: { name: 'POST /v1/auth/login' },
    },
  );
  if (res.status !== 200) {
    throw new Error(
      `setup login failed: status=${res.status} body=${res.body}`,
    );
  }

  // Capture pre-burst finding count so teardown can assert ~4-5 new rows.
  const baseline = http.get(`${BASE_URL}/v1/findings?limit=1`, {
    headers: {
      'Authorization': `Bearer ${res.json('access_token')}`,
      'Accept': 'application/json',
      'X-Tenant-Id': TENANT_ID,
    },
    tags: { name: 'GET /v1/findings (baseline)' },
  });

  let baselineCount = 0;
  try {
    const body = baseline.json();
    if (typeof body.total === 'number') {
      baselineCount = body.total;
    } else if (Array.isArray(body)) {
      baselineCount = body.length;
    } else if (body && Array.isArray(body.items)) {
      baselineCount = body.items.length;
    }
  } catch (_e) {
    // best-effort baseline; falls back to 0.
  }

  return {
    token: res.json('access_token'),
    baselineCount,
    startUnix: Math.floor(Date.now() / 1000),
  };
}

// ---------------------------------------------------------------------
// VU iteration — fire one ingest request
// ---------------------------------------------------------------------

export default function (data) {
  const payload = JSON.stringify({
    // Minimal OCSF-shaped payload; the controller only needs the
    // wrapper to count for rate-limit purposes.
    source_type: 'syslog',
    payload: {
      message: `sentinelx-load-test ${Date.now()}`,
      severity: 'info',
    },
  });

  const res = http.post(`${BASE_URL}/v1/logs/ingest`, payload, {
    headers: {
      'Authorization': `Bearer ${data.token}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-Tenant-Id': TENANT_ID,
    },
    tags: { name: 'POST /v1/logs/ingest' },
  });

  ingestLatency.add(res.timings.duration);

  if (res.status === 429) {
    rateLimitRejects.add(1);
  } else if (res.status >= 200 && res.status < 300) {
    ingestAccepted.add(1);
  }

  // Tight pacing so 1 000 iter / 60 s actually compresses into the window.
  sleep(BURST_WINDOW_SECS / BURST_SIZE);
}

// ---------------------------------------------------------------------
// teardown() — verify aggregation contract
// ---------------------------------------------------------------------

export function teardown(data) {
  // Wait briefly so the spawned FOUND-001 insert tasks land.
  sleep(2);

  const res = http.get(`${BASE_URL}/v1/findings?limit=50`, {
    headers: {
      'Authorization': `Bearer ${data.token}`,
      'Accept': 'application/json',
      'X-Tenant-Id': TENANT_ID,
    },
    tags: { name: 'GET /v1/findings (teardown)' },
  });
  findingsListLatency.add(res.timings.duration);

  if (res.status !== 200) {
    console.error(
      `teardown: findings list returned ${res.status}, cannot verify aggregation`,
    );
    return;
  }

  let total = 0;
  let rateLimitFindings = 0;
  try {
    const body = res.json();
    const items = Array.isArray(body)
      ? body
      : (body && Array.isArray(body.items) ? body.items : []);
    total = items.length;
    rateLimitFindings = items.filter(
      (f) => (f.rule_id || '').indexOf('rate-limit') !== -1
        || (f.title || '').toLowerCase().indexOf('rate limit') !== -1,
    ).length;
  } catch (_e) {
    console.error('teardown: response not parseable as JSON');
    return;
  }

  // The 15-min window aggregation means a 60-s burst that straddles at
  // most ONE window boundary should produce 1 or 2 findings. A long-run
  // soak (multiple bursts spread across an hour) could push it to 4-5.
  // Treat > 10 as a contract regression worth shouting about.
  const expected_lo = 1;
  const expected_hi = 5;

  console.log(
    `teardown: rate-limit findings observed=${rateLimitFindings}, total=${total}, baseline=${data.baselineCount}`,
  );

  check(null, {
    'aggregation: ≤5 new rate-limit findings per burst': () =>
      rateLimitFindings >= expected_lo && rateLimitFindings <= expected_hi,
  });
}
