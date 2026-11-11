// SentinelX scan-flow load test.
//
// Exercises the http-headers scanner end-to-end, including the
// TOP5-#3-P2-SARIF-API SARIF export endpoint:
//
//   POST /v1/auth/login              (line 581, crates/sx-api/src/router.rs)
//   POST /v1/scans/http-headers       (line 127)
//   GET  /v1/scans                    (line 130)  — used for polling
//   GET  /v1/scans/:id.sarif          (line 143)  — SARIF v2.1.0 export
//
// The SARIF endpoint mirrors the in-process gate at
// `crates/sx-api/tests/scan_sarif_endpoint.rs` — same Content-Type,
// same JSON shape, same enrichment surface.

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

const BASE_URL = __ENV.SX_BASE_URL || 'http://127.0.0.1:8080';
const ADMIN_EMAIL = __ENV.SX_ADMIN_EMAIL || 'admin@sentinelx.dev';
const ADMIN_PASSWORD = __ENV.SX_ADMIN_PASSWORD || 'sentinelx-admin-pw';
const TENANT_ID =
  __ENV.SX_TENANT_ID || '01010101-0101-0101-0101-010101010101';

// httpbin.org echoes arbitrary headers back; defaulting to a missing-HSTS
// payload exercises the enrichment path the in-process SARIF test pins.
const SCAN_TARGET =
  __ENV.SX_SCAN_TARGET ||
  'https://httpbin.org/response-headers?X-Test=sentinelx-load';

// ---------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------

const submitLatency = new Trend('sx_scan_submit_duration_ms', true);
const scanCompletionTime = new Trend('sx_scan_completion_time_ms', true);
const sarifLatency = new Trend('sx_scan_sarif_duration_ms', true);
const scanTimeouts = new Counter('sx_scan_timeouts');
const scanFlowErrors = new Rate('sx_scan_flow_errors');

// ---------------------------------------------------------------------
// k6 options — thresholds reflect docs/slos-production.md
// ---------------------------------------------------------------------

export const options = {
  vus: Number(__ENV.K6_VUS) || 10,
  duration: __ENV.K6_DURATION || '10m',

  thresholds: {
    'sx_scan_submit_duration_ms': ['p(95)<2000'], // submit is async, just enqueue
    'sx_scan_completion_time_ms': ['p(95)<30000', 'p(99)<60000'],
    'sx_scan_sarif_duration_ms': ['p(95)<1000', 'p(99)<2000'],
    'sx_scan_flow_errors': ['rate<0.05'], // 5% — scans depend on external target
    'sx_scan_timeouts': ['count<5'], // a few timeouts ok over 10min run
  },
};

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

function jsonHeaders(token, extra) {
  const base = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-Tenant-Id': TENANT_ID,
  };
  if (token) {
    base.Authorization = `Bearer ${token}`;
  }
  if (extra) {
    for (const k in extra) {
      base[k] = extra[k];
    }
  }
  return base;
}

function login() {
  const payload = JSON.stringify({
    email: ADMIN_EMAIL,
    password: ADMIN_PASSWORD,
  });
  const res = http.post(`${BASE_URL}/v1/auth/login`, payload, {
    headers: jsonHeaders(null),
    tags: { name: 'POST /v1/auth/login' },
  });
  const ok = check(res, {
    'login: status is 200': (r) => r.status === 200,
  });
  if (!ok) {
    return null;
  }
  return res.json('access_token');
}

// ---------------------------------------------------------------------
// VU lifecycle
// ---------------------------------------------------------------------

export default function () {
  const token = login();
  if (!token) {
    scanFlowErrors.add(1);
    sleep(1);
    return;
  }

  let scanId = null;

  group('submit scan', () => {
    const payload = JSON.stringify({ target: SCAN_TARGET });
    const start = Date.now();
    const res = http.post(`${BASE_URL}/v1/scans/http-headers`, payload, {
      headers: jsonHeaders(token),
      tags: { name: 'POST /v1/scans/http-headers' },
    });
    submitLatency.add(res.timings.duration);

    const ok = check(res, {
      'submit: status is 2xx': (r) => r.status >= 200 && r.status < 300,
      'submit: body has id': (r) => {
        try {
          const body = r.json();
          return typeof body.id === 'string' && body.id.length > 0;
        } catch (_e) {
          return false;
        }
      },
    });
    if (!ok) {
      scanFlowErrors.add(1);
      return;
    }
    scanFlowErrors.add(0);
    scanId = res.json('id');

    // Some implementations return a terminal status synchronously
    // (the in-process scan path computes the verdict in the same
    // request). Record completion immediately in that case.
    try {
      const status = res.json('status');
      if (status === 'completed' || status === 'failed') {
        scanCompletionTime.add(Date.now() - start);
      }
    } catch (_e) {
      // not a JSON we can introspect — fall through to polling
    }
  });

  if (!scanId) {
    return;
  }

  group('poll scan', () => {
    const deadline = Date.now() + 60_000;
    let completed = false;
    while (Date.now() < deadline) {
      const res = http.get(`${BASE_URL}/v1/scans`, {
        headers: jsonHeaders(token),
        tags: { name: 'GET /v1/scans' },
      });
      if (res.status !== 200) {
        // transient — retry until the deadline
        sleep(0.5);
        continue;
      }
      let list;
      try {
        list = res.json();
      } catch (_e) {
        sleep(0.5);
        continue;
      }
      // Tolerate both `[…]` and `{items: […]}` shapes — the wire
      // contract has wavered across migrations.
      const items = Array.isArray(list)
        ? list
        : (list && Array.isArray(list.items) ? list.items : []);
      const ours = items.find((s) => s.id === scanId);
      if (ours && (ours.status === 'completed' || ours.status === 'failed')) {
        scanCompletionTime.add(res.timings.duration);
        completed = true;
        break;
      }
      sleep(1);
    }
    if (!completed) {
      scanTimeouts.add(1);
      scanFlowErrors.add(1);
    }
  });

  group('fetch SARIF', () => {
    const res = http.get(`${BASE_URL}/v1/scans/${scanId}.sarif`, {
      headers: jsonHeaders(token),
      tags: { name: 'GET /v1/scans/:id.sarif' },
    });
    sarifLatency.add(res.timings.duration);
    const ok = check(res, {
      'sarif: status is 200': (r) => r.status === 200,
      'sarif: content-type is application/sarif+json': (r) =>
        (r.headers['Content-Type'] || '').includes('application/sarif+json'),
      'sarif: body parses as SARIF v2.1.0': (r) => {
        try {
          const body = r.json();
          return body.version === '2.1.0'
            && Array.isArray(body.runs)
            && body.runs.length > 0;
        } catch (_e) {
          return false;
        }
      },
    });
    scanFlowErrors.add(ok ? 0 : 1);
  });

  sleep(2);
}
