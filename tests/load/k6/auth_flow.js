// SentinelX auth-flow load test.
//
// Exercises the authenticated read path documented in
// `crates/sx-api/src/router.rs`:
//
//   POST /v1/auth/login         (line 581)
//   GET  /v1/engagements         (line 52)
//   GET  /v1/findings            (line 61)
//   GET  /v1/findings/:id        (line 62)
//   POST /v1/auth/logout         (line 43)
//
// Seed creds match `config/sentinelx.dev.example.yaml` and
// `services/sx-monolith/tests/login_with_readme_creds.rs`.

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

// ---------------------------------------------------------------------
// Configuration (env overrides — see tests/load/README.md §3)
// ---------------------------------------------------------------------

const BASE_URL = __ENV.SX_BASE_URL || 'http://127.0.0.1:8080';
const ADMIN_EMAIL = __ENV.SX_ADMIN_EMAIL || 'admin@sentinelx.dev';
const ADMIN_PASSWORD = __ENV.SX_ADMIN_PASSWORD || 'sentinelx-admin-pw';
const TENANT_ID =
  __ENV.SX_TENANT_ID || '01010101-0101-0101-0101-010101010101';

// ---------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------

const loginLatency = new Trend('sx_login_duration_ms', true);
const listEngagementsLatency = new Trend(
  'sx_list_engagements_duration_ms',
  true,
);
const listFindingsLatency = new Trend('sx_list_findings_duration_ms', true);
const getFindingLatency = new Trend('sx_get_finding_duration_ms', true);
const logoutLatency = new Trend('sx_logout_duration_ms', true);
const flowErrorRate = new Rate('sx_auth_flow_errors');

// ---------------------------------------------------------------------
// k6 options — thresholds reflect docs/slos-production.md
// ---------------------------------------------------------------------

export const options = {
  vus: Number(__ENV.K6_VUS) || 20,
  duration: __ENV.K6_DURATION || '5m',

  thresholds: {
    // Per-endpoint p95 budgets (tightest at login; SLO contract is 99th).
    'sx_login_duration_ms': ['p(95)<300', 'p(99)<500'],
    'sx_list_engagements_duration_ms': ['p(95)<500'],
    'sx_list_findings_duration_ms': ['p(95)<500'],
    'sx_get_finding_duration_ms': ['p(95)<500'],
    'sx_logout_duration_ms': ['p(95)<300'],

    // Workspace error budget.
    'sx_auth_flow_errors': ['rate<0.01'],
    'http_req_failed': ['rate<0.01'],
  },
};

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

function jsonHeaders(extra) {
  const base = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-Tenant-Id': TENANT_ID,
  };
  if (extra) {
    for (const k in extra) {
      base[k] = extra[k];
    }
  }
  return base;
}

function authHeaders(token) {
  return jsonHeaders({ Authorization: `Bearer ${token}` });
}

// ---------------------------------------------------------------------
// VU lifecycle
// ---------------------------------------------------------------------

export default function () {
  let accessToken = '';

  group('login', () => {
    const payload = JSON.stringify({
      email: ADMIN_EMAIL,
      password: ADMIN_PASSWORD,
    });

    const res = http.post(`${BASE_URL}/v1/auth/login`, payload, {
      headers: jsonHeaders(),
      tags: { name: 'POST /v1/auth/login' },
    });

    loginLatency.add(res.timings.duration);
    const ok = check(res, {
      'login: status is 200': (r) => r.status === 200,
      'login: body has access_token': (r) => {
        try {
          const body = r.json();
          return typeof body.access_token === 'string'
            && body.access_token.length > 0;
        } catch (_e) {
          return false;
        }
      },
    });
    if (!ok) {
      flowErrorRate.add(1);
      // Skip the rest of the journey for this iteration; the next iter
      // will retry and the threshold catches the systemic failure.
      return;
    }
    flowErrorRate.add(0);
    accessToken = res.json('access_token');
  });

  if (!accessToken) {
    return;
  }

  let firstFindingId = '';

  group('list engagements', () => {
    const res = http.get(`${BASE_URL}/v1/engagements`, {
      headers: authHeaders(accessToken),
      tags: { name: 'GET /v1/engagements' },
    });
    listEngagementsLatency.add(res.timings.duration);
    const ok = check(res, {
      'engagements: status is 200': (r) => r.status === 200,
    });
    flowErrorRate.add(ok ? 0 : 1);
  });

  group('list findings', () => {
    const res = http.get(`${BASE_URL}/v1/findings?limit=20`, {
      headers: authHeaders(accessToken),
      tags: { name: 'GET /v1/findings' },
    });
    listFindingsLatency.add(res.timings.duration);
    const ok = check(res, {
      'findings: status is 200': (r) => r.status === 200,
      'findings: body parses as array or object with items': (r) => {
        try {
          const body = r.json();
          if (Array.isArray(body)) {
            if (body.length > 0 && typeof body[0].id === 'string') {
              firstFindingId = body[0].id;
            }
            return true;
          }
          if (body && Array.isArray(body.items)) {
            if (body.items.length > 0 && typeof body.items[0].id === 'string') {
              firstFindingId = body.items[0].id;
            }
            return true;
          }
          return false;
        } catch (_e) {
          return false;
        }
      },
    });
    flowErrorRate.add(ok ? 0 : 1);
  });

  group('get finding detail', () => {
    // If the staging cluster has no findings (clean DB), skip without
    // failing — the threshold reflects steady-state load only.
    if (!firstFindingId) {
      return;
    }
    const res = http.get(`${BASE_URL}/v1/findings/${firstFindingId}`, {
      headers: authHeaders(accessToken),
      tags: { name: 'GET /v1/findings/:id' },
    });
    getFindingLatency.add(res.timings.duration);
    const ok = check(res, {
      'finding detail: status is 200 or 404': (r) =>
        r.status === 200 || r.status === 404,
    });
    flowErrorRate.add(ok ? 0 : 1);
  });

  group('logout', () => {
    const res = http.post(`${BASE_URL}/v1/auth/logout`, null, {
      headers: authHeaders(accessToken),
      tags: { name: 'POST /v1/auth/logout' },
    });
    logoutLatency.add(res.timings.duration);
    const ok = check(res, {
      'logout: status is 2xx': (r) => r.status >= 200 && r.status < 300,
    });
    flowErrorRate.add(ok ? 0 : 1);
  });

  // VU pacing — one full journey every ~1.5s when at 20 VUs ≈ 13 RPS
  // sustained. Matches the staging-class capacity claim.
  sleep(1 + Math.random());
}
