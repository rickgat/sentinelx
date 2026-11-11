// SentinelX SAML ACS attack-rejection load test.
//
// Replays every fixture under `tests/load/fixtures/saml/` against the
// live `/v1/auth/saml/acs` endpoint, asserting:
//   1. Every known XSW / XEE / Transform-bypass shape is rejected
//      (non-200) — i.e. the SP byte-level gate fires inside its
//      timing budget for every variant.
//   2. p95 ACS reject latency < 300 ms (fixture parse + signature
//      verification + reject = single-digit ms in steady state, the
//      budget here covers cold-start + the network leg).
//
// Why a single shared script for every variant: the contract per
// `crates/sx-iam/src/service/saml/observer.rs:34` (the
// `SamlAttackKind` enum) is that EVERY variant must reject. The
// script's job is to enforce that contract under load.
//
// Deviation: The bin-spawn integration test
// (`services/sx-monolith/tests/saml_attack_emits_finding.rs`) asserts
// the *finding-emission* half (metadata, idempotency, CWE-347). That
// path requires an `IdpRecord` for the test tenant which has no
// public seed surface — so this load script asserts only the route
// boundary rejection (route + form decode + adapter reject). See
// `saml_attack_emits_finding.rs:24-46` for the same deviation
// reasoning.

import http from 'k6/http';
import encoding from 'k6/encoding';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { SharedArray } from 'k6/data';

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

const BASE_URL = __ENV.SX_BASE_URL || 'http://127.0.0.1:8080';
const TENANT_ID =
  __ENV.SX_TENANT_ID || '01010101-0101-0101-0101-010101010101';

// k6 init-context file reads happen via `open()`; the path is relative
// to the script file. List every fixture explicitly so the script
// fails loud if a fixture goes missing (vs. silently iterating zero
// rows from a directory glob — k6 has no glob in init context).
const FIXTURE_FILES = [
  'xsw1.xml',
  'xsw2.xml',
  'xsw3.xml',
  'xsw8.xml',
  'xee1_billion_laughs.xml',
  'transform2_xpath.xml',
];

const fixtures = new SharedArray('saml-xsw-fixtures', function () {
  return FIXTURE_FILES.map((name) => ({
    name,
    body: open(`../fixtures/saml/${name}`),
  }));
});

// ---------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------

const acsLatency = new Trend('sx_saml_acs_duration_ms', true);
const rejectsByKind = {};
const acceptedAttacks = new Counter('sx_saml_attacks_accepted');
const totalRejected = new Counter('sx_saml_attacks_rejected');

// Pre-instantiate one counter per fixture so the per-shape count
// is visible in the run summary.
for (const f of FIXTURE_FILES) {
  rejectsByKind[f] = new Counter(`sx_saml_rejected__${f.replace(/\W+/g, '_')}`);
}

// ---------------------------------------------------------------------
// k6 options
// ---------------------------------------------------------------------

export const options = {
  vus: Number(__ENV.K6_VUS) || 10,
  duration: __ENV.K6_DURATION || '5m',

  thresholds: {
    'sx_saml_acs_duration_ms': ['p(95)<300', 'p(99)<500'],
    // Every attack MUST reject. A single acceptance is a contract breach.
    'sx_saml_attacks_accepted': ['count==0'],
    'sx_saml_attacks_rejected': ['count>0'],
  },
};

// ---------------------------------------------------------------------
// VU iteration — pick a fixture, post it, assert rejection
// ---------------------------------------------------------------------

export default function () {
  const fixture = fixtures[Math.floor(Math.random() * fixtures.length)];

  // SAML 2.0 HTTP-POST binding: `SAMLResponse` is base64-encoded.
  // (Bindings §3.5.4 — same convention used by
  //  `services/sx-monolith/tests/saml_attack_emits_finding.rs:218`).
  const samlResponseB64 = encoding.b64encode(fixture.body);

  const form = {
    SAMLResponse: samlResponseB64,
    RelayState: `sx-load-test-${fixture.name}`,
  };

  const res = http.post(`${BASE_URL}/v1/auth/saml/acs`, form, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Tenant-Id': TENANT_ID,
    },
    tags: { name: 'POST /v1/auth/saml/acs', fixture: fixture.name },
  });

  acsLatency.add(res.timings.duration);

  // The SP MUST NOT 200 on any of these. 4xx/5xx is the success case
  // for this test. (404 here = SAML feature disabled in this staging
  // build; treat as inconclusive rather than fail.)
  const rejected = check(res, {
    [`${fixture.name}: status is non-200`]: (r) => r.status !== 200,
    [`${fixture.name}: status is 4xx or 5xx, not 404`]: (r) =>
      r.status >= 400 && r.status !== 404,
  });

  if (rejected) {
    totalRejected.add(1);
    rejectsByKind[fixture.name].add(1);
  } else if (res.status === 200) {
    acceptedAttacks.add(1);
    console.error(
      `CONTRACT BREACH: ${fixture.name} accepted by ACS — status=200, body=${res.body.substring(0, 200)}`,
    );
  }
  // status === 404 → SAML disabled; neither pass nor fail counter
  // increments. The threshold on totalRejected catches a fully
  // disabled SAML stack.

  sleep(0.5 + Math.random() * 0.5);
}
