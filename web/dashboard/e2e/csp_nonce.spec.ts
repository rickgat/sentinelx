import { expect, test } from "@playwright/test";

import { ADMIN_USER, login, logout } from "./helpers/auth";

/**
 * LOW-003 browser verification.
 *
 * The dashboard's Next.js middleware (`web/dashboard/src/middleware.ts`)
 * mints a per-request nonce and emits a `Content-Security-Policy`
 * response header. This spec is the headless-browser confirmation owed
 * per the Sprint 5+ wave-2 handoff "Browser verification owed (PO)"
 * marker — it asserts the wire-level header shape rather than trusting
 * the middleware source by inspection.
 *
 * Contract under test (production-equivalent shape):
 *
 *   Content-Security-Policy:
 *     default-src 'self';
 *     style-src 'self' 'unsafe-inline';
 *     script-src 'self' 'nonce-<base64>' 'strict-dynamic' ['unsafe-eval'];
 *     img-src 'self' data: blob:;
 *     font-src 'self' data:;
 *     connect-src 'self' ...;
 *     frame-ancestors 'none';
 *     base-uri 'self';
 *     form-action 'self';
 *     object-src 'none';
 *
 * Hard requirements (the LOW-003 spec):
 *   1. The header MUST be present on every protected dashboard route.
 *   2. `script-src` MUST contain `'self'` AND a `'nonce-<value>'` token.
 *   3. `script-src` MUST NOT contain `'unsafe-inline'`.
 *   4. `style-src` SHOULD still carry `'unsafe-inline'` — tightening
 *      styles is a separate sweep deliberately deferred per the LOW-003
 *      spec; this spec asserts the current contract so a future style
 *      tightening will fail visibly here rather than silently regress.
 *   5. The nonce SHOULD be a base64 token (no padding, 16-byte source =>
 *      ~22 base64url-ish chars) and SHOULD change between requests
 *      (i.e. be per-request, not per-session).
 *
 * `'unsafe-eval'` is permitted in dev (Next turbopack / webpack-dev
 * eval-source-maps) but dropped in prod — we do not assert either way.
 */

interface CspDirectives {
  // Map from directive name (e.g. `script-src`) to its source-list tokens
  // (e.g. `["'self'", "'nonce-abc'"]`). Tokens are kept verbatim, including
  // quoting — that's how the wire format encodes `'self'` etc.
  readonly [directive: string]: ReadonlyArray<string>;
}

function parseCsp(header: string): CspDirectives {
  const out: Record<string, string[]> = {};
  for (const raw of header.split(";")) {
    const trimmed = raw.trim();
    if (trimmed === "") {
      continue;
    }
    const parts = trimmed.split(/\s+/);
    const name = parts[0];
    if (name === undefined || name === "") {
      continue;
    }
    out[name.toLowerCase()] = parts.slice(1);
  }
  return out;
}

function extractNonce(scriptSrc: ReadonlyArray<string>): string | null {
  for (const token of scriptSrc) {
    // Wire format: `'nonce-<base64>'` (single-quoted).
    const m = /^'nonce-([^']+)'$/.exec(token);
    if (m && m[1] !== undefined && m[1] !== "") {
      return m[1];
    }
  }
  return null;
}

async function fetchCspFor(
  page: import("@playwright/test").Page,
  pathname: string,
): Promise<string> {
  const response = await page.goto(pathname, { waitUntil: "domcontentloaded" });
  expect(
    response,
    `expected a Response object for ${pathname}`,
  ).not.toBeNull();
  // page.goto returns a Response | null; the assertion above narrows it.
  const headers = response!.headers();
  const csp = headers["content-security-policy"];
  expect(
    csp,
    `${pathname} response is missing Content-Security-Policy header`,
  ).toBeDefined();
  expect(csp).not.toBe("");
  return csp!;
}

test.describe("LOW-003 CSP nonce header", () => {
  test.beforeEach(async ({ page }) => {
    await login(page, ADMIN_USER);
  });

  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("/dashboard emits a per-request nonce'd CSP with no 'unsafe-inline' in script-src", async ({
    page,
  }) => {
    const csp = await fetchCspFor(page, "/dashboard");
    const directives = parseCsp(csp);

    const scriptSrc = directives["script-src"];
    expect(
      scriptSrc,
      "CSP is missing a script-src directive entirely",
    ).toBeDefined();
    expect(scriptSrc).toContain("'self'");

    // LOW-003 hard requirement: no 'unsafe-inline' for scripts.
    expect(
      scriptSrc,
      "script-src must NOT contain 'unsafe-inline' (LOW-003)",
    ).not.toContain("'unsafe-inline'");

    // LOW-003 hard requirement: a 'nonce-<value>' token is present.
    const nonce = extractNonce(scriptSrc!);
    expect(
      nonce,
      "script-src must contain a 'nonce-<base64>' token (LOW-003)",
    ).not.toBeNull();
    // 16 bytes => ~22 base64 chars after stripping `=` padding. Allow a
    // generous range (>= 16) without asserting an exact length to leave
    // the middleware free to bump the source-byte count.
    expect(nonce!.length).toBeGreaterThanOrEqual(16);
  });

  test("/dashboard CSP keeps 'unsafe-inline' in style-src (separate sweep)", async ({
    page,
  }) => {
    const csp = await fetchCspFor(page, "/dashboard");
    const directives = parseCsp(csp);

    const styleSrc = directives["style-src"];
    expect(styleSrc, "CSP is missing a style-src directive").toBeDefined();
    expect(styleSrc).toContain("'self'");

    // Per the LOW-003 spec, style tightening is deliberately deferred —
    // Tailwind / Next still inline small style blocks for hydration. If
    // a future sweep drops 'unsafe-inline' here, update this assertion.
    expect(
      styleSrc,
      "style-src should still carry 'unsafe-inline' until the style-tightening sweep",
    ).toContain("'unsafe-inline'");
  });

  test("/dashboard/findings is also covered by the nonce'd CSP middleware", async ({
    page,
  }) => {
    const csp = await fetchCspFor(page, "/dashboard/findings");
    const directives = parseCsp(csp);

    const scriptSrc = directives["script-src"];
    expect(scriptSrc).toBeDefined();
    expect(scriptSrc).toContain("'self'");
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(extractNonce(scriptSrc!)).not.toBeNull();
  });

  test("nonce is per-request (changes between two loads of the same route)", async ({
    page,
  }) => {
    const cspA = await fetchCspFor(page, "/dashboard");
    const nonceA = extractNonce(parseCsp(cspA)["script-src"] ?? []);
    expect(nonceA).not.toBeNull();

    const cspB = await fetchCspFor(page, "/dashboard");
    const nonceB = extractNonce(parseCsp(cspB)["script-src"] ?? []);
    expect(nonceB).not.toBeNull();

    expect(
      nonceA,
      "nonce must change between two requests to the same route — the middleware mints a new one per request",
    ).not.toBe(nonceB);
  });
});
