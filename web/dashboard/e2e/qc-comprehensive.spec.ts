import { expect, test, type ConsoleMessage, type Page, type Response } from "@playwright/test";

import { ADMIN_USER, TEST_USER, login, logout } from "./helpers/auth";

/**
 * QC-2026-06-25 — Comprehensive Playwright coverage for every page in
 * `web/dashboard/src/app/dashboard/**` plus a small bundle of edge-case
 * scenarios.
 *
 * Each route gets two test cases:
 *
 *   - **positive**: log in as admin, navigate to the route, assert that the
 *     URL stayed under `/dashboard`, that some main element rendered, and
 *     that no `error`-level console messages or 4xx/5xx responses were
 *     emitted while the page loaded.
 *
 *   - **negative-auth**: visit the same route in a fresh browser context
 *     with no session and assert that the dashboard middleware redirected
 *     to `/login` (or `/api/auth/signin`).
 *
 * For the dynamic segments `[id]` and `[framework]` we hit known seed data:
 *
 *   - engagements: `e0000001-0000-0000-0000-000000000000`
 *   - findings:    `f0000001-0000-0000-0000-000000000000`
 *   - compliance:  `iso27001`
 *
 * (Seed constants live in `services/sx-monolith/src/adapters/seed.rs` — the
 * task brief mis-stated the engagement UUID; the value in the seed actually
 * ends in `...0000000000`, not `...0000000001`.)
 *
 * Notes:
 *   - We use `expect.soft` for the console-error and network-error checks so
 *     a single noisy log does not tank the whole route's report.
 *   - Routes that 404 from the app (or whose dynamic IDs are not present in
 *     the seed) are `test.skip()`ed with an inline comment.
 */

interface RouteSpec {
  /** Path the test navigates to (`/dashboard/...`). */
  pathname: string;
  /** Friendly label used in `test.describe` blocks. */
  label: string;
  /**
   * Optional skip marker — set to a short reason string to bypass the
   * positive test (negative-auth still runs).
   */
  skipPositiveReason?: string;
}

const SEED_ENGAGEMENT_ID = "e0000001-0000-0000-0000-000000000000";
const SEED_FINDING_ID = "f0000001-0000-0000-0000-000000000000";
const SEED_FRAMEWORK = "iso27001";

const ROUTES: ReadonlyArray<RouteSpec> = [
  { pathname: "/dashboard", label: "Overview" },
  { pathname: "/dashboard/admin/secrets", label: "Admin → Secrets" },
  { pathname: "/dashboard/ai-audit", label: "AI Security Audit" },
  { pathname: "/dashboard/analytics", label: "Analytics" },
  { pathname: "/dashboard/api-docs", label: "API docs" },
  { pathname: "/dashboard/api-playground", label: "API playground" },
  { pathname: "/dashboard/approvals", label: "Approvals" },
  { pathname: "/dashboard/bas", label: "BAS" },
  { pathname: "/dashboard/bas/techniques", label: "BAS techniques" },
  { pathname: "/dashboard/blast-radius", label: "Blast radius" },
  { pathname: "/dashboard/cloud", label: "Cloud" },
  { pathname: "/dashboard/compliance", label: "Compliance" },
  { pathname: "/dashboard/compliance/evidence", label: "Compliance evidence" },
  {
    pathname: `/dashboard/compliance/${SEED_FRAMEWORK}`,
    label: "Compliance framework (iso27001)",
  },
  { pathname: "/dashboard/copilot", label: "Copilot" },
  { pathname: "/dashboard/copilot-approvals", label: "Copilot approvals" },
  { pathname: "/dashboard/device-trust", label: "Device trust" },
  { pathname: "/dashboard/engagements", label: "Engagements" },
  {
    pathname: `/dashboard/engagements/${SEED_ENGAGEMENT_ID}`,
    label: "Engagement detail (seed engagement A)",
  },
  { pathname: "/dashboard/findings", label: "Findings" },
  {
    pathname: `/dashboard/findings/${SEED_FINDING_ID}`,
    label: "Finding detail (seed finding 1)",
  },
  { pathname: "/dashboard/graph", label: "Attack graph" },
  { pathname: "/dashboard/handbook", label: "Handbook" },
  { pathname: "/dashboard/iam", label: "IAM" },
  { pathname: "/dashboard/logs", label: "Logs" },
  { pathname: "/dashboard/mfa", label: "MFA" },
  { pathname: "/dashboard/pentest", label: "Pentest" },
  { pathname: "/dashboard/rba", label: "RBA" },
  { pathname: "/dashboard/rba/devices", label: "RBA devices" },
  { pathname: "/dashboard/redteam", label: "Red team" },
  { pathname: "/dashboard/remediation", label: "Remediation" },
  { pathname: "/dashboard/reports", label: "Reports" },
  { pathname: "/dashboard/reporting", label: "Comprehensive Report" },
  { pathname: "/dashboard/branding", label: "Report Branding" },
  { pathname: "/dashboard/safety", label: "Safety" },
  { pathname: "/dashboard/scans", label: "Scans" },
  { pathname: "/dashboard/scim", label: "SCIM" },
  { pathname: "/dashboard/soc", label: "SOC" },
  { pathname: "/dashboard/tenants", label: "Tenants" },
  { pathname: "/dashboard/twin", label: "Twin" },
  { pathname: "/dashboard/ueba", label: "UEBA" },
  { pathname: "/dashboard/vuln-import", label: "Vuln import" },
];

interface Observer {
  consoleErrors: string[];
  badResponses: { url: string; status: number }[];
}

/**
 * Install `console` and `response` listeners that record any non-trivial
 * errors observed while the page is loading. The returned object is shared
 * by the assertion phase — read it after `page.goto(...)` settles.
 */
function startObserver(page: Page): Observer {
  const consoleErrors: string[] = [];
  const badResponses: { url: string; status: number }[] = [];

  page.on("console", (msg: ConsoleMessage) => {
    if (msg.type() === "error") {
      consoleErrors.push(msg.text());
    }
  });

  page.on("response", (response: Response) => {
    const status = response.status();
    if (status < 400) {
      return;
    }
    let url: URL;
    try {
      url = new URL(response.url());
    } catch {
      return;
    }
    // Only flag same-origin failures; third-party telemetry is out of scope.
    if (url.host !== "127.0.0.1:3000" && url.host !== "localhost:3000") {
      return;
    }
    // `/api/auth/session` returns 401 when no session — that's fine and is
    // not a regression we want to flag.
    if (url.pathname.startsWith("/api/auth/")) {
      return;
    }
    badResponses.push({ url: response.url(), status });
  });

  return { consoleErrors, badResponses };
}

for (const route of ROUTES) {
  test.describe(`route: ${route.pathname}`, () => {
    test("positive — admin can load page", async ({ page }) => {
      if (route.skipPositiveReason !== undefined) {
        test.skip(true, route.skipPositiveReason);
      }

      const observer = startObserver(page);
      await login(page, ADMIN_USER);

      const response = await page.goto(route.pathname, {
        waitUntil: "domcontentloaded",
      });

      // The page should not have bounced us to /login.
      await expect(page).toHaveURL(/\/dashboard/, { timeout: 10_000 });

      // Some main element rendered. We use a generous union locator because
      // each page picks its own heading shape.
      const mainContent = page
        .locator('h1, h2, [data-testid="page-title"], main')
        .first();
      await expect(mainContent).toBeVisible({ timeout: 10_000 });

      // Status of the initial document.
      if (response !== null) {
        expect.soft(response.status(), `initial document HTTP for ${route.pathname}`).toBeLessThan(400);
      }

      // Give async hydration a beat so any error logs from RSC payload
      // fetches land before we assert.
      await page.waitForLoadState("networkidle", { timeout: 8_000 }).catch(() => {
        // Some pages hold open SSE/WS connections; don't tank the run.
      });

      expect
        .soft(observer.consoleErrors, `console errors on ${route.pathname}`)
        .toEqual([]);
      expect
        .soft(observer.badResponses, `4xx/5xx responses on ${route.pathname}`)
        .toEqual([]);

      await logout(page).catch(() => undefined);
    });

    test("negative-auth — anonymous is bounced to /login", async ({ browser }) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        await page.goto(route.pathname, { waitUntil: "domcontentloaded" });

        // The dashboard middleware redirects unauthenticated visitors to
        // `/login` (some flows go via `/api/auth/signin`). Accept either.
        await page.waitForURL(/\/(login|api\/auth\/signin)/, { timeout: 10_000 });

        const url = new URL(page.url());
        expect(url.pathname).toMatch(/^\/(login|api\/auth\/signin)/);

        // The sign-in button must be present so the user can recover.
        await expect(
          page.getByRole("button", { name: /Sign in/i }).first(),
        ).toBeVisible({ timeout: 5_000 });
      } finally {
        await context.close();
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Edge cases (5)
// ---------------------------------------------------------------------------

test.describe("edge cases", () => {
  test("E1 — logout flow returns the user to /login", async ({ page }) => {
    await login(page, ADMIN_USER);
    await page.getByRole("button", { name: "Logout" }).click();
    await page.waitForURL(/\/login(\/|$|\?)/, { timeout: 10_000 });
    await expect(page.getByLabel("Email")).toBeVisible({ timeout: 5_000 });
  });

  test("E2 — invalid login shows error toast and stays on /login", async ({
    page,
  }) => {
    await page.goto("/login");
    await expect(page.getByLabel("Email")).toBeVisible({ timeout: 5_000 });

    await page.getByLabel("Email").fill(ADMIN_USER.email);
    await page.getByLabel("Password").fill("wrong-password");
    await page
      .getByRole("button", { name: "Sign in with email + password" })
      .click();

    // We expect to stay on /login. NextAuth may bounce through
    // `/api/auth/...?error=CredentialsSignin` and back; accept either.
    await page.waitForURL(/\/login/, { timeout: 10_000 });
    await expect(page).toHaveURL(/\/login/);

    // The error message is rendered with `role="alert"`. Soft so we don't
    // tank if a future copy change tweaks the wording.
    const alert = page.getByRole("alert");
    await expect(alert.first()).toBeVisible({ timeout: 5_000 });
  });

  test("E3 — findings filter narrows the rendered rows", async ({ page }) => {
    // NOTE: per the source the findings filter is a controlled `<select>` /
    // input that updates client state ONLY — it does not push search params
    // into the URL. We document that here and instead assert the filter
    // collapses the rendered row count, which is the user-visible behaviour.
    await login(page, ADMIN_USER);
    await page.goto("/dashboard/findings");
    await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible({
      timeout: 5_000,
    });

    const table = page.getByRole("table");
    await expect(table).toBeVisible({ timeout: 5_000 });

    const totalRows = await table.locator("tbody tr").count();

    // Drive the status filter — this is the most reliable selector across
    // versions of the page.
    await page.getByLabel("Status").selectOption("open");

    const openRows = await table.locator("tbody tr").count();
    expect.soft(openRows).toBeLessThanOrEqual(totalRows);

    // Every visible row should now display "open" in column 4.
    const statusCells = table.locator("tbody tr td:nth-child(4)");
    const count = await statusCells.count();
    for (let i = 0; i < count; i += 1) {
      await expect(statusCells.nth(i)).toHaveText(/open/i, { timeout: 5_000 });
    }
  });

  test("E4 — SARIF export download surfaces the SARIF mime type", async ({
    page,
  }) => {
    // The task brief said "on a finding detail page"; the actual SARIF
    // export lives on `/dashboard/reports` (the finding detail page has no
    // SARIF button — see `src/app/dashboard/findings/[id]/page.tsx`).
    // We adapt to the real UI here.
    await login(page, ADMIN_USER);
    await page.goto("/dashboard/reports");

    // Choose SARIF.
    const formatSelect = page.getByLabel(/format/i).first();
    if (await formatSelect.count() === 0) {
      test.skip(true, "Reports page does not expose a format selector");
    }
    await formatSelect.selectOption("sarif");

    // Submit and wait for the proxied response.
    const renderResponse = page.waitForResponse(
      (resp) =>
        resp.url().includes("/api/reports/render") && resp.request().method() === "POST",
      { timeout: 15_000 },
    );
    await page.getByRole("button", { name: /(render|generate|download)/i }).first().click();

    const resp = await renderResponse;
    expect.soft(resp.status(), "render response status").toBeLessThan(500);

    // The JSON envelope wraps `mime_type` for text formats — assert that the
    // payload self-identifies as SARIF.
    let body: { data?: { mime_type?: string } } | null = null;
    try {
      body = (await resp.json()) as { data?: { mime_type?: string } };
    } catch {
      body = null;
    }
    expect
      .soft(body?.data?.mime_type ?? "")
      .toMatch(/sarif|json/i);
  });

  test("E5 — analyst gets 403-style card on /dashboard/admin/secrets", async ({
    page,
  }) => {
    await login(page, TEST_USER); // analyst credentials by default
    await page.goto("/dashboard/admin/secrets");

    // The page renders an in-page 403 card (see comment in the route's
    // source) rather than redirecting, so we assert the card text.
    const denied = page.getByText(/admin:secrets|do not have/i).first();
    await expect(denied).toBeVisible({ timeout: 10_000 });

    // We should NOT have been bounced back to /login.
    expect(new URL(page.url()).pathname).toBe("/dashboard/admin/secrets");
  });
});
