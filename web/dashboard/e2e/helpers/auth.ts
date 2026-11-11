import { expect, type Page } from "@playwright/test";

/**
 * Test account credentials. These mirror the bootstrap seed in
 * `config/sentinelx.dev.example.yaml` (admin: SX-REVIEW-002 C2 path;
 * analyst: L1-FU1 path). Override via environment variables when
 * pointing the suite at a staging instance.
 *
 * Tenant id matches `bootstrap.admin_tenant_id` in the dev example
 * YAML — both admin and analyst land in the same tenant so the
 * dashboard list views render the same seed engagements / findings /
 * assets regardless of which user the spec logs in as.
 */
const DEV_BOOTSTRAP_TENANT_ID = "01010101-0101-0101-0101-010101010101";

export const TEST_USER = {
  tenantId: process.env.E2E_TENANT_ID ?? DEV_BOOTSTRAP_TENANT_ID,
  email: process.env.E2E_USER_EMAIL ?? "analyst@sentinelx.dev",
  password: process.env.E2E_USER_PASSWORD ?? "Analyst!Password1",
} as const;

export const ADMIN_USER = {
  tenantId: process.env.E2E_ADMIN_TENANT_ID ?? DEV_BOOTSTRAP_TENANT_ID,
  email: process.env.E2E_ADMIN_EMAIL ?? "admin@sentinelx.dev",
  password: process.env.E2E_ADMIN_PASSWORD ?? "sentinelx-admin-pw",
} as const;

interface Credentials {
  tenantId: string;
  email: string;
  password: string;
}

/**
 * Drive the credentials provider on the login page. On success the dashboard
 * server redirects to `/dashboard`, which this helper waits for.
 */
export async function login(
  page: Page,
  credentials: Credentials = TEST_USER,
): Promise<void> {
  await page.goto("/login");

  // The login form is rendered inside a `<Suspense>` boundary, so the email
  // input is the most reliable readiness signal.
  await expect(page.getByLabel("Email")).toBeVisible({ timeout: 5_000 });

  await page.getByLabel("Email").fill(credentials.email);
  await page.getByLabel("Password").fill(credentials.password);

  await page
    .getByRole("button", { name: "Sign in with email + password" })
    .click();

  await page.waitForURL(/\/dashboard(\/|$|\?)/, { timeout: 10_000 });
}

/**
 * Click the sidebar "Logout" button and wait for the redirect to `/login`.
 * Safe to call even when not signed in — the button will simply not be
 * present and the helper will short-circuit.
 */
export async function logout(page: Page): Promise<void> {
  const logoutButton = page.getByRole("button", { name: "Logout" });
  if ((await logoutButton.count()) === 0) {
    return;
  }
  await logoutButton.click();
  await page.waitForURL(/\/login(\/|$|\?)/, { timeout: 10_000 });
}
