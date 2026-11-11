import { expect, test } from "@playwright/test";

import { ADMIN_USER, login, logout } from "./helpers/auth";

/**
 * Provisioning flow for the IAM page. The page is gated by the
 * `admin:users` permission server-side, so we sign in as the admin seed
 * account before navigating. The create form is rendered by
 * `IamClient`; on success it pushes a toast and appends a row to the
 * "Created this session" table.
 */
test.describe("admin IAM provisioning", () => {
  test.beforeEach(async ({ page }) => {
    await login(page, ADMIN_USER);
  });

  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("creates a new user via the form", async ({ page }) => {
    await page.goto("/dashboard/iam");

    await expect(
      page.getByRole("heading", { name: "User & Access" }),
    ).toBeVisible({ timeout: 5_000 });

    // Tenant id is pre-populated from the session; keep it.
    const uniqueEmail = `e2e-${Date.now()}@sentinelx.dev`;

    await page.getByLabel("Email").fill(uniqueEmail);

    // Use the built-in generator to satisfy the 12-char minimum the form
    // enforces, rather than risking a brittle literal password.
    await page.getByRole("button", { name: "Generate" }).click();
    await expect(page.getByLabel(/^Password/)).not.toHaveValue("", {
      timeout: 5_000,
    });

    await page.getByRole("button", { name: "Create user" }).click();

    await expect(
      page.getByRole("status").filter({ hasText: "User created." }),
    ).toBeVisible({ timeout: 5_000 });

    // The freshly provisioned user should land in the session table.
    await expect(
      page.getByRole("cell", { name: uniqueEmail }),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("rejects an invalid email before hitting the backend", async ({
    page,
  }) => {
    await page.goto("/dashboard/iam");
    await expect(
      page.getByRole("heading", { name: "User & Access" }),
    ).toBeVisible({ timeout: 5_000 });

    // Two layers of rejection guard the backend:
    //   (a) HTML5 validity — the email input is `type="email"`, so the
    //       browser stops the submit and marks the input invalid.
    //   (b) JS fallback — if the browser did submit, iam-client's
    //       `submit()` runs `EMAIL_RE.test(email)` and pushes the
    //       "Enter a valid email address." error toast.
    // Layer (a) fires first in practice; the test asserts the input's
    // validity state so we don't depend on toast dispatch timing.
    const emailInput = page.getByLabel("Email");
    await emailInput.fill("not-an-email");
    await page.getByRole("button", { name: "Generate" }).click();
    await page.getByRole("button", { name: "Create user" }).click();

    // Assert the browser marked the email invalid AND the URL stayed on
    // /dashboard/iam (i.e. the form did not submit).
    const validity = await emailInput.evaluate(
      (el) => (el as HTMLInputElement).validity.valid,
    );
    expect(validity).toBe(false);
    await expect(page).toHaveURL(/\/dashboard\/iam/);
  });
});
