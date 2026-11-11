import { expect, test } from "@playwright/test";

import { ADMIN_USER, login, logout } from "./helpers/auth";

/**
 * The safety page hosts the emergency kill-switch. The dialog is a Radix
 * `Dialog.Root`, so the trigger toggles `data-state="open"` on the content
 * node. We drive it end-to-end:
 *   1. open the dialog
 *   2. fill an audit reason
 *   3. confirm
 *   4. assert the success toast plus the inline confirmation copy
 *
 * The backend `/api/safety/trip` endpoint must accept POST in the live
 * environment; if it returns non-2xx the success toast will not appear and
 * the test will fail with a useful diagnostic.
 */
test.describe("safety page kill-switch", () => {
  test.beforeEach(async ({ page }) => {
    // The kill-switch trip is gated `admin:safety` on the backend
    // (`/v1/safety/kill-switch` returns 403 for analyst). Sign in as
    // admin so the flow round-trips end-to-end.
    await login(page, ADMIN_USER);
  });

  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("trips the kill switch and surfaces a success toast", async ({
    page,
  }) => {
    await page.goto("/dashboard/safety");

    await expect(
      page.getByRole("heading", { name: "Emergency kill switch" }),
    ).toBeVisible({ timeout: 5_000 });

    await page.getByRole("button", { name: "Trip Kill Switch" }).click();

    // Radix renders the dialog title as a heading once open.
    await expect(
      page.getByRole("heading", { name: "Confirm kill switch" }),
    ).toBeVisible({ timeout: 5_000 });

    await page
      .getByLabel("Reason")
      .fill(`e2e-${new Date().toISOString().slice(0, 19)}`);

    await page.getByRole("button", { name: "Confirm trip" }).click();

    // The toast container is `aria-live=polite` and renders a status node.
    await expect(
      page.getByRole("status").filter({ hasText: "Kill switch tripped." }),
    ).toBeVisible({ timeout: 5_000 });

    // The dialog should auto-close on success.
    await expect(
      page.getByRole("heading", { name: "Confirm kill switch" }),
    ).toBeHidden({ timeout: 5_000 });

    // The inline confirmation copy under the card is also a regression signal.
    await expect(
      page.getByText("Kill switch tripped successfully."),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("rejects an empty reason without round-tripping the backend", async ({
    page,
  }) => {
    await page.goto("/dashboard/safety");
    await page.getByRole("button", { name: "Trip Kill Switch" }).click();

    await expect(
      page.getByRole("heading", { name: "Confirm kill switch" }),
    ).toBeVisible({ timeout: 5_000 });

    // Submit with no reason — the client-side guard demands ≥4 chars.
    await page.getByRole("button", { name: "Confirm trip" }).click();

    await expect(page.getByRole("alert")).toContainText(
      /at least 4 characters/i,
      { timeout: 5_000 },
    );
  });
});
