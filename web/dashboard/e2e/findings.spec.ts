import { expect, test } from "@playwright/test";

import { login, logout } from "./helpers/auth";

/**
 * The monolith seeds eight demo findings on first boot, spanning each of the
 * four canonical severity buckets. We assert the table renders every seeded
 * row and that at least one severity badge of each severity is visible.
 *
 * `MIN_SEED_FINDINGS` is a *floor* rather than an exact count so the test
 * stays green if the dev seed set grows in the future — any regression that
 * silently drops rows still trips the assertion.
 */
const MIN_SEED_FINDINGS = 8;
const SEVERITY_LABELS = ["critical", "high", "medium", "low"] as const;

test.describe("findings page", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("renders the eight seed findings", async ({ page }) => {
    await page.goto("/dashboard/findings");

    await expect(
      page.getByRole("heading", { name: "Findings" }),
    ).toBeVisible({ timeout: 5_000 });

    const table = page.getByRole("table");
    await expect(table).toBeVisible({ timeout: 10_000 });

    // Data loads asynchronously via a client-side fetch — wait for tbody
    // to populate before counting.
    const bodyRows = table.locator("tbody tr");
    await expect
      .poll(async () => bodyRows.count(), { timeout: 10_000 })
      .toBeGreaterThanOrEqual(MIN_SEED_FINDINGS);

    // First column is a `<SeverityBadge>` for each row.
    const severityCells = table.locator("tbody tr td:nth-child(1)");
    const cellCount = await severityCells.count();
    expect(cellCount).toBeGreaterThanOrEqual(MIN_SEED_FINDINGS);
  });

  test("renders a badge for every canonical severity bucket", async ({
    page,
  }) => {
    await page.goto("/dashboard/findings");

    const table = page.getByRole("table");
    await expect(table).toBeVisible({ timeout: 5_000 });

    for (const severity of SEVERITY_LABELS) {
      // Badge component renders the literal severity string inside a span.
      const badge = table
        .locator("tbody tr td:nth-child(1)")
        .filter({ hasText: new RegExp(`^${severity}$`, "i") })
        .first();
      await expect(badge).toBeVisible({ timeout: 5_000 });
    }
  });

  test("status filter narrows the table to a single status", async ({
    page,
  }) => {
    await page.goto("/dashboard/findings");

    await expect(
      page.getByRole("heading", { name: "Findings" }),
    ).toBeVisible({ timeout: 5_000 });

    await page.getByLabel("Status").selectOption("open");

    // Every visible row in the body should now display "open" in column 4.
    const statusCells = page.locator("tbody tr td:nth-child(4)");
    const count = await statusCells.count();
    for (let i = 0; i < count; i += 1) {
      await expect(statusCells.nth(i)).toHaveText(/open/i, { timeout: 5_000 });
    }
  });
});
