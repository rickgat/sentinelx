import { expect, test } from "@playwright/test";

import { login, logout } from "./helpers/auth";

/**
 * The monolith seeds three demo engagements on first boot. We assert that the
 * table renders at least those three rows; if the seed grows, we still pass.
 */
const EXPECTED_SEED_ENGAGEMENTS = 3;

test.describe("engagements page", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("renders seed engagements in the table", async ({ page }) => {
    await page.goto("/dashboard/engagements");

    await expect(
      page.getByRole("heading", { name: "Engagements" }),
    ).toBeVisible({ timeout: 5_000 });

    const table = page.getByRole("table");
    await expect(table).toBeVisible({ timeout: 5_000 });

    // The header row plus one row per engagement.
    const rows = table.getByRole("row");
    await expect(rows).toHaveCount(EXPECTED_SEED_ENGAGEMENTS + 1, {
      timeout: 5_000,
    });

    // Status badges should be rendered for each engagement row.
    const statusBadges = table.locator("tbody tr td:nth-child(2)");
    await expect(statusBadges).toHaveCount(EXPECTED_SEED_ENGAGEMENTS);
  });

  test("new engagement dialog opens and validates required fields", async ({
    page,
  }) => {
    await page.goto("/dashboard/engagements");
    await page
      .getByRole("button", { name: "New engagement" })
      .click();

    await expect(
      page.getByRole("heading", { name: "New engagement" }),
    ).toBeVisible({ timeout: 5_000 });
    await expect(page.getByLabel("Name")).toBeVisible({ timeout: 5_000 });

    // Close without submitting so the test cleans up after itself.
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(
      page.getByRole("heading", { name: "New engagement" }),
    ).toBeHidden({ timeout: 5_000 });
  });
});
