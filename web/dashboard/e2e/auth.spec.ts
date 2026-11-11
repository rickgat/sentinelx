import { expect, test } from "@playwright/test";

import { TEST_USER, login, logout } from "./helpers/auth";

test.describe("authentication", () => {
  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("credentials login redirects to /dashboard", async ({ page }) => {
    await page.goto("/login");

    await expect(
      page.getByRole("heading", { name: "Sign in" }),
    ).toBeVisible({ timeout: 5_000 });

    await page.getByLabel("Email").fill(TEST_USER.email);
    await page.getByLabel("Password").fill(TEST_USER.password);
    await page
      .getByRole("button", { name: "Sign in with email + password" })
      .click();

    await page.waitForURL(/\/dashboard(\/|$|\?)/, { timeout: 10_000 });
    expect(new URL(page.url()).pathname).toMatch(/^\/dashboard/);
  });

  test("logout from the sidebar redirects to /login", async ({ page }) => {
    await login(page);

    await page.getByRole("button", { name: "Logout" }).click();

    await page.waitForURL(/\/login(\/|$|\?)/, { timeout: 10_000 });
    expect(new URL(page.url()).pathname).toBe("/login");

    // The login form should be back on screen.
    await expect(page.getByLabel("Email")).toBeVisible({ timeout: 5_000 });
  });
});
