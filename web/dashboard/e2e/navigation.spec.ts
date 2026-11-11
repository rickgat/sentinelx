import { expect, test } from "@playwright/test";

import { ADMIN_USER, login, logout } from "./helpers/auth";

/**
 * Sidebar navigation smoke test. The admin seed account is the only one
 * that sees every entry (the IAM link is gated by `admin:users`), so we
 * sign in as admin and walk through all 15 items.
 *
 * For each item we click it via the sidebar link role and assert the URL
 * matches the expected pathname. This is the canonical regression net
 * for layout/`Sidebar` changes.
 */
interface NavCase {
  label: string;
  pathname: string;
}

// Sidebar auto-expands only the module owning the current route + a
// hard-coded default (`operations`). Every other module starts
// collapsed, so a bare `getByRole("link", ...)` cannot see child items
// until the corresponding group is opened. `openGroupFor` clicks the
// group toggle when needed; idempotent when the group is already open.
async function openGroupFor(
  page: import("@playwright/test").Page,
  groupTitle: string,
): Promise<void> {
  const toggle = page.getByRole("button", { name: new RegExp(groupTitle, "i") }).first();
  if ((await toggle.count()) === 0) {
    return;
  }
  const expanded = await toggle.getAttribute("aria-expanded");
  if (expanded !== "true") {
    await toggle.click();
  }
}

interface NavCaseGrouped extends NavCase {
  /** Group title in the sidebar (matches the `MODULES` label in `sidebar.tsx`). */
  group?: string;
}

const NAV_CASES_GROUPED: ReadonlyArray<NavCaseGrouped> = [
  { label: "Overview", pathname: "/dashboard", group: "Operations" },
  { label: "Engagements", pathname: "/dashboard/engagements", group: "Engagement & Findings" },
  { label: "Findings", pathname: "/dashboard/findings", group: "Engagement & Findings" },
  { label: "Attack Graph", pathname: "/dashboard/graph", group: "Offensive Simulation" },
  { label: "BAS Runs", pathname: "/dashboard/bas", group: "Offensive Simulation" },
  { label: "Approvals", pathname: "/dashboard/approvals", group: "Operations" },
  { label: "Reports", pathname: "/dashboard/reports", group: "Engagement & Findings" },
  { label: "SOC Alerts", pathname: "/dashboard/soc", group: "Operations" },
  { label: "Tenants", pathname: "/dashboard/tenants", group: "Discovery & Inventory" },
  { label: "Cloud Inventory", pathname: "/dashboard/cloud", group: "Discovery & Inventory" },
  { label: "Copilot", pathname: "/dashboard/copilot", group: "Engagement & Findings" },
  { label: "MFA", pathname: "/dashboard/mfa", group: "Identity & Access" },
  { label: "Controls", pathname: "/dashboard/compliance", group: "Compliance & Governance" },
  { label: "Safety / Kill-switch", pathname: "/dashboard/safety", group: "Operations" },
  { label: "IAM (Users & Roles)", pathname: "/dashboard/iam", group: "Identity & Access" },
];

test.describe("sidebar navigation", () => {
  test.beforeEach(async ({ page }) => {
    await login(page, ADMIN_USER);
  });

  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("renders all 15 sidebar entries for an admin", async ({ page }) => {
    await page.goto("/dashboard");

    // Expand every group so its children become visible.
    const uniqueGroups = new Set(NAV_CASES_GROUPED.map((c) => c.group ?? ""));
    for (const g of uniqueGroups) {
      if (g !== "") {
        await openGroupFor(page, g);
      }
    }

    for (const item of NAV_CASES_GROUPED) {
      await expect(
        page.getByRole("link", { name: item.label, exact: true }),
      ).toBeVisible({ timeout: 5_000 });
    }
  });

  test("each sidebar link routes to its dashboard page", async ({ page }) => {
    await page.goto("/dashboard");

    for (const item of NAV_CASES_GROUPED) {
      if (item.group !== undefined) {
        await openGroupFor(page, item.group);
      }
      await page.getByRole("link", { name: item.label, exact: true }).click();

      // `waitForURL` waits for the SPA navigation to complete without sleeping.
      await page.waitForURL(
        (url) => url.pathname === item.pathname,
        { timeout: 10_000 },
      );

      expect(new URL(page.url()).pathname).toBe(item.pathname);
    }
  });
});
