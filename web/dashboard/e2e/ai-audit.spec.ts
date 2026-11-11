import { expect, test } from "@playwright/test";

import { ADMIN_USER, login, logout } from "./helpers/auth";

/**
 * AI-SEC-001 smoke + run-flow spec for `/dashboard/ai-audit`.
 *
 * The page is gated by `ai-audit:read`; the admin seed account holds the
 * wildcard `*:*` grant, so we sign in as admin. The first test verifies the
 * inventory + governance-controls surface renders. The second mocks the
 * dashboard-side `/api/ai-audit/run` proxy (so the test is deterministic and
 * does not depend on upstream probe state) and asserts the full UI run flow:
 * click "Run audit" → POST fires → the completion summary renders.
 */
test.describe("AI Security Audit page", () => {
  test.beforeEach(async ({ page }) => {
    await login(page, ADMIN_USER);
  });

  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("renders the inventory and governance-controls surface", async ({ page }) => {
    await page.goto("/dashboard/ai-audit");

    await expect(
      page.getByRole("heading", { name: /AI Security Audit/i }),
    ).toBeVisible({ timeout: 5_000 });

    await expect(
      page.getByRole("heading", { name: /AI Asset Inventory/i }),
    ).toBeVisible({ timeout: 5_000 });

    await expect(
      page.getByRole("heading", { name: /AI Governance Controls/i }),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("operator runs an audit and sees the completion summary", async ({ page }) => {
    let runFired = false;

    // Mock the dashboard-side run proxy so the flow is deterministic.
    await page.route("**/api/ai-audit/run", async (route) => {
      if (route.request().method() !== "POST") {
        await route.continue();
        return;
      }
      runFired = true;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          data: {
            assets: [{ id: "ai-asset-llm-01" }],
            aibom: { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components: [] },
            probe_results: [],
            modelfile_findings: [],
            control_evidence: [{ control_id: "SX-AI-NIST-MAP-1", status: "pass", detail: "ok", collected_at: "2026-10-31T00:00:00Z" }],
          },
        }),
      });
    });

    await page.goto("/dashboard/ai-audit");

    const runButton = page.getByRole("button", { name: /Run audit/i });
    await expect(runButton).toBeVisible({ timeout: 5_000 });
    await runButton.click();

    await expect(page.getByText(/Audit complete/i)).toBeVisible({
      timeout: 10_000,
    });
    expect(runFired).toBe(true);
  });
});
