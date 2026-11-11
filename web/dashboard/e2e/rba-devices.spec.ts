import { expect, test } from "@playwright/test";

import { ADMIN_USER, login, logout } from "./helpers/auth";

/**
 * LOW-008 smoke: the "Known devices" panel at `/dashboard/rba/devices`.
 *
 * The page is gated by `admin:users` (same gate as `/dashboard/rba`),
 * so we sign in as the admin seed account. The empty-state checks
 * intentionally avoid depending on any specific user having enrolled
 * fingerprints; the panel always shows the empty placeholder until an
 * operator picks a user, and the "No devices recorded" copy then
 * appears when the upstream returns an empty list.
 *
 * LOW-008-FU1: the bottom of this file extends the smoke specs with a
 * pick → click-revoke → confirm-dialog → success-toast end-to-end
 * verification of the revoke flow. The dev seed never enrols a device
 * fingerprint organically (it's only created by the RBA device-fp
 * signal on a real login, and the e2e suite drives credentials-only
 * Auth.js flows that bypass the signal), so the FU1 test intercepts
 * the dashboard-side proxy routes for `/api/rba/users/.../devices`
 * with `page.route()` and injects a synthetic known device. The route
 * handler then asserts the dashboard issued the correct DELETE on the
 * fp-hash subroute when the operator confirmed the revoke. This is
 * the headless-browser verification owed per the Sprint 5+ wave-2
 * handoff "Browser verification owed (PO)" marker — it exercises
 * every UI hop (pick, button, dialog, toast, refetch) without coupling
 * to upstream RBA enrolment state.
 */
test.describe("RBA known devices panel", () => {
  test.beforeEach(async ({ page }) => {
    await login(page, ADMIN_USER);
  });

  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("renders the panel with empty selection prompt", async ({ page }) => {
    await page.goto("/dashboard/rba/devices");

    await expect(
      page.getByRole("heading", { name: /Known devices/i }),
    ).toBeVisible({ timeout: 5_000 });

    await expect(
      page.getByText(/Select a user above to load their known device/i),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("RBA root page links to the devices panel", async ({ page }) => {
    await page.goto("/dashboard/rba");

    const link = page.getByRole("link", { name: /Known devices/i });
    await expect(link).toBeVisible({ timeout: 5_000 });
    await link.click();

    await expect(page).toHaveURL(/\/dashboard\/rba\/devices/);
    await expect(
      page.getByRole("heading", { name: /Known devices/i }),
    ).toBeVisible({ timeout: 5_000 });
  });
});

/**
 * LOW-008-FU1: end-to-end pick → revoke flow.
 *
 * Strategy: the seed never registers a device organically, so we mock
 * the dashboard-side proxy `/api/rba/users/.../devices` with
 * `page.route()` — this is the boundary the React client (`devices-client.tsx`)
 * calls, so intercepting here exercises the full client flow (autocomplete
 * filter → `selectUser()` → `fetchDevices()` → revoke button → Radix
 * confirm dialog → `confirmRevoke()` DELETE → toast → refetch) while
 * staying deterministic.
 *
 * The mock asserts:
 *   - The DELETE proxy fires with the correct fp-hash in the path
 *     (proving the click drove the wired-up handler, not a stub).
 *   - The post-revoke refetch returns the device with status="revoked"
 *     (proving the client refreshes the table after success).
 */
test.describe("LOW-008-FU1: RBA devices pick → revoke flow", () => {
  // A synthetic but realistic-looking fingerprint hash (sha256 hex).
  const FP_HASH =
    "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";

  test.beforeEach(async ({ page }) => {
    await login(page, ADMIN_USER);
  });

  test.afterEach(async ({ page }) => {
    await logout(page);
  });

  test("operator picks a user, revokes a device, sees the success toast and refreshed row", async ({
    page,
  }) => {
    // Track DELETE so we can assert it fired with the right fp_hash.
    let deleteFiredForFp: string | null = null;
    // Track GET call count so we can assert the post-revoke refetch.
    let getDevicesCalls = 0;

    // Mock the per-user devices endpoint. First GET returns a single
    // `known` device; after the revoke fires, subsequent GETs return
    // the same device with status="revoked".
    await page.route(/\/api\/rba\/users\/[^/]+\/devices$/, async (route) => {
      if (route.request().method() !== "GET") {
        await route.continue();
        return;
      }
      getDevicesCalls += 1;
      const status = deleteFiredForFp === FP_HASH ? "revoked" : "known";
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          data: {
            devices: [
              {
                fp_hash: FP_HASH,
                status,
                last_seen_at: new Date().toISOString(),
              },
            ],
          },
        }),
      });
    });

    // Mock the per-fp DELETE endpoint.
    await page.route(
      /\/api\/rba\/users\/[^/]+\/devices\/[0-9a-fA-F]+$/,
      async (route) => {
        if (route.request().method() !== "DELETE") {
          await route.continue();
          return;
        }
        // Capture which fp_hash the dashboard asked to revoke.
        const url = route.request().url();
        const match = /\/devices\/([^/?#]+)$/.exec(url);
        deleteFiredForFp = match?.[1] ?? "";
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ data: { ok: true } }),
        });
      },
    );

    await page.goto("/dashboard/rba/devices");

    // The user picker is pre-loaded server-side from
    // `/v1/admin/users?limit=500` (see page.tsx). Typing the admin
    // email substring filters the listbox down to the seeded admin row;
    // clicking it triggers selectUser() which fires the GET.
    const userInput = page.getByLabel("User");
    await expect(userInput).toBeVisible({ timeout: 5_000 });
    await userInput.fill("admin@sentinelx");

    // Pick the first option from the autocomplete listbox. The listbox
    // has no accessible name (it's anchored to the input via
    // `aria-controls="user-options"`), so we target by the `option` role
    // that the `<button role="option">` children expose.
    await expect(page.locator("#user-options")).toBeVisible({
      timeout: 5_000,
    });
    await page.getByRole("option").first().click();

    // The devices table should render with one row (our mocked device).
    await expect(
      page.getByRole("cell", { name: new RegExp(FP_HASH.slice(-8)) }),
    ).toBeVisible({ timeout: 10_000 });

    // The action column has a "Revoke" destructive button on each row.
    // Scope to the row to avoid any future "Bulk Revoke" header collision.
    const revokeButton = page
      .getByRole("row", { name: new RegExp(FP_HASH.slice(-8)) })
      .getByRole("button", { name: /^Revoke$/ });
    await expect(revokeButton).toBeVisible({ timeout: 5_000 });
    await revokeButton.click();

    // The Radix confirm dialog opens. Its Title is the canonical anchor.
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible({ timeout: 5_000 });
    await expect(
      dialog.getByText(/Revoke device fingerprint/i),
    ).toBeVisible();
    // The full fp-hash is echoed in the dialog body for confirmation.
    await expect(dialog.getByText(FP_HASH)).toBeVisible();

    // Click the destructive "Revoke" button inside the dialog (the
    // outer-row button has the same label, so we scope to the dialog).
    await dialog.getByRole("button", { name: /^Revoke$/ }).click();

    // Success toast — the client pushes a `kind: "success"` toast with
    // the short fp pill in the message body.
    await expect(
      page.getByText(
        new RegExp(`Device .*${FP_HASH.slice(-8)}.*revoked`, "i"),
      ),
    ).toBeVisible({ timeout: 10_000 });

    // The dialog closes after a successful revoke.
    await expect(dialog).toBeHidden({ timeout: 5_000 });

    // The row is still present but its action button now reads
    // "Revoked" (disabled) because the refetch returned status="revoked".
    const refreshedRow = page.getByRole("row", {
      name: new RegExp(FP_HASH.slice(-8)),
    });
    await expect(
      refreshedRow.getByRole("button", { name: /^Revoked$/ }),
    ).toBeVisible({ timeout: 10_000 });

    // Wire-level assertions: the dashboard issued the DELETE against
    // the correct fp_hash, and refetched the device list after.
    expect(deleteFiredForFp).toBe(FP_HASH);
    expect(getDevicesCalls).toBeGreaterThanOrEqual(2);
  });
});
