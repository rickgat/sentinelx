import { defineConfig, devices, type PlaywrightTestConfig } from "@playwright/test";

/**
 * Playwright configuration for the SentinelX dashboard end-to-end suite.
 *
 * Assumes:
 *   - The Next.js dashboard is running at http://127.0.0.1:3000
 *     (`npm run dev` from web/dashboard)
 *   - The Rust monolith (sx-api) is running at http://127.0.0.1:18080
 *
 * The suite never spawns these processes itself — see e2e/README.md for the
 * exact orchestration the user is expected to perform before running
 * `npm run e2e`.
 */
const config: PlaywrightTestConfig = {
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: 2,
  reporter: [["html", { open: "never" }]],
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  use: {
    // Auth.js v5 in dev mode uses `localhost` as its internal baseUrl (the
    // authjs.callback-url cookie is set to `http://localhost:3000` regardless
    // of the AUTH_URL / AUTH_TRUST_HOST env). If Playwright drives 127.0.0.1
    // the sign-in redirect crosses hosts and the session cookie becomes
    // invisible to the target route. Align baseURL to `localhost` so the
    // whole flow stays same-origin. Override with PLAYWRIGHT_BASE_URL when
    // pointing at staging.
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3000",
    trace: "on-first-retry",
    video: "retain-on-failure",
    screenshot: "only-on-failure",
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
};

// `exactOptionalPropertyTypes` in tsconfig.json means we can only set
// `workers` when we have a concrete value — `undefined` is not assignable.
if (process.env.CI !== undefined) {
  config.workers = 1;
}

export default defineConfig(config);
