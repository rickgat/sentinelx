# SentinelX Dashboard — End-to-End Suite

Playwright tests that exercise the live SentinelX stack from the browser:

- **Dashboard (Next.js)** — `http://127.0.0.1:3000`
- **Monolith (`sx-api` Rust)** — `http://127.0.0.1:18080`

The suite never spawns or migrates those services itself; it assumes both are
already running with their default seed data.

## Specs

| File                          | Coverage                                                                 |
| ----------------------------- | ------------------------------------------------------------------------ |
| `auth.spec.ts`                | Credentials login redirects to `/dashboard`; logout returns to `/login`. |
| `engagements.spec.ts`         | `/dashboard/engagements` lists the three seed engagements.               |
| `findings.spec.ts`            | `/dashboard/findings` lists the eight seed findings and severity badges. |
| `safety.spec.ts`              | Kill-switch dialog → success toast on confirm; reason guard on empty.    |
| `admin.spec.ts`               | Admin IAM create-user form → success toast + session-table row.          |
| `navigation.spec.ts`          | Sidebar nav routes (15 entries) all resolve to their expected pathname.  |

## One-time setup

Install the browser binaries the very first time you run the suite:

```bash
cd web/dashboard
npm install
npx playwright install --with-deps chromium
```

`@playwright/test` is a regular devDependency and is picked up by
`npm install`.

## Running locally

In three terminals:

```bash
# Terminal 1 — monolith
cargo run -p sx-api

# Terminal 2 — dashboard
cd web/dashboard && npm run dev

# Terminal 3 — tests
cd web/dashboard && npm run e2e
```

Useful variants:

```bash
npm run e2e -- --headed              # see the browser
npm run e2e -- e2e/auth.spec.ts      # one file
npm run e2e -- --grep "kill switch"  # title substring
npm run e2e:ui                       # interactive Playwright UI
npm run e2e:report                   # open last HTML report
```

## Seed accounts

Defaults mirror the bootstrap seed in `config/sentinelx.dev.example.yaml`
(admin: SX-REVIEW-002 C2; analyst: L1-FU1). Both users land in the same
bootstrap tenant so the list views render identical seed data regardless
of which user is logged in. Override via env vars when targeting a
staging environment:

| Var                     | Default                                  |
| ----------------------- | ---------------------------------------- |
| `E2E_TENANT_ID`         | `01010101-0101-0101-0101-010101010101`   |
| `E2E_USER_EMAIL`        | `analyst@sentinelx.dev`                  |
| `E2E_USER_PASSWORD`     | `Analyst!Password1`                      |
| `E2E_ADMIN_TENANT_ID`   | `01010101-0101-0101-0101-010101010101`   |
| `E2E_ADMIN_EMAIL`       | `admin@sentinelx.dev`                    |
| `E2E_ADMIN_PASSWORD`    | `sentinelx-admin-pw`                     |

## CI mode

When `process.env.CI` is set, `playwright.config.ts` switches into a
stricter posture:

- `forbidOnly: true` — fails the run if any `test.only` slipped through.
- `workers: 1` — serialise execution, since the monolith is shared state.
- `retries: 2` — flaky-network tolerance (same in local dev).

Reports:

- `playwright-report/` — HTML report (`reporter: ["html"]`).
- `test-results/` — per-test artifacts (videos `retain-on-failure`,
  screenshots `only-on-failure`, traces `on-first-retry`).

Recommended CI invocation:

```bash
CI=1 npm run e2e -- --reporter=line,html
```

Upload `playwright-report/` and `test-results/` as build artifacts so
failures can be triaged after the fact.

## Authoring conventions

- Use the `login` / `logout` helpers from `helpers/auth.ts` in
  `beforeEach` / `afterEach` blocks.
- Prefer role-based selectors (`page.getByRole("button", { name: ... })`)
  over CSS or XPath.
- Never use hard-coded sleeps. Use
  `expect(locator).toBeVisible({ timeout: 5_000 })` or `page.waitForURL`.
- Group related tests under a `test.describe(...)` block.

## Troubleshooting

| Symptom                                                  | Likely cause                                                       |
| -------------------------------------------------------- | ------------------------------------------------------------------ |
| `net::ERR_CONNECTION_REFUSED` on `/login`                | `npm run dev` not running on port 3000.                            |
| Login times out at `waitForURL(/\/dashboard/)`           | Monolith not reachable at `http://127.0.0.1:18080` — auth fails.   |
| Engagements / findings row count mismatch                | Seed has been re-tuned — update the constants at the top of each spec. |
| `Cannot find module '@playwright/test'`                  | Run `npm install` in `web/dashboard`.                              |
