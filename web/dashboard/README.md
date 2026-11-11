# SentinelX Dashboard

Next.js 15 (App Router) + React 19 + TypeScript 5 (strict) + Tailwind v4 dashboard
for the SentinelX security platform.

## Quick start

```bash
cp .env.example .env.local        # fill in values
npm install                       # or pnpm / yarn / bun
npm run dev                       # http://localhost:3000
```

## Scripts

| Script | Purpose |
| --- | --- |
| `npm run dev` | Start Next dev server on :3000 |
| `npm run build` | Production build |
| `npm run start` | Run the production build |
| `npm run lint` | ESLint (`next/core-web-vitals` + `next/typescript`) |
| `npm run typecheck` | `tsc --noEmit` against strict config |

## Required env vars

| Variable | Scope | Description |
| --- | --- | --- |
| `NEXT_PUBLIC_SX_API_URL` | public | Base URL of `sx-api` |
| `NEXT_PUBLIC_DEFAULT_TENANT_ID` | public | Hidden tenant id on the login form |
| `NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN` | public | `"true"` to show the dev email+password form (default `"false"`) |
| `AUTH_SECRET` | server | 32+ byte random string (Auth.js v5) |
| `AUTH_URL` | server | Canonical origin of this dashboard |
| `OIDC_ISSUER` | server | IdP discovery URL |
| `OIDC_CLIENT_ID` | server | OIDC client id |
| `OIDC_CLIENT_SECRET` | server | OIDC client secret |
| `OIDC_SCOPES` | server | Space-separated OIDC scopes |

See `.env.example` for inline comments.

## Authentication

Sign-in is powered by **Auth.js v5** (`next-auth@5.0.0-beta.25`). The dashboard
supports two sign-in modes; the providers are registered conditionally based
on environment variables.

### 1. OIDC SSO (preferred, prod-grade)

Registered automatically when **all** of `OIDC_ISSUER`, `OIDC_CLIENT_ID`, and
`OIDC_CLIENT_SECRET` are set. The "Sign in with SSO" button on `/login` calls
`signIn("oidc", { callbackUrl: "/dashboard" })`, which redirects to the IdP.

Example IdP configuration:

| IdP | `OIDC_ISSUER` example |
| --- | --- |
| Keycloak | `https://idp.example.com/realms/sentinelx` |
| Auth0 | `https://your-tenant.us.auth0.com` |
| Okta | `https://your-tenant.okta.com/oauth2/default` |

Register the redirect URI `${AUTH_URL}/api/auth/callback/oidc` with the IdP.
Scopes default to `openid profile email`; override via `OIDC_SCOPES`.

### 2. Credentials (dev convenience)

Registered only when `NODE_ENV !== "production"` **and** shown only when
`NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN="true"`. It posts to
`POST ${SX_API}/v1/auth/login` and stores the returned SX access/refresh tokens
on the encrypted server-side JWT cookie. Use it for local development; flip the
flag off (or rely on the production guard) before promoting builds.

### Session model

- Strategy: `jwt` (no DB session table).
- Cookie: `sentinelx.session`, `httpOnly`, `sameSite=lax`, `secure` in production.
- The JWT holds `sxAccessToken`, `sxRefreshToken`, and `sxAccessTokenExp`. The
  refresh token is **server-only** — it is never serialized into `session`.
- When the access token is within 60 seconds of expiry, the `jwt` callback
  POSTs to `${SX_API}/v1/auth/refresh` and rotates the tokens transparently.

### Route protection

`src/middleware.ts` runs Auth.js v5 middleware against:

- `/dashboard/**`
- `/v1/safety/**`

Unauthenticated requests are redirected to `/login?callbackUrl=<original>`.
`/api/auth/**` and `/login` are exempt by virtue of not matching the
middleware matcher.

## Routes

| Path | Description |
| --- | --- |
| `/` | Redirects to `/dashboard` |
| `/login` | Email/password login form posting to `${SX_API}/v1/auth/login` |
| `/dashboard` | Executive overview — 4 KPI cards + 7-day posture trend |
| `/dashboard/engagements` | TanStack Table of engagements |
| `/dashboard/findings` | TanStack Table of findings with severity badges + status filter |
| `/dashboard/safety` | Kill-switch trigger with confirm dialog |
| `/api/auth/[...nextauth]` | Auth.js v5 OIDC handler (env-driven) |

## Notes

- Dark mode by default; no light theme in Phase 1.
- Strict CSP, `X-Frame-Options: DENY`, no-referrer policy set in `next.config.ts`.
- Live OIDC is wired in `lib/auth.ts`; the provider is registered only when
  `OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` are all set.
- The dev credentials provider is gated by `NODE_ENV !== "production"` server-side
  and `NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN="true"` client-side.
- No `node_modules` are committed; run a package install before `npm run dev`.
