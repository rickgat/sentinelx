import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";

/**
 * Build a per-request CSP header value with the given nonce.
 *
 * Notes (LOW-003):
 * - `script-src` uses `'self' 'nonce-<value>'` and NO `'unsafe-inline'`. In
 *   production this is the whole point of LOW-003: Next 15 App Router streams
 *   inline hydration scripts (`self.__next_f.push(...)`) that we previously
 *   had to allow via `'unsafe-inline'`. With the nonce propagated via the
 *   `x-nonce` request header, Next's runtime stamps every inline `<script>`
 *   it emits with `nonce="<value>"`, so we can drop `'unsafe-inline'`.
 * - `style-src` still keeps `'unsafe-inline'` — Tailwind / Next still inline
 *   small style blocks for hydration. Tightening styles is tracked as a
 *   separate follow-up (handoff §4 + LOW-003 spec explicitly defers this).
 * - `'unsafe-eval'` is still required for Next dev-mode HMR (turbopack /
 *   webpack-dev eval-source-maps). Production drops it.
 * - `'strict-dynamic'` lets the nonce'd entry script propagate trust to the
 *   chunks it loads without us having to enumerate every hash. Modern
 *   browsers honor it; older browsers fall back to `'self'`.
 */
function buildCsp(nonce: string): string {
  const isProd = process.env.NODE_ENV === "production";
  const scriptSrc = isProd
    ? `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`
    : `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`;

  const directives: string[] = [
    "default-src 'self'",
    // Styles still need 'unsafe-inline' — separate hardening task.
    "style-src 'self' 'unsafe-inline'",
    scriptSrc,
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src 'self' ${process.env.NEXT_PUBLIC_SX_API_URL ?? ""}`.trim(),
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ];

  return directives.join("; ");
}

/**
 * Generate a 16-byte (128-bit) cryptographically-random nonce, base64-encoded
 * without padding. Uses the Web Crypto API (`crypto.getRandomValues`), which
 * is available in the Edge runtime Next.js middleware runs under.
 */
function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // btoa expects a binary string; build one byte-by-byte.
  let bin = "";
  for (const b of bytes) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin).replace(/=+$/, "");
}

/**
 * Combined CSP-nonce + Auth.js v5 middleware.
 *
 * Order of operations on every request:
 *   1. Generate a per-request nonce.
 *   2. Forward it on the request as `x-nonce` so Next's runtime stamps every
 *      inline hydration script with `nonce="<value>"` (canonical Next App
 *      Router CSP pattern — see
 *      https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy).
 *   3. Run the existing auth-gate logic — redirect anonymous users on
 *      protected routes to `/login`.
 *   4. Set the matching `Content-Security-Policy` header on the response so
 *      the browser only executes scripts carrying our nonce.
 *
 * `/api/auth/**`, `/login`, `/_next/**`, and static assets are not matched —
 * see `config.matcher` below. Those responses still get the static CSP from
 * `next.config.ts` (which drops `'unsafe-inline'` for scripts in prod), but
 * they don't render inline scripts so a nonce isn't needed.
 */
export default auth((req) => {
  const nonce = generateNonce();
  const csp = buildCsp(nonce);

  // Forward nonce to Next's runtime via a request header. Next picks this up
  // and applies it to every inline <script> tag it emits during streaming.
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-nonce", nonce);
  // We also propagate the CSP itself on the request for Server Components
  // that want to introspect it (optional; harmless).
  requestHeaders.set("content-security-policy", csp);

  const { pathname, search } = req.nextUrl;
  const isLoggedIn = req.auth !== null;

  // Auth gate only fires on the formerly-matched protected routes. The
  // broader matcher (see `config.matcher` below) extended coverage to public
  // routes so they get the nonce'd CSP, but we must NOT redirect those to
  // `/login` — that would break the login page itself.
  const isProtected =
    pathname.startsWith("/dashboard") || pathname.startsWith("/v1/safety");

  let response: NextResponse;
  if (isProtected && !isLoggedIn) {
    const loginUrl = req.nextUrl.clone();
    loginUrl.pathname = "/login";
    loginUrl.search = "";
    loginUrl.searchParams.set("callbackUrl", `${pathname}${search}`);
    response = NextResponse.redirect(loginUrl);
  } else {
    response = NextResponse.next({
      request: { headers: requestHeaders },
    });
  }

  // Set CSP on the response so the browser enforces it.
  response.headers.set("Content-Security-Policy", csp);
  return response;
});

export const config = {
  // Match every HTML-bearing route so every page gets a per-request nonce.
  // Excluding:
  //   - `/api/auth/**` — Auth.js own callbacks; should not be auth-gated by
  //     this middleware (it'd cause a redirect loop), and they return JSON,
  //     not HTML.
  //   - `/_next/static/**`, `/_next/image/**` — static assets; the browser
  //     never executes them as HTML, so the per-request CSP would be wasted
  //     compute (and they're served by Next's static handler, which doesn't
  //     stream inline scripts).
  //   - `/favicon.svg` (+ any future static asset under `/public`).
  //
  // The auth gate inside the middleware only redirects when the path matches
  // `/dashboard/**` or `/v1/safety/**` — see the body of the handler — so
  // public routes like `/login`, `/signup` still render but ALSO receive the
  // nonce'd CSP. (LOW-003)
  matcher: [
    {
      source:
        "/((?!api/auth|_next/static|_next/image|favicon\\.svg|favicon\\.ico).*)",
    },
  ],
};
