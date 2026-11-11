import type { NextConfig } from "next";

// Static CSP fallback for routes that the middleware matcher does NOT cover
// (e.g. `/login`, `/api/auth/**`, `/_next/**`, static assets). The middleware
// at `src/middleware.ts` runs only on `/dashboard/**` and `/v1/safety/**`
// (see its `config.matcher`), and emits a per-request CSP with a nonce —
// `'unsafe-inline'` is NOT present on `script-src` for those routes (LOW-003).
//
// For the non-matched routes below, scripts are limited to `'self'` (Next's
// own chunks). `'unsafe-inline'` is intentionally dropped from `script-src`
// here as well, in line with LOW-003. `style-src 'unsafe-inline'` stays put
// — Tailwind / Next still inline small style blocks; tightening styles is a
// separate sweep.
const cspDirectives: ReadonlyArray<string> = [
  "default-src 'self'",
  // Next.js requires inline styles for hydration; use unsafe-inline only for styles.
  "style-src 'self' 'unsafe-inline'",
  // `script-src` no longer carries `'unsafe-inline'` (LOW-003). Dev builds
  // still need `'unsafe-eval'` for HMR (turbopack / webpack-dev source maps).
  process.env.NODE_ENV === "production"
    ? "script-src 'self'"
    : "script-src 'self' 'unsafe-eval'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' " + (process.env.NEXT_PUBLIC_SX_API_URL ?? ""),
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
];

const securityHeaders = [
  { key: "Content-Security-Policy", value: cspDirectives.join("; ") },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const nextConfig: NextConfig = {
  reactStrictMode: false,
  poweredByHeader: false,
  devIndicators: false,
  typescript: { ignoreBuildErrors: true },
  eslint: { ignoreDuringBuilds: true },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
