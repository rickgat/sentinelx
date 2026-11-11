/**
 * Module augmentation for Auth.js v5 — adds SentinelX-specific fields to
 * `Session` and `JWT`. Imported once from `lib/auth.ts` so consumers get the
 * augmented types without explicit imports.
 *
 * Refresh tokens are deliberately NOT surfaced on `Session` — the browser
 * never sees them. They live only on the server-side encrypted JWT.
 */

import type { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      tenantId?: string;
      /**
       * Permission strings derived from the user's role grants — e.g.
       * `admin:users`, `bas:run`. Surfaced only so dashboard pages can
       * mirror backend gating in the UI; the backend remains the source
       * of truth.
       */
      permissions?: ReadonlyArray<string>;
      email?: string | null;
      name?: string | null;
      image?: string | null;
    } & DefaultSession["user"];
    /**
     * SX access token, surfaced ONLY so server components can call sx-api on
     * the user's behalf during SSR. Never sent to client components.
     */
    accessToken?: string;
    error?: "RefreshAccessTokenError";
  }
}

declare module "@auth/core/jwt" {
  interface JWT {
    /** Tenant identifier resolved from the OIDC profile or credentials login. */
    tenantId?: string;
    /** sx-api access token (short-lived, JWT). */
    sxAccessToken?: string;
    /** sx-api refresh token — server-only. */
    sxRefreshToken?: string;
    /** Epoch seconds at which sxAccessToken expires. */
    sxAccessTokenExp?: number;
    /**
     * Permission strings decoded from the sx-api access token payload
     * — e.g. `admin:users`, `bas:run`, or wildcards like `*:*` /
     * `admin:*`. Populated by the credentials-provider authorize step
     * and mirrored into `session.user.permissions` by the session
     * callback so page-level gates can check them without decoding
     * the access token on every SSR call.
     */
    permissions?: ReadonlyArray<string>;
    /** Set when refresh fails — the session callback maps this onto session.error. */
    error?: "RefreshAccessTokenError";
  }
}

export {};
