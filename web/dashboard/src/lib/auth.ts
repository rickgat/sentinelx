import NextAuth, { type NextAuthConfig, type User } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";

import { getServerEnv, publicEnv } from "@/lib/env";
import "@/types/auth";

/**
 * Auth.js v5 configuration for SentinelX.
 *
 * Two provider paths:
 *
 *   1. `oidc`        — generic OIDC provider, registered only when
 *                      OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET
 *                      are all present.
 *   2. `credentials` — email + password against `${SX_API}/v1/auth/login`,
 *                      registered only when NODE_ENV !== "production".
 *
 * The browser never holds the refresh token — it lives only on the
 * server-side encrypted JWT cookie (sentinelx.session).
 */

const LOGIN_RESPONSE = z.object({
  data: z.object({
    access_token: z.string(),
    refresh_token: z.string().optional(),
    expires_in: z.number(),
    token_type: z.string().optional(),
    // The SX API does not currently return a nested `user` object — the
    // dashboard reconstructs the missing fields from the form input. Keep
    // this optional so the contract bends without breaking the round-trip.
    user: z
      .object({
        id: z.string().optional(),
        email: z.email().optional(),
        tenant_id: z.string().optional(),
      })
      .optional(),
  }),
});

const REFRESH_RESPONSE = z.object({
  data: z.object({
    access_token: z.string(),
    refresh_token: z.string().optional(),
    expires_in: z.number(),
  }),
});

const CREDENTIALS_SCHEMA = z.object({
  tenantId: z.string().min(1),
  email: z.email(),
  password: z.string().min(1),
});

/**
 * Decode a JWT's payload without verifying the signature. This is safe
 * for our use case — we are ONLY reading the payload to lift the
 * `permissions` claim onto the NextAuth session. The token itself is
 * still verified by sx-api on every API call (the dashboard never
 * trusts these permissions for enforcement, only for UI gating).
 *
 * Returns `null` on any parse failure so the caller can gracefully
 * default to an empty permission set.
 */
function extractPermissionsFromJwt(token: string): ReadonlyArray<string> | null {
  const parts = token.split(".");
  if (parts.length < 2) {
    return null;
  }
  const payload = parts[1];
  if (payload === undefined) {
    return null;
  }
  try {
    // JWT payload is base64url-encoded — Buffer/atob wants base64.
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
    const decoded = Buffer.from(padded, "base64").toString("utf8");
    const parsed = JSON.parse(decoded) as { permissions?: unknown };
    if (!Array.isArray(parsed.permissions)) {
      return null;
    }
    const perms: string[] = [];
    for (const p of parsed.permissions) {
      if (typeof p === "string") {
        perms.push(p);
      }
    }
    return perms;
  } catch {
    return null;
  }
}

/**
 * POST to the sx-api refresh endpoint and rotate the access token on the JWT.
 * Returns a fresh JWT shape; on failure, marks the token with an error so the
 * session callback can surface a re-auth requirement.
 */
async function refreshSxAccessToken(
  refreshToken: string,
  sxApiBase: string,
): Promise<{
  sxAccessToken: string;
  sxRefreshToken: string;
  sxAccessTokenExp: number;
} | null> {
  try {
    const res = await fetch(`${sxApiBase}/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
      cache: "no-store",
    });
    if (!res.ok) {
      return null;
    }
    const parsed = REFRESH_RESPONSE.safeParse(await res.json());
    if (!parsed.success) {
      return null;
    }
    const now = Math.floor(Date.now() / 1000);
    return {
      sxAccessToken: parsed.data.data.access_token,
      sxRefreshToken: parsed.data.data.refresh_token ?? refreshToken,
      sxAccessTokenExp: now + parsed.data.data.expires_in,
    };
  } catch {
    return null;
  }
}

export function buildAuthConfig(): NextAuthConfig {
  const env = getServerEnv();
  const sxApiBase = publicEnv.NEXT_PUBLIC_SX_API_URL.replace(/\/$/, "");
  const isProd = process.env.NODE_ENV === "production";

  const providers: NextAuthConfig["providers"] = [];

  // -------------------- OIDC (preferred) -----------------------------------
  if (
    env.OIDC_ISSUER !== undefined &&
    env.OIDC_CLIENT_ID !== undefined &&
    env.OIDC_CLIENT_SECRET !== undefined
  ) {
    providers.push({
      id: "oidc",
      name: "SSO",
      type: "oidc",
      issuer: env.OIDC_ISSUER,
      clientId: env.OIDC_CLIENT_ID,
      clientSecret: env.OIDC_CLIENT_SECRET,
      authorization: { params: { scope: env.OIDC_SCOPES } },
    });
  }

  // -------------------- Credentials (dev mode, or explicit opt-in) ---------
  // Honors NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN=true so a production-built
  // dev environment (cargo + next start, no IdP) can still log in.
  const allowCredentials =
    !isProd || publicEnv.NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN === "true";
  if (allowCredentials) {
    providers.push(
      Credentials({
        id: "credentials",
        name: "Email + password",
        credentials: {
          tenantId: { label: "Tenant ID", type: "text" },
          email: { label: "Email", type: "email" },
          password: { label: "Password", type: "password" },
        },
        async authorize(rawCredentials): Promise<User | null> {
          const parsed = CREDENTIALS_SCHEMA.safeParse(rawCredentials);
          if (!parsed.success) {
            return null;
          }
          const { tenantId, email, password } = parsed.data;

          const res = await fetch(`${sxApiBase}/v1/auth/login`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Accept: "application/json",
              // Dev-only: dashboard server-side fetch hits the API from
              // 127.0.0.1, which the RBA scorer treats as unknown geo
              // and blocks. In prod, the reverse proxy sets this header
              // from the real client IP.
              ...(!isProd ? { "X-Forwarded-For": "8.8.8.8" } : {}),
            },
            body: JSON.stringify({ tenant_id: tenantId, email, password }),
            cache: "no-store",
          });
          if (!res.ok) {
            return null;
          }
          const body = LOGIN_RESPONSE.safeParse(await res.json());
          if (!body.success) {
            return null;
          }

          const now = Math.floor(Date.now() / 1000);
          const data = body.data.data;

          // `User` here is what the `jwt` callback receives as `user` on first sign-in.
          // We stash sx-* fields onto it; they are read once and then promoted onto the JWT.
          const user: User & {
            tenantId?: string;
            sxAccessToken?: string;
            sxRefreshToken?: string;
            sxAccessTokenExp?: number;
            permissions?: ReadonlyArray<string>;
          } = {
            id: data.user?.id ?? `sx:${tenantId}:${email}`,
            email: data.user?.email ?? email,
            tenantId: data.user?.tenant_id ?? tenantId,
            sxAccessToken: data.access_token,
            sxAccessTokenExp: now + data.expires_in,
          };
          if (data.refresh_token !== undefined) {
            user.sxRefreshToken = data.refresh_token;
          }
          // Decode the backend JWT to lift the `permissions` claim onto
          // the NextAuth session. sx-api mints tokens with a
          // `permissions: string[]` claim (see
          // `crates/sx-iam/src/service/policy.rs`) — dashboard-side
          // gates need to see these to authorise pages.
          const perms = extractPermissionsFromJwt(data.access_token);
          if (perms !== null) {
            user.permissions = perms;
          }
          return user;
        },
      }),
    );
  }

  const config: NextAuthConfig = {
    session: {
      strategy: "jwt",
      maxAge: 60 * 60 * 8, // 8 hours
    },
    cookies: {
      sessionToken: {
        name: "sentinelx.session",
        options: {
          httpOnly: true,
          secure: isProd,
          sameSite: "lax",
          path: "/",
        },
      },
    },
    providers,
    callbacks: {
      async jwt({ token, user, account, profile }) {
        // -------------------- Initial sign-in --------------------
        if (user !== undefined) {
          const u = user as User & {
            tenantId?: string;
            sxAccessToken?: string;
            sxRefreshToken?: string;
            sxAccessTokenExp?: number;
            permissions?: ReadonlyArray<string>;
          };
          if (u.tenantId !== undefined) {
            token.tenantId = u.tenantId;
          }
          if (u.sxAccessToken !== undefined) {
            token.sxAccessToken = u.sxAccessToken;
          }
          if (u.sxRefreshToken !== undefined) {
            token.sxRefreshToken = u.sxRefreshToken;
          }
          if (u.sxAccessTokenExp !== undefined) {
            token.sxAccessTokenExp = u.sxAccessTokenExp;
          }
          if (u.permissions !== undefined) {
            token.permissions = u.permissions;
          }
        }

        // OIDC sign-in: prefer profile-level claims when present.
        if (profile !== undefined) {
          if (typeof profile.email === "string") {
            token.email = profile.email;
          }
          if (typeof profile.name === "string") {
            token.name = profile.name;
          }
          const tenantClaim = (profile as { tenant_id?: unknown }).tenant_id;
          if (typeof tenantClaim === "string") {
            token.tenantId = tenantClaim;
          }
        }

        // OIDC access + refresh tokens come back on `account` on first sign-in.
        if (account !== null && account !== undefined && account.provider === "oidc") {
          if (typeof account.access_token === "string") {
            token.sxAccessToken = account.access_token;
          }
          if (typeof account.refresh_token === "string") {
            token.sxRefreshToken = account.refresh_token;
          }
          if (typeof account.expires_at === "number") {
            token.sxAccessTokenExp = account.expires_at;
          }
        }

        // -------------------- Refresh window --------------------
        const now = Math.floor(Date.now() / 1000);
        const exp = token.sxAccessTokenExp;
        if (
          typeof exp === "number" &&
          typeof token.sxRefreshToken === "string" &&
          exp - now < 60
        ) {
          const refreshed = await refreshSxAccessToken(token.sxRefreshToken, sxApiBase);
          if (refreshed === null) {
            token.error = "RefreshAccessTokenError";
          } else {
            token.sxAccessToken = refreshed.sxAccessToken;
            token.sxRefreshToken = refreshed.sxRefreshToken;
            token.sxAccessTokenExp = refreshed.sxAccessTokenExp;
            // Re-decode permissions from the refreshed access token so a
            // role change server-side surfaces without requiring a
            // full re-sign-in.
            const refreshedPerms = extractPermissionsFromJwt(refreshed.sxAccessToken);
            if (refreshedPerms !== null) {
              token.permissions = refreshedPerms;
            }
            delete token.error;
          }
        }

        return token;
      },

      session({ session, token }) {
        if (typeof token.sub === "string") {
          session.user.id = token.sub;
        }
        if (typeof token.tenantId === "string") {
          session.user.tenantId = token.tenantId;
        }
        if (typeof token.email === "string") {
          session.user.email = token.email;
        }
        // Access token is exposed for SSR-only API calls. Refresh token
        // is NOT exposed — it stays on the encrypted JWT.
        if (typeof token.sxAccessToken === "string") {
          session.accessToken = token.sxAccessToken;
        }
        // Permissions decoded from the sx-api JWT payload — feeds the
        // wildcard-aware `hasPermission` gates on the IAM / SCIM /
        // admin/secrets pages + the sidebar filter.
        if (Array.isArray(token.permissions)) {
          session.user.permissions = token.permissions;
        }
        if (token.error !== undefined) {
          session.error = token.error;
        }
        return session;
      },
    },
    pages: {
      signIn: "/login",
    },
  };

  // Only set `secret` when present — `exactOptionalPropertyTypes` rejects
  // assigning `undefined` to an optional field.
  if (env.AUTH_SECRET !== undefined) {
    config.secret = env.AUTH_SECRET;
  }

  return config;
}

/**
 * Module-level Auth.js v5 handlers. Importing `handlers`, `auth`, `signIn`,
 * or `signOut` from this file is the canonical entry point.
 */
export const { handlers, auth, signIn, signOut } = NextAuth(buildAuthConfig());
