import { z } from "zod";

/**
 * Public (browser-exposed) environment schema. Anything in here is sent
 * to the client; never put secrets here.
 */
const publicEnvSchema = z.object({
  NEXT_PUBLIC_SX_API_URL: z.url(),
  NEXT_PUBLIC_DEFAULT_TENANT_ID: z.string().min(1),
  /**
   * Feature flag — when "true", the login page also offers the
   * email + password credentials form. Disabled by default and
   * forced off in production by `lib/auth.ts`.
   */
  NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN: z
    .enum(["true", "false"])
    .default("false"),
});

/**
 * Server-only environment schema. Only evaluated on the server.
 */
const serverEnvSchema = z.object({
  AUTH_SECRET: z.string().min(16).optional(),
  AUTH_URL: z.url().optional(),
  OIDC_ISSUER: z.url().optional(),
  OIDC_CLIENT_ID: z.string().min(1).optional(),
  OIDC_CLIENT_SECRET: z.string().min(1).optional(),
  OIDC_SCOPES: z.string().default("openid profile email"),
});

const rawPublic = {
  NEXT_PUBLIC_SX_API_URL: process.env.NEXT_PUBLIC_SX_API_URL,
  NEXT_PUBLIC_DEFAULT_TENANT_ID: process.env.NEXT_PUBLIC_DEFAULT_TENANT_ID,
  NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN: process.env.NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN,
};

const publicParsed = publicEnvSchema.safeParse(rawPublic);

/**
 * Throws at startup if required browser-visible vars are missing.
 * Keep this lazy so test runs don't crash.
 */
export const publicEnv = publicParsed.success
  ? publicParsed.data
  : {
      NEXT_PUBLIC_SX_API_URL: "http://localhost:8080",
      NEXT_PUBLIC_DEFAULT_TENANT_ID: "",
      NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN: "false" as const,
    };

let cachedServerEnv: z.infer<typeof serverEnvSchema> | null = null;

/**
 * Lazy server env accessor — only call from server components / route handlers.
 */
export function getServerEnv(): z.infer<typeof serverEnvSchema> {
  if (cachedServerEnv !== null) {
    return cachedServerEnv;
  }
  const parsed = serverEnvSchema.parse({
    AUTH_SECRET: process.env.AUTH_SECRET,
    AUTH_URL: process.env.AUTH_URL,
    OIDC_ISSUER: process.env.OIDC_ISSUER,
    OIDC_CLIENT_ID: process.env.OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET: process.env.OIDC_CLIENT_SECRET,
    OIDC_SCOPES: process.env.OIDC_SCOPES,
  });
  cachedServerEnv = parsed;
  return parsed;
}
