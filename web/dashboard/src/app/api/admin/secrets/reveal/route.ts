import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { hasPermission } from "@/lib/permissions";

/**
 * Stub for `POST /v1/admin/secrets/reveal`.
 *
 * Returns a synthesized, deterministic-looking masked value so the
 * dashboard's reveal UX can be exercised end-to-end without touching real
 * Vault material. The stub is wired to:
 *
 *   - reject callers that do not carry the `admin:secrets` permission,
 *   - validate the requested path against the canned allow-list (so an
 *     attacker cannot smuggle arbitrary paths into the audit log),
 *   - return a `[STUB]<12 random chars>` body that mimics the masked
 *     shape the real backend will produce.
 *
 * IMPORTANT: the generated value MUST NOT be passed to `console.*` or any
 * other logging sink. Even though it is fake, the route is the contract
 * the production backend will inherit, and the production version will
 * return real secret material. Treat it as sensitive from day one.
 */

const ALLOWED_PATHS: ReadonlySet<string> = new Set([
  "secret/sentinelx/jwt",
  "secret/sentinelx/db",
  "secret/sentinelx/aws/access-key",
  "secret/sentinelx/aws/secret-key",
  "secret/sentinelx/anthropic",
  "secret/sentinelx/vault-token",
  "secret/sentinelx/oidc-client-secret",
  "secret/sentinelx/audit-hmac",
  "secret/sentinelx/iam-pepper",
  "secret/sentinelx/redis-password",
]);

const MASK_LEN = 12;
const MASK_ALPHABET =
  "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";

interface RevealBody {
  path?: unknown;
}

function generateMaskedValue(): string {
  const buf = new Uint32Array(MASK_LEN);
  crypto.getRandomValues(buf);
  let out = "";
  for (let i = 0; i < MASK_LEN; i += 1) {
    const v = buf[i] ?? 0;
    out += MASK_ALPHABET[v % MASK_ALPHABET.length];
  }
  return `[STUB]${out}`;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const permissions = session.user.permissions ?? [];
  if (!hasPermission(permissions, "admin:secrets")) {
    return NextResponse.json(
      { error: { code: "FORBIDDEN", message: "admin:secrets permission required" } },
      { status: 403 },
    );
  }

  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "invalid JSON body" } },
      { status: 400 },
    );
  }

  if (raw === null || typeof raw !== "object") {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "path is required" } },
      { status: 400 },
    );
  }
  const body = raw as RevealBody;
  if (typeof body.path !== "string" || body.path.trim().length === 0) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "path is required" } },
      { status: 400 },
    );
  }
  const path = body.path.trim();
  if (!ALLOWED_PATHS.has(path)) {
    return NextResponse.json(
      { error: { code: "NOT_FOUND", message: "secret path not found" } },
      { status: 404 },
    );
  }

  // Generate the masked stub value. Do NOT log it.
  const value = generateMaskedValue();
  return NextResponse.json({ data: { value } });
}
