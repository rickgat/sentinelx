import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { hasPermission } from "@/lib/permissions";

/**
 * Stub for `GET /v1/admin/secrets`.
 *
 * Returns the canned list of Vault paths the SentinelX platform proxies on
 * the operator's behalf. The list is intentionally small and static — once
 * the backend lands, this route will fan out to Vault's `LIST` operation
 * scoped to the tenant's mount. Until then the dashboard team uses the
 * canned set to wire the UI without touching production secrets.
 *
 * The route is gated by the `admin:secrets` permission. Paths are non-
 * sensitive (they are metadata, not values), but exposing them broadly
 * still leaks operational information so we keep the same gate as
 * `/reveal`.
 */

const CANNED_PATHS: ReadonlyArray<string> = [
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
];

/**
 * Stable identifier for the active envelope-encryption KEK provider.
 *
 * Mirrors the snake_case identifiers emitted by
 * `sx_monolith::adapters::secrets::KekKind::as_str` (P1-005 / P1-006 /
 * P1-007). The dashboard renders this verbatim above the Vault path
 * list so operators can confirm at-a-glance which cloud KMS is wrapping
 * tenant DEKs without having to SSH into the host. The value is
 * advisory: it never gates any control-plane action.
 *
 * When the backend is wired this stub will be replaced by a fetch
 * against `/v1/admin/secrets`. Until then the canned `"disabled"`
 * surfaces the safe-default state.
 */
const KEK_PROVIDER: string = "disabled";

export async function GET(): Promise<NextResponse> {
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

  return NextResponse.json({
    data: { paths: CANNED_PATHS, kek_provider: KEK_PROVIDER },
  });
}
