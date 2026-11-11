import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { apiDelete, ApiError } from "@/lib/api-client";

/**
 * Proxy for `DELETE /v1/rba/users/{user_id}/devices/{fp_hash}`
 * (HIGH-001 FU2, LOW-008).
 *
 * Revokes a single enrolled device fingerprint. Idempotent — revoking
 * an already-revoked fingerprint returns 204 from upstream. The
 * dashboard surfaces a `{ ok: true }` envelope so the client can branch
 * on success without parsing an empty body.
 *
 * Backend requires the `admin:users` permission and resolves the
 * tenant from the bearer claims.
 */

interface RouteContext {
  params: Promise<{ userId: string; fpHash: string }>;
}

export async function DELETE(
  _req: Request,
  ctx: RouteContext,
): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const { userId, fpHash } = await ctx.params;
  if (userId === "" || userId.includes("/")) {
    return NextResponse.json(
      { error: { code: "INVALID_USER_ID", message: "invalid user_id" } },
      { status: 400 },
    );
  }
  if (fpHash === "" || fpHash.includes("/")) {
    return NextResponse.json(
      { error: { code: "INVALID_FP_HASH", message: "invalid fp_hash" } },
      { status: 400 },
    );
  }

  try {
    await apiDelete(
      `/v1/rba/users/${encodeURIComponent(userId)}/devices/${encodeURIComponent(fpHash)}`,
      session.accessToken,
    );
    return NextResponse.json({ data: { ok: true } });
  } catch (err) {
    if (err instanceof ApiError) {
      return NextResponse.json(
        {
          error: {
            code: err.code,
            message: err.message,
            request_id: err.requestId,
          },
        },
        { status: err.status },
      );
    }
    return NextResponse.json(
      { error: { code: "UPSTREAM_ERROR", message: "Upstream request failed" } },
      { status: 502 },
    );
  }
}
