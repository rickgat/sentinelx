import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/rba/users/{user_id}/devices` (HIGH-001 FU2, LOW-008).
 *
 * Returns every device fingerprint the RBA device-fp signal has
 * observed for `user_id` within the caller's tenant — known and
 * revoked alike. Tenant scoping is enforced server-side from the
 * bearer claims; the dashboard never plumbs `tenant_id` explicitly.
 *
 * Backend requires the `admin:users` permission; the dashboard sidebar
 * already gates `/dashboard/rba` on that permission, so users without
 * it should not reach this endpoint via the UI.
 */

interface KnownDeviceView {
  fp_hash: string;
  /** `known` (currently enrolled) or `revoked` (locked out). */
  status: string;
  /** ISO-8601 timestamp of the most recent successful login. */
  last_seen_at: string;
}

interface KnownDevicesBody {
  devices: KnownDeviceView[];
}

interface RouteContext {
  params: Promise<{ userId: string }>;
}

export async function GET(
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

  const { userId } = await ctx.params;
  if (userId === "" || userId.includes("/")) {
    return NextResponse.json(
      { error: { code: "INVALID_USER_ID", message: "invalid user_id" } },
      { status: 400 },
    );
  }

  try {
    const data = await apiGet<KnownDevicesBody>(
      `/v1/rba/users/${encodeURIComponent(userId)}/devices`,
      session.accessToken,
    );
    return NextResponse.json({ data });
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
