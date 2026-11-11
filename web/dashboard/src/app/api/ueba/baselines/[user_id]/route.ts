import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/ueba/baselines/{user_id}`.
 *
 * Returns the per-user UEBA behavioural baseline. The bearer token is
 * read from the active Auth.js session; the response is wrapped in the
 * standard `{ data: { ... } }` envelope.
 */

interface BaselineBody {
  tenant_id?: string;
  user_id: string;
  login_hour_counts: number[];
  ip_prefixes: Record<string, number>;
  accessed_assets: Record<string, number>;
  updated_at?: string;
}

interface RouteContext {
  params: Promise<{ user_id: string }>;
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

  const { user_id: userId } = await ctx.params;
  if (userId === "" || userId.includes("/")) {
    return NextResponse.json(
      { error: { code: "INVALID_USER_ID", message: "invalid user_id" } },
      { status: 400 },
    );
  }

  try {
    const data = await apiGet<BaselineBody>(
      `/v1/ueba/baselines/${encodeURIComponent(userId)}`,
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
