import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/twin/{engagement_id}`.
 *
 * Returns the Cyber Digital Twin projection for an engagement: assets,
 * edges, and the currently-compromised set. The response shape stays
 * loose at the proxy layer so the renderer can evolve without a round
 * trip through the proxy contract.
 */

interface RouteContext {
  params: Promise<{ engagement_id: string }>;
}

export async function GET(
  _req: NextRequest,
  ctx: RouteContext,
): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const params = await ctx.params;
  const engagementId = params.engagement_id.trim();
  if (engagementId.length === 0) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "engagement_id is required" } },
      { status: 400 },
    );
  }

  try {
    const data = await apiGet<unknown>(
      `/v1/twin/engagement/${encodeURIComponent(engagementId)}`,
      session.accessToken,
    );
    return NextResponse.json({ data, meta: { engagement_id: engagementId } });
  } catch (err) {
    if (err instanceof ApiError) {
      return NextResponse.json(
        { error: { code: err.code, message: err.message, request_id: err.requestId } },
        { status: err.status },
      );
    }
    return NextResponse.json(
      { error: { code: "UPSTREAM_ERROR", message: "Upstream request failed" } },
      { status: 502 },
    );
  }
}
