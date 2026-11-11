import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";
import type { Finding, Page } from "@/lib/types";

/**
 * Proxy for `GET /v1/findings`.
 *
 * Used by the SOC alert feed's 30 s auto-refresh interval so the bearer
 * token never leaves the server. Forwards `limit` (clamped) and an
 * optional `sort` querystring; everything else is owned by sx-api.
 */

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const url = new URL(req.url);
  const limitParam = Number.parseInt(url.searchParams.get("limit") ?? "", 10);
  const limit = Number.isFinite(limitParam) && limitParam > 0
    ? Math.min(limitParam, MAX_LIMIT)
    : DEFAULT_LIMIT;
  const sort = url.searchParams.get("sort") ?? "last_seen:desc";

  const query = `limit=${limit}&sort=${encodeURIComponent(sort)}`;

  try {
    const data = await apiGet<Page<Finding>>(
      `/v1/findings?${query}`,
      session.accessToken,
    );
    return NextResponse.json({ data });
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
