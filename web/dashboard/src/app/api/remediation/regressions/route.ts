import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";
import type { RegressionList } from "@/types/remediation";

/**
 * Proxy for `GET /v1/remediation/outcomes/regressions?limit=N`.
 *
 * Returns newest-first regression events for the dashboard's
 * regression-feed panel. Defaults `limit` to 50; capped server-side
 * at 500.
 */

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const url = new URL(req.url);
  const raw = Number.parseInt(url.searchParams.get("limit") ?? "", 10);
  const limit =
    Number.isFinite(raw) && raw > 0 ? Math.min(raw, MAX_LIMIT) : DEFAULT_LIMIT;

  try {
    const data = await apiGet<RegressionList>(
      `/v1/remediation/outcomes/regressions?limit=${limit}`,
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
