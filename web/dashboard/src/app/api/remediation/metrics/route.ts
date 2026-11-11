import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";
import type { RemediationMetrics } from "@/types/remediation";

/**
 * Proxy for `GET /v1/remediation/outcomes/metrics?window_days=N`.
 *
 * Returns per-severity MTTR, regression rate, and top regressing
 * `check_id`s. Default window is 30 days; capped server-side at 365.
 */

const DEFAULT_WINDOW_DAYS = 30;
const MAX_WINDOW_DAYS = 365;

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const url = new URL(req.url);
  const raw = Number.parseInt(url.searchParams.get("window_days") ?? "", 10);
  const window =
    Number.isFinite(raw) && raw > 0
      ? Math.min(raw, MAX_WINDOW_DAYS)
      : DEFAULT_WINDOW_DAYS;

  try {
    const data = await apiGet<RemediationMetrics>(
      `/v1/remediation/outcomes/metrics?window_days=${window}`,
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
