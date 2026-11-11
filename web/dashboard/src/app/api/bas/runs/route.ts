import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/bas/runs`.
 *
 * Backs `/dashboard/bas` so the persisted BAS run history is rendered
 * server-side from the bearer-token-protected backend.
 */

interface BasRunHistoryItem {
  simulation_id: string;
  tenant_id: string;
  engagement_id?: string;
  technique_id: string;
  target: string;
  mode: string;
  dry_run: boolean;
  outcome: string;
  evidence_count: number;
  created_at: string;
}

interface ListBasRunsBody {
  items: BasRunHistoryItem[];
}

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
  const engagementId = url.searchParams.get("engagement_id");

  const qs = new URLSearchParams({ limit: limit.toString() });
  if (engagementId !== null && engagementId.length > 0) {
    qs.set("engagement_id", engagementId);
  }

  try {
    const data = await apiGet<ListBasRunsBody>(
      `/v1/bas/runs?${qs.toString()}`,
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
