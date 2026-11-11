import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/scans`. Returns persistent scan history newest-first.
 */

export interface ScanFinding {
  check_id: string;
  severity: string;
  title: string;
  description: string;
  recommendation?: string;
}

export interface ScanRecord {
  id: string;
  tenant_id: string;
  kind: string;
  target: string;
  engagement_id?: string;
  started_at: string;
  finished_at: string;
  status: string;
  error?: string;
  findings: ScanFinding[];
}

interface ListScansBody {
  items: ScanRecord[];
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
    const data = await apiGet<ListScansBody>(
      `/v1/scans?${qs.toString()}`,
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
