import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/device-trust/sessions` (P2-008).
 *
 * Returns recent posture observations newest-first, capped by the
 * `limit` query parameter (default 50, max 500). The sx-api side
 * clamps the value too; we duplicate the upper bound here so a
 * malicious client cannot drive a giant fetch through the dashboard.
 */

export interface PostureClaimsSummary {
  os_name?: string;
  os_version?: string;
  disk_encrypted: boolean;
  edr_present: boolean;
  edr_vendor?: string;
  screen_lock_minutes?: number;
}

export interface PostureSessionView {
  id: string;
  user_id: string;
  session_id: string;
  status: "trusted" | "untrusted" | "stale";
  reasons: string[];
  claims: PostureClaimsSummary;
  observed_at: string;
}

interface ListSessionsBody {
  items: PostureSessionView[];
}

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
  const limitParam = Number.parseInt(url.searchParams.get("limit") ?? "", 10);
  const limit = Number.isFinite(limitParam) && limitParam > 0
    ? Math.min(limitParam, MAX_LIMIT)
    : DEFAULT_LIMIT;

  try {
    const data = await apiGet<ListSessionsBody>(
      `/v1/device-trust/sessions?limit=${limit}`,
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
