import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Attack-graph proxy.
 *
 * The dashboard wants to fetch the graph for a single engagement, but the
 * backend currently exposes the lower-level `POST /v1/graph/attack-paths`
 * endpoint (a tenant-scoped top-k attack-path search). We bridge the two
 * here so the page-side code can stay declarative: hand us an engagement
 * id, get back a graph-shaped payload.
 *
 * The response shape returned to the client is intentionally loose so the
 * client can render whatever the backend currently emits (paths, plus any
 * future nodes/edges fields) without another round-trip.
 */

const DEFAULT_MAX_DEPTH = 5;
const DEFAULT_MAX_PATHS = 50;

interface RouteContext {
  params: Promise<{ engagementId: string }>;
}

export async function GET(
  req: NextRequest,
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
  const engagementId = params.engagementId.trim();
  if (engagementId.length === 0) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "engagementId is required" } },
      { status: 400 },
    );
  }

  const tenantId = session.user.tenantId;
  if (typeof tenantId !== "string" || tenantId.length === 0) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "tenant id missing on session" } },
      { status: 400 },
    );
  }

  const url = new URL(req.url);
  const maxDepth = clampInt(
    url.searchParams.get("max_depth"),
    DEFAULT_MAX_DEPTH,
    1,
    10,
  );
  const maxPaths = clampInt(
    url.searchParams.get("max_paths"),
    DEFAULT_MAX_PATHS,
    1,
    200,
  );

  try {
    const data = await apiPost<unknown>(
      "/v1/graph/attack-paths",
      {
        tenant_id: tenantId,
        max_depth: maxDepth,
        max_paths: maxPaths,
      },
      session.accessToken,
    );
    return NextResponse.json({
      data,
      meta: { engagement_id: engagementId, max_depth: maxDepth, max_paths: maxPaths },
    });
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

function clampInt(raw: string | null, fallback: number, lo: number, hi: number): number {
  if (raw === null) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    return fallback;
  }
  if (parsed < lo) {
    return lo;
  }
  if (parsed > hi) {
    return hi;
  }
  return parsed;
}
