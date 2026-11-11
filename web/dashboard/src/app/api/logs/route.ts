import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/logs?limit=N`.
 *
 * Backs the OCSF log viewer on `/dashboard/logs`. The dashboard polls
 * this route on demand so the bearer token never leaves the server.
 *
 * Upstream wire shape (per `crates/sx-api/src/view/log_ingest_view.rs`):
 *
 * ```json
 * {
 *   "data": {
 *     "items": [
 *       {
 *         "class_uid": 6003,
 *         "category_uid": 6,
 *         "time": "2026-06-12T10:30:01Z",
 *         "severity_id": 3,
 *         "raw": "{...}",
 *         "metadata": {
 *           "version": "1.1.0",
 *           "product": "AWS CloudTrail (us-east-1)",
 *           "source_type": "cloudtrail",
 *           "tenant_id": "uuid"
 *         },
 *         "observables": [
 *           { "name": "src_ip", "type": "ip", "value": "203.0.113.5" }
 *         ]
 *       }
 *     ]
 *   }
 * }
 * ```
 */

interface OcsfMetadataView {
  version: string;
  product: string;
  source_type: string;
  tenant_id: string;
}

interface ObservableView {
  name: string;
  type: string;
  value: string;
}

interface OcsfEventView {
  class_uid: number;
  category_uid: number;
  time: string;
  severity_id: number;
  raw: string;
  metadata: OcsfMetadataView;
  observables: ObservableView[];
}

interface ListLogsResponse {
  items: OcsfEventView[];
}

const MIN_LIMIT = 1;
const MAX_LIMIT = 500;
const DEFAULT_LIMIT = 50;

function parseLimit(raw: string | null): number {
  if (raw === null) {
    return DEFAULT_LIMIT;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_LIMIT;
  }
  if (parsed < MIN_LIMIT) {
    return MIN_LIMIT;
  }
  if (parsed > MAX_LIMIT) {
    return MAX_LIMIT;
  }
  return parsed;
}

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const limit = parseLimit(req.nextUrl.searchParams.get("limit"));

  try {
    const data = await apiGet<ListLogsResponse>(
      `/v1/logs?limit=${limit}`,
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
