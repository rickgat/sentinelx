import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";
import type { ScanRecord } from "../route";

/**
 * Proxy for `POST /v1/scans/http-headers`. Triggers the passive HTTP-header
 * scanner against `target` and returns the produced `ScanRecord` (also
 * persisted server-side so `GET /v1/scans` will surface it).
 */

interface ScanBody {
  target?: unknown;
  engagement_id?: unknown;
}

interface ParsedBody {
  target: string;
  engagement_id?: string;
}

function parseBody(input: unknown): ParsedBody | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const b = input as ScanBody;
  if (typeof b.target !== "string" || b.target.trim().length === 0) {
    return null;
  }
  const result: ParsedBody = { target: b.target.trim() };
  if (typeof b.engagement_id === "string" && b.engagement_id.trim().length > 0) {
    result.engagement_id = b.engagement_id.trim();
  }
  return result;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "invalid JSON body" } },
      { status: 400 },
    );
  }

  const parsed = parseBody(raw);
  if (parsed === null) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "target is required" } },
      { status: 400 },
    );
  }

  try {
    const data = await apiPost<ScanRecord>(
      "/v1/scans/http-headers",
      parsed,
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
