import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Proxy for `POST /v1/logs/ingest`.
 *
 * Forwards a single `{ source, payload }` body to the backend's OCSF
 * ingest endpoint. The bearer token never leaves the server. The body is
 * validated and capped before the upstream call so a hostile client
 * cannot push oversized payloads through the dashboard.
 */

interface IngestLogResponse {
  accepted: number;
}

interface IngestBody {
  source?: unknown;
  payload?: unknown;
}

const MAX_PAYLOAD_BYTES = 16 * 1024;
const MAX_SOURCE_LEN = 64;

function parseBody(input: unknown): { source: string; payload: string } | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as IngestBody;
  if (typeof body.source !== "string" || body.source.trim().length === 0) {
    return null;
  }
  if (body.source.length > MAX_SOURCE_LEN) {
    return null;
  }
  if (typeof body.payload !== "string" || body.payload.length === 0) {
    return null;
  }
  if (body.payload.length > MAX_PAYLOAD_BYTES) {
    return null;
  }
  return { source: body.source.trim(), payload: body.payload };
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
      {
        error: {
          code: "BAD_REQUEST",
          message: "source (1..64 chars) and payload (1..16384 bytes) are required",
        },
      },
      { status: 400 },
    );
  }

  try {
    const data = await apiPost<IngestLogResponse>(
      "/v1/logs/ingest",
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
