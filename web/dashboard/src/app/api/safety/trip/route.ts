import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

interface TripBody {
  reason?: unknown;
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
  const body = (raw ?? {}) as TripBody;
  if (typeof body.reason !== "string" || body.reason.trim().length < 4) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "reason must be at least 4 characters" } },
      { status: 400 },
    );
  }

  const actor = session.user.email ?? session.user.id ?? "unknown";

  try {
    const data = await apiPost<unknown>(
      "/v1/safety/kill-switch",
      { actor, reason: body.reason.trim() },
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
