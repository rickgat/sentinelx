import { NextResponse, type NextRequest } from "next/server";

import { apiPostPublic, ApiError } from "@/lib/api-client";

/**
 * Public proxy for `POST /v1/auth/verify-email`.
 *
 * Accepts `{ token: string }` and forwards it verbatim to the backend.
 */

interface VerifyBody {
  token?: unknown;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "invalid JSON body" } },
      { status: 400 },
    );
  }

  const body = (raw ?? {}) as VerifyBody;
  if (typeof body.token !== "string" || body.token.trim().length === 0) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "token is required" } },
      { status: 400 },
    );
  }

  try {
    const data = await apiPostPublic<unknown>("/v1/auth/verify-email", {
      token: body.token.trim(),
    });
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
