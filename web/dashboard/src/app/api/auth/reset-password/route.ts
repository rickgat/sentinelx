import { NextResponse, type NextRequest } from "next/server";

import { apiPostPublic, ApiError } from "@/lib/api-client";

/**
 * Public proxy for `POST /v1/auth/reset-password`.
 *
 * Accepts `{ token, new_password }`. Mirrors the operator UI 12-char
 * password floor. The password is never logged.
 */

const PASSWORD_MIN = 12;

interface ResetBody {
  token?: unknown;
  new_password?: unknown;
}

interface ParsedBody {
  token: string;
  new_password: string;
}

function parseBody(input: unknown): ParsedBody | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as ResetBody;
  if (typeof body.token !== "string" || body.token.trim().length === 0) {
    return null;
  }
  if (typeof body.new_password !== "string" || body.new_password.length < PASSWORD_MIN) {
    return null;
  }
  return {
    token: body.token.trim(),
    new_password: body.new_password,
  };
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

  const parsed = parseBody(raw);
  if (parsed === null) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "token and new_password (>= 12 chars) are required",
        },
      },
      { status: 400 },
    );
  }

  try {
    const data = await apiPostPublic<unknown>("/v1/auth/reset-password", parsed);
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
