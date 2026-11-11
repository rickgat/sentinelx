import { NextResponse, type NextRequest } from "next/server";

import { apiPostPublic, ApiError } from "@/lib/api-client";

/**
 * Public proxy for `POST /v1/auth/signup`.
 *
 * The dashboard enforces:
 *   - tenant_id is a non-empty string,
 *   - email is RFC-shaped,
 *   - password is >= 12 chars (matches the operator UI floor).
 *
 * The password is intentionally never logged.
 */

const PASSWORD_MIN = 12;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;

interface SignupBody {
  tenant_id?: unknown;
  email?: unknown;
  password?: unknown;
}

interface ParsedBody {
  tenant_id: string;
  email: string;
  password: string;
}

function parseBody(input: unknown): ParsedBody | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as SignupBody;
  if (typeof body.tenant_id !== "string" || body.tenant_id.trim().length === 0) {
    return null;
  }
  if (typeof body.email !== "string" || !EMAIL_RE.test(body.email)) {
    return null;
  }
  if (typeof body.password !== "string" || body.password.length < PASSWORD_MIN) {
    return null;
  }
  return {
    tenant_id: body.tenant_id.trim(),
    email: body.email.trim().toLowerCase(),
    password: body.password,
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
          message: "tenant_id, email and password (>= 12 chars) are required",
        },
      },
      { status: 400 },
    );
  }

  try {
    const data = await apiPostPublic<unknown>("/v1/auth/signup", parsed);
    return NextResponse.json({ data, meta: { email: parsed.email } });
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
