import { NextResponse, type NextRequest } from "next/server";

import { apiPostPublic, ApiError } from "@/lib/api-client";

/**
 * Public proxy for `POST /v1/auth/forgot-password`.
 *
 * The backend deliberately returns the same response whether or not the
 * account exists, so this route does not leak existence either. We still
 * surface upstream errors (e.g. 502) so the UI can decide what to render;
 * the page itself always shows a generic message.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;

interface ForgotBody {
  tenant_id?: unknown;
  email?: unknown;
}

interface ParsedBody {
  tenant_id: string;
  email: string;
}

function parseBody(input: unknown): ParsedBody | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as ForgotBody;
  if (typeof body.tenant_id !== "string" || body.tenant_id.trim().length === 0) {
    return null;
  }
  if (typeof body.email !== "string" || !EMAIL_RE.test(body.email)) {
    return null;
  }
  return {
    tenant_id: body.tenant_id.trim(),
    email: body.email.trim().toLowerCase(),
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
      { error: { code: "BAD_REQUEST", message: "tenant_id and email are required" } },
      { status: 400 },
    );
  }

  try {
    const data = await apiPostPublic<unknown>("/v1/auth/forgot-password", parsed);
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
