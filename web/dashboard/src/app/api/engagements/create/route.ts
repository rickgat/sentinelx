import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";
import type { Engagement } from "@/lib/types";

interface CreateBody {
  name?: unknown;
  description?: unknown;
  scopes?: unknown;
}

function parseBody(input: unknown): { name: string; description?: string; scopes: string[] } | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as CreateBody;
  if (typeof body.name !== "string" || body.name.trim().length === 0) {
    return null;
  }
  if (!Array.isArray(body.scopes)) {
    return null;
  }
  const scopes: string[] = [];
  for (const s of body.scopes) {
    if (typeof s !== "string") {
      return null;
    }
    const trimmed = s.trim();
    if (trimmed.length > 0) {
      scopes.push(trimmed);
    }
  }
  const result: { name: string; description?: string; scopes: string[] } = {
    name: body.name.trim(),
    scopes,
  };
  if (typeof body.description === "string" && body.description.trim().length > 0) {
    result.description = body.description.trim();
  }
  return result;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json({ error: { code: "UNAUTHORIZED", message: "unauthorized" } }, { status: 401 });
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
      { error: { code: "BAD_REQUEST", message: "name and scopes[] are required" } },
      { status: 400 },
    );
  }

  try {
    const data = await apiPost<Engagement>("/v1/engagements", parsed, session.accessToken);
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
