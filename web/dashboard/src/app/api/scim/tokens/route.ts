import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiDelete, apiGet, apiPost, ApiError } from "@/lib/api-client";

/**
 * Dashboard proxy for the SCIM 2.0 admin-token surface.
 *
 *   GET    /api/scim/tokens          -> GET    /v1/admin/scim/tokens
 *   POST   /api/scim/tokens          -> POST   /v1/admin/scim/tokens
 *   DELETE /api/scim/tokens?id=...   -> DELETE /v1/admin/scim/tokens/:id
 *
 * The bearer JWT lives in the dashboard's HTTP-only session cookie; it
 * is forwarded to sx-api server-side and never reaches the browser.
 */

interface ScimTokenView {
  id: string;
  tenant_id: string;
  name: string;
  created_at: string;
  last_used_at?: string;
}

interface CreateScimTokenResponse {
  token: ScimTokenView;
  plaintext: string;
}

interface CreateBody {
  name?: unknown;
}

const NAME_MAX = 128;

function unauthorized(): NextResponse {
  return NextResponse.json(
    { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
    { status: 401 },
  );
}

function badRequest(message: string): NextResponse {
  return NextResponse.json(
    { error: { code: "BAD_REQUEST", message } },
    { status: 400 },
  );
}

function fromApiError(err: unknown): NextResponse {
  if (err instanceof ApiError) {
    return NextResponse.json(
      {
        error: {
          code: err.code,
          message: err.message,
          request_id: err.requestId,
        },
      },
      { status: err.status },
    );
  }
  return NextResponse.json(
    { error: { code: "UPSTREAM_ERROR", message: "Upstream request failed" } },
    { status: 502 },
  );
}

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return unauthorized();
  }
  try {
    const data = await apiGet<ReadonlyArray<ScimTokenView>>(
      "/v1/admin/scim/tokens",
      session.accessToken,
    );
    return NextResponse.json({ data });
  } catch (err) {
    return fromApiError(err);
  }
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return unauthorized();
  }
  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    return badRequest("invalid JSON body");
  }
  if (raw === null || typeof raw !== "object") {
    return badRequest("body must be an object");
  }
  const body = raw as CreateBody;
  if (typeof body.name !== "string") {
    return badRequest("name is required");
  }
  const trimmed = body.name.trim();
  if (trimmed.length === 0 || trimmed.length > NAME_MAX) {
    return badRequest(`name must be 1-${NAME_MAX} characters`);
  }

  try {
    const data = await apiPost<CreateScimTokenResponse>(
      "/v1/admin/scim/tokens",
      { name: trimmed },
      session.accessToken,
    );
    return NextResponse.json({ data });
  } catch (err) {
    return fromApiError(err);
  }
}

export async function DELETE(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return unauthorized();
  }
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  if (id === null || id.trim().length === 0) {
    return badRequest("id query param is required");
  }
  try {
    await apiDelete(
      `/v1/admin/scim/tokens/${encodeURIComponent(id)}`,
      session.accessToken,
    );
    return new NextResponse(null, { status: 204 });
  } catch (err) {
    return fromApiError(err);
  }
}
