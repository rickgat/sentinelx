import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxies for the sx-api device-trust policy endpoints (P2-008):
 *
 *   GET /v1/device-trust/policy
 *   PUT /v1/device-trust/policy   (requires admin:users)
 *
 * Both routes return the standard `{ data }` / `{ error }` envelope. PUT
 * forwards the validated body verbatim — the backend rejects any extra
 * fields with a 422.
 */

export interface PosturePolicyView {
  os_allow_list: string[];
  os_block_list: string[];
  minimum_os_versions: Record<string, string>;
  edr_vendor_allow_list: string[];
  max_screen_lock_minutes: number | null;
  rules: ReadonlyArray<
    | "require_disk_encryption"
    | "require_edr"
    | "require_screen_lock"
  >;
}

function unauthorized(): NextResponse {
  return NextResponse.json(
    { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
    { status: 401 },
  );
}

function envelopeError(err: unknown): NextResponse {
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

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) return unauthorized();
  try {
    const data = await apiGet<PosturePolicyView>(
      "/v1/device-trust/policy",
      session.accessToken,
    );
    return NextResponse.json({ data });
  } catch (err) {
    return envelopeError(err);
  }
}

export async function PUT(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) return unauthorized();

  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "invalid JSON body" } },
      { status: 400 },
    );
  }

  // Forward verbatim — sx-api re-validates the shape via `validator`.
  const apiBase = process.env.NEXT_PUBLIC_SX_API_URL?.replace(/\/$/, "") ?? "";
  try {
    const res = await fetch(`${apiBase}/v1/device-trust/policy`, {
      method: "PUT",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${session.accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(raw),
      cache: "no-store",
    });
    const text = await res.text();
    let body: { data?: PosturePolicyView; error?: { code?: string; message?: string; request_id?: string } } = {};
    if (text.length > 0) {
      try {
        body = JSON.parse(text);
      } catch {
        body = {};
      }
    }
    if (!res.ok) {
      return NextResponse.json(
        {
          error: {
            code: body.error?.code ?? "UPSTREAM_ERROR",
            message: body.error?.message ?? `Upstream returned ${res.status}`,
            request_id: body.error?.request_id ?? "",
          },
        },
        { status: res.status },
      );
    }
    return NextResponse.json({ data: body.data });
  } catch {
    return NextResponse.json(
      { error: { code: "UPSTREAM_ERROR", message: "Upstream request failed" } },
      { status: 502 },
    );
  }
}
