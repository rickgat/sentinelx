import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, apiPut, ApiError } from "@/lib/api-client";

/**
 * Proxy for the per-tenant report branding surface (P2-002 MSSP
 * white-label):
 *   GET  /v1/reports/branding
 *   PUT  /v1/reports/branding
 *
 * The tenant is derived from the authenticated session on the backend
 * (JWT claim); clients never supply it. The logo travels as a base64 PNG.
 */

interface BrandingView {
  logo_png_base64?: string | null;
  primary_color_hex?: string;
  cover_md?: string | null;
  footer_md?: string | null;
}

function unauthorized(): NextResponse {
  return NextResponse.json(
    { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
    { status: 401 },
  );
}

function upstreamError(err: unknown): NextResponse {
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
  if (session?.accessToken === undefined) {
    return unauthorized();
  }
  try {
    const data = await apiGet<BrandingView>("/v1/reports/branding", session.accessToken);
    return NextResponse.json({ data });
  } catch (err) {
    return upstreamError(err);
  }
}

export async function PUT(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return unauthorized();
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

  if (raw === null || typeof raw !== "object") {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "object body required" } },
      { status: 400 },
    );
  }
  const body = raw as BrandingView;
  const color = typeof body.primary_color_hex === "string" ? body.primary_color_hex : "";
  if (!/^#[0-9a-fA-F]{6}$/.test(color)) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "primary_color_hex must be #RRGGBB" } },
      { status: 400 },
    );
  }

  const upstream = {
    primary_color_hex: color,
    logo_png_base64: typeof body.logo_png_base64 === "string" ? body.logo_png_base64 : null,
    cover_md: typeof body.cover_md === "string" ? body.cover_md : null,
    footer_md: typeof body.footer_md === "string" ? body.footer_md : null,
  };

  try {
    const data = await apiPut<BrandingView>(
      "/v1/reports/branding",
      upstream,
      session.accessToken,
    );
    return NextResponse.json({ data });
  } catch (err) {
    return upstreamError(err);
  }
}
