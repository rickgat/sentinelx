import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, apiPut, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/rba/config` and `PUT /v1/rba/config`.
 *
 * The `PUT` path requires the `admin:users` permission server-side
 * (enforced by sx-api). Operators without that permission will see
 * a `403 Forbidden` returned verbatim from upstream.
 */

interface RbaWeightsView {
  w_ip_geo: number;
  w_velocity: number;
  w_business_hours: number;
  w_device_fp: number;
  w_mfa_recent: number;
  w_success_rate: number;
  w_impossible_travel: number;
}

interface RbaFeatureFlagsView {
  enable_ip_geo: boolean;
  enable_velocity: boolean;
  enable_business_hours: boolean;
  enable_device_fp: boolean;
  enable_mfa_recent: boolean;
  enable_success_rate: boolean;
  enable_impossible_travel: boolean;
}

interface RbaConfigView {
  allow_threshold: number;
  block_threshold: number;
  weights: RbaWeightsView;
  feature_flags: RbaFeatureFlagsView;
  business_tz: string;
  business_hours_start: number;
  business_hours_end: number;
}

function unauthorizedJson(): NextResponse {
  return NextResponse.json(
    { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
    { status: 401 },
  );
}

function upstreamJson(err: unknown): NextResponse {
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
    return unauthorizedJson();
  }
  try {
    const data = await apiGet<RbaConfigView>(
      "/v1/rba/config",
      session.accessToken,
    );
    return NextResponse.json({ data });
  } catch (err) {
    return upstreamJson(err);
  }
}

export async function PUT(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return unauthorizedJson();
  }
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: { code: "INVALID_BODY", message: "request body is not JSON" } },
      { status: 400 },
    );
  }
  try {
    const data = await apiPut<RbaConfigView>(
      "/v1/rba/config",
      body,
      session.accessToken,
    );
    return NextResponse.json({ data });
  } catch (err) {
    return upstreamJson(err);
  }
}
