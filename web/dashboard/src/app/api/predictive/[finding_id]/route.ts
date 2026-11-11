import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Proxy for `POST /v1/ml/predict/finding`.
 *
 * The dashboard's `<PredictivePanel>` calls `GET /api/predictive/<finding_id>`
 * — we accept that GET, forward the `finding_id` as the POST body to the
 * backend, and pass the response envelope through unchanged.
 *
 * Wire shape (per `crates/sx-api/src/view/predictive_view.rs`):
 *
 * ```json
 * {
 *   "data": {
 *     "probability": 0.42,
 *     "confidence": 0.16,
 *     "risk_band": "medium"
 *   }
 * }
 * ```
 *
 * `risk_band` is one of `low | medium | high | critical`.
 */

interface PredictResponse {
  probability: number;
  confidence: number;
  risk_band: string;
}

interface RouteContext {
  params: Promise<{ finding_id: string }>;
}

export async function GET(
  _req: Request,
  ctx: RouteContext,
): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const params = await ctx.params;
  const findingId = params.finding_id.trim();
  if (findingId.length === 0) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "finding_id is required" } },
      { status: 400 },
    );
  }

  try {
    const data = await apiPost<PredictResponse>(
      "/v1/ml/predict/finding",
      { finding_id: findingId },
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
