import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Proxy for `POST /v1/cloud/blast-radius`.
 *
 * Forwards `{ seed_asset_id, max_depth }` to sx-api with the session
 * bearer so the token never reaches the browser. Strictly validates the
 * body before the upstream round-trip — `max_depth` is bounded to
 * `1..=5` matching `BlastRadiusRequestView::validate` server-side.
 *
 * Backend semantics:
 *   - 200: `{ data: BlastRadiusResponse }`
 *   - 401: session expired; client redirects to /login.
 *   - 422: invalid seed / tenant boundary violation.
 *   - 404: seed asset not in graph.
 */

interface BlastBody {
  seed_asset_id?: unknown;
  max_depth?: unknown;
}

interface ImpactedAsset {
  asset_id: string;
  name: string;
  depth: number;
  edge_kind: string;
  criticality: string;
  impact_score: number;
}

interface BlastRadiusResponse {
  seed_asset_id: string;
  max_depth: number;
  decay_base: number;
  impacted: ImpactedAsset[];
  total_score: number;
  cached: boolean;
}

const MAX_DEPTH = 5;
const MIN_DEPTH = 1;
const MAX_SEED_LEN = 512;

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
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

  const body = (raw ?? {}) as BlastBody;
  if (typeof body.seed_asset_id !== "string") {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "seed_asset_id must be a string" } },
      { status: 400 },
    );
  }
  const seed = body.seed_asset_id.trim();
  if (seed.length === 0 || seed.length > MAX_SEED_LEN) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: `seed_asset_id length must be 1..=${MAX_SEED_LEN}`,
        },
      },
      { status: 400 },
    );
  }
  if (typeof body.max_depth !== "number" || !Number.isInteger(body.max_depth)) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "max_depth must be an integer" } },
      { status: 400 },
    );
  }
  if (body.max_depth < MIN_DEPTH || body.max_depth > MAX_DEPTH) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: `max_depth must be in [${MIN_DEPTH}, ${MAX_DEPTH}]`,
        },
      },
      { status: 400 },
    );
  }

  try {
    const data = await apiPost<BlastRadiusResponse>(
      "/v1/cloud/blast-radius",
      { seed_asset_id: seed, max_depth: body.max_depth },
      session.accessToken,
    );
    return NextResponse.json({ data });
  } catch (err) {
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
}
