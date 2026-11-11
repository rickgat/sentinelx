import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Proxy for `POST /v1/redteam/chain`.
 *
 * The backend composes an AI-orchestrated kill-chain for a given
 * engagement, returning an ordered sequence of MITRE ATT&CK steps with
 * per-step confidence and an aggregate chain score.
 *
 * Only cheap structural checks happen here so the upstream validator
 * remains the single source of truth for chain-composition rules.
 */

const MIN_STEPS = 1;
const MAX_STEPS = 14;
const DEFAULT_STEPS = 8;

interface ChainBody {
  engagement_id?: unknown;
  max_steps?: unknown;
}

interface ParsedBody {
  engagement_id: string;
  max_steps: number;
}

function parseBody(input: unknown): ParsedBody | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as ChainBody;
  if (typeof body.engagement_id !== "string" || body.engagement_id.trim().length === 0) {
    return null;
  }
  let maxSteps = DEFAULT_STEPS;
  if (typeof body.max_steps === "number" && Number.isFinite(body.max_steps)) {
    maxSteps = Math.floor(body.max_steps);
  }
  if (maxSteps < MIN_STEPS) {
    maxSteps = MIN_STEPS;
  }
  if (maxSteps > MAX_STEPS) {
    maxSteps = MAX_STEPS;
  }
  return {
    engagement_id: body.engagement_id.trim(),
    max_steps: maxSteps,
  };
}

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

  const parsed = parseBody(raw);
  if (parsed === null) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "engagement_id is required; max_steps must be between 1 and 14",
        },
      },
      { status: 400 },
    );
  }

  try {
    const data = await apiPost<unknown>(
      "/v1/redteam/chain",
      parsed,
      session.accessToken,
    );
    return NextResponse.json({ data, meta: { max_steps: parsed.max_steps } });
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
