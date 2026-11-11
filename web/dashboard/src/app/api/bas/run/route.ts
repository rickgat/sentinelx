import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Proxy for `POST /v1/bas/run`.
 *
 * The backend enforces:
 *   - the `bas:run` permission on the bearer token,
 *   - a canonical attack-mode (`theoretical`, `passive_validation`,
 *     `safe_interactive`, `active_exploit`, `red_team`),
 *   - non-empty `technique_id` and `target`.
 *
 * We mirror only the cheap structural checks here so a malformed form
 * never burns an upstream round-trip; everything load-bearing is owned
 * by sx-api's validator.
 */

const ALLOWED_MODES: ReadonlyArray<string> = [
  "theoretical",
  "passive_validation",
  "safe_interactive",
  "active_exploit",
  "red_team",
];

interface BasRunBody {
  technique_id?: unknown;
  target?: unknown;
  mode?: unknown;
  dry_run?: unknown;
}

interface ParsedBody {
  technique_id: string;
  target: string;
  mode: string;
  dry_run: boolean;
}

function parseBody(input: unknown): ParsedBody | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as BasRunBody;
  if (typeof body.technique_id !== "string" || body.technique_id.trim().length === 0) {
    return null;
  }
  if (typeof body.target !== "string" || body.target.trim().length === 0) {
    return null;
  }
  if (typeof body.mode !== "string" || !ALLOWED_MODES.includes(body.mode)) {
    return null;
  }
  const dryRun = typeof body.dry_run === "boolean" ? body.dry_run : true;
  return {
    technique_id: body.technique_id.trim(),
    target: body.target.trim(),
    mode: body.mode,
    dry_run: dryRun,
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
          message:
            "technique_id, target, and a valid mode are required",
        },
      },
      { status: 400 },
    );
  }

  try {
    const data = await apiPost<unknown>(
      "/v1/bas/run",
      parsed,
      session.accessToken,
    );
    return NextResponse.json({ data, meta: { mode: parsed.mode, dry_run: parsed.dry_run } });
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
