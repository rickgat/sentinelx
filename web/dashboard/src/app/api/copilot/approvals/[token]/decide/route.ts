import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Proxy for `POST /v1/copilot/approvals/{token}/decide` (P1-012).
 *
 * Forwards the reviewer's decision (approve / reject) to sx-api with
 * the session bearer; the access token never reaches the browser.
 *
 * Backend semantics:
 *   - 200: `{ data: DecisionOutcomeView }`
 *   - 422: malformed token, missing reason on reject, or already
 *          decided / expired token.
 *   - 401: session expired; client redirects to /login.
 *   - 403: caller lacks `copilot:review` permission.
 */

interface DecideBody {
  decision?: unknown;
  reason?: unknown;
}

interface DecisionOutcomeView {
  token: string;
  status: string;
  reviewer: string;
  reason?: string;
  decided_at: string;
}

const MAX_REASON_CHARS = 1024;

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ token: string }> },
): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const { token } = await params;
  if (typeof token !== "string" || token.length === 0) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "missing token" } },
      { status: 400 },
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

  const body = (raw ?? {}) as DecideBody;
  const decision = typeof body.decision === "string" ? body.decision : "";
  if (decision !== "approve" && decision !== "reject") {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: 'decision must be "approve" or "reject"',
        },
      },
      { status: 400 },
    );
  }

  let reason: string | undefined;
  if (typeof body.reason === "string") {
    const trimmed = body.reason.trim();
    if (trimmed.length > 0) {
      if (trimmed.length > MAX_REASON_CHARS) {
        return NextResponse.json(
          {
            error: {
              code: "BAD_REQUEST",
              message: `reason must be at most ${MAX_REASON_CHARS} characters`,
            },
          },
          { status: 400 },
        );
      }
      reason = trimmed;
    }
  }
  if (decision === "reject" && reason === undefined) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "reason is required when rejecting",
        },
      },
      { status: 400 },
    );
  }

  try {
    const payload: { decision: string; reason?: string } = { decision };
    if (reason !== undefined) {
      payload.reason = reason;
    }
    const data = await apiPost<DecisionOutcomeView>(
      `/v1/copilot/approvals/${encodeURIComponent(token)}/decide`,
      payload,
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
