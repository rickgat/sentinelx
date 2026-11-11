import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Proxy for `POST /v1/copilot/chat`.
 *
 * Forwards a single-turn prompt to sx-api with the session bearer so the
 * token never reaches the browser. The prompt body is **never** logged
 * by this route — only the request id surfaced by the backend envelope
 * is bubbled back to the caller.
 *
 * Backend semantics:
 *   - 200: `{ data: { reply, model } }`
 *   - 422 UNPROCESSABLE_ENTITY: copilot disabled / credential-shaped
 *         prompt / config error. Surfaced verbatim so the client can
 *         render the upstream message inline.
 *   - 401: session expired; client redirects to /login.
 *   - 403: caller lacks `copilot:use` permission.
 */

interface ChatBody {
  prompt?: unknown;
}

interface ChatReply {
  reply: string;
  model: string;
}

const MAX_PROMPT_CHARS = 4000;

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

  const body = (raw ?? {}) as ChatBody;
  if (typeof body.prompt !== "string") {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "prompt must be a string" } },
      { status: 400 },
    );
  }
  const prompt = body.prompt.trim();
  if (prompt.length === 0) {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "prompt must not be empty" } },
      { status: 400 },
    );
  }
  if (prompt.length > MAX_PROMPT_CHARS) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: `prompt must be at most ${MAX_PROMPT_CHARS} characters`,
        },
      },
      { status: 400 },
    );
  }

  try {
    // NOTE: never log the `prompt` value — only its length, if at all.
    const data = await apiPost<ChatReply>(
      "/v1/copilot/chat",
      { prompt },
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
