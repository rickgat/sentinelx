import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { publicEnv } from "@/lib/env";

interface ExecBody {
  method?: unknown;
  url?: unknown;
  headers?: unknown;
  body?: unknown;
  use_session_token?: unknown;
}

const ALLOWED_METHODS = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
]);

const TIMEOUT_MS = 30_000;
const MAX_BODY_LEN = 1_000_000;

function parseBody(raw: unknown): {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | undefined;
  use_session_token: boolean;
} | null {
  if (raw === null || typeof raw !== "object") return null;
  const r = raw as ExecBody;
  if (typeof r.method !== "string") return null;
  const method = r.method.toUpperCase();
  if (!ALLOWED_METHODS.has(method)) return null;
  if (typeof r.url !== "string" || r.url.length === 0) return null;
  let parsed: URL;
  try {
    parsed = new URL(r.url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  const headers: Record<string, string> = {};
  if (r.headers !== undefined) {
    if (typeof r.headers !== "object" || r.headers === null) return null;
    for (const [k, v] of Object.entries(r.headers as Record<string, unknown>)) {
      if (typeof v !== "string") return null;
      if (k.length === 0 || k.length > 256) return null;
      headers[k] = v;
    }
  }
  const body =
    typeof r.body === "string" && r.body.length > 0 ? r.body : undefined;
  if (body !== undefined && body.length > MAX_BODY_LEN) return null;
  const use_session_token = r.use_session_token === true;
  return { method, url: r.url, headers, body, use_session_token };
}

export async function POST(req: NextRequest): Promise<NextResponse> {
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
            "expected { method, url, headers?, body?, use_session_token? }",
        },
      },
      { status: 400 },
    );
  }

  // When the user opts in, inject the dashboard session's bearer token. This
  // is the convenience path for testing sx-api endpoints without copying the
  // token out by hand. The proxy never returns the token back to the client.
  const finalHeaders: Record<string, string> = { ...parsed.headers };
  if (parsed.use_session_token) {
    const session = await auth();
    if (session?.accessToken !== undefined) {
      finalHeaders["Authorization"] = `Bearer ${session.accessToken}`;
    }
  }
  if (parsed.body !== undefined && finalHeaders["Content-Type"] === undefined) {
    finalHeaders["Content-Type"] = "application/json";
  }

  const startedAt = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let upstream: Response;
  try {
    const init: RequestInit = {
      method: parsed.method,
      headers: finalHeaders,
      redirect: "manual",
      signal: controller.signal,
      cache: "no-store",
    };
    if (
      parsed.method !== "GET" &&
      parsed.method !== "HEAD" &&
      parsed.body !== undefined
    ) {
      init.body = parsed.body;
    }
    upstream = await fetch(parsed.url, init);
  } catch (err) {
    clearTimeout(timer);
    const msg = err instanceof Error ? err.message : "fetch failed";
    return NextResponse.json(
      {
        error: { code: "UPSTREAM_ERROR", message: msg },
        elapsed_ms: Date.now() - startedAt,
      },
      { status: 502 },
    );
  }
  clearTimeout(timer);

  const respHeaders: Record<string, string> = {};
  upstream.headers.forEach((value, key) => {
    respHeaders[key] = value;
  });
  const bodyText = await upstream.text();
  return NextResponse.json({
    data: {
      status: upstream.status,
      status_text: upstream.statusText,
      headers: respHeaders,
      body: bodyText.length > MAX_BODY_LEN ? bodyText.slice(0, MAX_BODY_LEN) : bodyText,
      truncated: bodyText.length > MAX_BODY_LEN,
      elapsed_ms: Date.now() - startedAt,
    },
    meta: { sx_api_base: publicEnv.NEXT_PUBLIC_SX_API_URL },
  });
}
