import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/rba/decisions?limit=N`.
 *
 * Returns the most recent RBA decisions for the caller's tenant,
 * newest-first. The bearer token is read from the active Auth.js
 * session and never leaks to the browser; the response is the standard
 * `{ data: { decisions: [...] } }` envelope.
 */

interface Decision {
  id: string;
  tenant_id: string;
  user_id?: string;
  ip: string;
  score: number;
  action: string;
  reason: string;
  decided_at: string;
}

interface ListBody {
  decisions: Decision[];
}

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const url = new URL(req.url);
  const limitParam = Number.parseInt(url.searchParams.get("limit") ?? "", 10);
  const limit =
    Number.isFinite(limitParam) && limitParam > 0
      ? Math.min(limitParam, MAX_LIMIT)
      : DEFAULT_LIMIT;

  try {
    const data = await apiGet<ListBody>(
      `/v1/rba/decisions?limit=${limit.toString()}`,
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
