import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/soc/alerts`.
 *
 * Backs the live SOC alert feed on `/dashboard/soc`. The dashboard polls
 * this route every 30 s so the bearer token never leaves the server.
 *
 * Upstream wire shape (per `crates/sx-api/src/view/soc_view.rs`):
 *
 * ```json
 * {
 *   "data": {
 *     "items": [
 *       {
 *         "id": "uuid",
 *         "severity": "high",
 *         "kind": "auth.bruteforce",
 *         "title": "5 failed logins",
 *         "fired_at": "2026-05-30T12:00:00Z",
 *         "tenant_id": "tenant-7" | null
 *       }
 *     ]
 *   }
 * }
 * ```
 */

interface SocAlertView {
  id: string;
  severity: string;
  kind: string;
  title: string;
  fired_at: string;
  tenant_id: string | null;
}

interface ListSocAlertsResponse {
  items: SocAlertView[];
}

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  try {
    const data = await apiGet<ListSocAlertsResponse>(
      "/v1/soc/alerts",
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
