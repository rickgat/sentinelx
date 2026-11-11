import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Dashboard proxy for the SCIM 2.0 user-listing surface.
 *
 *   GET /api/scim/users?count=N&filter=...
 *     -> GET /v1/admin/scim/users?count=N&filter=...
 *
 * The SCIM surface (`/scim/v2/...`) itself authenticates with per-tenant
 * SCIM bearer tokens (held by Okta / AAD / Workspace, not by the human
 * admin). To let the dashboard preview SCIM-provisioned users without
 * minting an admin-side SCIM token, sx-api exposes a JWT-authed mirror
 * at `/v1/admin/scim/users` that resolves the tenant from the operator's
 * claims. This proxy forwards the admin's session JWT to that mirror.
 *
 * The plaintext SCIM token itself is NEVER stored in the dashboard.
 */

interface ListResponseEnvelope {
  totalResults?: number;
  startIndex?: number;
  itemsPerPage?: number;
  Resources?: ReadonlyArray<unknown>;
}

const MAX_COUNT = 200;

function unauthorized(): NextResponse {
  return NextResponse.json(
    { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
    { status: 401 },
  );
}

function fromApiError(err: unknown): NextResponse {
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

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return unauthorized();
  }

  const url = new URL(req.url);
  const countParam = Number.parseInt(url.searchParams.get("count") ?? "", 10);
  const count = Number.isFinite(countParam) && countParam > 0
    ? Math.min(countParam, MAX_COUNT)
    : 25;
  const filter = url.searchParams.get("filter");

  const query = new URLSearchParams();
  query.set("count", String(count));
  if (filter !== null && filter.trim().length > 0) {
    query.set("filter", filter.trim());
  }

  try {
    const data = await apiGet<ListResponseEnvelope>(
      `/v1/admin/scim/users?${query.toString()}`,
      session.accessToken,
    );
    return NextResponse.json({ data });
  } catch (err) {
    return fromApiError(err);
  }
}
