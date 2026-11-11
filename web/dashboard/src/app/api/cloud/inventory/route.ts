import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/cloud/inventory`.
 *
 * Forwards `provider` and `region` query parameters. Provider is
 * constrained to the three connectors the backend currently recognises
 * so a typo never burns an upstream round-trip.
 */

const ALLOWED_PROVIDERS: ReadonlyArray<string> = ["aws", "gcp", "azure"];

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const url = new URL(req.url);
  const provider = (url.searchParams.get("provider") ?? "").trim();
  const region = (url.searchParams.get("region") ?? "").trim();

  if (!ALLOWED_PROVIDERS.includes(provider)) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "provider must be one of aws, gcp, azure",
        },
      },
      { status: 400 },
    );
  }

  const params = new URLSearchParams({ provider });
  if (region.length > 0) {
    params.set("region", region);
  }

  try {
    const data = await apiGet<unknown>(
      `/v1/cloud/inventory?${params.toString()}`,
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
