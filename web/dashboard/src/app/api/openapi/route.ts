import { NextResponse } from "next/server";

import { publicEnv } from "@/lib/env";

/**
 * Same-origin proxy for `GET ${SX_API}/openapi.json`.
 *
 * Swagger UI fetches the schema from the dashboard origin via this route
 * to avoid CORS headaches when the API is hosted on a separate origin.
 * The backend route is public (registered on the `public` subrouter in
 * `crates/sx-api/src/router.rs`) so no `Authorization` header is sent.
 *
 * The proxy intentionally returns whatever the upstream returns, with
 * the body re-encoded as JSON. Failure to reach upstream produces a
 * `502 Bad Gateway` envelope rather than letting the client see a raw
 * network error.
 */
export async function GET(): Promise<NextResponse> {
  const base = publicEnv.NEXT_PUBLIC_SX_API_URL.replace(/\/$/, "");
  const url = `${base}/openapi.json`;

  try {
    const upstream = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const text = await upstream.text();
    if (!upstream.ok) {
      return NextResponse.json(
        {
          error: {
            code: "UPSTREAM_ERROR",
            message: `Upstream returned ${upstream.status}`,
          },
        },
        { status: upstream.status },
      );
    }
    // Parse-and-re-emit so a malformed upstream body surfaces here
    // rather than reaching Swagger UI's parser as raw text.
    const json = JSON.parse(text) as unknown;
    return NextResponse.json(json);
  } catch {
    return NextResponse.json(
      {
        error: {
          code: "UPSTREAM_ERROR",
          message: "Failed to reach sx-api for openapi.json",
        },
      },
      { status: 502 },
    );
  }
}
