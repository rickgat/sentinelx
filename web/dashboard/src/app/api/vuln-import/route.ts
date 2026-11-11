import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { publicEnv } from "@/lib/env";

/**
 * Proxy for `POST /v1/vuln/import`.
 *
 * Forwards the browser's `multipart/form-data` payload (Nessus / OpenVAS
 * XML + `source` part) to sx-api with the caller's bearer token attached.
 * The 100 MiB ceiling is enforced server-side; we only sanity-check the
 * declared Content-Length here so a wildly oversized upload short-circuits
 * before we tie up the upstream socket.
 */

const MAX_PAYLOAD_BYTES = 100 * 1024 * 1024;

interface UpstreamEnvelope {
  data?: unknown;
  error?: { code?: string; message?: string; request_id?: string };
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("multipart/form-data")) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "Content-Type must be multipart/form-data",
        },
      },
      { status: 400 },
    );
  }

  const declaredLen = Number.parseInt(
    req.headers.get("content-length") ?? "",
    10,
  );
  if (Number.isFinite(declaredLen) && declaredLen > MAX_PAYLOAD_BYTES) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "payload exceeds 100 MiB limit",
        },
      },
      { status: 413 },
    );
  }

  // Buffer the body into a Blob so we can forward it with a known length.
  // The dashboard rarely uploads near the 100 MiB ceiling and Next.js's
  // body-size limit guards against runaway buffering at the framework level.
  const body = await req.arrayBuffer();
  if (body.byteLength > MAX_PAYLOAD_BYTES) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "payload exceeds 100 MiB limit",
        },
      },
      { status: 413 },
    );
  }

  const baseUrl = publicEnv.NEXT_PUBLIC_SX_API_URL.replace(/\/$/, "");

  try {
    const upstream = await fetch(`${baseUrl}/v1/vuln/import`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        "Content-Type": contentType,
        Accept: "application/json",
      },
      body,
      cache: "no-store",
    });
    const text = await upstream.text();
    let parsed: UpstreamEnvelope = {};
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text) as UpstreamEnvelope;
      } catch {
        parsed = {};
      }
    }
    if (!upstream.ok) {
      return NextResponse.json(
        {
          error: {
            code: parsed.error?.code ?? "UPSTREAM_ERROR",
            message: parsed.error?.message ?? `Upstream ${upstream.status}`,
            request_id: parsed.error?.request_id ?? "",
          },
        },
        { status: upstream.status },
      );
    }
    return NextResponse.json({ data: parsed.data });
  } catch {
    return NextResponse.json(
      { error: { code: "UPSTREAM_ERROR", message: "Upstream request failed" } },
      { status: 502 },
    );
  }
}
