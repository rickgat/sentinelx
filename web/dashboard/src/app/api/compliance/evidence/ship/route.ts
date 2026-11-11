import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";

/**
 * Stub proxy for `POST /v1/compliance/evidence/ship`.
 *
 * Once the S3 shipper is callable from web, this route will POST the
 * artifact manifest to sx-api which uploads to the tenant evidence bucket
 * with server-side encryption and emits an audit event. For now we return
 * a deterministic success envelope so the UI can be wired end-to-end.
 *
 * Body shape:
 *   { artifact_ids: string[] }   // optional — defaults to "ship all known"
 */

interface ShipBody {
  artifact_ids?: unknown;
}

interface ParsedBody {
  artifact_ids: ReadonlyArray<string>;
}

function parseBody(input: unknown): ParsedBody {
  if (input === null || typeof input !== "object") {
    return { artifact_ids: [] };
  }
  const body = input as ShipBody;
  if (!Array.isArray(body.artifact_ids)) {
    return { artifact_ids: [] };
  }
  const ids: string[] = [];
  for (const item of body.artifact_ids) {
    if (typeof item === "string" && item.length > 0) {
      ids.push(item);
    }
  }
  return { artifact_ids: ids };
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  let raw: unknown = {};
  try {
    raw = await req.json();
  } catch {
    raw = {};
  }
  const parsed = parseBody(raw);

  const shipped = parsed.artifact_ids.length === 0 ? 10 : parsed.artifact_ids.length;
  const ts = Date.now().toString(36);

  return NextResponse.json({
    data: {
      shipped,
      manifest_key: `fake/key.json`,
      bucket: "sentinelx-evidence-stub",
      manifest_uri: `s3://sentinelx-evidence-stub/manifests/${ts}.json`,
      shipped_at: new Date().toISOString(),
    },
    meta: {
      stub: true,
    },
  });
}
