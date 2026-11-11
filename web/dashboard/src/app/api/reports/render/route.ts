import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Proxy for `POST /v1/reports/render`.
 *
 * Body forwarded to sx-api:
 *   { tenant_id, engagement_id, format }
 *
 * `tenant_id` is taken from the authenticated session — clients cannot
 * supply it directly.
 *
 * Backend formats:
 *   executive_pdf | technical_pdf | sarif | stix | csv
 *
 * Backend response:
 *   { filename, mime_type, byte_count, inline_payload? }
 *
 * For text formats (sarif/stix/csv) `inline_payload` is base64-encoded.
 * For PDF formats the binary is fetched by the dashboard separately
 * (current monolith returns base64 for those too).
 */

const ALLOWED_FORMATS: ReadonlyArray<string> = [
  "executive_pdf",
  "technical_pdf",
  "sarif",
  "stix",
  "csv",
];

interface RenderBody {
  engagement_id?: unknown;
  format?: unknown;
}

interface ParsedBody {
  engagement_id: string;
  format: string;
}

function parseBody(input: unknown): ParsedBody | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as RenderBody;
  if (typeof body.engagement_id !== "string" || body.engagement_id.trim().length === 0) {
    return null;
  }
  if (typeof body.format !== "string" || !ALLOWED_FORMATS.includes(body.format)) {
    return null;
  }
  return {
    engagement_id: body.engagement_id.trim(),
    format: body.format,
  };
}

interface RenderResponse {
  filename?: string;
  mime_type?: string;
  byte_count?: number;
  inline_payload?: string;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const tenantId = session.user?.tenantId;
  if (typeof tenantId !== "string" || tenantId.length === 0) {
    return NextResponse.json(
      { error: { code: "TENANT_MISSING", message: "session has no tenant" } },
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

  const parsed = parseBody(raw);
  if (parsed === null) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message:
            "engagement_id and format (executive_pdf|technical_pdf|sarif|stix|csv) are required",
        },
      },
      { status: 400 },
    );
  }

  const upstream = {
    tenant_id: tenantId,
    engagement_id: parsed.engagement_id,
    format: parsed.format,
  };

  try {
    const data = await apiPost<RenderResponse>(
      "/v1/reports/render",
      upstream,
      session.accessToken,
    );
    return NextResponse.json({
      data,
      meta: { format: parsed.format, engagement_id: parsed.engagement_id },
    });
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
