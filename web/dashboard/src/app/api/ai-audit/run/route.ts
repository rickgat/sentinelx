import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { apiPost, ApiError } from "@/lib/api-client";

/**
 * Browser proxy for `POST /v1/ai-audit/run` (AI-SEC-001).
 *
 * Forwards the caller's session bearer token to sx-api and returns the full
 * AI audit report under the standard `{ data }` envelope. The run is gated
 * server-side by the `ai-audit:run` permission and recorded in the
 * copilot-decision audit trail.
 */

interface AiAuditReportView {
  assets: unknown[];
  aibom: unknown;
  probe_results: unknown[];
  modelfile_findings: unknown[];
  control_evidence: unknown[];
}

export async function POST(): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  try {
    const data = await apiPost<AiAuditReportView>(
      "/v1/ai-audit/run",
      {},
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
