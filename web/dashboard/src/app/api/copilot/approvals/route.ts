import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/copilot/approvals` (P1-012).
 *
 * Forwards the session bearer so the access token never reaches the
 * browser. The pending-approval list is returned as-is — the dashboard
 * renders each entry as a labelled card with `Approve` / `Reject`
 * buttons.
 *
 * Backend semantics:
 *   - 200: `{ data: { items: PendingApprovalView[] } }`
 *   - 401: session expired; client redirects to /login.
 *   - 403: caller lacks `copilot:review` permission.
 */

interface PendingApprovalView {
  token: string;
  tenant_id: string;
  action_kind: string;
  action: unknown;
  proposer: string;
  status: string;
  proposed_at: string;
  expires_at: string;
}

interface PendingApprovalListView {
  items: ReadonlyArray<PendingApprovalView>;
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
    const data = await apiGet<PendingApprovalListView>(
      "/v1/copilot/approvals",
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
