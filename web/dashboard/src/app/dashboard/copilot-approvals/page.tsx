import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";

import {
  CopilotApprovalsClient,
  type PendingApprovalView,
} from "./copilot-approvals-client";

/**
 * Copilot Human-in-Loop approvals page (P1-012).
 *
 * SSR-hydrates the pending-approval queue scoped to the caller's tenant
 * via `GET /v1/copilot/approvals`. The client component renders one
 * card per entry with Approve / Reject controls; the buttons fire the
 * `POST /api/copilot/approvals/{token}/decide` proxy which forwards
 * the session bearer.
 */

interface PendingApprovalListEnvelope {
  items: ReadonlyArray<PendingApprovalView>;
}

export default async function CopilotApprovalsPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let items: ReadonlyArray<PendingApprovalView> = [];
  let apiAvailable = true;
  let errorMessage: string | null = null;
  try {
    const env = await apiGet<PendingApprovalListEnvelope>(
      "/v1/copilot/approvals",
      token,
    );
    items = env.items;
  } catch (err) {
    apiAvailable = false;
    if (err instanceof ApiError) {
      errorMessage = err.message;
    } else {
      errorMessage = "Upstream request failed";
    }
  }

  return (
    <CopilotApprovalsClient
      items={items}
      apiAvailable={apiAvailable}
      errorMessage={errorMessage}
    />
  );
}
