import { apiGet } from "@/lib/api-client";
import type { Finding, Page } from "@/lib/types";

/**
 * Counts surfaced as pill badges on sidebar items.
 *
 * `undefined` → API failed for that section; render no badge (silent
 * degradation is intentional so a dead endpoint doesn't scream at the
 * operator every route change).
 * `0` → API succeeded, nothing to attend to; also renders no badge.
 * `> 0` → render pill with tone.
 */
export interface NavBadges {
  findingsOpen?: number | undefined;
  findingsCritical?: number | undefined;
  socAlertsOpen?: number | undefined;
  approvalsPending?: number | undefined;
  copilotApprovalsPending?: number | undefined;
}

interface AlertLike {
  status?: string;
  severity?: string;
}

interface ApprovalLike {
  status?: string;
  decided_at?: string | null;
}

async function safeCount<T>(
  path: string,
  token: string,
  predicate: (item: T) => boolean,
): Promise<number | undefined> {
  try {
    const page = await apiGet<Page<T>>(path, token);
    return page.items.filter(predicate).length;
  } catch {
    return undefined;
  }
}

export async function getNavBadges(token: string): Promise<NavBadges> {
  const [findings, alerts, basApprovals, copilotApprovals] = await Promise.all([
    safeCount<Finding>(
      "/v1/findings?limit=500",
      token,
      (f) => f.status === "open" || f.status === "triaged" || f.status === "in_progress",
    ),
    safeCount<AlertLike>(
      "/v1/soc/alerts?limit=500",
      token,
      (a) => a.status !== "closed" && a.status !== "resolved",
    ),
    safeCount<ApprovalLike>(
      "/v1/bas/approvals?limit=500",
      token,
      (a) => a.status === "pending" || (a.decided_at ?? null) === null,
    ),
    safeCount<ApprovalLike>(
      "/v1/copilot/approvals?limit=500",
      token,
      (a) => a.status === "pending" || (a.decided_at ?? null) === null,
    ),
  ]);

  // Critical count is a second pass over findings so the badge on
  // /dashboard/findings can highlight the severe-only count. Cheap
  // enough that a second fetch beats piping raw items through.
  let findingsCritical: number | undefined;
  try {
    const page = await apiGet<Page<Finding>>(
      "/v1/findings?limit=500&severity=critical",
      token,
    );
    findingsCritical = page.items.filter(
      (f) => f.status === "open" || f.status === "triaged" || f.status === "in_progress",
    ).length;
  } catch {
    findingsCritical = undefined;
  }

  return {
    findingsOpen: findings,
    findingsCritical,
    socAlertsOpen: alerts,
    approvalsPending: basApprovals,
    copilotApprovalsPending: copilotApprovals,
  };
}
