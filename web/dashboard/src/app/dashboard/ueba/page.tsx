import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";

import { UebaClient, type UebaAnomalyView } from "./ueba-client";

/**
 * UEBA (User & Entity Behavioural Analytics) dashboard.
 *
 * Server-rendered: pulls the most recent anomalies for the caller's
 * tenant from sx-api, sorts them by score descending (tie-broken by
 * detected_at descending) and hands them to the client component. The
 * client component fetches the per-user baseline on-demand when the
 * operator drills in on a row.
 */

interface ListBody {
  anomalies: UebaAnomalyView[];
}

export default async function UebaPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const settled = await Promise.allSettled([
    apiGet<ListBody>("/v1/ueba/anomalies?limit=200", token),
  ]);
  const result = settled[0];

  const raw: UebaAnomalyView[] =
    result.status === "fulfilled" ? result.value.anomalies : [];
  void (result.status === "rejected" && result.reason instanceof ApiError);

  // Sort by score descending; tie-break by detected_at descending so the
  // dashboard surfaces the highest-signal anomalies first.
  const sorted = [...raw].sort((a, b) => {
    if (b.score !== a.score) {
      return b.score - a.score;
    }
    return b.detected_at.localeCompare(a.detected_at);
  });

  return <UebaClient initialAnomalies={sorted} />;
}
