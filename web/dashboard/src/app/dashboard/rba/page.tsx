import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";

import { RbaClient, type RbaConfigView, type RbaDecisionView } from "./rba-client";

/**
 * Adaptive Authentication (RBA) dashboard.
 *
 * Server-rendered: pulls the last 100 RBA decisions + the active
 * per-tenant configuration from sx-api and hands them to the client
 * component for filtering / tuning.
 */

interface DecisionsBody {
  decisions: RbaDecisionView[];
}

const DEFAULT_CONFIG: RbaConfigView = {
  allow_threshold: 30,
  block_threshold: 70,
  weights: {
    w_ip_geo: 0.25,
    w_velocity: 0.20,
    w_business_hours: 0.10,
    w_device_fp: 0.15,
    w_mfa_recent: 0.10,
    w_success_rate: 0.05,
    w_impossible_travel: 0.15,
  },
  feature_flags: {
    enable_ip_geo: true,
    enable_velocity: true,
    enable_business_hours: true,
    enable_device_fp: true,
    enable_mfa_recent: true,
    enable_success_rate: true,
    enable_impossible_travel: true,
  },
  business_tz: "UTC",
  business_hours_start: 9,
  business_hours_end: 18,
};

export default async function RbaPage(): Promise<React.JSX.Element> {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const [decisionsResult, configResult] = await Promise.allSettled([
    apiGet<DecisionsBody>("/v1/rba/decisions?limit=100", token),
    apiGet<RbaConfigView>("/v1/rba/config", token),
  ]);

  const decisions: RbaDecisionView[] =
    decisionsResult.status === "fulfilled"
      ? decisionsResult.value.decisions
      : [];
  const config: RbaConfigView =
    configResult.status === "fulfilled" ? configResult.value : DEFAULT_CONFIG;

  // Surface upstream errors silently — the client still renders an
  // empty list + the defaults so the operator can at least tune the
  // thresholds and try again.
  void (decisionsResult instanceof ApiError);

  return <RbaClient initialDecisions={decisions} initialConfig={config} />;
}
