import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Asset, Engagement, Page } from "@/lib/types";
import { BasClient, type BasRunHistoryItem } from "./bas-client";

/**
 * Breach & Attack Simulation page.
 *
 * Server component fan-out: BAS run history, engagements (for dropdown),
 * and assets (for target suggestions). Each fetch absorbs its own error
 * so the form still renders if one source is unavailable.
 */

interface ListBody {
  items: BasRunHistoryItem[];
}

export default async function BasPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const [runsResult, engagementsResult, assetsResult] = await Promise.allSettled([
    apiGet<ListBody>("/v1/bas/runs?limit=200", token),
    apiGet<Page<Engagement>>("/v1/engagements?limit=200", token),
    apiGet<Page<Asset>>("/v1/assets?limit=200", token),
  ]);

  const items: BasRunHistoryItem[] =
    runsResult.status === "fulfilled" ? runsResult.value.items : [];
  const engagements: Engagement[] =
    engagementsResult.status === "fulfilled" ? engagementsResult.value.items : [];
  const assets: Asset[] =
    assetsResult.status === "fulfilled" ? assetsResult.value.items : [];

  void (runsResult instanceof ApiError);

  return (
    <BasClient initial={items} engagements={engagements} assets={assets} />
  );
}
