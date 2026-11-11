import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Asset, Engagement, Page } from "@/lib/types";
import { ScansClient, type ScanRecord } from "./scans-client";

interface ListBody {
  items: ScanRecord[];
}

export default async function ScansPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const [scansResult, engagementsResult, assetsResult] = await Promise.allSettled([
    apiGet<ListBody>("/v1/scans?limit=200", token),
    apiGet<Page<Engagement>>("/v1/engagements?limit=200", token),
    apiGet<Page<Asset>>("/v1/assets?limit=200", token),
  ]);

  const items: ScanRecord[] =
    scansResult.status === "fulfilled" ? scansResult.value.items : [];
  const engagements: Engagement[] =
    engagementsResult.status === "fulfilled" ? engagementsResult.value.items : [];
  const assets: Asset[] =
    assetsResult.status === "fulfilled" ? assetsResult.value.items : [];

  void (scansResult instanceof ApiError);

  return (
    <ScansClient initial={items} engagements={engagements} assets={assets} />
  );
}
