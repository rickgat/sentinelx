import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Asset, Page } from "@/lib/types";

import { BlastRadiusClient } from "./blast-radius-client";

/**
 * Cloud blast-radius viewer.
 *
 * Server-side bootstrap: resolves the access token and pre-loads the
 * asset list so the client component can render an asset picker without
 * an extra round trip. The blast-radius computation itself is fetched
 * lazily by the client when the operator picks a seed and clicks
 * "Compute blast radius".
 */
export default async function BlastRadiusPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let assets: ReadonlyArray<Asset> = [];
  let apiAvailable = true;
  try {
    const page = await apiGet<Page<Asset>>("/v1/assets?limit=200", token);
    assets = page.items;
  } catch (err) {
    apiAvailable = false;
    void (err instanceof ApiError);
  }

  return <BlastRadiusClient assets={assets} apiAvailable={apiAvailable} />;
}
