import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { CloudClient } from "./cloud-client";

/**
 * Cloud inventory browser.
 *
 * The result table is populated client-side via the dashboard's own
 * `/api/cloud/inventory` proxy so we can attach the bearer server-side
 * without leaking it into the browser.
 */
export default async function CloudPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return <CloudClient />;
}
