import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import { VulnImportClient, type VulnImportView } from "./vuln-import-client";

interface ListBody {
  items: VulnImportView[];
}

export default async function VulnImportPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const result = await Promise.allSettled([
    apiGet<ListBody>("/v1/vuln/imports?limit=200", token),
  ]);

  const settled = result[0];
  const items: VulnImportView[] =
    settled.status === "fulfilled" ? settled.value.items : [];
  void (settled.status === "rejected" && settled.reason instanceof ApiError);

  return <VulnImportClient initial={items} />;
}
