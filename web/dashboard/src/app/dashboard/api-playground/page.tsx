import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";
import { publicEnv } from "@/lib/env";
import { PlaygroundClient } from "./playground-client";

export default async function ApiPlaygroundPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">API Playground</h1>
        <p className="text-xs text-muted-foreground">
          Free-form HTTP requests. Multi-tab, environment variables,
          and a 50-entry history. Requests are proxied server-side so
          you can hit any HTTPS endpoint without CORS issues.
        </p>
      </div>
      <PlaygroundClient sxApiBase={publicEnv.NEXT_PUBLIC_SX_API_URL} />
    </div>
  );
}
