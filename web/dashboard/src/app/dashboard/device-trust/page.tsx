import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import {
  DeviceTrustClient,
  type PosturePolicyView,
  type PostureSessionView,
} from "./device-trust-client";

interface SessionsBody {
  items: PostureSessionView[];
}

export default async function DeviceTrustPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const [policyResult, sessionsResult] = await Promise.allSettled([
    apiGet<PosturePolicyView>("/v1/device-trust/policy", token),
    apiGet<SessionsBody>("/v1/device-trust/sessions?limit=50", token),
  ]);

  void (policyResult instanceof ApiError);

  const policy: PosturePolicyView =
    policyResult.status === "fulfilled"
      ? policyResult.value
      : {
          os_allow_list: [],
          os_block_list: [],
          minimum_os_versions: {},
          edr_vendor_allow_list: [],
          max_screen_lock_minutes: null,
          rules: [],
        };

  const sessions: PostureSessionView[] =
    sessionsResult.status === "fulfilled" ? sessionsResult.value.items : [];

  return <DeviceTrustClient initialPolicy={policy} initialSessions={sessions} />;
}
