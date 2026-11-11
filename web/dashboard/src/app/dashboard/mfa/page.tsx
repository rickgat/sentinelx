import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { MfaClient } from "./mfa-client";

/**
 * MFA enrollment — stubbed.
 *
 * The TOTP enrollment ceremony is fully client-side: the QR code is a
 * placeholder SVG and the verify button does not call the backend.
 * Real MFA support lands in a future round.
 */
export default async function MfaPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return <MfaClient />;
}
