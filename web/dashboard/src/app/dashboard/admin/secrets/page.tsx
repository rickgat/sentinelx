import { redirect } from "next/navigation";
import { KeyRound } from "lucide-react";

import { auth } from "@/lib/auth";
import { hasPermission } from "@/lib/permissions";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

import { SecretsClient } from "./secrets-client";

/**
 * Vault secret browser — administrative surface for inspecting which
 * sensitive material the platform proxies through Vault. The page is
 * gated by the `admin:secrets` permission, which the backend mirrors on
 * every reveal request; this server check is the cheap first line of
 * defence to avoid leaking the existence of paths.
 *
 * Returns a 403-style card (not a redirect) when the caller lacks the
 * grant so the IAM team can hand the link to operators and have them
 * see a clear "ask an admin" message rather than a confusing bounce.
 */
export default async function AdminSecretsPage() {
  const session = await auth();
  if (session?.accessToken === undefined) {
    redirect("/login");
  }

  const permissions = session.user.permissions ?? [];
  const allowed = hasPermission(permissions, "admin:secrets");

  if (!allowed) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-accent" aria-hidden />
            Vault Secrets
          </CardTitle>
          <CardDescription>
            403 — you do not have the <code>admin:secrets</code> permission
            required to view the Vault secret browser.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground">
            Ask a workspace administrator to grant the role. Every reveal is
            recorded in the audit log; access is intentionally restricted.
          </p>
        </CardContent>
      </Card>
    );
  }

  return <SecretsClient />;
}
