import { redirect } from "next/navigation";
import { UsersRound } from "lucide-react";

import { auth } from "@/lib/auth";
import { apiGet, ApiError } from "@/lib/api-client";
import { hasPermission } from "@/lib/permissions";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

import { ScimClient } from "./scim-client";

/**
 * SCIM 2.0 admin page (P0-005).
 *
 * Shows the per-tenant SCIM token catalogue and a snapshot of synced
 * users. The mint / revoke flows live in the client component; the
 * server component does the initial fetch so the page renders with
 * data already on screen.
 */

interface ScimTokenView {
  id: string;
  tenant_id: string;
  name: string;
  created_at: string;
  last_used_at?: string;
}

interface ScimUserSummary {
  id?: string;
  user_name: string;
  display_name?: string;
  active: boolean;
}

interface ListResponseEnvelope<T> {
  totalResults?: number;
  Resources?: ReadonlyArray<T>;
}

interface ScimUserResource {
  id?: string;
  userName?: string;
  displayName?: string;
  active?: boolean;
}

async function fetchTokens(token: string): Promise<ReadonlyArray<ScimTokenView>> {
  try {
    return await apiGet<ReadonlyArray<ScimTokenView>>(
      "/v1/admin/scim/tokens",
      token,
    );
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      return [];
    }
    return [];
  }
}

async function fetchUsersSummary(
  token: string,
): Promise<{ total: number; users: ReadonlyArray<ScimUserSummary> }> {
  try {
    const env = await apiGet<ListResponseEnvelope<ScimUserResource>>(
      "/v1/admin/scim/users?count=5",
      token,
    );
    const total = env.totalResults ?? 0;
    const users: ReadonlyArray<ScimUserSummary> = (env.Resources ?? []).map(
      (r) => {
        const summary: ScimUserSummary = {
          user_name: r.userName ?? "",
          active: r.active ?? true,
        };
        if (r.id !== undefined) summary.id = r.id;
        if (r.displayName !== undefined) summary.display_name = r.displayName;
        return summary;
      },
    );
    return { total, users };
  } catch {
    return { total: 0, users: [] };
  }
}

export default async function ScimPage() {
  const session = await auth();
  if (session?.accessToken === undefined) {
    redirect("/login");
  }
  const permissions = session.user.permissions ?? [];
  const isAdmin = hasPermission(permissions, "admin:users");
  if (!isAdmin) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UsersRound className="h-4 w-4 text-accent" aria-hidden />
            SCIM 2.0 provisioning
          </CardTitle>
          <CardDescription>
            You do not have the <code>admin:users</code> permission required to
            mint SCIM tokens for this tenant.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground">
            Ask a workspace administrator to grant you the role.
          </p>
        </CardContent>
      </Card>
    );
  }

  const tokens = await fetchTokens(session.accessToken);
  const usersSummary = await fetchUsersSummary(session.accessToken);

  return (
    <ScimClient
      initialTokens={tokens}
      initialUsers={usersSummary.users}
      initialUserTotal={usersSummary.total}
    />
  );
}
