import { redirect } from "next/navigation";
import { Users } from "lucide-react";

import { auth } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { hasPermission } from "@/lib/permissions";

import { IamClient } from "./iam-client";

export default async function IamPage() {
  const session = await auth();
  if (session?.accessToken === undefined) {
    redirect("/login");
  }
  const permissions = session.user.permissions ?? [];
  const tenantId = session.user.tenantId ?? "";
  const isAdmin = hasPermission(permissions, "admin:users");

  if (!isAdmin) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-4 w-4 text-accent" aria-hidden />
            User &amp; Access
          </CardTitle>
          <CardDescription>
            You do not have the <code>admin:users</code> permission required to provision new
            users.
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

  return <IamClient defaultTenantId={tenantId} />;
}
