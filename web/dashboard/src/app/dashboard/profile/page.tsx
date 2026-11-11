import { redirect } from "next/navigation";
import { UserCircle } from "lucide-react";

import { auth } from "@/lib/auth";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/**
 * Account profile — read-only view of the signed-in user resolved from the
 * session (JWT claims): identity, tenant, and granted permissions. Linked
 * from the top-bar account menu.
 */
export default async function ProfilePage(): Promise<React.JSX.Element> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    redirect("/login");
  }

  const user = session.user;
  const permissions = user?.permissions ?? [];

  const rows: Array<[string, string]> = [
    ["Name", user?.name ?? "—"],
    ["Email", user?.email ?? "—"],
    ["User ID", user?.id ?? "—"],
    ["Tenant ID", user?.tenantId ?? "—"],
    ["Permissions", String(permissions.length)],
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Profile</h1>
        <p className="text-muted-foreground">Your account identity and access.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserCircle className="h-4 w-4 text-accent" aria-hidden />
            Account
          </CardTitle>
          <CardDescription>Resolved from your current session token.</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="space-y-2 text-sm">
            {rows.map(([label, value]) => (
              <div key={label} className="flex justify-between gap-4 border-b border-border/50 pb-2">
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="font-mono text-right">{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Granted permissions</CardTitle>
          <CardDescription>
            Resource:action grants carried in your access token (wildcards allowed).
          </CardDescription>
        </CardHeader>
        <CardContent>
          {permissions.length === 0 ? (
            <p className="text-sm text-muted-foreground">No explicit permissions.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {permissions.map((p) => (
                <span
                  key={p}
                  className="rounded border border-border bg-card px-2 py-0.5 font-mono text-xs"
                >
                  {p}
                </span>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
