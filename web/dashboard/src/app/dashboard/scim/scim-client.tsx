"use client";

import * as React from "react";
import { UsersRound, Trash2, Copy } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/toast";

/**
 * SCIM 2.0 admin console (P0-005).
 *
 * Three panels: token mint form, token list (with revoke), and a
 * snapshot of synced users. Every backend call goes through the
 * dashboard's proxy API routes so the JWT never leaves the server.
 *
 * The minted plaintext token is only ever visible inside the
 * "just minted" callout immediately after a successful POST. It is
 * never persisted in client state for longer than the current page
 * lifecycle.
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

interface CreateTokenResponse {
  data?: {
    token?: ScimTokenView;
    plaintext?: string;
  };
  error?: { code?: string; message?: string; request_id?: string };
}

interface Props {
  initialTokens: ReadonlyArray<ScimTokenView>;
  initialUsers: ReadonlyArray<ScimUserSummary>;
  initialUserTotal: number;
}

const NAME_MAX = 128;

export function ScimClient({
  initialTokens,
  initialUsers,
  initialUserTotal,
}: Props) {
  const toast = useToast();
  const [tokens, setTokens] =
    React.useState<ReadonlyArray<ScimTokenView>>(initialTokens);
  const [users, setUsers] =
    React.useState<ReadonlyArray<ScimUserSummary>>(initialUsers);
  const [userTotal, setUserTotal] = React.useState<number>(initialUserTotal);
  const [name, setName] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [justMinted, setJustMinted] = React.useState<{
    name: string;
    plaintext: string;
  } | null>(null);

  function reset() {
    setName("");
    setJustMinted(null);
  }

  async function mintToken(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = name.trim();
    if (trimmed.length === 0 || trimmed.length > NAME_MAX) {
      toast.push({
        kind: "error",
        message: `Token name must be 1-${NAME_MAX} characters.`,
      });
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch("/api/scim/tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: trimmed }),
      });
      const body = (await res.json()) as CreateTokenResponse;
      if (!res.ok || body.error !== undefined) {
        toast.push({
          kind: "error",
          message: body.error?.message ?? "Failed to mint SCIM token.",
        });
        return;
      }
      const token = body.data?.token;
      const plaintext = body.data?.plaintext;
      if (token === undefined || plaintext === undefined) {
        toast.push({ kind: "error", message: "Malformed mint response." });
        return;
      }
      setTokens((prev) => [...prev, token]);
      setJustMinted({ name: token.name, plaintext });
      setName("");
      toast.push({
        kind: "success",
        message: "SCIM token minted. Copy it now — it will not be shown again.",
      });
    } catch (err) {
      toast.push({
        kind: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function revokeToken(id: string) {
    if (!window.confirm("Revoke this SCIM token? Synced clients will lose access immediately.")) {
      return;
    }
    try {
      const res = await fetch(`/api/scim/tokens?id=${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as {
          error?: { message?: string };
        };
        toast.push({
          kind: "error",
          message: body.error?.message ?? "Failed to revoke token.",
        });
        return;
      }
      setTokens((prev) => prev.filter((t) => t.id !== id));
      toast.push({ kind: "success", message: "SCIM token revoked." });
    } catch (err) {
      toast.push({
        kind: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async function refreshUsers() {
    try {
      const res = await fetch("/api/scim/users", { method: "GET" });
      const body = (await res.json()) as {
        data?: {
          totalResults?: number;
          Resources?: ReadonlyArray<{
            id?: string;
            userName?: string;
            displayName?: string;
            active?: boolean;
          }>;
        };
        error?: { message?: string };
      };
      if (!res.ok || body.error !== undefined) {
        toast.push({
          kind: "error",
          message: body.error?.message ?? "Failed to refresh users.",
        });
        return;
      }
      const total = body.data?.totalResults ?? 0;
      const resources = body.data?.Resources ?? [];
      setUserTotal(total);
      const mapped: ReadonlyArray<ScimUserSummary> = resources.map((r) => {
        const summary: ScimUserSummary = {
          user_name: r.userName ?? "",
          active: r.active ?? true,
        };
        if (r.id !== undefined) summary.id = r.id;
        if (r.displayName !== undefined) summary.display_name = r.displayName;
        return summary;
      });
      setUsers(mapped);
    } catch (err) {
      toast.push({
        kind: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async function copyToClipboard(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast.push({ kind: "success", message: "Copied to clipboard." });
    } catch {
      toast.push({ kind: "error", message: "Copy failed; select manually." });
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UsersRound className="h-4 w-4 text-accent" aria-hidden />
            SCIM 2.0 provisioning
            <Badge variant="outline" className="ml-2">
              RFC 7643 / 7644
            </Badge>
          </CardTitle>
          <CardDescription>
            Mint per-tenant bearer tokens for SCIM provisioning agents (Okta,
            Azure AD, Google Workspace). The plaintext token is shown
            exactly once — only its SHA-256 hash is stored server-side.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={mintToken} className="flex items-end gap-2">
            <div className="flex-1 space-y-1.5">
              <Label htmlFor="scim-token-name">Token name</Label>
              <Input
                id="scim-token-name"
                value={name}
                onChange={(event) => setName(event.currentTarget.value)}
                placeholder="okta-production"
                maxLength={NAME_MAX}
                disabled={submitting}
              />
            </div>
            <Button type="submit" disabled={submitting || name.trim().length === 0}>
              {submitting ? "Minting…" : "Mint token"}
            </Button>
            {justMinted !== null ? (
              <Button type="button" variant="outline" onClick={reset}>
                Reset
              </Button>
            ) : null}
          </form>

          {justMinted !== null ? (
            <div
              role="alert"
              className="mt-4 space-y-2 rounded-sx border border-success/40 bg-success/10 px-3 py-2 text-xs text-success"
            >
              <p>
                Token <code>{justMinted.name}</code> minted. Copy it now — this
                is the only time it will be shown.
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 truncate rounded-sx border border-border bg-background/40 px-2 py-1 font-mono">
                  {justMinted.plaintext}
                </code>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => copyToClipboard(justMinted.plaintext)}
                >
                  <Copy className="h-3 w-3" aria-hidden /> Copy
                </Button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Active tokens ({tokens.length})</CardTitle>
          <CardDescription>
            Revoking a token disconnects every SCIM agent authenticated with
            it. There is no recovery path — mint a new one if needed.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {tokens.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No SCIM tokens minted yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last used</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tokens.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-mono text-xs">{t.name}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {t.created_at}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {t.last_used_at ?? "never"}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={() => revokeToken(t.id)}
                      >
                        <Trash2 className="h-3 w-3" aria-hidden /> Revoke
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Synced users ({userTotal})</span>
            <Button type="button" size="sm" variant="outline" onClick={refreshUsers}>
              Refresh
            </Button>
          </CardTitle>
          <CardDescription>
            Snapshot of the first five users SCIM-provisioned into this tenant.
            Showing {users.length} of {userTotal}.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {users.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No SCIM users provisioned yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>userName</TableHead>
                  <TableHead>displayName</TableHead>
                  <TableHead>active</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id ?? u.user_name}>
                    <TableCell className="font-mono text-xs">{u.user_name}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {u.display_name ?? "—"}
                    </TableCell>
                    <TableCell>
                      <Badge variant={u.active ? "success" : "outline"}>
                        {u.active ? "active" : "inactive"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
