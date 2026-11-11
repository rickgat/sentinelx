"use client";

import * as React from "react";
import { Users } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
 * User & Access provisioning page.
 *
 * Backend gating: the server-side page already verifies that the caller
 * carries the `admin:users` permission. We still soft-validate the form
 * (email format, password length, ≥1 role) so a typo never burns an
 * upstream round-trip. Passwords are never logged or persisted on the
 * client beyond the in-memory `password` state for the active form.
 */

const ROLES: ReadonlyArray<string> = ["admin", "analyst", "ops"];
const PASSWORD_MIN = 12;
const PASSWORD_GENERATED_LEN = 24;

interface CreatedRow {
  id: number;
  email: string;
  roles: ReadonlyArray<string>;
  created_at: string;
  backend_id?: string;
}

interface CreateResponse {
  data?: {
    id?: string;
    email?: string;
    roles?: ReadonlyArray<string>;
    created_at?: string;
  };
  error?: { code?: string; message?: string; request_id?: string };
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;

interface Props {
  defaultTenantId: string;
}

export function IamClient({ defaultTenantId }: Props) {
  const toast = useToast();
  const [tenantId, setTenantId] = React.useState(defaultTenantId);
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [roles, setRoles] = React.useState<ReadonlyArray<string>>(["analyst"]);
  const [submitting, setSubmitting] = React.useState(false);
  const [created, setCreated] = React.useState<ReadonlyArray<CreatedRow>>([]);
  const idRef = React.useRef(0);

  function toggleRole(role: string) {
    setRoles((current) =>
      current.includes(role) ? current.filter((r) => r !== role) : [...current, role],
    );
  }

  function generatePassword() {
    const next = generateStrongPassword(PASSWORD_GENERATED_LEN);
    setPassword(next);
  }

  function pushCreated(row: Omit<CreatedRow, "id">) {
    idRef.current += 1;
    const id = idRef.current;
    setCreated((current) => [{ ...row, id }, ...current]);
  }

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!EMAIL_RE.test(email)) {
      toast.push({ kind: "error", message: "Enter a valid email address." });
      return;
    }
    if (password.length < PASSWORD_MIN) {
      toast.push({
        kind: "error",
        message: `Password must be at least ${PASSWORD_MIN} characters.`,
      });
      return;
    }
    if (roles.length === 0) {
      toast.push({ kind: "error", message: "Select at least one role." });
      return;
    }
    if (tenantId.trim().length === 0) {
      toast.push({ kind: "error", message: "Tenant id is required." });
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch("/api/admin/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId.trim(),
          email: email.trim().toLowerCase(),
          password,
          roles: [...roles],
        }),
      });
      const parsed: CreateResponse = await res.json().catch(() => ({}));
      if (!res.ok) {
        toast.push({
          kind: "error",
          message: parsed.error?.message ?? `Create failed (${res.status})`,
        });
        return;
      }
      const now = parsed.data?.created_at ?? new Date().toISOString();
      const row: Omit<CreatedRow, "id"> = {
        email: parsed.data?.email ?? email.trim().toLowerCase(),
        roles: parsed.data?.roles ?? [...roles],
        created_at: now,
      };
      if (typeof parsed.data?.id === "string") {
        row.backend_id = parsed.data.id;
      }
      pushCreated(row);
      toast.push({ kind: "success", message: "User created." });
      // Clear sensitive fields; keep tenant + roles for quick repeat provisioning.
      setEmail("");
      setPassword("");
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-4 w-4 text-accent" aria-hidden />
            User &amp; Access
          </CardTitle>
          <CardDescription>
            Provision a new user under a tenant. The backend hashes the password before
            storage; it is never logged.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="iam-tenant">Tenant ID</Label>
              <Input
                id="iam-tenant"
                value={tenantId}
                onChange={(event) => setTenantId(event.currentTarget.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="iam-email">Email</Label>
              <Input
                id="iam-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.currentTarget.value)}
                placeholder="analyst@example.com"
                required
              />
            </div>
            <div className="md:col-span-2 space-y-1.5">
              <Label htmlFor="iam-password">
                Password <span className="opacity-70">(min {PASSWORD_MIN} chars)</span>
              </Label>
              <div className="flex gap-2">
                <Input
                  id="iam-password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.currentTarget.value)}
                  autoComplete="new-password"
                  required
                />
                <Button type="button" variant="outline" onClick={generatePassword}>
                  Generate
                </Button>
              </div>
            </div>
            <div className="md:col-span-2 space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">Roles</span>
              <div className="flex flex-wrap gap-3">
                {ROLES.map((role) => (
                  <label
                    key={role}
                    className="flex items-center gap-2 rounded-sx border border-border px-3 py-1.5 text-xs text-foreground"
                  >
                    <input
                      type="checkbox"
                      checked={roles.includes(role)}
                      onChange={() => toggleRole(role)}
                      className="h-4 w-4 rounded border-border accent-accent"
                    />
                    <span>{role}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="md:col-span-2 flex justify-end">
              <Button type="submit" disabled={submitting}>
                {submitting ? "Creating…" : "Create user"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Created this session</CardTitle>
          <CardDescription>
            Backend does not yet expose <code>GET /v1/admin/users</code>; this list is reset
            on reload.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Roles</TableHead>
                <TableHead>Created at</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {created.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={3}
                    className="py-8 text-center text-xs text-muted-foreground"
                  >
                    No users created yet.
                  </TableCell>
                </TableRow>
              ) : (
                created.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="text-xs">{row.email}</TableCell>
                    <TableCell className="flex flex-wrap gap-1">
                      {row.roles.map((r) => (
                        <Badge key={r} variant="info">
                          {r}
                        </Badge>
                      ))}
                    </TableCell>
                    <TableCell className="text-xs font-mono">
                      {row.created_at.slice(0, 19).replace("T", " ")}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

/**
 * Generate a high-entropy password using the Web Crypto RNG.
 * Alphabet covers upper/lower/digit/symbol to satisfy common policies.
 */
function generateStrongPassword(length: number): string {
  const alphabet =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*_-+=";
  const buf = new Uint32Array(length);
  crypto.getRandomValues(buf);
  let out = "";
  for (let i = 0; i < length; i += 1) {
    const v = buf[i] ?? 0;
    out += alphabet[v % alphabet.length];
  }
  return out;
}
