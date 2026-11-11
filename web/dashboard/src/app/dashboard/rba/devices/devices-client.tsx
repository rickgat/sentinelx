"use client";

import * as React from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Smartphone } from "lucide-react";

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
 * LOW-008 "Known devices" panel.
 *
 * Operator picks a user from the autocomplete (filters the pre-loaded
 * tenant user list by email substring), the panel loads that user's
 * device fingerprint inventory via the proxied `GET
 * /v1/rba/users/{user_id}/devices` endpoint, and lets the operator
 * revoke any single fingerprint with a confirm dialog. After a
 * successful revoke the table refetches so the new `revoked` row is
 * visible immediately.
 *
 * No dashboard-side tenant plumbing — the upstream sx-api resolves the
 * caller's tenant from the bearer claims.
 */

export interface AdminUserOption {
  id: string;
  email: string;
  is_active: boolean;
}

export interface KnownDevice {
  fp_hash: string;
  status: string;
  last_seen_at: string;
}

interface RbaDevicesClientProps {
  initialUsers: AdminUserOption[];
}

/** Show last 8 chars of a fingerprint hash in a monospace pill. */
function shortFp(fp: string): string {
  if (fp.length <= 8) {
    return fp;
  }
  return `…${fp.slice(-8)}`;
}

/**
 * Render an ISO-8601 timestamp as a coarse relative duration
 * ("2 hours ago", "3 days ago"). Deliberately hand-rolled — the
 * dashboard does not currently ship date-fns and the precision needed
 * here is coarse anyway.
 *
 * Returns the literal `"never"` when the upstream timestamp is the
 * zero value (`0001-01-01T00:00:00Z`), which the storage layer uses
 * for "never seen". Returns `"unknown"` for unparseable input.
 */
function relativeTime(iso: string, now: number = Date.now()): string {
  if (iso === "" || iso.startsWith("0001-")) {
    return "never";
  }
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) {
    return "unknown";
  }
  const diffMs = now - t;
  if (diffMs < 0) {
    return "in the future";
  }
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) {
    return `${sec.toString()}s ago`;
  }
  const min = Math.floor(sec / 60);
  if (min < 60) {
    return `${min.toString()} minute${min === 1 ? "" : "s"} ago`;
  }
  const hr = Math.floor(min / 60);
  if (hr < 24) {
    return `${hr.toString()} hour${hr === 1 ? "" : "s"} ago`;
  }
  const day = Math.floor(hr / 24);
  if (day < 30) {
    return `${day.toString()} day${day === 1 ? "" : "s"} ago`;
  }
  const month = Math.floor(day / 30);
  if (month < 12) {
    return `${month.toString()} month${month === 1 ? "" : "s"} ago`;
  }
  const yr = Math.floor(day / 365);
  return `${yr.toString()} year${yr === 1 ? "" : "s"} ago`;
}

const STATUS_VARIANT: Record<string, "success" | "critical" | "outline"> = {
  known: "success",
  revoked: "critical",
};

function statusLabel(status: string): string {
  if (status === "" || status === "known" || status === "revoked") {
    return status === "" ? "unknown" : status;
  }
  return status;
}

// Exported for unit-testing convenience even though we ship none in this PR.
export const __test__ = { relativeTime, shortFp };

export function RbaDevicesClient({
  initialUsers,
}: RbaDevicesClientProps): React.JSX.Element {
  const toast = useToast();

  const [users] = React.useState<ReadonlyArray<AdminUserOption>>(initialUsers);
  const [filter, setFilter] = React.useState("");
  const [selectedUser, setSelectedUser] =
    React.useState<AdminUserOption | null>(null);
  const [devices, setDevices] = React.useState<ReadonlyArray<KnownDevice>>([]);
  const [loading, setLoading] = React.useState(false);
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [pendingRevoke, setPendingRevoke] = React.useState<KnownDevice | null>(
    null,
  );
  const [revoking, setRevoking] = React.useState(false);
  // Cheap monotonic counter so the relative-time column re-renders
  // every minute without us needing a per-row hook.
  const [, setNowTick] = React.useState(0);

  React.useEffect(() => {
    const handle = window.setInterval(() => {
      setNowTick((n) => n + 1);
    }, 60_000);
    return () => {
      window.clearInterval(handle);
    };
  }, []);

  const filteredUsers = React.useMemo<ReadonlyArray<AdminUserOption>>(() => {
    const q = filter.trim().toLowerCase();
    if (q === "") {
      return users.slice(0, 20);
    }
    return users
      .filter((u) => u.email.toLowerCase().includes(q) || u.id.includes(q))
      .slice(0, 20);
  }, [users, filter]);

  const fetchDevices = React.useCallback(
    async (userId: string): Promise<void> => {
      setLoading(true);
      setLoadError(null);
      try {
        const res = await fetch(
          `/api/rba/users/${encodeURIComponent(userId)}/devices`,
          { method: "GET", cache: "no-store" },
        );
        if (!res.ok) {
          const text = await res.text();
          throw new Error(text || `load failed: ${res.status.toString()}`);
        }
        const body: { data?: { devices: KnownDevice[] } } = await res.json();
        setDevices(body.data?.devices ?? []);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "load failed";
        setLoadError(msg);
        setDevices([]);
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  function selectUser(u: AdminUserOption): void {
    setSelectedUser(u);
    setFilter(u.email);
    void fetchDevices(u.id);
  }

  function clearSelection(): void {
    setSelectedUser(null);
    setDevices([]);
    setFilter("");
    setLoadError(null);
  }

  async function confirmRevoke(): Promise<void> {
    if (pendingRevoke === null || selectedUser === null) {
      return;
    }
    setRevoking(true);
    try {
      const res = await fetch(
        `/api/rba/users/${encodeURIComponent(selectedUser.id)}/devices/${encodeURIComponent(pendingRevoke.fp_hash)}`,
        { method: "DELETE", cache: "no-store" },
      );
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `revoke failed: ${res.status.toString()}`);
      }
      toast.push({
        kind: "success",
        message: `Device ${shortFp(pendingRevoke.fp_hash)} revoked`,
      });
      setPendingRevoke(null);
      await fetchDevices(selectedUser.id);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "revoke failed";
      toast.push({ kind: "error", message: msg });
    } finally {
      setRevoking(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="h-4 w-4 text-accent" aria-hidden />
            Known devices
            <Badge variant="medium" className="ml-2">
              HIGH-001
            </Badge>
          </CardTitle>
          <CardDescription>
            Inspect and revoke the device fingerprints the RBA engine
            has enrolled for any user in your tenant. Revoking a
            fingerprint locks future logins from that device to the
            highest device-fp risk sub-score. The action is idempotent
            and audit-logged server-side.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="user-filter">User</Label>
            <div className="relative">
              <Input
                id="user-filter"
                autoComplete="off"
                placeholder={
                  users.length === 0
                    ? "No users available — check upstream connectivity"
                    : "Type an email or user-id to filter…"
                }
                value={filter}
                onChange={(e) => {
                  setFilter(e.currentTarget.value);
                  if (
                    selectedUser !== null &&
                    e.currentTarget.value !== selectedUser.email
                  ) {
                    setSelectedUser(null);
                    setDevices([]);
                  }
                }}
                disabled={users.length === 0}
                aria-autocomplete="list"
                aria-controls="user-options"
                aria-expanded={
                  selectedUser === null && filteredUsers.length > 0
                }
              />
              {selectedUser === null && filter.trim() !== "" &&
              filteredUsers.length > 0 ? (
                <ul
                  id="user-options"
                  role="listbox"
                  className="absolute z-10 mt-1 max-h-64 w-full overflow-y-auto rounded-sx border border-border bg-card shadow-lg"
                >
                  {filteredUsers.map((u) => (
                    <li key={u.id}>
                      <button
                        type="button"
                        role="option"
                        aria-selected={false}
                        className="block w-full px-3 py-2 text-left text-xs hover:bg-muted"
                        onClick={() => {
                          selectUser(u);
                        }}
                      >
                        <span className="font-medium">{u.email}</span>
                        <span className="ml-2 font-mono text-[10px] text-muted-foreground">
                          {u.id}
                        </span>
                        {!u.is_active ? (
                          <Badge variant="outline" className="ml-2">
                            inactive
                          </Badge>
                        ) : null}
                      </button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
            {selectedUser !== null ? (
              <div className="flex items-center justify-between pt-1 text-xs text-muted-foreground">
                <span>
                  Showing devices for{" "}
                  <span className="font-medium text-foreground">
                    {selectedUser.email}
                  </span>{" "}
                  <span className="font-mono">({selectedUser.id})</span>
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={clearSelection}
                  disabled={loading || revoking}
                >
                  Clear
                </Button>
              </div>
            ) : null}
          </div>

          {selectedUser === null ? (
            <p className="text-sm text-muted-foreground">
              Select a user above to load their known device fingerprints.
            </p>
          ) : loading ? (
            <p className="text-sm text-muted-foreground">Loading devices…</p>
          ) : loadError !== null ? (
            <p className="text-sm text-critical">
              Failed to load devices: {loadError}
            </p>
          ) : devices.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No devices recorded for this user.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Fingerprint</TableHead>
                  <TableHead className="w-[120px]">Status</TableHead>
                  <TableHead className="w-[160px]">Last seen</TableHead>
                  <TableHead className="w-[120px] text-right">
                    Actions
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((d) => (
                  <TableRow key={d.fp_hash}>
                    <TableCell>
                      <span
                        className="font-mono text-xs"
                        title={d.fp_hash}
                        aria-label={`fingerprint ${d.fp_hash}`}
                      >
                        {shortFp(d.fp_hash)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={STATUS_VARIANT[d.status] ?? "outline"}
                      >
                        {statusLabel(d.status)}
                      </Badge>
                    </TableCell>
                    <TableCell
                      className="text-xs text-muted-foreground"
                      title={d.last_seen_at}
                    >
                      {relativeTime(d.last_seen_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => {
                          setPendingRevoke(d);
                        }}
                        disabled={d.status === "revoked" || revoking}
                      >
                        {d.status === "revoked" ? "Revoked" : "Revoke"}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog.Root
        open={pendingRevoke !== null}
        onOpenChange={(next) => {
          if (!next && !revoking) {
            setPendingRevoke(null);
          }
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-sx border border-border bg-card p-6 shadow-xl"
            aria-describedby="revoke-desc"
          >
            <Dialog.Title className="text-base font-semibold text-foreground">
              Revoke device fingerprint
            </Dialog.Title>
            <Dialog.Description
              id="revoke-desc"
              className="mt-1 text-xs text-muted-foreground"
            >
              Future logins from this device will be locked to the highest
              device-fp risk sub-score until it is re-enrolled. This action
              is recorded in the audit log. Proceed?
            </Dialog.Description>
            {pendingRevoke !== null ? (
              <p className="mt-3 break-all rounded-sx border border-border bg-muted/50 px-3 py-2 font-mono text-xs text-foreground">
                {pendingRevoke.fp_hash}
              </p>
            ) : null}
            <div className="mt-6 flex justify-end gap-2">
              <Dialog.Close asChild>
                <Button variant="outline" disabled={revoking}>
                  Cancel
                </Button>
              </Dialog.Close>
              <Button
                variant="destructive"
                onClick={() => {
                  void confirmRevoke();
                }}
                disabled={revoking}
              >
                {revoking ? "Revoking…" : "Revoke"}
              </Button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
