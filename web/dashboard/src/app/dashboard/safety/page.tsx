"use client";

import * as React from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { ShieldAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/toast";

type TripState = "idle" | "submitting" | "success" | "error";

export default function SafetyPage() {
  const toast = useToast();
  const [open, setOpen] = React.useState(false);
  const [reason, setReason] = React.useState("");
  const [state, setState] = React.useState<TripState>("idle");
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null);

  async function trip() {
    if (reason.trim().length < 4) {
      setErrorMessage("Reason must be at least 4 characters.");
      return;
    }
    setState("submitting");
    setErrorMessage(null);
    try {
      const res = await fetch("/api/safety/trip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason.trim() }),
      });
      const parsed: { error?: { message?: string } } = await res.json().catch(() => ({}));
      if (!res.ok) {
        const message = parsed.error?.message ?? `Trip failed (${res.status})`;
        setState("error");
        setErrorMessage(message);
        toast.push({ kind: "error", message });
        return;
      }
      setState("success");
      setOpen(false);
      setReason("");
      toast.push({ kind: "success", message: "Kill switch tripped." });
    } catch {
      const message = "Network error — please retry.";
      setState("error");
      setErrorMessage(message);
      toast.push({ kind: "error", message });
    }
  }

  return (
    <div className="max-w-xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-critical" aria-hidden />
            Emergency kill switch
          </CardTitle>
          <CardDescription>
            Halts all in-flight scans and quarantines active engagements. This action is
            audit-logged and requires a reason.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Dialog.Root open={open} onOpenChange={setOpen}>
            <Dialog.Trigger asChild>
              <Button variant="destructive" size="lg" className="w-full">
                Trip Kill Switch
              </Button>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" />
              <Dialog.Content
                className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-sx border border-border bg-card p-6 shadow-xl"
                aria-describedby="kill-switch-desc"
              >
                <Dialog.Title className="text-base font-semibold text-critical">
                  Confirm kill switch
                </Dialog.Title>
                <Dialog.Description id="kill-switch-desc" className="mt-1 text-xs text-muted-foreground">
                  This will halt every active engagement immediately. Type a reason below.
                </Dialog.Description>
                <div className="mt-4 space-y-1.5">
                  <Label htmlFor="reason">Reason</Label>
                  <Input
                    id="reason"
                    value={reason}
                    onChange={(event) => setReason(event.currentTarget.value)}
                    placeholder="e.g. incident-23, customer escalation"
                    autoFocus
                  />
                  {errorMessage !== null ? (
                    <p role="alert" className="text-xs text-critical">
                      {errorMessage}
                    </p>
                  ) : null}
                </div>
                <div className="mt-6 flex justify-end gap-2">
                  <Dialog.Close asChild>
                    <Button variant="outline">Cancel</Button>
                  </Dialog.Close>
                  <Button variant="destructive" onClick={trip} disabled={state === "submitting"}>
                    {state === "submitting" ? "Tripping…" : "Confirm trip"}
                  </Button>
                </div>
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>
          {state === "success" ? (
            <p className="mt-3 text-xs text-success">Kill switch tripped successfully.</p>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
