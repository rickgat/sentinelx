"use client";

import * as React from "react";
import { KeyRound } from "lucide-react";

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
import { useToast } from "@/components/toast";

type Phase = "idle" | "enrolling" | "verified";

const CODE_LEN = 6;

export function MfaClient() {
  const toast = useToast();
  const [phase, setPhase] = React.useState<Phase>("idle");
  const [code, setCode] = React.useState("");

  function startEnroll() {
    setPhase("enrolling");
    setCode("");
  }

  function verify() {
    if (code.length !== CODE_LEN || !/^\d+$/u.test(code)) {
      toast.push({
        kind: "error",
        message: `Enter the ${CODE_LEN}-digit code from your authenticator.`,
      });
      return;
    }
    setPhase("verified");
    toast.push({
      kind: "success",
      message: "Code accepted (stub). Backend MFA verification is not wired up yet.",
    });
  }

  function reset() {
    setPhase("idle");
    setCode("");
  }

  const status: string = phase === "verified" ? "Enrolled (stub)" : "Not enrolled";

  return (
    <div className="max-w-xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-accent" aria-hidden />
            Multi-factor authentication
            <Badge variant="medium" className="ml-2">preview · stubbed</Badge>
          </CardTitle>
          <CardDescription>
            Time-based one-time password (TOTP) enrollment preview. Backend MFA
            support is queued for a future release; every action on this page
            is local-only.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div
            role="alert"
            className="rounded-sx border border-medium/40 bg-medium/10 px-3 py-2 text-xs text-medium"
          >
            Stubbed enrollment — the QR code is a placeholder, no secret is
            generated, and the verify button does not call the backend.
          </div>
          <div className="flex items-center justify-between rounded-sx border border-border bg-background/40 px-3 py-2">
            <span className="text-sm">Current status</span>
            <Badge variant={phase === "verified" ? "success" : "outline"}>
              {status}
            </Badge>
          </div>

          {phase === "idle" ? (
            <Button onClick={startEnroll}>Enroll TOTP</Button>
          ) : null}

          {phase === "enrolling" ? (
            <div className="space-y-3 rounded-sx border border-border bg-background/40 p-4">
              <p className="text-xs text-muted-foreground">
                Scan this placeholder QR code with your authenticator app, then
                enter the {CODE_LEN}-digit code below.
              </p>
              <div className="flex items-center justify-center">
                <PlaceholderQrCode />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="mfa-code">Verification code</Label>
                <Input
                  id="mfa-code"
                  value={code}
                  onChange={(event) =>
                    setCode(
                      event.currentTarget.value.replace(/\D/gu, "").slice(0, CODE_LEN),
                    )
                  }
                  inputMode="numeric"
                  placeholder="000000"
                  maxLength={CODE_LEN}
                  className="font-mono tracking-widest"
                />
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={reset}>
                  Cancel
                </Button>
                <Button onClick={verify}>Verify</Button>
              </div>
            </div>
          ) : null}

          {phase === "verified" ? (
            <div className="space-y-2 rounded-sx border border-success/40 bg-success/10 px-3 py-2 text-xs text-success">
              <p>TOTP verified locally (stub). No backend call was made.</p>
              <Button size="sm" variant="outline" onClick={reset}>
                Reset
              </Button>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

function PlaceholderQrCode() {
  // A static checker-pattern SVG that visually reads as a QR code without
  // implying a real secret has been provisioned.
  const cells: ReadonlyArray<[number, number]> = [
    [0, 0], [1, 0], [2, 0], [3, 0], [4, 0], [5, 0], [6, 0],
    [0, 1], [6, 1],
    [0, 2], [2, 2], [3, 2], [4, 2], [6, 2],
    [0, 3], [2, 3], [3, 3], [4, 3], [6, 3],
    [0, 4], [2, 4], [3, 4], [4, 4], [6, 4],
    [0, 5], [6, 5],
    [0, 6], [1, 6], [2, 6], [3, 6], [4, 6], [5, 6], [6, 6],
    [8, 1], [9, 2], [8, 3], [10, 3], [9, 4], [8, 5], [10, 5],
    [12, 0], [13, 1], [14, 2], [12, 3], [14, 4], [13, 5], [12, 6],
    [0, 8], [2, 8], [4, 8], [6, 8], [8, 8], [10, 8], [12, 8], [14, 8],
    [1, 10], [3, 10], [5, 10], [9, 10], [11, 10], [13, 10],
    [0, 12], [2, 12], [4, 12], [6, 12], [10, 12], [12, 12], [14, 12],
    [0, 14], [3, 14], [5, 14], [7, 14], [9, 14], [11, 14], [14, 14],
  ];
  const size = 15;
  return (
    <svg
      role="img"
      aria-label="Placeholder QR code"
      viewBox={`0 0 ${size} ${size}`}
      className="h-40 w-40 rounded-sx border border-border bg-white p-1"
    >
      <rect width={size} height={size} fill="#fff" />
      {cells.map(([x, y]) => (
        <rect key={`${x}-${y}`} x={x} y={y} width={1} height={1} fill="#000" />
      ))}
    </svg>
  );
}
