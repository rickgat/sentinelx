"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";

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

const PASSWORD_MIN = 12;

interface ErrorEnvelope {
  error?: { message?: string };
}

/**
 * Next 15 requires `useSearchParams()` consumers to sit under a Suspense
 * boundary so the page can prerender without it.
 */
export default function ResetPasswordPage() {
  return (
    <React.Suspense fallback={<ResetShell />}>
      <ResetPasswordInner />
    </React.Suspense>
  );
}

function ResetShell() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-base">Reset password</CardTitle>
          <CardDescription>Loading…</CardDescription>
        </CardHeader>
      </Card>
    </main>
  );
}

function ResetPasswordInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token") ?? "";

  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (token.trim().length === 0) {
      setError("Missing reset token.");
      return;
    }

    const formData = new FormData(event.currentTarget);
    const newPassword = String(formData.get("new_password") ?? "");
    const confirm = String(formData.get("confirm") ?? "");

    if (newPassword.length < PASSWORD_MIN) {
      setError(`Password must be at least ${PASSWORD_MIN} characters.`);
      return;
    }
    if (newPassword !== confirm) {
      setError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: newPassword }),
      });
      if (!res.ok) {
        let message = "Reset failed. The link may have expired.";
        try {
          const body = (await res.json()) as ErrorEnvelope;
          if (typeof body.error?.message === "string") {
            message = body.error.message;
          }
        } catch {
          // keep default
        }
        setError(message);
        setSubmitting(false);
        return;
      }
      router.push("/login");
    } catch {
      setError("Network error. Please try again.");
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-accent" aria-hidden />
            <span className="text-sm font-semibold tracking-tight">SentinelX</span>
          </div>
          <div>
            <CardTitle className="text-base">Choose a new password</CardTitle>
            <CardDescription>
              Your new password must be at least {PASSWORD_MIN} characters.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {token.trim().length === 0 ? (
            <p role="alert" className="text-xs text-critical">
              Missing reset token. Open the link from your email again.
            </p>
          ) : (
            <form className="space-y-4" onSubmit={onSubmit} noValidate>
              <div className="space-y-1.5">
                <Label htmlFor="new_password">New password</Label>
                <Input
                  id="new_password"
                  name="new_password"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={PASSWORD_MIN}
                  placeholder="At least 12 characters"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirm">Confirm password</Label>
                <Input
                  id="confirm"
                  name="confirm"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={PASSWORD_MIN}
                  placeholder="Re-enter password"
                />
              </div>
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "Resetting…" : "Reset password"}
              </Button>
            </form>
          )}

          {error !== null ? (
            <p role="alert" className="text-xs text-critical">
              {error}
            </p>
          ) : null}

          <p className="text-xs text-muted-foreground">
            <Link
              href="/login"
              className="text-accent underline-offset-4 hover:underline"
            >
              Back to sign in
            </Link>
          </p>
        </CardContent>
      </Card>
    </main>
  );
}
