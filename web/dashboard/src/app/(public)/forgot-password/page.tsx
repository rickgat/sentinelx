"use client";

import * as React from "react";
import Link from "next/link";
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
import { publicEnv } from "@/lib/env";

const GENERIC_MESSAGE =
  "If that account exists, we've sent instructions to reset its password.";

export default function ForgotPasswordPage() {
  const [submitting, setSubmitting] = React.useState(false);
  const [submitted, setSubmitted] = React.useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const tenantId = String(formData.get("tenant_id") ?? "").trim();
    const email = String(formData.get("email") ?? "").trim();

    setSubmitting(true);
    try {
      await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_id: tenantId, email }),
      });
    } catch {
      // Intentionally swallow — we always display the generic message so
      // we never reveal whether the account exists.
    } finally {
      setSubmitting(false);
      setSubmitted(true);
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
            <CardTitle className="text-base">Forgot your password?</CardTitle>
            <CardDescription>
              Enter your tenant ID and email and we&apos;ll send you a reset link.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {submitted ? (
            <div className="rounded-sx border border-border bg-muted/40 p-3">
              <p className="text-xs text-muted-foreground">{GENERIC_MESSAGE}</p>
            </div>
          ) : (
            <form className="space-y-4" onSubmit={onSubmit} noValidate>
              <div className="space-y-1.5">
                <Label htmlFor="tenant_id">Tenant ID</Label>
                <Input
                  id="tenant_id"
                  name="tenant_id"
                  type="text"
                  required
                  defaultValue={publicEnv.NEXT_PUBLIC_DEFAULT_TENANT_ID}
                  placeholder="00000000-0000-0000-0000-000000000000"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="username"
                  required
                  placeholder="you@company.com"
                />
              </div>
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "Sending…" : "Send reset link"}
              </Button>
            </form>
          )}

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
