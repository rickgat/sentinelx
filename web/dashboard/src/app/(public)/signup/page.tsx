"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
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

const PASSWORD_MIN = 12;

interface ErrorEnvelope {
  error?: { message?: string };
}

export default function SignupPage() {
  const router = useRouter();
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    const formData = new FormData(event.currentTarget);
    const tenantId = String(formData.get("tenant_id") ?? "").trim();
    const email = String(formData.get("email") ?? "").trim();
    const password = String(formData.get("password") ?? "");

    if (tenantId.length === 0) {
      setError("Tenant ID is required.");
      return;
    }
    if (email.length === 0) {
      setError("Email is required.");
      return;
    }
    if (password.length < PASSWORD_MIN) {
      setError(`Password must be at least ${PASSWORD_MIN} characters.`);
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_id: tenantId, email, password }),
      });
      if (!res.ok) {
        let message = "Sign up failed. Please try again.";
        try {
          const body = (await res.json()) as ErrorEnvelope;
          if (typeof body.error?.message === "string") {
            message = body.error.message;
          }
        } catch {
          // fall through with default message
        }
        setError(message);
        setSubmitting(false);
        return;
      }
      router.push("/verify-email-sent");
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
            <CardTitle className="text-base">Create your account</CardTitle>
            <CardDescription>
              We&apos;ll email you a verification link to confirm your address.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
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
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="new-password"
                required
                minLength={PASSWORD_MIN}
                placeholder="At least 12 characters"
              />
            </div>
            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? "Creating account…" : "Create account"}
            </Button>
          </form>

          {error !== null ? (
            <p role="alert" className="text-xs text-critical">
              {error}
            </p>
          ) : null}

          <p className="text-xs text-muted-foreground">
            Already have an account?{" "}
            <Link href="/login" className="text-accent underline-offset-4 hover:underline">
              Sign in
            </Link>
          </p>
        </CardContent>
      </Card>
    </main>
  );
}
