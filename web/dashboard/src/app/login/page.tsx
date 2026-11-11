"use client";

import * as React from "react";
import { signIn } from "next-auth/react";
import { useSearchParams } from "next/navigation";
import { ShieldCheck, Radar, Network, Fingerprint, Sparkles } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { publicEnv } from "@/lib/env";

const ALLOW_CREDENTIALS = publicEnv.NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN === "true";

/**
 * Next 15 requires `useSearchParams()` consumers to sit under a Suspense
 * boundary so the page can prerender without it. Splitting the inner client
 * component keeps the build clean.
 */
export default function LoginPage() {
  return (
    <React.Suspense fallback={<LoginShell />}>
      <LoginForm />
    </React.Suspense>
  );
}

function LoginShell() {
  return (
    <main className="grid min-h-screen grid-cols-1 lg:grid-cols-2 bg-background">
      <BrandHero />
      <div className="flex items-center justify-center p-6">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="text-base">Sign in</CardTitle>
            <CardDescription>Loading…</CardDescription>
          </CardHeader>
        </Card>
      </div>
    </main>
  );
}

/**
 * Brand hero panel — shown on ≥ lg viewports next to the auth form.
 *
 * Enterprise sales cycles typically flow through a self-guided trial or
 * pilot; the first screen the buyer sees is the login page. Filling that
 * blank canvas with the value proposition + capability chips creates a
 * demo moment the prospect can screenshot for their team lead.
 */
function BrandHero() {
  const pillars = [
    { icon: Radar, label: "Vulnerability Assessment", detail: "Continuous scanning across cloud + code + infra." },
    { icon: Network, label: "Attack Path Simulation", detail: "Breach & attack simulation with MITRE ATT&CK coverage." },
    { icon: Fingerprint, label: "Identity Analytics", detail: "UEBA, adaptive MFA, and privileged access reviews." },
    { icon: Sparkles, label: "Autonomous Remediation", detail: "AI-guided fix workflows with human-in-the-loop safeguards." },
  ];
  return (
    <aside
      className="relative hidden overflow-hidden bg-gradient-to-br from-card via-background to-background lg:flex lg:flex-col lg:justify-between lg:p-12"
      aria-labelledby="brand-hero-title"
    >
      {/* Ambient accent glow — subtle depth without becoming decoration */}
      <div
        aria-hidden
        className="pointer-events-none absolute -top-32 -right-24 h-96 w-96 rounded-full bg-accent/10 blur-3xl"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute -bottom-24 -left-24 h-72 w-72 rounded-full bg-accent/5 blur-3xl"
      />

      <div className="relative z-10 flex items-center gap-2">
        <ShieldCheck className="h-6 w-6 text-accent" aria-hidden />
        <span className="text-lg font-semibold tracking-tight">SentinelX</span>
      </div>

      <div className="relative z-10 space-y-8">
        <div className="space-y-3">
          <h2
            id="brand-hero-title"
            className="text-3xl font-semibold tracking-tight text-foreground xl:text-4xl"
          >
            One control plane.
            <br />
            <span className="text-accent">Replace 5–7 vendors.</span>
          </h2>
          <p className="max-w-md text-sm text-muted-foreground">
            SentinelX unifies vulnerability assessment, breach &amp; attack simulation,
            attack-surface discovery, cloud posture, threat intelligence, and SOC
            correlation into a single Rust modular monolith.
          </p>
        </div>

        <ul className="space-y-4">
          {pillars.map((p) => {
            const Icon = p.icon;
            return (
              <li key={p.label} className="flex gap-3">
                <span
                  className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-sx bg-accent/10 text-accent"
                  aria-hidden
                >
                  <Icon className="h-4 w-4" />
                </span>
                <div>
                  <div className="text-sm font-medium text-foreground">{p.label}</div>
                  <div className="text-xs text-muted-foreground">{p.detail}</div>
                </div>
              </li>
            );
          })}
        </ul>
      </div>

      <div className="relative z-10 text-xs text-muted-foreground">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span>SOC 2 Type II · ISO 27001 · GDPR</span>
          <span aria-hidden>·</span>
          <span>Zero-trust by default · Rust safety by construction</span>
        </div>
      </div>
    </aside>
  );
}

function LoginForm() {
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/dashboard";
  const errorParam = searchParams.get("error");

  const [submitting, setSubmitting] = React.useState(false);
  const [credentialsSubmitting, setCredentialsSubmitting] = React.useState(false);
  // Progressive disclosure of the dev/credentials form — collapsed by
  // default so SSO stays the primary CTA. Users click "Advanced sign-in"
  // to reveal email+password fallback.
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [error, setError] = React.useState<string | null>(
    errorParam !== null ? "Sign-in failed. Please try again." : null,
  );

  async function onSsoClick() {
    setError(null);
    setSubmitting(true);
    try {
      await signIn("oidc", { callbackUrl });
    } catch {
      setError("Could not start SSO flow. Please try again.");
      setSubmitting(false);
    }
  }

  async function onCredentialsSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setCredentialsSubmitting(true);
    const formData = new FormData(event.currentTarget);
    const tenantId = String(formData.get("tenant_id") ?? "");
    const email = String(formData.get("email") ?? "");
    const password = String(formData.get("password") ?? "");

    const result = (await signIn("credentials", {
      tenantId,
      email,
      password,
      callbackUrl,
      redirect: true,
    })) as { error?: string } | undefined;

    // `redirect: true` short-circuits the promise on success; if we land here,
    // the IdP returned an error object on the redirect.
    if (result !== undefined && result.error !== undefined) {
      setError("Invalid credentials.");
    }
    setCredentialsSubmitting(false);
  }

  return (
    <main className="grid min-h-screen grid-cols-1 lg:grid-cols-2 bg-background">
      <BrandHero />
      <div className="flex items-center justify-center p-6">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-3">
            {/* Mobile-only brand mark — brand hero is hidden below lg */}
            <div className="flex items-center gap-2 lg:hidden">
              <ShieldCheck className="h-5 w-5 text-accent" aria-hidden />
              <span className="text-sm font-semibold tracking-tight">SentinelX</span>
            </div>
            <div className="space-y-1">
              <CardTitle className="text-lg tracking-tight">Sign in</CardTitle>
              <CardDescription>
                Use your organisation SSO to continue.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <Button
              type="button"
              className="h-11 w-full text-sm"
              onClick={onSsoClick}
              disabled={submitting}
              aria-busy={submitting}
            >
              {submitting ? "Redirecting to your identity provider…" : "Sign in with SSO"}
            </Button>

            <p className="text-center text-xs text-muted-foreground">
              We&rsquo;ll send you to your company&rsquo;s identity provider.
              {" "}
              <a
                href="mailto:security@sentinelx.example"
                className="text-accent underline-offset-2 hover:underline"
              >
                No SSO yet?
              </a>
            </p>

            {ALLOW_CREDENTIALS ? (
              <div className="border-t border-border pt-4">
                <button
                  type="button"
                  onClick={() => setShowAdvanced((s) => !s)}
                  className="flex w-full items-center justify-between text-xs font-medium uppercase tracking-wider text-muted-foreground transition-colors hover:text-foreground"
                  aria-expanded={showAdvanced}
                  aria-controls="credentials-form"
                >
                  <span>Advanced sign-in</span>
                  <span aria-hidden className="text-[10px]">
                    {showAdvanced ? "▲" : "▼"}
                  </span>
                </button>
                {showAdvanced ? (
                  <form
                    id="credentials-form"
                    className="mt-4 space-y-4"
                    onSubmit={onCredentialsSubmit}
                    noValidate
                  >
                    <input
                      type="hidden"
                      name="tenant_id"
                      defaultValue={publicEnv.NEXT_PUBLIC_DEFAULT_TENANT_ID}
                    />
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
                      <div className="flex items-center justify-between">
                        <Label htmlFor="password">Password</Label>
                        <a
                          href="/reset-password"
                          className="text-[11px] text-muted-foreground hover:text-accent"
                        >
                          Forgot?
                        </a>
                      </div>
                      <Input
                        id="password"
                        name="password"
                        type="password"
                        autoComplete="current-password"
                        required
                        placeholder="••••••••"
                      />
                    </div>
                    <Button
                      type="submit"
                      variant="outline"
                      className="w-full"
                      disabled={credentialsSubmitting}
                      aria-busy={credentialsSubmitting}
                    >
                      {credentialsSubmitting ? "Signing in…" : "Sign in with email"}
                    </Button>
                    <p className="text-[11px] text-muted-foreground">
                      Development-only fallback. In production, everyone signs in via SSO.
                    </p>
                  </form>
                ) : null}
              </div>
            ) : null}

            {error !== null ? (
              <div
                role="alert"
                className="rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
              >
                {error}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
