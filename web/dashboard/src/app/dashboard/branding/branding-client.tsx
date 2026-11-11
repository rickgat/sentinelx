"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";

/** Per-tenant branding as returned by `GET /v1/reports/branding`. */
export interface BrandingView {
  logo_png_base64?: string | null;
  primary_color_hex: string;
  cover_md?: string | null;
  footer_md?: string | null;
}

interface Props {
  initial: BrandingView;
  canWrite: boolean;
}

const HEX_RE = /^#[0-9a-fA-F]{6}$/;

/**
 * Edits the tenant's report branding and PUTs it to the proxy. Logo files
 * are read as base64 PNG; the backend enforces the 200 KiB / PNG-magic
 * limits, mirrored here for a fast client-side message.
 */
export function BrandingClient({ initial, canWrite }: Props): React.JSX.Element {
  const [color, setColor] = React.useState(initial.primary_color_hex || "#C71920");
  const [coverMd, setCoverMd] = React.useState(initial.cover_md ?? "");
  const [footerMd, setFooterMd] = React.useState(initial.footer_md ?? "");
  const [logoB64, setLogoB64] = React.useState<string | null>(initial.logo_png_base64 ?? null);
  const [status, setStatus] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  async function onLogoChange(e: React.ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = e.target.files?.[0];
    if (file === undefined) {
      return;
    }
    if (file.type !== "image/png") {
      setStatus("Logo must be a PNG image.");
      return;
    }
    if (file.size > 200 * 1024) {
      setStatus("Logo exceeds 200 KiB.");
      return;
    }
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (const b of bytes) {
      binary += String.fromCharCode(b);
    }
    setLogoB64(btoa(binary));
    setStatus(null);
  }

  async function onSave(): Promise<void> {
    if (!HEX_RE.test(color)) {
      setStatus("Primary colour must be #RRGGBB.");
      return;
    }
    setSaving(true);
    setStatus(null);
    try {
      const res = await fetch("/api/reports/branding", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          primary_color_hex: color,
          logo_png_base64: logoB64,
          cover_md: coverMd.trim() === "" ? null : coverMd,
          footer_md: footerMd.trim() === "" ? null : footerMd,
        }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as
          | { error?: { message?: string } }
          | null;
        setStatus(`Save failed: ${body?.error?.message ?? res.statusText}`);
        return;
      }
      setStatus("Branding saved — applies to the next rendered report.");
    } catch {
      setStatus("Save failed: network error.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <label htmlFor="brand-color" className="w-40 text-sm font-medium">
          Primary colour
        </label>
        <input
          id="brand-color"
          type="color"
          value={HEX_RE.test(color) ? color : "#C71920"}
          disabled={!canWrite}
          onChange={(e) => setColor(e.target.value)}
          className="h-9 w-16 rounded border border-border bg-transparent"
        />
        <input
          type="text"
          value={color}
          disabled={!canWrite}
          onChange={(e) => setColor(e.target.value)}
          className="w-28 rounded border border-border bg-transparent px-2 py-1 text-sm"
          aria-label="Primary colour hex"
        />
      </div>

      <div className="flex items-center gap-3">
        <label htmlFor="brand-logo" className="w-40 text-sm font-medium">
          Logo (PNG ≤ 200 KiB)
        </label>
        <input
          id="brand-logo"
          type="file"
          accept="image/png"
          disabled={!canWrite}
          onChange={(e) => void onLogoChange(e)}
          className="text-sm"
        />
        {logoB64 !== null && (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={`data:image/png;base64,${logoB64}`}
            alt="Current logo preview"
            className="h-9 w-auto rounded border border-border"
          />
        )}
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="brand-cover" className="text-sm font-medium">
          Cover Markdown
        </label>
        <textarea
          id="brand-cover"
          value={coverMd}
          disabled={!canWrite}
          onChange={(e) => setCoverMd(e.target.value)}
          rows={3}
          className="rounded border border-border bg-transparent px-2 py-1 text-sm"
        />
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="brand-footer" className="text-sm font-medium">
          Footer Markdown
        </label>
        <textarea
          id="brand-footer"
          value={footerMd}
          disabled={!canWrite}
          onChange={(e) => setFooterMd(e.target.value)}
          rows={2}
          className="rounded border border-border bg-transparent px-2 py-1 text-sm"
        />
      </div>

      {canWrite ? (
        <Button onClick={() => void onSave()} disabled={saving}>
          {saving ? "Saving…" : "Save branding"}
        </Button>
      ) : (
        <p className="text-sm text-muted-foreground">
          You have read-only access (<code>report:read</code>). The{" "}
          <code>report:write</code> permission is required to change branding.
        </p>
      )}

      {status !== null && (
        <p className="text-sm text-muted-foreground" role="status">
          {status}
        </p>
      )}
    </div>
  );
}
