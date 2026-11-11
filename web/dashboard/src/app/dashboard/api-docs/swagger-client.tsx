"use client";

import { useEffect, useRef } from "react";
import type { ReactElement } from "react";

import "swagger-ui-dist/swagger-ui.css";

/**
 * Swagger UI mount that points at the same-origin `/api/openapi` proxy.
 *
 * Uses `swagger-ui-dist` (vanilla browser bundle) instead of
 * `swagger-ui-react` to avoid the `@swagger-api/apidom-ns-openapi-3-1`
 * ESM/Turbopack interop failure that surfaces as
 * `OpenApi3_1Element.refract is not a function` during dev.
 */
export function SwaggerClient(): ReactElement {
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const mod = (await import(
        // @ts-expect-error swagger-ui-dist ships untyped ES bundles
        "swagger-ui-dist/swagger-ui-es-bundle.js"
      )) as { default: (opts: unknown) => unknown };
      if (cancelled || containerRef.current === null) {
        return;
      }
      const SwaggerUIBundle = mod.default;
      SwaggerUIBundle({
        url: "/api/openapi",
        domNode: containerRef.current,
        deepLinking: true,
        docExpansion: "list",
        defaultModelsExpandDepth: 0,
      });
    })().catch((err) => {
      console.error("swagger-ui-dist init failed", err);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="rounded-sx border border-border bg-white text-black">
      <div ref={containerRef} />
    </div>
  );
}
