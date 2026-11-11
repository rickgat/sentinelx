"use client";

import * as React from "react";

import { cn } from "@/lib/utils";

export type Toast = { kind: "success" | "error"; message: string };

interface ToastInternal extends Toast {
  id: number;
}

interface ToastContextValue {
  push: (toast: Toast) => void;
}

const ToastContext = React.createContext<ToastContextValue | null>(null);

const AUTO_DISMISS_MS = 4000;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<ReadonlyArray<ToastInternal>>([]);
  const idRef = React.useRef(0);

  const push = React.useCallback((toast: Toast) => {
    idRef.current += 1;
    const id = idRef.current;
    setToasts((current) => [...current, { ...toast, id }]);
    setTimeout(() => {
      setToasts((current) => current.filter((t) => t.id !== id));
    }, AUTO_DISMISS_MS);
  }, []);

  const value = React.useMemo<ToastContextValue>(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        aria-live="polite"
        aria-atomic="true"
        className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            role="status"
            className={cn(
              "pointer-events-auto rounded-sx border px-3 py-2 text-xs shadow-lg backdrop-blur",
              toast.kind === "success"
                ? "border-success/40 bg-success/10 text-success"
                : "border-critical/40 bg-critical/10 text-critical",
            )}
          >
            {toast.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = React.useContext(ToastContext);
  if (ctx === null) {
    // Outside a provider (shouldn't happen — provider is mounted in root layout).
    // Return a no-op so dependent components never crash.
    return {
      push: () => {
        /* no-op */
      },
    };
  }
  return ctx;
}
