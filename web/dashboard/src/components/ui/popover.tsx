"use client";

import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * Minimalist Popover — click-outside dismiss + Escape close, positioned
 * relative to its trigger. No portal (renders inline) so it inherits
 * z-index and stacking from the caller. Good enough for tooltips,
 * inline hints, and small side panels; upgrade to Radix if we need
 * collision-aware positioning.
 */

interface PopoverContextValue {
  open: boolean;
  setOpen: (v: boolean) => void;
  triggerRef: React.RefObject<HTMLElement | null>;
}

const PopoverContext = React.createContext<PopoverContextValue | null>(null);

function usePopoverContext(hook: string): PopoverContextValue {
  const ctx = React.useContext(PopoverContext);
  if (ctx === null) throw new Error(`${hook} must be rendered inside <Popover>`);
  return ctx;
}

interface PopoverProps {
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
  children: React.ReactNode;
}

export function Popover({ open: controlled, defaultOpen, onOpenChange, children }: PopoverProps) {
  const [internal, setInternal] = React.useState(defaultOpen ?? false);
  const isControlled = controlled !== undefined;
  const open = isControlled ? controlled : internal;
  const triggerRef = React.useRef<HTMLElement>(null);

  const setOpen = React.useCallback(
    (next: boolean) => {
      if (!isControlled) setInternal(next);
      onOpenChange?.(next);
    },
    [isControlled, onOpenChange],
  );

  return (
    <PopoverContext.Provider value={{ open, setOpen, triggerRef }}>
      <div className="relative inline-block">{children}</div>
    </PopoverContext.Provider>
  );
}

interface PopoverTriggerProps {
  children: React.ReactElement;
  asChild?: boolean;
}

export function PopoverTrigger({ children }: PopoverTriggerProps) {
  const ctx = usePopoverContext("PopoverTrigger");
  const child = React.Children.only(children);
  return React.cloneElement(child as React.ReactElement<React.HTMLAttributes<HTMLElement>>, {
    ref: ctx.triggerRef as unknown as React.Ref<HTMLElement>,
    onClick: (e: React.MouseEvent<HTMLElement>) => {
      (child.props as React.HTMLAttributes<HTMLElement>).onClick?.(e);
      ctx.setOpen(!ctx.open);
    },
    "aria-expanded": ctx.open,
    "aria-haspopup": "dialog",
  } as React.HTMLAttributes<HTMLElement>);
}

interface PopoverContentProps extends React.HTMLAttributes<HTMLDivElement> {
  side?: "top" | "bottom" | "left" | "right";
  align?: "start" | "center" | "end";
  sideOffset?: number;
}

export function PopoverContent({
  side = "bottom",
  align = "start",
  sideOffset = 6,
  className,
  children,
  ...props
}: PopoverContentProps) {
  const ctx = usePopoverContext("PopoverContent");
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!ctx.open) return;
    const onDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (ref.current !== null && !ref.current.contains(target)) {
        if (ctx.triggerRef.current !== null && !ctx.triggerRef.current.contains(target)) {
          ctx.setOpen(false);
        }
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        ctx.setOpen(false);
        ctx.triggerRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [ctx]);

  if (!ctx.open) return null;

  const positionCls =
    side === "bottom"
      ? "top-full"
      : side === "top"
        ? "bottom-full"
        : side === "left"
          ? "right-full top-0"
          : "left-full top-0";
  const alignCls =
    side === "left" || side === "right"
      ? ""
      : align === "start"
        ? "left-0"
        : align === "end"
          ? "right-0"
          : "left-1/2 -translate-x-1/2";

  return (
    <div
      ref={ref}
      role="dialog"
      style={{ marginTop: side === "bottom" ? sideOffset : undefined, marginBottom: side === "top" ? sideOffset : undefined }}
      className={cn(
        "absolute z-50 min-w-[12rem] rounded-sx border border-border bg-card p-3 text-foreground shadow-lg",
        "animate-in fade-in-0 zoom-in-95",
        positionCls,
        alignCls,
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}
