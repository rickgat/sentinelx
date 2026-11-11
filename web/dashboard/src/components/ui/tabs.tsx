"use client";

import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * Zero-dependency Tabs primitive — WAI-ARIA compliant (roles: tablist,
 * tab, tabpanel; roving tabindex for keyboard nav). We build our own
 * instead of pulling @radix-ui/react-tabs because the surface area we need
 * (uncontrolled + controlled, keyboard arrow nav, activation on focus)
 * is small enough that a ~120-line implementation beats a new dep.
 */

interface TabsContextValue {
  value: string;
  setValue: (next: string) => void;
  baseId: string;
  orientation: "horizontal" | "vertical";
  register: (val: string) => void;
  unregister: (val: string) => void;
  order: React.MutableRefObject<string[]>;
}

const TabsContext = React.createContext<TabsContextValue | null>(null);

function useTabsContext(hook: string): TabsContextValue {
  const ctx = React.useContext(TabsContext);
  if (ctx === null) {
    throw new Error(`${hook} must be rendered inside <Tabs>`);
  }
  return ctx;
}

interface TabsProps {
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  orientation?: "horizontal" | "vertical";
  className?: string;
  children: React.ReactNode;
}

let idCounter = 0;
function nextId(): string {
  idCounter += 1;
  return `tabs-${idCounter}`;
}

export function Tabs({
  value: controlledValue,
  defaultValue,
  onValueChange,
  orientation = "horizontal",
  className,
  children,
}: TabsProps) {
  const [internalValue, setInternalValue] = React.useState(defaultValue ?? "");
  const isControlled = controlledValue !== undefined;
  const value = isControlled ? controlledValue : internalValue;
  const baseId = React.useMemo(() => nextId(), []);
  const order = React.useRef<string[]>([]);

  const setValue = React.useCallback(
    (next: string) => {
      if (!isControlled) setInternalValue(next);
      onValueChange?.(next);
    },
    [isControlled, onValueChange],
  );

  const register = React.useCallback((val: string) => {
    if (!order.current.includes(val)) order.current.push(val);
  }, []);
  const unregister = React.useCallback((val: string) => {
    order.current = order.current.filter((v) => v !== val);
  }, []);

  return (
    <TabsContext.Provider
      value={{ value, setValue, baseId, orientation, register, unregister, order }}
    >
      <div className={className} data-orientation={orientation}>
        {children}
      </div>
    </TabsContext.Provider>
  );
}

export function TabsList({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  const { orientation } = useTabsContext("TabsList");
  return (
    <div
      role="tablist"
      aria-orientation={orientation}
      className={cn(
        "inline-flex items-center gap-1 rounded-sx border border-border bg-card p-1 text-muted-foreground",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}

interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string;
}

export function TabsTrigger({ value, className, children, ...props }: TabsTriggerProps) {
  const ctx = useTabsContext("TabsTrigger");
  const isActive = ctx.value === value;
  const tabId = `${ctx.baseId}-tab-${value}`;
  const panelId = `${ctx.baseId}-panel-${value}`;

  React.useEffect(() => {
    ctx.register(value);
    return () => ctx.unregister(value);
    // deliberately track only `value`; register/unregister are stable
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  const onKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>) => {
    const order = ctx.order.current;
    if (order.length === 0) return;
    const forward = ctx.orientation === "vertical" ? "ArrowDown" : "ArrowRight";
    const backward = ctx.orientation === "vertical" ? "ArrowUp" : "ArrowLeft";
    if (event.key !== forward && event.key !== backward && event.key !== "Home" && event.key !== "End") {
      return;
    }
    event.preventDefault();
    const idx = order.indexOf(value);
    let target = idx;
    if (event.key === forward) target = (idx + 1) % order.length;
    else if (event.key === backward) target = (idx - 1 + order.length) % order.length;
    else if (event.key === "Home") target = 0;
    else if (event.key === "End") target = order.length - 1;
    const nextValue = order[target];
    if (nextValue === undefined) return;
    ctx.setValue(nextValue);
    const nextEl = document.getElementById(`${ctx.baseId}-tab-${nextValue}`);
    nextEl?.focus();
  };

  return (
    <button
      type="button"
      role="tab"
      id={tabId}
      aria-controls={panelId}
      aria-selected={isActive}
      tabIndex={isActive ? 0 : -1}
      onClick={() => ctx.setValue(value)}
      onKeyDown={onKeyDown}
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap rounded-sx px-3 py-1.5 text-xs font-medium transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
        isActive
          ? "bg-muted text-foreground shadow-sm"
          : "text-muted-foreground hover:bg-muted/60 hover:text-foreground",
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
  forceMount?: boolean;
}

export function TabsContent({ value, forceMount, className, children, ...props }: TabsContentProps) {
  const ctx = useTabsContext("TabsContent");
  const isActive = ctx.value === value;
  if (!isActive && forceMount !== true) return null;
  return (
    <div
      role="tabpanel"
      id={`${ctx.baseId}-panel-${value}`}
      aria-labelledby={`${ctx.baseId}-tab-${value}`}
      hidden={!isActive}
      className={cn("mt-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent", className)}
      tabIndex={0}
      {...props}
    >
      {isActive ? children : null}
    </div>
  );
}
