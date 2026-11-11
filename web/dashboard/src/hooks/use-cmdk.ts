"use client";

import * as React from "react";

/**
 * Wires a global `keydown` listener that toggles a piece of state when the
 * user presses `Cmd+K` on macOS or `Ctrl+K` elsewhere — the standard
 * command-palette shortcut.
 *
 * The handler skips when focus is inside a text-entry surface
 * (INPUT / TEXTAREA / SELECT / contenteditable) so the shortcut never
 * eats keystrokes the user intends for a form field.
 */
export interface UseCmdkResult {
  open: boolean;
  setOpen: React.Dispatch<React.SetStateAction<boolean>>;
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (target === null || !(target instanceof HTMLElement)) {
    return false;
  }
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") {
    return true;
  }
  return target.isContentEditable;
}

export function useCmdk(): UseCmdkResult {
  const [open, setOpen] = React.useState(false);

  React.useEffect(() => {
    function handler(event: KeyboardEvent) {
      const isShortcut =
        (event.key === "k" || event.key === "K") && (event.metaKey || event.ctrlKey);
      if (!isShortcut) {
        return;
      }
      // Suppress the shortcut while focus is inside an editable surface so
      // we don't eat keystrokes a user intends for that field. The dialog's
      // own Esc handling (built into Radix) is the canonical close path.
      if (isEditableTarget(event.target)) {
        return;
      }
      event.preventDefault();
      setOpen((prev) => !prev);
    }
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return { open, setOpen };
}
