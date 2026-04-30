"use client";

import { useEffect, useRef } from "react";

/**
 * Trap keyboard focus inside ``ref``'s subtree while ``active`` is true,
 * restore focus to the previously-focused element when ``active`` flips
 * back to false. Use on modals so Tab cycles the modal's focusable
 * elements instead of escaping into the underlying page, and so closing
 * the modal returns focus to the trigger that opened it.
 *
 * Lightweight, no deps. Listens for Tab / Shift+Tab on the document
 * during the active window and forces wrap-around when focus would
 * leave the container.
 */
export function useFocusTrap<T extends HTMLElement>(
  active: boolean,
): React.RefObject<T> {
  const ref = useRef<T>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!active) return;
    if (typeof document === "undefined") return;

    // Remember whoever had focus when the modal opened.
    restoreRef.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;

    const container = ref.current;
    if (!container) return;

    // Move focus into the modal — first focusable element if any, else
    // the container itself (set tabIndex=-1 on the root if you want
    // something better than this fallback).
    const first = getFirstFocusable(container);
    (first ?? container).focus();

    function onKeyDown(e: KeyboardEvent) {
      if (e.key !== "Tab") return;
      const focusables = getFocusableList(container!);
      if (focusables.length === 0) {
        e.preventDefault();
        return;
      }
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const activeEl = document.activeElement as HTMLElement | null;
      if (e.shiftKey && activeEl === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && activeEl === last) {
        e.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      // Restore focus to whatever opened us. Guard against the trigger
      // having unmounted in the meantime.
      const target = restoreRef.current;
      if (target && document.contains(target)) {
        try {
          target.focus();
        } catch {
          /* ignore */
        }
      }
      restoreRef.current = null;
    };
  }, [active]);

  return ref as React.RefObject<T>;
}

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function getFocusableList(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR))
    // querySelectorAll matches detached/hidden elements too; filter on
    // visibility so we don't focus something a user can't see.
    .filter((el) => el.offsetParent !== null || el === container);
}

function getFirstFocusable(container: HTMLElement): HTMLElement | null {
  return getFocusableList(container)[0] ?? null;
}
