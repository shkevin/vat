"use client";

import { useState, useRef, useEffect } from "react";
import { createPortal } from "react-dom";
import { sans } from "@/lib/styles";

interface ThemedTooltipProps {
  content: string;
  children: React.ReactNode;
  /** Placement relative to trigger. Default: top */
  placement?: "top" | "bottom" | "left" | "right";
  style?: React.CSSProperties;
}

export function ThemedTooltip({
  content,
  children,
  placement = "top",
  style,
}: ThemedTooltipProps) {
  const [visible, setVisible] = useState(false);
  const [coords, setCoords] = useState<{ top: number; left: number; transform: string } | null>(null);
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!visible || !ref.current) return;
    const onOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setVisible(false);
    };
    document.addEventListener("mousedown", onOutside);
    return () => document.removeEventListener("mousedown", onOutside);
  }, [visible]);

  useEffect(() => {
    if (!visible || !ref.current) {
      setCoords(null);
      return;
    }
    const el = ref.current;
    const rect = el.getBoundingClientRect();
    const gap = 6;
    let top = 0;
    let left = rect.left + rect.width / 2;
    let transform = "translateX(-50%)";
    switch (placement) {
      case "top":
        top = rect.top - gap;
        transform = "translateX(-50%) translateY(-100%)";
        break;
      case "bottom":
        top = rect.bottom + gap;
        break;
      case "left":
        top = rect.top + rect.height / 2;
        left = rect.left - gap;
        transform = "translate(-100%, -50%)";
        break;
      case "right":
        top = rect.top + rect.height / 2;
        left = rect.right + gap;
        transform = "translateY(-50%)";
        break;
    }
    setCoords({ top, left, transform });
  }, [visible, placement]);

  const base: React.CSSProperties = {
    position: "fixed",
    zIndex: 9999,
    minWidth: 240,
    maxWidth: 320,
    padding: 10,
    background: "var(--app-card-bg)",
    border: "1px solid var(--app-border-subtle)",
    borderRadius: 6,
    boxShadow: "0 4px 12px rgba(0,0,0,0.2)",
    ...sans,
    fontSize: 12,
    lineHeight: 1.5,
    color: "var(--app-fg)",
    whiteSpace: "pre-line",
  };

  const tooltipEl =
    visible && coords ? (
      <div
        role="tooltip"
        style={{
          ...base,
          top: coords.top,
          left: coords.left,
          transform: coords.transform,
        }}
      >
        {content}
      </div>
    ) : null;

  const Wrapper = "span";
  return (
    <>
      <Wrapper
        ref={ref}
        style={{ position: "relative", display: "inline-flex", ...style }}
        onMouseEnter={() => setVisible(true)}
        onMouseLeave={() => setVisible(false)}
      >
        {children}
      </Wrapper>
      {typeof document !== "undefined" && tooltipEl
        ? createPortal(tooltipEl, document.body)
        : null}
    </>
  );
}
