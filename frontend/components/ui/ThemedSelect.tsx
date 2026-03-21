"use client";

import { useState, useRef, useEffect } from "react";
import { ChevronDown } from "lucide-react";
import { sans } from "@/lib/styles";

export interface ThemedSelectOption {
  value: string;
  label: string;
}

interface ThemedSelectProps {
  value: string;
  options: ThemedSelectOption[];
  onChange: (value: string) => void;
  placeholder?: string;
  icon?: React.ReactNode;
  "aria-label"?: string;
}

/**
 * Custom dropdown that respects theme variables.
 * Native <select> options often render with system styling (white bg) in dark themes.
 */
export function ThemedSelect({
  value,
  options,
  onChange,
  placeholder = "—",
  icon,
  "aria-label": ariaLabel,
}: ThemedSelectProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onOutside);
    return () => document.removeEventListener("mousedown", onOutside);
  }, [open]);

  const selectedLabel =
    options.find((o) => o.value === value)?.label ?? (value || placeholder);

  return (
    <div ref={ref} style={{ position: "relative", minWidth: 140 }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-label={ariaLabel}
        aria-expanded={open}
        aria-haspopup="listbox"
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          width: "100%",
          padding: "6px 12px",
          borderRadius: 6,
          border: "1px solid var(--app-border)",
          background: "var(--app-input-bg)",
          color: options.length > 0 ? "var(--app-fg)" : "var(--app-muted)",
          fontSize: 12,
          cursor: "pointer",
          textAlign: "left",
          ...sans,
        }}
      >
        {icon}
        <span
          style={{
            flex: 1,
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {selectedLabel}
        </span>
        <ChevronDown
          size={12}
          style={{
            color: "var(--app-muted)",
            flexShrink: 0,
            transform: open ? "rotate(180deg)" : undefined,
            transition: "transform 0.15s",
          }}
        />
      </button>
      {open && (
        <ul
          role="listbox"
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            right: 0,
            margin: 0,
            marginTop: 4,
            padding: 4,
            listStyle: "none",
            background: "var(--app-card-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 6,
            boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
            zIndex: 50,
            maxHeight: 220,
            overflowY: "auto",
          }}
        >
          {options.map((opt) => (
            <li
              key={opt.value}
              role="option"
              aria-selected={opt.value === value}
              onClick={() => {
                onChange(opt.value);
                setOpen(false);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onChange(opt.value);
                  setOpen(false);
                }
              }}
              tabIndex={0}
              style={{
                padding: "8px 12px",
                borderRadius: 4,
                cursor: "pointer",
                color: "var(--app-fg)",
                background:
                  opt.value === value
                    ? "color-mix(in srgb, var(--app-accent) 20%, transparent)"
                    : "transparent",
                fontSize: 12,
                ...sans,
              }}
              onMouseEnter={(e) => {
                if (opt.value !== value) {
                  (e.currentTarget as HTMLElement).style.background =
                    "color-mix(in srgb, var(--app-accent) 12%, transparent)";
                }
              }}
              onMouseLeave={(e) => {
                if (opt.value !== value) {
                  (e.currentTarget as HTMLElement).style.background =
                    "transparent";
                }
              }}
            >
              {opt.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
