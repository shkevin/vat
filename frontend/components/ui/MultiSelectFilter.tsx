"use client";

import { useState, useRef, useEffect } from "react";
import { ChevronDown, Filter } from "lucide-react";
import { sans } from "@/lib/styles";

export interface MultiSelectOption {
  value: string;
  label: string;
  /** Optional count shown to the right of the label */
  count?: number;
}

interface MultiSelectFilterProps {
  label: string;
  options: MultiSelectOption[];
  selected: Set<string>;
  onChange: (selected: Set<string>) => void;
  placeholder?: string;
  "aria-label"?: string;
}

/**
 * Multi-select filter dropdown. Shows "All" when empty, or "X selected" when some chosen.
 */
export function MultiSelectFilter({
  label,
  options,
  selected,
  onChange,
  placeholder = "All",
  "aria-label": ariaLabel,
}: MultiSelectFilterProps) {
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

  const toggle = (value: string) => {
    const next = new Set(selected);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    onChange(next);
  };

  const clearAll = () => {
    onChange(new Set());
    setOpen(false);
  };

  const selectAll = () => {
    onChange(new Set(options.map((o) => o.value)));
  };

  const displayText =
    selected.size === 0
      ? placeholder
      : selected.size === options.length
        ? "All"
        : `${selected.size} selected`;

  return (
    <div ref={ref} style={{ position: "relative", minWidth: 120 }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-label={ariaLabel ?? `Filter by ${label}`}
        aria-expanded={open}
        aria-haspopup="listbox"
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          width: "100%",
          padding: "6px 10px",
          borderRadius: 6,
          border: "1px solid var(--app-border)",
          background:
            selected.size > 0
              ? "color-mix(in srgb, var(--app-accent) 12%, transparent)"
              : "var(--app-input-bg)",
          color: "var(--app-fg)",
          fontSize: 11,
          cursor: "pointer",
          textAlign: "left",
          ...sans,
        }}
      >
        <Filter
          size={12}
          style={{ color: "var(--app-muted)", flexShrink: 0 }}
        />
        <span
          style={{
            flex: 1,
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {label}: {displayText}
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
        <div
          role="listbox"
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            minWidth: 180,
            marginTop: 4,
            padding: 6,
            background: "var(--app-card-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 6,
            boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
            zIndex: 50,
            maxHeight: 280,
            overflowY: "auto",
          }}
        >
          <div style={{ display: "flex", gap: 6, marginBottom: 6 }}>
            <button
              type="button"
              onClick={selectAll}
              style={{
                fontSize: 10,
                padding: "4px 8px",
                background: "var(--app-input-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 4,
                color: "var(--app-fg)",
                cursor: "pointer",
                ...sans,
              }}
            >
              All
            </button>
            <button
              type="button"
              onClick={clearAll}
              style={{
                fontSize: 10,
                padding: "4px 8px",
                background: "var(--app-input-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 4,
                color: "var(--app-fg)",
                cursor: "pointer",
                ...sans,
              }}
            >
              Clear
            </button>
          </div>
          {options.map((opt) => (
            <label
              key={opt.value}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "6px 12px",
                borderRadius: 4,
                cursor: "pointer",
                color: "var(--app-fg)",
                fontSize: 12,
                ...sans,
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLElement).style.background =
                  "color-mix(in srgb, var(--app-accent) 12%, transparent)";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.background =
                  "transparent";
              }}
            >
              <input
                type="checkbox"
                checked={selected.has(opt.value)}
                onChange={() => toggle(opt.value)}
                style={{ accentColor: "var(--app-accent)", cursor: "pointer" }}
              />
              <span style={{ flex: 1 }}>{opt.label}</span>
              {opt.count !== undefined && (
                <span style={{ color: "var(--app-muted)", fontSize: 11 }}>
                  {opt.count}
                </span>
              )}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}
