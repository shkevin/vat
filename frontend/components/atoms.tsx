"use client";

import { useState } from "react";
import { SEV, ST, FINDING_TYPES } from "@/lib/constants";
import { mono, sans } from "@/lib/styles";

export { mono, sans };

export function Tag({
  children,
  color,
  bg,
}: {
  children: React.ReactNode;
  color: string;
  bg?: string;
}) {
  return (
    <span
      style={{
        ...mono,
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: "0.1em",
        color,
        background: bg || color + "18",
        padding: "2px 7px",
        borderRadius: 2,
        border: `1px solid ${color}28`,
        whiteSpace: "nowrap" as const,
        textTransform: "uppercase",
      }}
    >
      {children}
    </span>
  );
}

export function SevTag({ sev }: { sev: string }) {
  const s = SEV[sev] || SEV.Informational;
  return (
    <Tag color={s.c} bg={s.bg}>
      {sev}
    </Tag>
  );
}

export function StTag({ status }: { status: string }) {
  const s = ST[status] || ST["Open"];
  return (
    <Tag color={s.c} bg={s.b}>
      {status}
    </Tag>
  );
}

import { displaySourceName } from "@/lib/utils";

export function SrcTag({
  source,
  sources,
}: {
  source: string;
  sources: Array<{ id?: string; name: string; color?: string }>;
}) {
  const cfg = sources?.find((s) => s.id === source || s.name === source);
  return <Tag color={cfg?.color || "#888"}>{displaySourceName(source)}</Tag>;
}

export function TypeTag({ type }: { type: string }) {
  const t = FINDING_TYPES[type] || FINDING_TYPES.SCA;
  return (
    <Tag color={t.color}>
      {t.icon} {type}
    </Tag>
  );
}

export function Dot({ color }: { color: string }) {
  return (
    <span
      style={{
        display: "inline-block",
        width: 6,
        height: 6,
        borderRadius: "50%",
        background: color,
        flexShrink: 0,
      }}
    />
  );
}

const VARIANTS: Record<
  string,
  { bg: string; hv: string; c: string; bd: string }
> = {
  primary: { bg: "#1e3a5f", hv: "#1d4ed8", c: "#93c5fd", bd: "#1d4ed8" },
  approve: { bg: "#14532d", hv: "#166534", c: "#86efac", bd: "#16a34a" },
  reject: { bg: "#450a0a", hv: "#7f1d1d", c: "#fca5a5", bd: "#dc2626" },
  ghost: { bg: "transparent", hv: "#1e293b", c: "#64748b", bd: "#1e293b" },
  /** Theme-aware secondary: visible border + readable text on all themes */
  secondary: {
    bg: "var(--app-input-bg)",
    hv: "var(--app-card-bg)",
    c: "var(--app-fg)",
    bd: "var(--app-border)",
  },
  warn: { bg: "#431407", hv: "#78350f", c: "#fde68a", bd: "#d97706" },
  accent: { bg: "#0c2340", hv: "#0369a1", c: "#38bdf8", bd: "#0369a1" },
  purple: { bg: "#1e1040", hv: "#4c1d95", c: "#c084fc", bd: "#7c3aed" },
  orange: { bg: "#431407", hv: "#9a3412", c: "#fb923c", bd: "#ea580c" },
};

export function Btn({
  children,
  onClick,
  variant = "primary",
  size = "md",
  disabled = false,
  fullWidth = false,
  className,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: string;
  size?: string;
  disabled?: boolean;
  fullWidth?: boolean;
  className?: string;
}) {
  const [hov, setHov] = useState(false);
  const v = VARIANTS[variant] || VARIANTS.primary;
  return (
    <button
      className={className}
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        ...mono,
        background: hov && !disabled ? v.hv : v.bg,
        border: `1px solid ${v.bd}`,
        borderRadius: 4,
        padding: size === "sm" ? "4px 10px" : "7px 14px",
        color: v.c,
        fontSize: size === "sm" ? 11 : 12,
        fontWeight: 600,
        letterSpacing: "0.05em",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
        transition: "background 0.12s",
        whiteSpace: "nowrap" as const,
        width: fullWidth ? "100%" : undefined,
      }}
    >
      {children}
    </button>
  );
}

export function Field({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  rows,
  disabled,
  mono: m,
}: {
  label?: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
  rows?: number;
  disabled?: boolean;
  mono?: boolean;
}) {
  const base = {
    background: "var(--app-input-bg)",
    border: "1px solid var(--app-border)",
    borderRadius: 4,
    padding: "7px 11px",
    color: "var(--app-fg)",
    fontSize: 13,
    outline: "none",
    width: "100%",
    boxSizing: "border-box" as const,
    opacity: disabled ? 0.5 : 1,
    ...(m ? mono : sans),
    transition: "border-color 0.15s",
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {label && (
        <label
          style={{
            ...mono,
            fontSize: 10,
            fontWeight: 600,
            letterSpacing: "0.1em",
            color: "var(--app-muted)",
            textTransform: "uppercase",
          }}
        >
          {label}
        </label>
      )}
      {rows ? (
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          rows={rows}
          disabled={disabled}
          style={{ ...base, resize: "vertical" as const }}
          onFocus={(e) => (e.target.style.borderColor = "var(--app-accent)")}
          onBlur={(e) => (e.target.style.borderColor = "var(--app-border)")}
        />
      ) : (
        <input
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          disabled={disabled}
          style={base}
          onFocus={(e) => (e.target.style.borderColor = "var(--app-accent)")}
          onBlur={(e) => (e.target.style.borderColor = "var(--app-border)")}
        />
      )}
    </div>
  );
}
