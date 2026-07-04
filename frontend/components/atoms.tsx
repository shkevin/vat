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
      className="modern-chip"
      style={{
        ...sans,
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: "0.01em",
        color,
        background: bg || color + "22",
        padding: "3px 9px",
        borderRadius: 999,
        border: `1px solid ${color}59`,
        whiteSpace: "nowrap" as const,
        textTransform: "none",
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
  const normalized = (source || "").trim().toLowerCase();
  const isFeedMaterialized = normalized === "vuln_feed_match";
  return (
    <Tag color={isFeedMaterialized ? "var(--app-accent)" : (cfg?.color || "var(--app-muted)")}>
      {displaySourceName(source)}
    </Tag>
  );
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
  primary: {
    bg: "color-mix(in srgb, var(--ui-accent) 24%, transparent)",
    hv: "color-mix(in srgb, var(--ui-accent) 34%, transparent)",
    c: "var(--ui-accent)",
    bd: "color-mix(in srgb, var(--ui-accent) 45%, transparent)",
  },
  approve: {
    bg: "color-mix(in srgb, var(--ui-success) 24%, transparent)",
    hv: "color-mix(in srgb, var(--ui-success) 34%, transparent)",
    c: "var(--ui-success)",
    bd: "color-mix(in srgb, var(--ui-success) 45%, transparent)",
  },
  reject: {
    bg: "color-mix(in srgb, var(--ui-danger) 22%, transparent)",
    hv: "color-mix(in srgb, var(--ui-danger) 30%, transparent)",
    c: "var(--ui-danger)",
    bd: "color-mix(in srgb, var(--ui-danger) 45%, transparent)",
  },
  ghost: {
    bg: "transparent",
    hv: "color-mix(in srgb, var(--ui-surface-2) 80%, transparent)",
    c: "var(--ui-text-muted)",
    bd: "var(--ui-border-subtle)",
  },
  /** Theme-aware secondary: visible border + readable text on all themes */
  secondary: {
    bg: "var(--ui-surface-2)",
    hv: "var(--ui-surface-1)",
    c: "var(--ui-text-primary)",
    bd: "var(--ui-border)",
  },
  warn: {
    bg: "color-mix(in srgb, var(--ui-warning) 22%, transparent)",
    hv: "color-mix(in srgb, var(--ui-warning) 30%, transparent)",
    c: "var(--ui-warning)",
    bd: "color-mix(in srgb, var(--ui-warning) 45%, transparent)",
  },
  accent: {
    bg: "color-mix(in srgb, var(--ui-accent) 20%, transparent)",
    hv: "color-mix(in srgb, var(--ui-accent) 32%, transparent)",
    c: "var(--ui-accent)",
    bd: "color-mix(in srgb, var(--ui-accent) 48%, transparent)",
  },
  purple: {
    bg: "color-mix(in srgb, var(--ui-accent-strong) 20%, transparent)",
    hv: "color-mix(in srgb, var(--ui-accent-strong) 32%, transparent)",
    c: "var(--ui-accent-strong)",
    bd: "color-mix(in srgb, var(--ui-accent-strong) 50%, transparent)",
  },
  orange: {
    bg: "color-mix(in srgb, var(--ui-warning) 22%, transparent)",
    hv: "color-mix(in srgb, var(--ui-warning) 34%, transparent)",
    c: "var(--ui-warning)",
    bd: "color-mix(in srgb, var(--ui-warning) 48%, transparent)",
  },
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
        ...sans,
        background: hov && !disabled ? v.hv : v.bg,
        border: `1px solid ${v.bd}`,
        borderRadius: 10,
        padding: size === "sm" ? "6px 11px" : "9px 14px",
        color: v.c,
        fontSize: size === "sm" ? 12 : 13,
        fontWeight: 600,
        letterSpacing: "0.01em",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
        transition: "background var(--motion-fast) ease",
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
            ...sans,
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.02em",
            color: "var(--app-muted)",
            textTransform: "none",
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
