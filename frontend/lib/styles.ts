/**
 * Shared typography and theme tokens for VAT UI.
 */

export const mono = {
  fontFamily: "var(--font-mono), 'JetBrains Mono', monospace",
} as const;

export const sans = {
  fontFamily: "var(--font-sans), 'IBM Plex Sans', system-ui, sans-serif",
} as const;

/** Alert type metadata for AlertsPanel */
export const ALERT_META: Record<
  string,
  { icon: string; color: string; label: string }
> = {
  "expired-waiver": { icon: "⏰", color: "#f87060", label: "EXPIRED WAIVER" },
  "waiver-expiring": { icon: "⚠️", color: "#f5a623", label: "WAIVER EXPIRING" },
  "sla-48h": { icon: "🔔", color: "#f5a623", label: "SLA 48H" },
  overdue: { icon: "🚨", color: "#f87060", label: "OVERDUE" },
  regression: { icon: "🔁", color: "#fb923c", label: "REGRESSION" },
  "secret-open": { icon: "🔑", color: "#f87060", label: "OPEN SECRET" },
} as const;
