"use client";

import { useMemo } from "react";
import { AlertsPanel } from "@/components/alerts/AlertsPanel";
import { getGroupedFindings } from "@/lib/findingGroupUtils";
import { mono, sans } from "@/lib/styles";
import { FINDING_TYPES, SEV_ORDER, SEV } from "@/lib/constants";
import type { Alert } from "@/types";
import type { Finding } from "@/types";

function normalizeSeverity(s: string): string {
  const lower = (s ?? "").toLowerCase().trim();
  if (lower === "info" || lower === "informational") return "Informational";
  if (lower === "critical") return "Critical";
  if (lower === "high") return "High";
  if (lower === "medium" || lower === "moderate") return "Medium";
  if (lower === "low") return "Low";
  return s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "Informational";
}

interface MetricsDashboardProps {
  alerts: Alert[];
  active: Finding[];
  total: number;
  open: number;
  inRev: number;
  overdue: number;
  waiverExpiring: number;
  archivedCount: number;
  onNavigate: (fId: string) => void;
  /** When true, total/open/etc are group counts. Severity and type breakdowns use groups. */
  groupFindings?: boolean;
}

function KeyMetricsTable({
  metrics,
}: {
  metrics: { label: string; value: number; color?: string; warn?: boolean }[];
}) {
  return (
    <div
      style={{
        background: "var(--app-card-bg)",
        border: "1px solid var(--app-border-subtle)",
        borderRadius: 8,
        overflow: "hidden",
      }}
    >
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <tbody>
          {metrics.map((m, i) => {
            const isWarn = m.warn && m.value > 0;
            const valColor = isWarn ? "var(--app-danger)" : m.color ?? "var(--app-fg)";
            return (
              <tr
                key={m.label}
                style={{
                  borderBottom: i < metrics.length - 1 ? "1px solid var(--app-border-subtle)" : undefined,
                }}
              >
                <td
                  style={{
                    padding: "12px 16px",
                    ...sans,
                    fontSize: 12,
                    color: "var(--app-muted)",
                    fontWeight: 500,
                  }}
                >
                  {m.label}
                </td>
                <td
                  style={{
                    padding: "12px 16px",
                    textAlign: "right",
                    ...mono,
                    fontSize: 18,
                    fontWeight: 600,
                    color: valColor,
                    fontVariantNumeric: "tabular-nums",
                  }}
                >
                  {m.value.toLocaleString()}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function TypeCard({
  type,
  count,
  total,
  color,
  icon,
}: {
  type: string;
  count: number;
  total: number;
  color: string;
  icon: string;
}) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div
      style={{
        background: "var(--app-card-bg)",
        border: `1px solid ${color}30`,
        borderRadius: 10,
        padding: "16px 18px",
        overflow: "hidden",
        boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 12,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span
            style={{
              fontSize: 20,
              width: 28,
              height: 28,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: `${color}20`,
              borderRadius: 6,
            }}
          >
            {icon}
          </span>
          <span
            style={{
              ...mono,
              fontSize: 12,
              fontWeight: 600,
              color: color,
            }}
          >
            {type}
          </span>
        </div>
        <span
          style={{
            ...mono,
            fontSize: 20,
            fontWeight: 700,
            color: color,
          }}
        >
          {count.toLocaleString()}
        </span>
      </div>
      <div
        style={{
          height: 6,
          background: "var(--app-border-subtle)",
          borderRadius: 3,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${Math.min(pct, 100)}%`,
            background: `linear-gradient(90deg, ${color}80, ${color})`,
            borderRadius: 3,
            transition: "width 0.4s ease",
          }}
        />
      </div>
    </div>
  );
}

function SectionHeader({ title }: { title: string }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        marginBottom: 16,
      }}
    >
      <div
        style={{
          ...mono,
          fontSize: 11,
          fontWeight: 700,
          letterSpacing: "0.12em",
          color: "var(--app-muted)",
          textTransform: "uppercase",
        }}
      >
        {title}
      </div>
      <div
        style={{
          flex: 1,
          height: 1,
          background: "var(--app-border-subtle)",
        }}
      />
    </div>
  );
}

function SeverityPill({
  severity,
  count,
}: {
  severity: string;
  count: number;
}) {
  const s = SEV[severity] ?? SEV.Informational;
  const c = s.c;
  const bg = s.bg;
  return (
    <span
      style={{
        ...mono,
        fontSize: 12,
        fontWeight: 600,
        padding: "6px 12px",
        borderRadius: 6,
        background: bg,
        color: c,
        border: `1px solid ${c}40`,
      }}
    >
      {severity}: {count.toLocaleString()}
    </span>
  );
}

export function MetricsDashboard({
  alerts,
  active,
  total,
  open,
  inRev,
  overdue,
  waiverExpiring,
  archivedCount,
  onNavigate,
  groupFindings = true,
}: MetricsDashboardProps) {
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const sev of SEV_ORDER) counts[sev] = 0;
    if (groupFindings) {
      const groups = getGroupedFindings(active, SEV_ORDER);
      for (const { findings } of groups) {
        const worst = findings.reduce((a, b) =>
          SEV_ORDER.indexOf(a.severity as (typeof SEV_ORDER)[number]) <=
          SEV_ORDER.indexOf(b.severity as (typeof SEV_ORDER)[number])
            ? a
            : b
        );
        const s = normalizeSeverity(worst.severity ?? "Informational");
        const key = (SEV_ORDER as readonly string[]).includes(s) ? s : "Informational";
        counts[key] = (counts[key] ?? 0) + 1;
      }
    } else {
      for (const f of active) {
        const s = normalizeSeverity(f.severity ?? "Informational");
        const key = (SEV_ORDER as readonly string[]).includes(s) ? s : "Informational";
        counts[key] = (counts[key] ?? 0) + 1;
      }
    }
    return SEV_ORDER.map((sev) => ({
      severity: sev,
      count: counts[sev] ?? 0,
    }));
  }, [active, groupFindings]);

  const keyMetrics = [
    { label: "Total active", value: total },
    { label: "Open", value: open },
    { label: "In review", value: inRev, color: "var(--app-accent)" },
    { label: "SLA overdue", value: overdue, warn: true },
    { label: "Alerts", value: alerts.length, warn: true, color: "var(--app-danger)" },
    { label: "Waiver expiring", value: waiverExpiring, color: "var(--app-warning)", warn: waiverExpiring > 0 },
    { label: "Archived", value: archivedCount },
  ];

  const metricsSection = (
    <div style={{ minWidth: 0 }}>
      <SectionHeader title="Key metrics" />
      <div style={{ marginBottom: 24 }}>
        <KeyMetricsTable metrics={keyMetrics} />
      </div>

      <SectionHeader title="By severity" />
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 8,
          marginBottom: 24,
        }}
      >
        {severityCounts.map(({ severity, count }) => (
          <SeverityPill key={severity} severity={severity} count={count} />
        ))}
      </div>

      <SectionHeader title="By type & status" />
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
          gap: 12,
        }}
      >
        {Object.keys(FINDING_TYPES).map((type) => {
          const ft = FINDING_TYPES[type];
          const n = groupFindings
            ? getGroupedFindings(active, SEV_ORDER).filter(
                (g) => g.findings.some((f) => f.findingType === type)
              ).length
            : active.filter((f) => f.findingType === type).length;
          if (!n) return null;
          return (
            <TypeCard
              key={type}
              type={type}
              count={n}
              total={total}
              color={ft.color}
              icon={ft.icon}
            />
          );
        })}
      </div>
    </div>
  );

  return (
    <div
      style={{
        padding: "0 4px",
        display: "flex",
        flexDirection: "column",
        gap: 20,
        flex: 1,
        minHeight: 0,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          paddingBottom: 16,
          borderBottom: "1px solid var(--app-border-subtle)",
          flexShrink: 0,
        }}
      >
        <h1
          style={{
            ...sans,
            fontSize: 24,
            fontWeight: 600,
            color: "var(--app-fg)",
            margin: 0,
            letterSpacing: "-0.02em",
          }}
        >
          Vulnerability Metrics
        </h1>
        <p
          style={{
            ...sans,
            fontSize: 12,
            color: "var(--app-muted)",
            marginTop: 4,
            marginBottom: 0,
          }}
        >
          Overview of active findings, SLA status, and compliance posture
        </p>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 10,
            marginTop: 16,
            alignItems: "center",
          }}
        >
          <span
            style={{
              ...mono,
              fontSize: 13,
              fontWeight: 600,
              color: "var(--app-fg)",
            }}
          >
            Total: {total.toLocaleString()}
          </span>
          {severityCounts
            .filter(({ count }) => count > 0)
            .map(({ severity, count }) => (
              <SeverityPill key={severity} severity={severity} count={count} />
            ))}
        </div>
      </div>

      <div
        className="metrics-dashboard-grid"
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1fr) minmax(320px, 400px)",
          gap: 24,
          flex: 1,
          minHeight: 0,
          overflow: "hidden",
          alignContent: "stretch",
        }}
      >
        <div
          style={{
            minWidth: 0,
            display: "flex",
            flexDirection: "column",
            minHeight: 0,
            overflow: "hidden",
          }}
        >
          <AlertsPanel alerts={alerts} onNavigate={onNavigate} />
        </div>
        <div
          style={{
            minWidth: 0,
            overflowY: "auto",
            overflowX: "hidden",
          }}
        >
          {metricsSection}
        </div>
      </div>
    </div>
  );
}
