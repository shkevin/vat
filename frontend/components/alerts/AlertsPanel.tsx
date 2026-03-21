"use client";

import { Tag } from "@/components/atoms";
import { sans } from "@/lib/styles";
import { ALERT_META } from "@/lib/styles";
import type { Alert } from "@/types";

interface AlertsPanelProps {
  alerts: Alert[];
  onNavigate: (fId: string) => void;
}

export function AlertsPanel({ alerts, onNavigate }: AlertsPanelProps) {
  if (!alerts.length) {
    return (
      <div
        style={{
          background: "var(--app-card-bg)",
          border: "1px solid var(--app-border-subtle)",
          borderRadius: 10,
          padding: "20px 24px",
          marginBottom: 24,
          display: "flex",
          gap: 14,
          alignItems: "center",
          boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
        }}
      >
        <span
          style={{
            fontSize: 22,
            width: 40,
            height: 40,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "var(--app-success)20",
            borderRadius: 8,
          }}
        >
          ✓
        </span>
        <div>
          <div
            style={{
              ...sans,
              fontSize: 14,
              fontWeight: 600,
              color: "var(--app-fg)",
            }}
          >
            All clear
          </div>
          <span
            style={{
              ...sans,
              fontSize: 12,
              color: "var(--app-muted)",
            }}
          >
            No active alerts. All SLAs on track, no expired waivers.
          </span>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        flex: 1,
        minHeight: 0,
        overflow: "hidden",
        background: "var(--app-card-bg)",
        border: "1px solid var(--app-danger)40",
        borderRadius: 10,
        boxShadow: "0 1px 3px rgba(248,112,96,0.08)",
      }}
    >
      <div
        style={{
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "14px 20px",
          background: "var(--app-danger)08",
          borderBottom: "1px solid var(--app-danger)20",
        }}
      >
        <span
          style={{
            fontSize: 16,
            width: 28,
            height: 28,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "var(--app-danger)20",
            borderRadius: 6,
          }}
        >
          ▣
        </span>
        <span
          style={{
            ...sans,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: "0.1em",
            color: "var(--app-danger)",
            textTransform: "uppercase",
          }}
        >
          {alerts.length} Active Alert{alerts.length !== 1 ? "s" : ""}
        </span>
      </div>
      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          gap: 6,
          overflowY: "auto",
          padding: 12,
        }}
      >
        {alerts.map((a, i) => {
          const meta = ALERT_META[a.type] ?? {
            icon: "⚠️",
            color: "#f5a623",
            label: "ALERT",
          };
          return (
            <div
              key={`${a.type}-${a.fId ?? i}`}
              onClick={() => a.fId && onNavigate(a.fId)}
              style={{
                display: "flex",
                gap: 12,
                alignItems: "flex-start",
                padding: "10px 14px",
                background: "var(--app-header-bg)",
                borderRadius: 8,
                border: `1px solid ${meta.color}20`,
                cursor: a.fId ? "pointer" : "default",
                transition: "background 0.15s ease, border-color 0.15s ease",
              }}
            >
              <span
                style={{
                  fontSize: 14,
                  flexShrink: 0,
                  width: 24,
                  height: 24,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: `${meta.color}20`,
                  borderRadius: 4,
                }}
              >
                {meta.icon}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    marginBottom: 2,
                  }}
                >
                  <Tag color={meta.color}>{meta.label}</Tag>
                  {a.waiverRef && (
                    <span
                      style={{
                        fontFamily: "monospace",
                        fontSize: 10,
                        color: "var(--app-muted)",
                      }}
                    >
                      {a.waiverRef}
                    </span>
                  )}
                </div>
                <span
                  style={{
                    ...sans,
                    fontSize: 12,
                    color: "var(--app-muted)",
                    lineHeight: 1.4,
                  }}
                >
                  {a.msg}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
