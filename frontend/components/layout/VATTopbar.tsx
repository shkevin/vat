"use client";

import { mono } from "@/lib/styles";

interface TabConfig {
  id: string;
  label: string;
  badge?: number;
  warn?: boolean;
}

interface VATTopbarProps {
  view: string;
  onViewChange: (id: string) => void;
  tabs: TabConfig[];
  alertCount: number;
}

export function VATTopbar({
  view,
  onViewChange,
  tabs,
  alertCount,
}: VATTopbarProps) {
  return (
    <div
      style={{
        background: "#060d1b",
        borderBottom: "1px solid #0d1a2e",
        padding: "0 20px",
        display: "flex",
        alignItems: "center",
        height: 48,
        position: "sticky",
        top: 0,
        zIndex: 50,
        flexWrap: "wrap",
      }}
    >
      <div
        style={{
          ...mono,
          fontSize: 13,
          fontWeight: 700,
          color: "#f1f5f9",
          letterSpacing: "0.06em",
          marginRight: 18,
        }}
      >
        <span style={{ color: "#1d4ed8" }}>▣</span> VAT
        <span
          style={{
            fontSize: 9,
            color: "#1e3a5f",
            marginLeft: 8,
            fontWeight: 400,
          }}
        >
          v4
        </span>
      </div>

      {tabs.map(({ id, label, badge = 0, warn }) => {
        const active = view === id;
        return (
          <button
            key={id}
            onClick={() => onViewChange(id)}
            style={{
              ...mono,
              background: "none",
              border: "none",
              borderBottom: active ? "2px solid #3b82f6" : "2px solid transparent",
              color: active ? "#e2e8f0" : "#475569",
              padding: "0 14px",
              height: 48,
              cursor: "pointer",
              fontSize: 12,
              fontWeight: active ? 700 : 400,
              letterSpacing: "0.05em",
              display: "flex",
              alignItems: "center",
              gap: 7,
              transition: "color 0.15s",
            }}
          >
            {label}
            {badge > 0 && (
              <span
                style={{
                  background: warn ? "#f87060" : "#1d4ed8",
                  color: "#fff",
                  fontSize: 9,
                  fontWeight: 700,
                  padding: "1px 5px",
                  borderRadius: 10,
                }}
              >
                {badge}
              </span>
            )}
          </button>
        );
      })}

      {alertCount > 0 && (
        <div
          style={{
            marginLeft: "auto",
            display: "flex",
            alignItems: "center",
            gap: 6,
            cursor: "pointer",
          }}
          onClick={() => onViewChange("dash")}
        >
          <span
            style={{
              ...mono,
              fontSize: 10,
              fontWeight: 700,
              color: "#f87060",
            }}
          >
            🚨 {alertCount}
          </span>
        </div>
      )}
    </div>
  );
}
