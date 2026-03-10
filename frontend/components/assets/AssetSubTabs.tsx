"use client";

import type { AppConfig } from "@/config/app";
import { mono } from "@/lib/styles";

export type AssetTabId = "findings" | "waivers" | "sbom" | "review";

const TABS: { id: AssetTabId; label: string; adminOnly?: boolean }[] = [
  { id: "findings", label: "Findings" },
  { id: "waivers", label: "Waivers" },
  { id: "sbom", label: "SBOM/Licenses" },
  { id: "review", label: "Review", adminOnly: true },
];

interface AssetSubTabsProps {
  config: AppConfig;
  currentTab: AssetTabId;
  onTabChange: (tab: AssetTabId) => void;
}

export function AssetSubTabs({ config, currentTab, onTabChange }: AssetSubTabsProps) {
  const isAdmin = config.isAdmin ?? false;

  return (
    <nav
      style={{
        display: "flex",
        alignItems: "center",
        gap: 2,
        padding: "0 20px",
        background: "color-mix(in srgb, var(--app-header-bg) 95%, var(--app-border))",
        borderBottom: "1px solid var(--app-header-border)",
        minHeight: 36,
      }}
    >
      {TABS.filter((t) => !t.adminOnly || isAdmin).map((tab) => {
        const active = currentTab === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onTabChange(tab.id)}
            style={{
              ...mono,
              background: "none",
              border: "none",
              borderBottom: active ? "2px solid var(--app-accent-emerald)" : "2px solid transparent",
              color: active ? "var(--app-accent-emerald)" : "var(--app-muted)",
              padding: "6px 12px",
              marginBottom: -1,
              borderRadius: 0,
              cursor: "pointer",
              fontSize: 11,
              fontWeight: active ? 600 : 400,
            }}
          >
            {tab.label}
          </button>
        );
      })}
    </nav>
  );
}
