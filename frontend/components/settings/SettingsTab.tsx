"use client";

import { useState } from "react";
import { IntegrationCanvas } from "./IntegrationCanvas";
import { AccessSettingsPage } from "./AccessSettingsPage";
import { mono } from "@/lib/styles";
import type { Source } from "@/types";
import type { Tracker } from "@/types";
import type { WatchedLabel } from "@/types";

interface SettingsTabProps {
  sources: Source[];
  tracker: Tracker;
  labels: WatchedLabel[];
  onSourcesChange?: (sources: Source[]) => void;
  onTrackerChange?: (tracker: Tracker) => void;
  onLabelsChange?: (labels: WatchedLabel[]) => void;
}

type SettingsSubTab = "integrations" | "access";

/** Settings with sub-tabs: Integrations (flow canvas) | Access (tenants & users) */
export function SettingsTab({
  sources,
  tracker,
  labels,
  onSourcesChange,
  onTrackerChange,
  onLabelsChange,
}: SettingsTabProps) {
  const [subTab, setSubTab] = useState<SettingsSubTab>("integrations");

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        flex: 1,
        minHeight: 0,
        overflow: "hidden",
      }}
    >
      {/* Sub-tab navigation */}
      <div
        style={{
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          gap: 0,
          borderBottom: "1px solid var(--app-border)",
          padding: "0 20px",
        }}
      >
        <button
          onClick={() => setSubTab("integrations")}
          style={{
            ...mono,
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.06em",
            padding: "14px 20px",
            background: "none",
            border: "none",
            borderBottom:
              subTab === "integrations"
                ? "2px solid var(--app-accent)"
                : "2px solid transparent",
            color:
              subTab === "integrations" ? "var(--app-fg)" : "var(--app-muted)",
            cursor: "pointer",
            marginBottom: -1,
            transition: "color 0.15s, border-color 0.15s",
          }}
        >
          Integrations
        </button>
        <button
          onClick={() => setSubTab("access")}
          style={{
            ...mono,
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.06em",
            padding: "14px 20px",
            background: "none",
            border: "none",
            borderBottom:
              subTab === "access"
                ? "2px solid var(--app-accent)"
                : "2px solid transparent",
            color: subTab === "access" ? "var(--app-fg)" : "var(--app-muted)",
            cursor: "pointer",
            marginBottom: -1,
            transition: "color 0.15s, border-color 0.15s",
          }}
        >
          Access
        </button>
      </div>

      <div
        style={{
          flex: 1,
          minHeight: 0,
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {subTab === "integrations" && (
          <div
            style={{
              flex: 1,
              minHeight: 0,
              overflow: "hidden",
              display: "flex",
              flexDirection: "column",
            }}
          >
            <IntegrationCanvas
              sources={sources}
              tracker={tracker}
              labels={labels}
              onSourcesChange={onSourcesChange}
              onTrackerChange={onTrackerChange}
              onLabelsChange={onLabelsChange}
            />
          </div>
        )}
        {subTab === "access" && (
          <div
            style={{
              flex: 1,
              minHeight: 0,
              overflow: "hidden",
              display: "flex",
              flexDirection: "column",
            }}
          >
            <AccessSettingsPage />
          </div>
        )}
      </div>
    </div>
  );
}
