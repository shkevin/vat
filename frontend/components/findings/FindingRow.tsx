"use client";

import { useState } from "react";
import { SevTag, StTag, SrcTag, TypeTag, Dot } from "@/components/atoms";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { mono, sans } from "@/lib/styles";

const ROW_PADDING = {
  compact: "4px 14px",
  default: "8px 14px",
  comfortable: "12px 14px",
} as const;
import { SEV, FINDING_TYPES } from "@/lib/constants";
import { daysLeft, displayTitle, slaDot } from "@/lib/utils";
import type { Finding, Source } from "@/types";

interface FindingRowProps {
  finding: Finding;
  sources: Source[];
  selected: boolean;
  checked: boolean;
  onCheck: (v: boolean) => void;
  onClick: () => void;
  /** When > 1, shows badge for grouped findings */
  groupCount?: number;
  /** When in instance mode with multi-source finding, which source this row represents */
  instanceSource?: string;
}

export function FindingRow({
  finding,
  sources,
  selected,
  checked,
  onCheck,
  onClick,
  groupCount,
  instanceSource,
}: FindingRowProps) {
  const { preferences } = useUserPreferences();
  const density = preferences.tableDensity ?? "default";
  const [hov, setHov] = useState(false);
  const d = daysLeft(finding.slaDue);
  const slaC = slaDot(finding.slaDue, finding.status);
  const fType = FINDING_TYPES[finding.findingType] ?? FINDING_TYPES.SCA;
  const hasMultiSrc = (finding.sources?.length ?? 0) > 1;

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "grid",
        gridTemplateColumns: "26px 4px 32px 130px 1fr 160px 60px 100px 90px 80px",
        gap: 8,
        padding: ROW_PADDING[density],
        cursor: "pointer",
        alignItems: "center",
        background: finding.archived
          ? hov
            ? "var(--app-input-bg)"
            : "var(--app-card-bg)"
          : selected
            ? "var(--app-input-bg)"
            : hov
              ? "var(--app-card-bg)"
              : "transparent",
        borderBottom: "1px solid var(--app-border-subtle)",
        transition: "background 0.1s",
        opacity: finding.archived ? 0.7 : 1,
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        onClick={(e) => e.stopPropagation()}
        onChange={(e) => onCheck(e.target.checked)}
        style={{ accentColor: "var(--app-accent)", cursor: "pointer" }}
      />
      <div
        style={{
          width: 4,
          height: 24,
          borderRadius: 2,
          background: SEV[finding.severity]?.c ?? "#888",
        }}
      />
      <span style={{ fontSize: 14 }} title={fType.label}>
        {fType.icon}
      </span>
      <span
        style={{
          ...mono,
          fontSize: 11,
          fontWeight: 700,
          color: "var(--app-accent)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {finding.cveId}
      </span>
      <div style={{ minWidth: 0 }}>
        <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
          <span
            style={{
              ...sans,
              fontSize: 12,
              fontWeight: 500,
              color: "var(--app-fg)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              flex: 1,
            }}
          >
            {displayTitle(finding)}
          </span>
          {(groupCount ?? 0) > 1 && !instanceSource && (
            <span
              style={{
                ...mono,
                fontSize: 8,
                color: "var(--app-accent)",
                background: "var(--app-input-bg)",
                padding: "1px 4px",
                borderRadius: 2,
                flexShrink: 0,
              }}
              title={`Grouped: same finding in ${groupCount ?? 0} place${(groupCount ?? 0) > 1 ? "s" : ""}`}
            >
              ×{groupCount ?? 0}
            </span>
          )}
          {hasMultiSrc && (groupCount ?? 0) <= 1 && !instanceSource && (
            <span
              style={{
                ...mono,
                fontSize: 8,
                color: "var(--app-accent)",
                background: "var(--app-input-bg)",
                padding: "1px 4px",
                borderRadius: 2,
                flexShrink: 0,
              }}
            >
              ×{finding.sources!.length}
            </span>
          )}
          {(finding.regressionCount ?? 0) > 0 && (
            <span
              style={{
                ...mono,
                fontSize: 8,
                color: "var(--app-warning)",
                background: "color-mix(in srgb, var(--app-warning) 15%, transparent)",
                padding: "1px 4px",
                borderRadius: 2,
                flexShrink: 0,
              }}
            >
              REG×{finding.regressionCount}
            </span>
          )}
        </div>
        <div style={{ ...mono, fontSize: 9, color: "var(--app-muted)", marginTop: 1 }}>
          {(() => {
            // For Secret/IaC/SAST, prefer filePath (location) when available — more useful than generic component
            const ft = (finding.findingType ?? "").toLowerCase();
            const isLocationType = ft === "secret" || ft === "iac" || ft === "sast";
            const showPath = isLocationType && finding.filePath?.trim();
            const subtitle = showPath ? finding.filePath!.trim() : (finding.component ?? "—");
            return <>{subtitle} · {finding.team ?? "—"}</>;
          })()}
        </div>
      </div>
      <StTag status={finding.status === "Synced to Tracker" ? "Open" : finding.status} />
      <span
        style={{
          ...mono,
          fontSize: 10,
          color: finding.trackerId ? "var(--app-accent)" : "var(--app-muted)",
        }}
        title={finding.trackerId ? "Tracked in Linear" : "Not tracked"}
      >
        {finding.trackerId ? "✓" : "—"}
      </span>
      <SevTag sev={finding.severity} />
      <SrcTag source={instanceSource ?? finding.source ?? ""} sources={sources} />
      <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
        <Dot color={slaC} />
        <span style={{ ...mono, fontSize: 10, color: slaC }}>
          {d !== null ? (d < 0 ? `${Math.abs(d)}d OD` : `${d}d`) : "—"}
        </span>
      </div>
    </div>
  );
}
