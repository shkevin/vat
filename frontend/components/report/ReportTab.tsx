"use client";

import { useMemo } from "react";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { groupFindingsByKey } from "@/lib/findingGroupUtils";
import { toVATDashboardData } from "@/lib/report/vatReportAdapter";
import { ReportBuilderView } from "./ReportBuilderView";
import type { Finding, Asset } from "@/types";

interface ReportTabProps {
  findings: Finding[];
  allAssets: Asset[];
  total: number;
  open: number;
  inRev: number;
  overdue: number;
  waiverExpiring: number;
  archivedCount: number;
  favoriteAssetIds?: Set<string>;
}

/**
 * Report uses the same filtered data as the Findings tab.
 * VAT passes reportFilteredFindings (findings belonging to displayedAssets) and
 * displayedAssets (sidebar-filtered: status, asset type, ABC, verified, ORA, favorites, search)
 * so Report and Findings totals match.
 *
 * Data is built with canonical VAT grouping (groupFindingsByKey). The sidebar
 * "Group findings" toggle only affects count mode (groups vs instances), not the underlying data.
 */
export function ReportTab({ findings, allAssets }: ReportTabProps) {
  const { preferences } = useUserPreferences();
  const groupFindings = preferences.groupFindings ?? true;
  const displayCount = groupFindings
    ? groupFindingsByKey(findings).size
    : findings.length;

  // Match data structure to display mode: groups = canonical grouping, instances = one per finding.
  const data = useMemo(
    () => toVATDashboardData(findings, allAssets, "VAT", { groupFindings }),
    [findings, allAssets, groupFindings],
  );

  return (
    <div
      style={{
        flex: 1,
        minHeight: 0,
        overflow: "hidden",
        display: "flex",
        flexDirection: "column",
        gap: 12,
      }}
    >
      <section className="vat-tab-hero modern-card">
        <div>
          <p className="vat-tab-eyebrow">Reporting</p>
          <h2 className="vat-tab-title">Executive Report Builder</h2>
          <p className="vat-tab-subtitle">
            Build shareable security summaries with the same filtered data as the
            findings workspace.
          </p>
        </div>
        <div className="vat-tab-hero-chips">
          <span className="vat-tab-chip">
            {displayCount.toLocaleString()}{" "}
            {groupFindings ? "groups" : "instances"}
          </span>
          {groupFindings && (
            <span className="vat-tab-chip">
              {findings.length.toLocaleString()} instances
            </span>
          )}
          <span className="vat-tab-chip">
            Mode: {groupFindings ? "Grouped" : "Instances"}
          </span>
        </div>
      </section>

      <div
        className="modern-card"
        style={{
          flex: 1,
          minHeight: 0,
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <ReportBuilderView
          data={data}
          allAssets={allAssets}
          defaultCountMode={groupFindings ? "groups" : "instances"}
        />
      </div>
    </div>
  );
}
