"use client";

import { useCallback, useEffect, useMemo } from "react";
import dynamic from "next/dynamic";
import { useSearchParams, useRouter, usePathname } from "next/navigation";
import { useVATData } from "@/contexts/VATDataContext";
import { VATLayout } from "@/components/layout/VATLayout";
import { MetricsDashboard } from "@/components/metrics/MetricsDashboard";
import { AssetsTable } from "@/components/assets/AssetsTable";
import { ReviewQueue } from "@/components/review/ReviewQueue";
import { DetailPanel } from "@/components/detail/DetailPanel";

// Lazy-load heavy tabs: SettingsTab pulls in @xyflow/react (~200KB+), ReportTab pulls in report engine + regression + many icons
const ReportTab = dynamic(() => import("@/components/report/ReportTab").then((m) => ({ default: m.ReportTab })), {
  ssr: false,
  loading: () => (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 200, color: "var(--app-muted)" }}>
      Loading report…
    </div>
  ),
});
const SettingsTab = dynamic(() => import("@/components/settings/SettingsTab").then((m) => ({ default: m.SettingsTab })), {
  ssr: false,
  loading: () => (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 200, color: "var(--app-muted)" }}>
      Loading settings…
    </div>
  ),
});
import { useAuth } from "@/contexts/AuthContext";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { useDashboardFilters } from "@/hooks/useDashboardFilters";
import { getGroupedFindings } from "@/lib/findingGroupUtils";
import { SEV_ORDER } from "@/lib/constants";
import { daysLeft } from "@/lib/utils";
import { mono, sans } from "@/lib/styles";
import type { AppConfig } from "@/config/app";

interface VATProps {
  config: AppConfig;
}

const VALID_TABS = ["findings", "review", "report", "dash", "settings"] as const;

export default function VAT({ config }: VATProps) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const data = useVATData();
  const { user } = useAuth();
  const { preferences } = useUserPreferences();
  const readOnly = user?.role === "read_only";
  const isAdmin = user?.role === "admin";
  const groupFindings = preferences.groupFindings ?? true;
  const [dashboardState, setDashboardState] = useDashboardFilters();

  const {
    loading,
    view,
    setView,
    selected,
    setSelected,
    alerts,
    active,
    archivedCount,
    reviewQueue,
    total,
    open,
    inRev,
    overdue,
    waiverExpiring,
    displayed,
    displayedAssets,
    allAssets,
    reportAssets,
    reportFilteredFindings,
    totalAssets,
    findings,
    sources,
    tracker,
    trackers,
    labels,
    checked,
    search,
    filterFindingStatuses,
    filterABC,
    filterVerifiedRange,
    filterORARange,
    filterAssetTypes,
    setFilterAssetTypes,
    showArchived,
    setSearch,
    setFilterFindingStatuses,
    setFilterABC,
    setFilterVerifiedRange,
    setFilterORARange,
    setShowArchived,
    onlyFavorites,
    setOnlyFavorites,
    needsJustification,
    setNeedsJustification,
    searchFields,
    setSearchFields,
    handleBulk,
    toggleCheck,
    navigateToFinding,
    error,
    refetch,
  } = data;

  // Counts that respect groupFindings — same logic as Findings tab and report.
  const { total: displayTotal, open: displayOpen, inRev: displayInRev, overdue: displayOverdue, waiverExpiring: displayWaiverExpiring } = useMemo(() => {
    if (!groupFindings) {
      return { total, open, inRev, overdue, waiverExpiring };
    }
    const groups = getGroupedFindings(active, SEV_ORDER);
    const hasOpen = (fs: { status?: string }[]) => fs.some((f) => f.status === "Open");
    const hasInRev = (fs: { status?: string }[]) => fs.some((f) => f.status === "In Review");
    const hasOverdue = (fs: { status?: string; slaDue?: string }[]) =>
      fs.some((f) => {
        if (["Resolved", "False Positive", "Duplicate", "Not Applicable", "Approved", "Suppressed"].includes(f.status ?? ""))
          return false;
        const d = daysLeft(f.slaDue);
        return d !== null && d < 0;
      });
    const hasWaiverExpiring = (fs: { attestation?: { expiresAt?: string } }[]) =>
      fs.some((f) => {
        const d = daysLeft(f.attestation?.expiresAt);
        return !!f.attestation && d !== null && d >= 0 && d <= 30;
      });
    return {
      total: groups.length,
      open: groups.filter((g) => hasOpen(g.findings)).length,
      inRev: groups.filter((g) => hasInRev(g.findings)).length,
      overdue: groups.filter((g) => hasOverdue(g.findings)).length,
      waiverExpiring: groups.filter((g) => hasWaiverExpiring(g.findings)).length,
    };
  }, [groupFindings, active, total, open, inRev, overdue, waiverExpiring]);

  // Sidebar filters must update nuqs (setDashboardState) so state persists on refresh.
  const handleFilterFindingStatusesChange = useCallback(
    (v: Set<string> | ((prev: Set<string>) => Set<string>)) => {
      const next = typeof v === "function" ? v(filterFindingStatuses) : v;
      setDashboardState({ status: [...next] });
    },
    [filterFindingStatuses, setDashboardState]
  );
  const handleFilterAssetTypesChange = useCallback(
    (v: Set<string> | ((prev: Set<string>) => Set<string>)) => {
      const next = typeof v === "function" ? v(filterAssetTypes) : v;
      setDashboardState({ assetTypes: [...next] });
    },
    [filterAssetTypes, setDashboardState]
  );
  const handleFilterABCChange = useCallback(
    (v: Set<string> | ((prev: Set<string>) => Set<string>)) => {
      const next = typeof v === "function" ? v(filterABC) : v;
      setDashboardState({ abc: [...next] });
    },
    [filterABC, setDashboardState]
  );
  const handleFilterVerifiedRangeChange = useCallback(
    (v: [number, number]) => setDashboardState({ verifiedMin: v[0], verifiedMax: v[1] }),
    [setDashboardState]
  );
  const handleFilterORARangeChange = useCallback(
    (v: [number, number]) => setDashboardState({ oraMin: v[0], oraMax: v[1] }),
    [setDashboardState]
  );

  const handleViewChange = useCallback(
    (tabId: string) => {
      data.setView(tabId);
      const params = new URLSearchParams(searchParams.toString());
      params.set("tab", tabId);
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    },
    [data.setView, searchParams, router, pathname]
  );

  useEffect(() => {
    if (view === "waivers" || view === "sbom") setView("findings");
  }, [view, setView]);

  const tabs = [
    { id: "findings", label: "Findings" },
    { id: "review", label: "Review", badge: inRev },
    { id: "report", label: "Report" },
    { id: "dash", label: "Metrics" },
    { id: "settings", label: "Settings" },
  ];

  const mainContent = (() => {
    if (loading && !error) {
      return (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            minHeight: 300,
            color: "#1d4ed8",
            ...mono,
            fontSize: 12,
          }}
        >
          ▣ Loading VAT…
        </div>
      );
    }

    if (error) {
      return (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            minHeight: 300,
            color: "#f87060",
            gap: 12,
            ...mono,
            fontSize: 12,
          }}
        >
          <span>Failed to load findings: {error}</span>
          <button
            onClick={() => refetch()}
            style={{
              background: "#1a0a2e",
              border: "1px solid #7c3aed",
              borderRadius: 4,
              padding: "8px 16px",
              color: "#c084fc",
              cursor: "pointer",
              ...sans,
            }}
          >
            Retry
          </button>
        </div>
      );
    }

    if (view === "dash") {
      return (
        <MetricsDashboard
          alerts={alerts}
          active={active}
          total={displayTotal}
          open={displayOpen}
          inRev={displayInRev}
          overdue={displayOverdue}
          waiverExpiring={displayWaiverExpiring}
          archivedCount={archivedCount}
          onNavigate={navigateToFinding}
          groupFindings={groupFindings}
        />
      );
    }

    if (view === "findings") {
      return (
        <AssetsTable
          displayedAssets={displayedAssets}
          groupFindings={groupFindings}
          sources={sources}
          selected={selected}
          checked={checked}
          showArchived={showArchived}
          archivedCount={archivedCount}
          total={totalAssets}
          filterAssetTypes={filterAssetTypes}
          onFilterAssetTypesChange={handleFilterAssetTypesChange}
          favoriteAssetIds={data.favoriteAssetIds}
          onToggleFavorite={data.toggleFavorite}
          search={search}
          onSearchChange={setSearch}
          searchPlaceholder={config.banner.searchPlaceholder}
          onSelect={setSelected}
          onCheck={toggleCheck}
          onBulkAction={handleBulk}
          onDeselectAll={data.clearChecked}
        />
      );
    }

    if (view === "review") {
      return (
        <ReviewQueue
          reviewQueue={reviewQueue}
          sources={sources}
          tracker={tracker}
          onSelect={setSelected}
        />
      );
    }

    if (view === "report") {
      return (
        <ReportTab
          findings={reportFilteredFindings}
          allAssets={displayedAssets}
          total={displayTotal}
          open={open}
          inRev={inRev}
          overdue={overdue}
          waiverExpiring={waiverExpiring}
          archivedCount={archivedCount}
        />
      );
    }

    if (view === "settings") {
      return (
        <SettingsTab
          sources={sources}
          tracker={tracker}
          labels={labels}
          onSourcesChange={data.onSourcesChange}
          onTrackerChange={data.onTrackerChange}
          onLabelsChange={data.onLabelsChange}
        />
      );
    }

    return null;
  })();

  return (
    <>
      <VATLayout
        config={config}
        tabs={tabs}
        view={view}
        onViewChange={handleViewChange}
        search={search}
        onSearchChange={setSearch}
        filterFindingStatuses={filterFindingStatuses}
        onFilterFindingStatusesChange={handleFilterFindingStatusesChange}
        filterAssetTypes={filterAssetTypes}
        onFilterAssetTypesChange={handleFilterAssetTypesChange}
        filterABC={filterABC}
        onFilterABCChange={handleFilterABCChange}
        filterVerifiedRange={filterVerifiedRange}
        onFilterVerifiedRangeChange={handleFilterVerifiedRangeChange}
        filterORARange={filterORARange}
        onFilterORARangeChange={handleFilterORARangeChange}
        showArchived={showArchived}
        onShowArchivedToggle={() => setDashboardState({ archived: !dashboardState.archived })}
        onlyFavorites={onlyFavorites}
        onOnlyFavoritesToggle={() => setDashboardState({ favorites: !dashboardState.favorites })}
        needsJustification={needsJustification}
        onNeedsJustificationToggle={() =>
          setDashboardState({ needsJustification: !dashboardState.needsJustification })
        }
        alertCount={alerts.length}
        onApply={refetch}
        applyLabel="Apply"
        waiverExpiringCount={waiverExpiring}
      >
        {mainContent}
      </VATLayout>
      {selected && (
        <DetailPanel
          finding={selected}
          allFindings={data.findings}
          sources={data.sources}
          tracker={data.tracker}
          trackers={data.trackers}
          onClose={() => setSelected(null)}
          onUpdate={data.handleUpdate}
          onArchive={data.handleArchive}
          onUnarchive={data.handleUnarchive}
          onRevert={data.handleRevert}
          onOverrideFingerprint={data.handleOverrideFingerprint}
          readOnly={readOnly}
          isAdmin={isAdmin}
          repoBaseUrl={config.repoBaseUrl}
          repoUrlType={config.repoUrlType}
          groupFindings={groupFindings}
        />
      )}
    </>
  );
}
