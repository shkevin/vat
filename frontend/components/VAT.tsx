"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import { useSearchParams, useRouter, usePathname } from "next/navigation";
import { useVATData } from "@/contexts/VATDataContext";
import { VATLayout } from "@/components/layout/VATLayout";
import { MetricsDashboard } from "@/components/metrics/MetricsDashboard";
import { AssetsTable } from "@/components/assets/AssetsTable";
import { ReviewQueue } from "@/components/review/ReviewQueue";
import { DetailPanel } from "@/components/detail/DetailPanel";
import { ActivityFeedPanel } from "@/components/activity/ActivityFeedPanel";
import { useActivityFeed } from "@/components/activity/useActivityFeed";
import { VulnerabilityFeedsTab } from "@/components/feeds/VulnerabilityFeedsTab";

// Lazy-load heavy tabs: SettingsTab pulls in @xyflow/react (~200KB+), ReportTab pulls in report engine + regression + many icons
const ReportTab = dynamic(
  () =>
    import("@/components/report/ReportTab").then((m) => ({
      default: m.ReportTab,
    })),
  {
    ssr: false,
    loading: () => (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          minHeight: 200,
          color: "var(--app-muted)",
        }}
      >
        Loading report…
      </div>
    ),
  },
);
const SettingsTab = dynamic(
  () =>
    import("@/components/settings/SettingsTab").then((m) => ({
      default: m.SettingsTab,
    })),
  {
    ssr: false,
    loading: () => (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          minHeight: 200,
          color: "var(--app-muted)",
        }}
      >
        Loading settings…
      </div>
    ),
  },
);
import { useAuth } from "@/contexts/AuthContext";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { useDashboardFilters } from "@/hooks/useDashboardFilters";
import { getGroupedFindings } from "@/lib/findingGroupUtils";
import { SEV_ORDER } from "@/lib/constants";
import { daysLeft } from "@/lib/utils";
import { mono, sans } from "@/lib/styles";
import {
  fetchAssetMergeSuggestions,
  type AssetMergeSuggestion,
} from "@/lib/api";
import type { AppConfig } from "@/config/app";

interface VATProps {
  config: AppConfig;
}

const VALID_TABS = [
  "findings",
  "review",
  "report",
  "dash",
  "feeds",
  "settings",
] as const;

export default function VAT({ config }: VATProps) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const data = useVATData();
  const { user, token } = useAuth();
  const { preferences, setPreferences } = useUserPreferences();
  const readOnly = user?.role === "read_only";
  const isAdmin = user?.role === "admin";
  const canReviewAssets = user?.role === "admin" || user?.role === "reviewer";
  const groupFindings = preferences.groupFindings ?? true;
  const [dashboardState, setDashboardState] = useDashboardFilters();
  const [mergeReviewItems, setMergeReviewItems] = useState<
    Array<{
      assetId: string;
      count: number;
      topTargetAssetId: string;
      topStrategy:
        | "digest"
        | "exact_ref"
        | "sbom_similarity"
        | "name_heuristic";
      topScore: number;
      topConfidence: "high" | "medium" | "low";
    }>
  >([]);
  const [mergeReviewLoading, setMergeReviewLoading] = useState(false);
  const [mergeReviewError, setMergeReviewError] = useState<string | null>(null);

  const activityFeedCollapsed = preferences.activityFeedCollapsed ?? false;
  const activityFeedSourceFilter = preferences.activityFeedSourceFilter ?? "all";

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
    showEmptyAssets,
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

  const activityFeed = useActivityFeed({
    findings,
    auth: { token, userEmail: user?.email },
    isAdmin,
    sourceFilter: activityFeedSourceFilter,
    enabled: view !== "report",
  });

  // Counts that respect groupFindings — same logic as Findings tab and report.
  const {
    total: displayTotal,
    open: displayOpen,
    inRev: displayInRev,
    overdue: displayOverdue,
    waiverExpiring: displayWaiverExpiring,
  } = useMemo(() => {
    if (!groupFindings) {
      return { total, open, inRev, overdue, waiverExpiring };
    }
    const groups = getGroupedFindings(active, SEV_ORDER);
    const hasOpen = (fs: { status?: string }[]) =>
      fs.some((f) => f.status === "Open");
    const hasInRev = (fs: { status?: string }[]) =>
      fs.some((f) => f.status === "In Review");
    const hasOverdue = (fs: { status?: string; slaDue?: string }[]) =>
      fs.some((f) => {
        if (
          [
            "Resolved",
            "False Positive",
            "Duplicate",
            "Not Applicable",
            "Approved",
            "Suppressed",
          ].includes(f.status ?? "")
        )
          return false;
        const d = daysLeft(f.slaDue);
        return d !== null && d < 0;
      });
    const hasWaiverExpiring = (
      fs: { attestation?: { expiresAt?: string } | null }[],
    ) =>
      fs.some((f) => {
        const d = daysLeft(f.attestation?.expiresAt);
        return !!f.attestation && d !== null && d >= 0 && d <= 30;
      });
    return {
      total: groups.length,
      open: groups.filter((g) => hasOpen(g.findings)).length,
      inRev: groups.filter((g) => hasInRev(g.findings)).length,
      overdue: groups.filter((g) => hasOverdue(g.findings)).length,
      waiverExpiring: groups.filter((g) => hasWaiverExpiring(g.findings))
        .length,
    };
  }, [groupFindings, active, total, open, inRev, overdue, waiverExpiring]);

  // Sidebar filters must update nuqs (setDashboardState) so state persists on refresh.
  const handleFilterFindingStatusesChange = useCallback(
    (v: Set<string> | ((prev: Set<string>) => Set<string>)) => {
      const next = typeof v === "function" ? v(filterFindingStatuses) : v;
      setDashboardState({ status: [...next] });
    },
    [filterFindingStatuses, setDashboardState],
  );
  const handleFilterAssetTypesChange = useCallback(
    (v: Set<string> | ((prev: Set<string>) => Set<string>)) => {
      const next = typeof v === "function" ? v(filterAssetTypes) : v;
      setDashboardState({ assetTypes: [...next] });
    },
    [filterAssetTypes, setDashboardState],
  );
  const handleFilterABCChange = useCallback(
    (v: Set<string> | ((prev: Set<string>) => Set<string>)) => {
      const next = typeof v === "function" ? v(filterABC) : v;
      setDashboardState({ abc: [...next] });
    },
    [filterABC, setDashboardState],
  );
  const handleFilterVerifiedRangeChange = useCallback(
    (v: [number, number]) =>
      setDashboardState({ verifiedMin: v[0], verifiedMax: v[1] }),
    [setDashboardState],
  );
  const handleFilterORARangeChange = useCallback(
    (v: [number, number]) => setDashboardState({ oraMin: v[0], oraMax: v[1] }),
    [setDashboardState],
  );

  const handleViewChange = useCallback(
    (tabId: string) => {
      data.setView(tabId);
      const params = new URLSearchParams(searchParams.toString());
      params.set("tab", tabId);
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    },
    [data.setView, searchParams, router, pathname],
  );

  useEffect(() => {
    if (view === "waivers" || view === "sbom") setView("findings");
  }, [view, setView]);

  const tabs = [
    { id: "findings", label: "Assets" },
    { id: "review", label: "Review", badge: inRev },
    { id: "report", label: "Report" },
    { id: "dash", label: "Metrics" },
    { id: "feeds", label: "Vuln Feeds" },
    { id: "settings", label: "Settings" },
  ];

  const strategyLabel: Record<
    "digest" | "exact_ref" | "sbom_similarity" | "name_heuristic",
    string
  > = {
    digest: "Digest",
    exact_ref: "Exact image/ref",
    sbom_similarity: "SBOM similarity",
    name_heuristic: "Name heuristic",
  };

  useEffect(() => {
    let cancelled = false;
    async function loadMergeReviewItems() {
      if (view !== "review" || !canReviewAssets) {
        setMergeReviewItems([]);
        setMergeReviewError(null);
        return;
      }
      const candidateIds = reportAssets
        .filter((a) => {
          const id = (a.id || "").trim();
          return id.includes("/images/") || id.startsWith("containers");
        })
        .sort((a, b) => (b.openCount ?? 0) - (a.openCount ?? 0))
        .map((a) => (a.id || "").trim())
        .filter(Boolean)
        .slice(0, 40);
      if (candidateIds.length === 0) {
        setMergeReviewItems([]);
        setMergeReviewError(null);
        return;
      }
      setMergeReviewLoading(true);
      setMergeReviewError(null);
      try {
        const auth = { token: token ?? undefined, userEmail: user?.email };
        const responses = await Promise.all(
          candidateIds.map(async (assetId) => {
            try {
              return await fetchAssetMergeSuggestions(assetId, auth, 1);
            } catch {
              return null;
            }
          }),
        );
        if (cancelled) return;
        const rows = responses
          .filter(
            (
              r,
            ): r is {
              source_asset_id: string;
              count: number;
              suggestions: AssetMergeSuggestion[];
            } => Boolean(r && (r.suggestions?.length ?? 0) > 0),
          )
          .map((r) => ({
            assetId: r.source_asset_id,
            count: r.count,
            topTargetAssetId: r.suggestions[0].target_asset_id,
            topStrategy: r.suggestions[0].strategy,
            topScore: r.suggestions[0].score,
            topConfidence: r.suggestions[0].confidence,
          }))
          .sort((a, b) => b.count - a.count || b.topScore - a.topScore)
          .slice(0, 25);
        setMergeReviewItems(rows);
      } catch (err) {
        if (cancelled) return;
        setMergeReviewError(
          err instanceof Error
            ? err.message
            : "Failed to load asset merge reviews",
        );
      } finally {
        if (!cancelled) setMergeReviewLoading(false);
      }
    }
    void loadMergeReviewItems();
    return () => {
      cancelled = true;
    };
  }, [view, canReviewAssets, reportAssets, token, user?.email]);

  const mainContent = (() => {
    if (loading && !error && findings.length === 0) {
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
          showArchived={showArchived === true}
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
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {canReviewAssets && (
            <section
              style={{
                background: "var(--app-card-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: "12px 14px",
              }}
            >
              <div
                style={{
                  ...mono,
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: "0.12em",
                  textTransform: "uppercase",
                  color: "var(--app-muted)",
                  marginBottom: 6,
                }}
              >
                Asset Merge Review Queue
              </div>
              {mergeReviewError && (
                <div
                  style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}
                >
                  {mergeReviewError}
                </div>
              )}
              {mergeReviewLoading && !mergeReviewError && (
                <div
                  style={{ ...sans, fontSize: 12, color: "var(--app-muted)" }}
                >
                  Loading merge review items…
                </div>
              )}
              {!mergeReviewLoading &&
                !mergeReviewError &&
                mergeReviewItems.length === 0 && (
                  <div
                    style={{ ...sans, fontSize: 12, color: "var(--app-muted)" }}
                  >
                    No pending asset merge suggestions.
                  </div>
                )}
              {mergeReviewItems.length > 0 && (
                <div
                  style={{ display: "flex", flexDirection: "column", gap: 8 }}
                >
                  {mergeReviewItems.map((item) => (
                    <div
                      key={item.assetId}
                      style={{
                        border: "1px solid var(--app-border)",
                        borderRadius: 6,
                        padding: "9px 10px",
                        background: "var(--app-input-bg)",
                        display: "flex",
                        justifyContent: "space-between",
                        gap: 12,
                        alignItems: "center",
                      }}
                    >
                      <div style={{ minWidth: 260, flex: 1 }}>
                        <div
                          style={{
                            ...mono,
                            fontSize: 12,
                            color: "var(--app-fg)",
                          }}
                        >
                          {item.assetId}
                        </div>
                        <div
                          style={{
                            ...mono,
                            fontSize: 10,
                            color: "var(--app-muted)",
                          }}
                        >
                          {item.count} suggestion{item.count !== 1 ? "s" : ""} ·{" "}
                          {strategyLabel[item.topStrategy]} · confidence{" "}
                          {item.topConfidence} · score{" "}
                          {item.topScore.toFixed(2)}
                        </div>
                      </div>
                      <a
                        href={`/assets/${encodeURIComponent(
                          item.assetId,
                        )}?tab=review`}
                        style={{
                          ...mono,
                          fontSize: 11,
                          color: "var(--app-accent)",
                          textDecoration: "none",
                          border: "1px solid var(--app-border)",
                          borderRadius: 6,
                          padding: "6px 8px",
                        }}
                        title={`Top target: ${item.topTargetAssetId}`}
                      >
                        Open asset review
                      </a>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}
          <ReviewQueue
            reviewQueue={reviewQueue}
            sources={sources}
            tracker={tracker}
            onSelect={setSelected}
          />
        </div>
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

    if (view === "feeds") {
      return <VulnerabilityFeedsTab />;
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
        showArchived={showArchived === true}
        onShowArchivedToggle={() =>
          setDashboardState({ archived: !dashboardState.archived })
        }
        onlyFavorites={onlyFavorites}
        onOnlyFavoritesToggle={() =>
          setDashboardState({ favorites: !dashboardState.favorites })
        }
        showEmptyAssets={showEmptyAssets}
        onShowEmptyAssetsToggle={() =>
          setDashboardState({
            showEmptyAssets: !dashboardState.showEmptyAssets,
          })
        }
        needsJustification={needsJustification}
        onNeedsJustificationToggle={() =>
          setDashboardState({
            needsJustification: !dashboardState.needsJustification,
          })
        }
        alertCount={alerts.length}
        onApply={refetch}
        applyLabel="Apply"
        waiverExpiringCount={waiverExpiring}
        activityFeed={
          view === "report" ? null : (
            <ActivityFeedPanel
              events={activityFeed.events}
              loadingSystem={activityFeed.loadingSystem}
              systemError={activityFeed.systemError}
              canViewSystem={activityFeed.canViewSystem}
              collapsed={activityFeedCollapsed}
              onCollapsedChange={(next) =>
                setPreferences({ activityFeedCollapsed: next })
              }
              sourceFilter={activityFeedSourceFilter}
              onSourceFilterChange={(next) =>
                setPreferences({ activityFeedSourceFilter: next })
              }
              onNavigateToFinding={navigateToFinding}
            />
          )
        }
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
