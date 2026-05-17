"use client";

import { useEffect } from "react";
import { ClassificationBanner } from "./ClassificationBanner";
import { AppBanner } from "./AppBanner";
import { FilterSidebar } from "./FilterSidebar";
import { AppFooter } from "./AppFooter";
import { useShellContext } from "@/contexts/ShellContext";
import { useFilterSidebar } from "@/contexts/FilterSidebarContext";
import { useMediaQuery } from "@/hooks/useMediaQuery";
import type { AppConfig } from "@/config/app";

interface TabConfig {
  id: string;
  label: string;
  badge?: number;
  warn?: boolean;
}

interface VATLayoutProps {
  config: AppConfig;
  tabs: TabConfig[];
  view: string;
  onViewChange: (id: string) => void;
  search: string;
  onSearchChange: (v: string) => void;
  filterFindingStatuses: Set<string>;
  onFilterFindingStatusesChange: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  filterAssetTypes: Set<string>;
  onFilterAssetTypesChange: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  filterABC: Set<string>;
  onFilterABCChange: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  filterVerifiedRange: [number, number];
  onFilterVerifiedRangeChange: (v: [number, number]) => void;
  filterORARange: [number, number];
  onFilterORARangeChange: (v: [number, number]) => void;
  showArchived: boolean;
  onShowArchivedToggle: () => void;
  onlyFavorites: boolean;
  onOnlyFavoritesToggle: () => void;
  showEmptyAssets: boolean;
  onShowEmptyAssetsToggle: () => void;
  needsJustification: boolean;
  onNeedsJustificationToggle: () => void;
  onApply?: () => void;
  applyLabel?: string;
  alertCount: number;
  waiverExpiringCount?: number;
  exportAssetIds?: string[];
  activityFeed?: React.ReactNode;
  children: React.ReactNode;
}

export function VATLayout({
  config,
  tabs,
  view,
  onViewChange,
  search,
  onSearchChange,
  filterFindingStatuses,
  onFilterFindingStatusesChange,
  filterAssetTypes,
  onFilterAssetTypesChange,
  filterABC,
  onFilterABCChange,
  filterVerifiedRange,
  onFilterVerifiedRangeChange,
  filterORARange,
  onFilterORARangeChange,
  showArchived,
  onShowArchivedToggle,
  onlyFavorites,
  onOnlyFavoritesToggle,
  showEmptyAssets,
  onShowEmptyAssetsToggle,
  needsJustification,
  onNeedsJustificationToggle,
  alertCount,
  waiverExpiringCount = 0,
  exportAssetIds,
  activityFeed,
  onApply,
  applyLabel,
  children,
}: VATLayoutProps) {
  const isSidebarCollapsed = useMediaQuery("(max-width: 1024px)");
  const { embedded } = useShellContext();
  const { open: sidebarOpen, onOpenChange: setSidebarOpen } =
    useFilterSidebar();

  useEffect(() => {
    if (!isSidebarCollapsed || !sidebarOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSidebarOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isSidebarCollapsed, sidebarOpen, setSidebarOpen]);

  const shell = !embedded;

  return (
    <div
      className="modern-shell"
      style={{
        display: "flex",
        flexDirection: "column",
        height: shell ? "100vh" : "100%",
        flex: shell ? undefined : 1,
        minHeight: 0,
        overflow: "hidden",
        background: "var(--app-bg)",
      }}
    >
      {shell && (
        <>
          {config.banner.classification && (
            <ClassificationBanner
              classification={config.banner.classification}
            />
          )}
          <AppBanner
            config={config.banner}
            tabs={tabs}
            currentView={view}
            onViewChange={onViewChange}
            searchValue={search}
            onSearchChange={onSearchChange}
            alertCount={alertCount}
            waiverExpiringCount={waiverExpiringCount}
            exportAssetIds={exportAssetIds}
            hideSearch={view === "findings"}
            showFilterButton={isSidebarCollapsed}
            onFilterClick={() => setSidebarOpen(true)}
          />
        </>
      )}
      <div
        className="vat-layout-content"
        style={{
          display: "flex",
          flex: 1,
          minHeight: 0,
          position: "relative",
        }}
      >
        {isSidebarCollapsed && sidebarOpen && (
          <div
            role="presentation"
            aria-hidden
            onClick={() => setSidebarOpen(false)}
            style={{
              position: "fixed",
              inset: 0,
              background: "rgba(0,0,0,0.5)",
              zIndex: 40,
              cursor: "pointer",
            }}
          />
        )}
        <div
          className={isSidebarCollapsed ? "filter-sidebar-overlay" : undefined}
          style={{
            display: isSidebarCollapsed
              ? sidebarOpen
                ? "block"
                : "none"
              : "flex",
            flexDirection: "column",
            position: isSidebarCollapsed ? "fixed" : "relative",
            top: isSidebarCollapsed ? 0 : undefined,
            left: isSidebarCollapsed ? 0 : undefined,
            bottom: isSidebarCollapsed ? 0 : undefined,
            zIndex: isSidebarCollapsed ? 50 : undefined,
            width: isSidebarCollapsed ? 280 : undefined,
            boxShadow: isSidebarCollapsed
              ? "4px 0 24px rgba(0,0,0,0.3)"
              : undefined,
            height: isSidebarCollapsed ? "100vh" : "100%",
            minHeight: 0,
            overflowY: isSidebarCollapsed ? "auto" : "hidden",
          }}
        >
          <FilterSidebar
            filterFindingStatuses={filterFindingStatuses}
            onFilterFindingStatusesChange={onFilterFindingStatusesChange}
            filterAssetTypes={filterAssetTypes}
            onFilterAssetTypesChange={onFilterAssetTypesChange}
            filterABC={filterABC}
            onFilterABCChange={onFilterABCChange}
            filterVerifiedRange={filterVerifiedRange}
            onFilterVerifiedRangeChange={onFilterVerifiedRangeChange}
            filterORARange={filterORARange}
            onFilterORARangeChange={onFilterORARangeChange}
            showArchived={showArchived}
            onShowArchivedToggle={onShowArchivedToggle}
            onlyFavorites={onlyFavorites}
            onOnlyFavoritesToggle={onOnlyFavoritesToggle}
            showEmptyAssets={showEmptyAssets}
            onShowEmptyAssetsToggle={onShowEmptyAssetsToggle}
            needsJustification={needsJustification}
            onNeedsJustificationToggle={onNeedsJustificationToggle}
            onApply={onApply}
            applyLabel={applyLabel}
            onClose={
              isSidebarCollapsed ? () => setSidebarOpen(false) : undefined
            }
          />
        </div>
        <main
          className="modern-main vat-main"
          style={{
            flex: 1,
            minHeight: 0,
            overflow: view === "report" ? "hidden" : "auto",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {children}
        </main>
        {activityFeed}
      </div>
      {shell && config.footer.classification && (
        <AppFooter
          classification={config.footer.classification}
          suffix={config.footer.suffix}
        />
      )}
    </div>
  );
}
