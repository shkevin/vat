"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { ClassificationBanner } from "./ClassificationBanner";
import { AppBanner } from "./AppBanner";
import { AppFooter } from "./AppFooter";
import { ShellProvider } from "@/contexts/ShellContext";
import { FilterSidebarProvider } from "@/contexts/FilterSidebarContext";
import { useVATData } from "@/contexts/VATDataContext";
import { useMediaQuery } from "@/hooks/useMediaQuery";
import { useDashboardFilters } from "@/hooks/useDashboardFilters";
import {
  loadDashboardFiltersFromStorage,
  saveDashboardFiltersToStorage,
} from "@/lib/dashboardFilterStorage";
import type { AppConfig } from "@/config/app";

interface MainAppShellProps {
  config: AppConfig;
  children: React.ReactNode;
}

const VALID_TABS = [
  "findings",
  "review",
  "report",
  "dash",
  "settings",
] as const;

export function MainAppShell({ config, children }: MainAppShellProps) {
  const pathname = usePathname();
  const router = useRouter();
  const isSidebarCollapsed = useMediaQuery("(max-width: 1024px)");
  const [filterSidebarOpen, setFilterSidebarOpen] = useState(false);
  const data = useVATData();
  const prevPathnameRef = useRef<string | null>(null);

  const isAssetPage = pathname?.startsWith("/assets/");
  const currentView = isAssetPage ? "findings" : data.view;

  const [dashboardState, setDashboardState] = useDashboardFilters();

  // Sync nuqs (URL) -> useVATData when on dashboard.
  // Use ref to skip when URL state hasn't actually changed (nuqs may return new ref each render).
  // Re-run when loading finishes so we apply URL state after VAT data is ready.
  const dataRef = useRef(data);
  dataRef.current = data;
  const lastUrlStateRef = useRef<string>("");
  const prevLoadingRef = useRef(data.loading);
  useEffect(() => {
    if (isAssetPage) return;
    // When loading finishes, force re-apply so URL state wins over any initial defaults
    if (prevLoadingRef.current && !data.loading) {
      lastUrlStateRef.current = "";
    }
    prevLoadingRef.current = data.loading;

    const s = dashboardState;
    const urlKey = JSON.stringify({
      tab: s.tab,
      search: s.search,
      status: s.status ?? [],
      abc: s.abc ?? [],
      verifiedMin: s.verifiedMin,
      verifiedMax: s.verifiedMax,
      oraMin: s.oraMin,
      oraMax: s.oraMax,
      assetTypes: s.assetTypes ?? [],
      archived: s.archived,
      favorites: s.favorites,
      showEmptyAssets: s.showEmptyAssets,
      needsJustification: s.needsJustification,
    });
    if (lastUrlStateRef.current === urlKey) return;
    lastUrlStateRef.current = urlKey;

    const d = dataRef.current;
    if (s.tab !== d.view) d.setView(s.tab);
    if (s.search !== d.search) d.setSearch(s.search);
    const statusSet = new Set(s.status ?? []);
    if (
      statusSet.size !== d.filterFindingStatuses.size ||
      [...statusSet].some((x) => !d.filterFindingStatuses.has(x))
    ) {
      d.setFilterFindingStatuses(statusSet);
    }
    const abcSet = new Set(s.abc ?? []);
    if (
      abcSet.size !== d.filterABC.size ||
      [...abcSet].some((x) => !d.filterABC.has(x))
    ) {
      d.setFilterABC(abcSet);
    }
    const vr: [number, number] = [s.verifiedMin ?? 0, s.verifiedMax ?? 100];
    if (
      vr[0] !== d.filterVerifiedRange[0] ||
      vr[1] !== d.filterVerifiedRange[1]
    ) {
      d.setFilterVerifiedRange(vr);
    }
    const or: [number, number] = [s.oraMin ?? 0, s.oraMax ?? 100];
    if (or[0] !== d.filterORARange[0] || or[1] !== d.filterORARange[1]) {
      d.setFilterORARange(or);
    }
    const atSet = new Set(s.assetTypes ?? []);
    if (
      atSet.size !== d.filterAssetTypes.size ||
      [...atSet].some((x) => !d.filterAssetTypes.has(x))
    ) {
      d.setFilterAssetTypes(atSet);
    }
    if (s.archived !== d.showArchived) d.setShowArchived(s.archived);
    if (s.favorites !== d.onlyFavorites) d.setOnlyFavorites(s.favorites);
    if (s.showEmptyAssets !== d.showEmptyAssets)
      d.setShowEmptyAssets(s.showEmptyAssets);
    if (s.needsJustification !== d.needsJustification)
      d.setNeedsJustification(s.needsJustification);
  }, [isAssetPage, dashboardState, data.loading]);

  // Persist VAT filter state to localStorage when user changes filters in sidebar.
  // This ensures favorites, archived, status, etc. survive refresh.
  useEffect(() => {
    if (isAssetPage) return;
    if (typeof window === "undefined") return;
    saveDashboardFiltersToStorage({
      tab: data.view,
      search: data.search,
      status: [...data.filterFindingStatuses],
      abc: [...data.filterABC],
      verifiedMin: data.filterVerifiedRange[0],
      verifiedMax: data.filterVerifiedRange[1],
      oraMin: data.filterORARange[0],
      oraMax: data.filterORARange[1],
      assetTypes: [...data.filterAssetTypes],
      archived: data.showArchived === true,
      favorites: data.onlyFavorites,
      showEmptyAssets: data.showEmptyAssets,
      needsJustification: data.needsJustification,
    });
  }, [
    isAssetPage,
    data.view,
    data.search,
    data.filterFindingStatuses,
    data.filterABC,
    data.filterVerifiedRange,
    data.filterORARange,
    data.filterAssetTypes,
    data.showArchived,
    data.onlyFavorites,
    data.showEmptyAssets,
    data.needsJustification,
  ]);

  // Restore selected finding from URL when findings are loaded
  useEffect(() => {
    if (isAssetPage) return;
    const findingId = dashboardState.finding;
    if (!findingId || data.findings.length === 0) return;
    const f = data.findings.find((x) => x.id === findingId);
    if (f) data.setSelected(f);
  }, [isAssetPage, dashboardState.finding, data.findings, data.setSelected]);

  // Close detail pane only when navigating to a different page
  useEffect(() => {
    if (
      prevPathnameRef.current !== null &&
      prevPathnameRef.current !== pathname
    ) {
      data.setSelected(null);
    }
    prevPathnameRef.current = pathname;
  }, [pathname, data.setSelected]);

  const handleSearchChange = useCallback(
    (v: string) => {
      data.setSearch(v);
      if (!isAssetPage) setDashboardState({ search: v });
    },
    [isAssetPage, data.setSearch, setDashboardState],
  );

  const handleViewChange = useCallback(
    (tabId: string) => {
      if (isAssetPage) {
        const stored = loadDashboardFiltersFromStorage();
        const params = new URLSearchParams();
        params.set("tab", tabId);
        if (stored?.status?.length)
          params.set("status", stored.status.join(","));
        if (stored?.abc?.length) params.set("abc", stored.abc.join(","));
        if (stored?.verifiedMin != null)
          params.set("verifiedMin", String(stored.verifiedMin));
        if (stored?.verifiedMax != null)
          params.set("verifiedMax", String(stored.verifiedMax));
        if (stored?.oraMin != null) params.set("oraMin", String(stored.oraMin));
        if (stored?.oraMax != null) params.set("oraMax", String(stored.oraMax));
        if (stored?.assetTypes?.length)
          params.set("assetTypes", stored.assetTypes.join(","));
        if (stored?.archived) params.set("archived", "true");
        if (stored?.favorites) params.set("favorites", "true");
        if (stored?.showEmptyAssets) params.set("showEmptyAssets", "true");
        if (stored?.needsJustification)
          params.set("needsJustification", "true");
        router.push(`/?${params.toString()}`);
      } else {
        data.setView(tabId);
        setDashboardState({
          tab: tabId as "findings" | "review" | "report" | "dash" | "settings",
        });
      }
    },
    [isAssetPage, data.setView, router, setDashboardState],
  );

  const tabs = [
    { id: "findings", label: "Assets" },
    { id: "review", label: "Review", badge: data.inRev },
    { id: "report", label: "Report" },
    { id: "dash", label: "Metrics" },
    { id: "settings", label: "Settings" },
  ];

  return (
    <ShellProvider embedded>
      <FilterSidebarProvider
        open={filterSidebarOpen}
        onOpenChange={setFilterSidebarOpen}
      >
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            minHeight: "100vh",
            height: "100%",
            background: "var(--app-bg)",
          }}
        >
          {config.banner.classification && (
            <ClassificationBanner
              classification={config.banner.classification}
            />
          )}
          <AppBanner
            config={config.banner}
            tabs={tabs}
            currentView={currentView}
            onViewChange={handleViewChange}
            searchValue={data.search}
            onSearchChange={handleSearchChange}
            alertCount={data.alerts.length}
            waiverExpiringCount={data.waiverExpiring}
            hideSearch={!isAssetPage && data.view === "findings"}
            showFilterButton={isSidebarCollapsed && !isAssetPage}
            onFilterClick={() => setFilterSidebarOpen(true)}
          />
          <div
            style={{
              flex: 1,
              minHeight: 0,
              overflow: "auto",
              display: "flex",
              flexDirection: "column",
            }}
          >
            {children}
          </div>
          {config.footer.classification && (
            <AppFooter
              classification={config.footer.classification}
              suffix={config.footer.suffix}
            />
          )}
        </div>
      </FilterSidebarProvider>
    </ShellProvider>
  );
}
