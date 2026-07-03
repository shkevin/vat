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
import { loadDashboardFiltersFromStorage } from "@/lib/dashboardFilterStorage";
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
  "feeds",
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

  // Dashboard filter URL state + writer come from the single useDashboardFilters
  // instance owned by useVATData (which also runs the one URL->state sync). No
  // second instance, sync, or persist effect lives here.
  const { dashboardState, setDashboardState } = data;

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
          tab: tabId as
            | "findings"
            | "review"
            | "report"
            | "dash"
            | "feeds"
            | "settings",
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
    { id: "feeds", label: "Vuln Feeds" },
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
