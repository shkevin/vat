"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useQueryStates } from "nuqs";
import { usePathname, useSearchParams } from "next/navigation";
import { dashboardParsers } from "@/lib/dashboardParsers";
import {
  loadDashboardFiltersFromStorage,
  saveDashboardFiltersToStorage,
} from "@/lib/dashboardFilterStorage";

/**
 * Type-safe dashboard filter state synced with URL via nuqs.
 * Falls back to localStorage when no URL params (e.g. fresh navigation).
 */
export function useDashboardFilters() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const isDashboard = !pathname?.startsWith("/assets/");

  const [state, setStateNuqs] = useQueryStates(dashboardParsers, {
    shallow: true,
    throttleMs: 100,
  });

  // Search is local state only (never in URL) so it clears on refresh
  const [search, setSearch] = useState("");
  const mergedState = { ...state, search };

  const setState = useCallback(
    (
      updates:
        | Record<string, unknown>
        | ((prev: typeof mergedState) => Record<string, unknown>),
    ) => {
      const resolved =
        typeof updates === "function" ? updates(mergedState) : updates;
      if (resolved && "search" in resolved) {
        setSearch((resolved.search as string) ?? "");
        const { search: _s, ...rest } = resolved;
        if (Object.keys(rest).length > 0)
          setStateNuqs(rest as Parameters<typeof setStateNuqs>[0]);
      } else {
        setStateNuqs(resolved as Parameters<typeof setStateNuqs>[0]);
      }
    },
    [mergedState, setStateNuqs],
  );

  // Restore from localStorage: full restore when URL empty, merge stored values for params not in URL.
  // Run only once per session to avoid overwriting user toggles. Logo/tab nav now preserves params.
  const hasRestoredRef = useRef(false);
  useEffect(() => {
    if (!isDashboard) return;
    if (typeof window === "undefined") return;
    if (hasRestoredRef.current) return;

    const stored = loadDashboardFiltersFromStorage();
    if (!stored) return;

    const params = searchParams;

    if (params.size === 0) {
      // Full restore when URL is clean (search intentionally not restored; reset on refresh)
      setState({
        tab:
          (stored.tab as
            | "findings"
            | "review"
            | "report"
            | "dash"
            | "feeds"
            | "settings") ?? undefined,
        status: Array.isArray(stored.status) ? stored.status : undefined,
        abc: Array.isArray(stored.abc) ? stored.abc : undefined,
        verifiedMin: stored.verifiedMin,
        verifiedMax: stored.verifiedMax,
        oraMin: stored.oraMin,
        oraMax: stored.oraMax,
        assetTypes: Array.isArray(stored.assetTypes)
          ? stored.assetTypes
          : undefined,
        archived: stored.archived,
        favorites: stored.favorites,
        showEmptyAssets: stored.showEmptyAssets,
        needsJustification: stored.needsJustification,
      });
    } else {
      // URL has params: merge stored values for params NOT in URL (e.g. ?tab=findings loses favorites)
      const updates: Record<string, unknown> = {};
      if (!params.has("tab") && stored.tab != null) updates.tab = stored.tab;
      // search intentionally not restored; reset on refresh
      if (!params.has("status") && Array.isArray(stored.status))
        updates.status = stored.status;
      if (!params.has("abc") && Array.isArray(stored.abc))
        updates.abc = stored.abc;
      if (!params.has("verifiedMin") && stored.verifiedMin != null)
        updates.verifiedMin = stored.verifiedMin;
      if (!params.has("verifiedMax") && stored.verifiedMax != null)
        updates.verifiedMax = stored.verifiedMax;
      if (!params.has("oraMin") && stored.oraMin != null)
        updates.oraMin = stored.oraMin;
      if (!params.has("oraMax") && stored.oraMax != null)
        updates.oraMax = stored.oraMax;
      if (!params.has("assetTypes") && Array.isArray(stored.assetTypes))
        updates.assetTypes = stored.assetTypes;
      if (!params.has("archived") && stored.archived != null)
        updates.archived = stored.archived;
      if (!params.has("favorites") && stored.favorites != null)
        updates.favorites = stored.favorites;
      if (!params.has("showEmptyAssets") && stored.showEmptyAssets != null)
        updates.showEmptyAssets = stored.showEmptyAssets;
      if (
        !params.has("needsJustification") &&
        stored.needsJustification != null
      )
        updates.needsJustification = stored.needsJustification;
      if (Object.keys(updates).length > 0)
        setState(updates as Parameters<typeof setState>[0]);
    }
    hasRestoredRef.current = true;
  }, [isDashboard, setState, searchParams]);

  // Persist to localStorage when state changes (search excluded)
  useEffect(() => {
    if (!isDashboard) return;
    saveDashboardFiltersToStorage({
      tab: mergedState.tab,
      status: mergedState.status,
      abc: mergedState.abc,
      verifiedMin: mergedState.verifiedMin,
      verifiedMax: mergedState.verifiedMax,
      oraMin: mergedState.oraMin,
      oraMax: mergedState.oraMax,
      assetTypes: mergedState.assetTypes,
      archived: mergedState.archived,
      favorites: mergedState.favorites,
      showEmptyAssets: mergedState.showEmptyAssets,
      needsJustification: mergedState.needsJustification,
    });
  }, [isDashboard, mergedState]);

  return [mergedState, setState] as const;
}
