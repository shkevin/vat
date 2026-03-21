"use client";

import { useEffect, useRef, useCallback, useState } from "react";
import { useQueryStates } from "nuqs";
import { assetParsers } from "@/lib/assetParsers";
import {
  loadFiltersFromStorage,
  saveFiltersToStorage,
  DEFAULT_FILTER_STATE,
  type AssetFilterState,
} from "@/lib/assetFilterStorage";

/**
 * Persisted asset filters via nuqs (URL) + localStorage fallback.
 * - URL params: source of truth when present. Enables shareable links.
 * - localStorage: restores when navigating without params.
 */
export function useAssetFilters(assetId: string | null) {
  const hasRestoredFromStorage = useRef(false);
  const [hasRestored, setHasRestored] = useState(() => {
    if (typeof window === "undefined") return false;
    if (window.location.search.length > 0) return true;
    if (assetId && loadFiltersFromStorage(assetId)) return true;
    return false;
  });

  const [state, setState] = useQueryStates(assetParsers, {
    shallow: true,
    throttleMs: 100,
  });

  // Search is local state only (never in URL) so it clears on refresh
  const [findingsSearch, setFindingsSearchState] = useState("");

  // Restore from localStorage when no URL params
  useEffect(() => {
    if (!assetId || typeof window === "undefined") return;
    if (hasRestoredFromStorage.current) return;
    if (window.location.search.length > 0) {
      setHasRestored(true);
      return;
    }

    const stored = loadFiltersFromStorage(assetId);
    if (!stored) return;

    hasRestoredFromStorage.current = true;
    setHasRestored(true);
    setState({
      status: stored.status.length
        ? stored.status
        : DEFAULT_FILTER_STATE.status,
      severity: stored.severity?.length ? stored.severity : undefined,
      source: stored.source?.length ? stored.source : undefined,
      type: stored.type?.length ? stored.type : undefined,
      sort:
        (stored.sort as
          | "severity"
          | "status"
          | "cve"
          | "title"
          | "source"
          | "sla") ?? DEFAULT_FILTER_STATE.sort,
      branch: stored.branch ?? undefined,
      tag: stored.tag ?? undefined,
    });
  }, [assetId, setState]);

  // Persist to localStorage when state changes (search excluded)
  useEffect(() => {
    if (!assetId) return;
    const full: AssetFilterState = {
      status: state.status,
      severity: state.severity,
      source: state.source,
      type: state.type,
      search: findingsSearch,
      sort: state.sort,
      branch: state.branch,
      tag: state.tag,
    };
    saveFiltersToStorage(assetId, full);
  }, [assetId, state, findingsSearch]);

  const setStatusFilter = useCallback(
    (v: Set<string>) => setState({ status: [...v] }),
    [setState],
  );
  const setSeverityFilter = useCallback(
    (v: Set<string>) => setState({ severity: [...v] }),
    [setState],
  );
  const setSourceFilter = useCallback(
    (v: Set<string>) => setState({ source: [...v] }),
    [setState],
  );
  const setFindingTypeFilter = useCallback(
    (v: Set<string>) => setState({ type: [...v] }),
    [setState],
  );
  const setFindingsSearch = useCallback(
    (v: string) => setFindingsSearchState(v),
    [],
  );
  const setSortBy = useCallback(
    (v: string) =>
      setState({
        sort: v as "severity" | "status" | "cve" | "title" | "source" | "sla",
      }),
    [setState],
  );
  const setBranchFilter = useCallback(
    (v: string) => setState({ branch: v }),
    [setState],
  );
  const setTagFilter = useCallback(
    (v: string) => setState({ tag: v }),
    [setState],
  );
  const resetFilters = useCallback(() => {
    setState({
      status: DEFAULT_FILTER_STATE.status,
      severity: [],
      source: [],
      type: [],
    });
    setFindingsSearchState("");
  }, [setState]);

  return {
    statusFilter: new Set(state.status),
    severityFilter: new Set(state.severity),
    sourceFilter: new Set(state.source),
    findingTypeFilter: new Set(state.type),
    findingsSearch,
    sortBy: state.sort,
    branchFilter: state.branch,
    tagFilter: state.tag,
    hasRestored,
    setStatusFilter,
    setSeverityFilter,
    setSourceFilter,
    setFindingTypeFilter,
    setFindingsSearch,
    setSortBy,
    setBranchFilter,
    setTagFilter,
    resetFilters,
  };
}
