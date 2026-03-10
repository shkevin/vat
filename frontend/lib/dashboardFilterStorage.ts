/**
 * Dashboard filter persistence via localStorage.
 * Used as fallback when no URL params (nuqs handles URL).
 */

const STORAGE_KEY = "vat-dashboard-filters";

export interface DashboardFilterState {
  tab: string;
  search: string;
  status: string[];
  abc: string[];
  verifiedMin: number;
  verifiedMax: number;
  oraMin: number;
  oraMax: number;
  assetTypes: string[];
  archived: boolean;
  favorites: boolean;
  needsJustification: boolean;
}

export function loadDashboardFiltersFromStorage(): Partial<DashboardFilterState> | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const stored = JSON.parse(raw) as Record<string, unknown>;
    if (!stored || typeof stored !== "object") return null;
    return {
      tab: typeof stored.tab === "string" ? stored.tab : undefined,
      status: Array.isArray(stored.status) ? stored.status.filter((s): s is string => typeof s === "string") : undefined,
      abc: Array.isArray(stored.abc) ? stored.abc.filter((s): s is string => typeof s === "string") : undefined,
      verifiedMin: typeof stored.verifiedMin === "number" ? stored.verifiedMin : undefined,
      verifiedMax: typeof stored.verifiedMax === "number" ? stored.verifiedMax : undefined,
      oraMin: typeof stored.oraMin === "number" ? stored.oraMin : undefined,
      oraMax: typeof stored.oraMax === "number" ? stored.oraMax : undefined,
      assetTypes: Array.isArray(stored.assetTypes) ? stored.assetTypes.filter((s): s is string => typeof s === "string") : undefined,
      archived: typeof stored.archived === "boolean" ? stored.archived : undefined,
      favorites: typeof stored.favorites === "boolean" ? stored.favorites : undefined,
      needsJustification: typeof stored.needsJustification === "boolean" ? stored.needsJustification : undefined,
    };
  } catch {
    return null;
  }
}

export function saveDashboardFiltersToStorage(state: Partial<DashboardFilterState>): void {
  if (typeof window === "undefined") return;
  try {
    const toStore: Record<string, unknown> = {};
    if (state.tab != null) toStore.tab = state.tab;
    // search is intentionally not persisted; reset on refresh
    if (state.status != null) toStore.status = state.status;
    if (state.abc != null) toStore.abc = state.abc;
    if (state.verifiedMin != null) toStore.verifiedMin = state.verifiedMin;
    if (state.verifiedMax != null) toStore.verifiedMax = state.verifiedMax;
    if (state.oraMin != null) toStore.oraMin = state.oraMin;
    if (state.oraMax != null) toStore.oraMax = state.oraMax;
    if (state.assetTypes != null) toStore.assetTypes = state.assetTypes;
    if (state.archived != null) toStore.archived = state.archived;
    if (state.favorites != null) toStore.favorites = state.favorites;
    if (state.needsJustification != null) toStore.needsJustification = state.needsJustification;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(toStore));
  } catch {
    /* ignore */
  }
}
