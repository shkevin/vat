/**
 * Asset filter persistence via localStorage.
 * Used as fallback when no URL params (nuqs handles URL).
 */

const STORAGE_KEY = "vat-asset-filters";

export interface AssetFilterState {
  status: string[];
  severity: string[];
  source: string[];
  type: string[];
  search: string;
  sort: string;
  branch: string;
  tag: string;
}

export const DEFAULT_FILTER_STATE: AssetFilterState = {
  status: ["Open"],
  severity: [],
  source: [],
  type: [],
  search: "",
  sort: "severity",
  branch: "",
  tag: "",
};

export function loadFiltersFromStorage(assetId: string): AssetFilterState | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const all = JSON.parse(raw) as Record<string, AssetFilterState>;
    const stored = all[assetId];
    if (!stored || typeof stored !== "object") return null;
    return {
      ...DEFAULT_FILTER_STATE,
      ...stored,
      status: Array.isArray(stored.status) ? stored.status : [],
      severity: Array.isArray(stored.severity) ? stored.severity : [],
      source: Array.isArray(stored.source) ? stored.source : [],
      type: Array.isArray(stored.type) ? stored.type : [],
      search: "", // Never restore search from storage; reset on refresh
    };
  } catch {
    return null;
  }
}

export function saveFiltersToStorage(assetId: string, state: Partial<AssetFilterState>): void {
  if (typeof window === "undefined") return;
  try {
    const { search: _search, ...stateWithoutSearch } = state;
    const raw = localStorage.getItem(STORAGE_KEY);
    const all: Record<string, AssetFilterState> = raw ? (JSON.parse(raw) as Record<string, AssetFilterState>) : {};
    all[assetId] = { ...DEFAULT_FILTER_STATE, ...all[assetId], ...stateWithoutSearch };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
  } catch {
    /* ignore */
  }
}
