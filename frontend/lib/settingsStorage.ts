/**
 * Settings persistence — tries backend API first, falls back to localStorage when unavailable.
 * Ensures settings work in both full-stack and frontend-only (demo) modes.
 */

const STORAGE_KEY = "vat-settings";

export interface StoredSettings {
  sources: Array<Record<string, unknown>>;
  tracker: Record<string, unknown>;
  labels: Array<Record<string, unknown>>;
}

function loadFromStorage(): StoredSettings | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as StoredSettings;
    if (parsed && typeof parsed === "object") {
      return {
        sources: Array.isArray(parsed.sources) ? parsed.sources : [],
        tracker:
          parsed.tracker && typeof parsed.tracker === "object"
            ? parsed.tracker
            : {},
        labels: Array.isArray(parsed.labels) ? parsed.labels : [],
      };
    }
  } catch {
    /* ignore */
  }
  return null;
}

export function saveToStorage(settings: Partial<StoredSettings>): void {
  if (typeof window === "undefined") return;
  try {
    const current = loadFromStorage() ?? {
      sources: [],
      tracker: {},
      labels: [],
    };
    const merged: StoredSettings = {
      sources: settings.sources ?? current.sources,
      tracker: settings.tracker ?? current.tracker,
      labels: settings.labels ?? current.labels,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
  } catch {
    /* ignore */
  }
}

export function loadSettingsFromStorage(): StoredSettings {
  const stored = loadFromStorage();
  if (
    stored &&
    (stored.sources.length > 0 ||
      Object.keys(stored.tracker).length > 0 ||
      stored.labels.length > 0)
  ) {
    return stored;
  }
  return { sources: [], tracker: {}, labels: [] };
}
