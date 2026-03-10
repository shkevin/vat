/**
 * Unified user settings — aggregates all localStorage-backed user data.
 * Favorites, report presets, saved reports, and display preferences.
 */

import { getReportPersistence } from "@/lib/report/report-persistence";
import type { SavedReportMeta } from "@/lib/report/report-persistence";
import { loadAssetLoadouts } from "@/lib/assetLoadoutStorage";
import {
  loadUserPreferences,
  saveUserPreferences,
  type UserPreferences,
} from "@/lib/userPreferencesStorage";

export const FAVORITES_KEY = "vat-favorite-assets";
const REPORT_PRESETS_KEY = "vat:report-saved-presets";

/** A favorite stores assetId + optional branch/tag context (captured when favoriting from asset page). */
export interface FavoriteEntry {
  assetId: string;
  branch?: string;
  tag?: string;
}

export interface SavedPresetMeta {
  id: string;
  name: string;
  savedAt: string;
}

export interface UserSettingsSummary {
  favoriteCount: number;
  loadoutCount: number;
  reportPresetCount: number;
  savedReportCount: number;
  preferences: UserPreferences;
}

function parseFavoriteEntries(raw: string | null): FavoriteEntry[] {
  if (typeof window === "undefined" || !raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    const migrated: FavoriteEntry[] = [];
    for (const x of parsed) {
      if (typeof x === "string") {
        migrated.push({ assetId: x });
      } else if (x && typeof x === "object" && typeof (x as { assetId?: unknown }).assetId === "string") {
        const e = x as { assetId: string; branch?: string; tag?: string };
        migrated.push({
          assetId: e.assetId,
          branch: typeof e.branch === "string" ? e.branch : undefined,
          tag: typeof e.tag === "string" ? e.tag : undefined,
        });
      }
    }
    return migrated;
  } catch {
    return [];
  }
}

export function loadFavoriteEntries(): FavoriteEntry[] {
  return parseFavoriteEntries(typeof window !== "undefined" ? localStorage.getItem(FAVORITES_KEY) : null);
}

export function saveFavoriteEntries(entries: FavoriteEntry[]): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(FAVORITES_KEY, JSON.stringify(entries));
  } catch {
    /* ignore */
  }
}

/** @deprecated Use loadFavoriteEntries. Returns unique asset IDs for backward compat. */
export function loadFavoriteIds(): string[] {
  const entries = loadFavoriteEntries();
  return [...new Set(entries.map((e) => e.assetId))];
}

export function loadReportPresetMetas(): SavedPresetMeta[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(REPORT_PRESETS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(
        (p): p is { id: string; name: string; savedAt: string } =>
          p && typeof p === "object" && typeof (p as { id: unknown }).id === "string" && typeof (p as { name: unknown }).name === "string" && typeof (p as { savedAt: unknown }).savedAt === "string"
      )
      .map((p) => ({ id: p.id, name: p.name, savedAt: p.savedAt }));
  } catch {
    return [];
  }
}

export async function loadSavedReportMetas(): Promise<SavedReportMeta[]> {
  if (typeof window === "undefined") return [];
  try {
    return await getReportPersistence().list();
  } catch {
    return [];
  }
}

export async function loadUserSettingsSummary(): Promise<UserSettingsSummary> {
  const savedReports = await loadSavedReportMetas();
  const preferences = loadUserPreferences();
  return {
    favoriteCount: loadFavoriteEntries().length,
    loadoutCount: loadAssetLoadouts().length,
    reportPresetCount: loadReportPresetMetas().length,
    savedReportCount: savedReports.length,
    preferences,
  };
}

export { loadUserPreferences, saveUserPreferences, type UserPreferences };
