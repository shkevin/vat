/**
 * Asset loadout storage — named sets of favorite asset entries (assetId + optional branch/tag).
 * Enables quick switching between different asset views (e.g. Production, Staging, Critical).
 * Pattern inspired by Destiny Item Manager, The Division 2, and similar loadout systems.
 */

import type { FavoriteEntry } from "@/lib/userSettings";

export const ASSET_LOADOUTS_KEY = "vat-asset-loadouts";

export interface AssetLoadout {
  id: string;
  name: string;
  /** @deprecated Use entries. Kept for backward compat. */
  assetIds: string[];
  /** Favorite entries with optional branch/tag context. When present, used instead of assetIds. */
  entries?: FavoriteEntry[];
  savedAt: string;
}

function readStored(): AssetLoadout[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(ASSET_LOADOUTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(
        (l): l is AssetLoadout =>
          l &&
          typeof l === "object" &&
          typeof (l as AssetLoadout).id === "string" &&
          typeof (l as AssetLoadout).name === "string" &&
          Array.isArray((l as AssetLoadout).assetIds) &&
          typeof (l as AssetLoadout).savedAt === "string",
      )
      .map((l) => {
        const loadout = l as AssetLoadout;
        const entries = Array.isArray(loadout.entries)
          ? loadout.entries.filter(
              (e): e is FavoriteEntry =>
                e &&
                typeof e === "object" &&
                typeof (e as FavoriteEntry).assetId === "string",
            )
          : undefined;
        return { ...loadout, entries };
      });
  } catch {
    return [];
  }
}

function writeStored(loadouts: AssetLoadout[]): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(ASSET_LOADOUTS_KEY, JSON.stringify(loadouts));
  } catch {
    // ignore
  }
}

function generateId(): string {
  return `loadout-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

/** List all saved loadouts, sorted by most recently saved. */
export function loadAssetLoadouts(): AssetLoadout[] {
  const loadouts = readStored();
  return [...loadouts].sort(
    (a, b) => new Date(b.savedAt).getTime() - new Date(a.savedAt).getTime(),
  );
}

/** Save a new loadout or update an existing one. Returns the loadout id. */
export function saveAssetLoadout(
  id: string | null,
  name: string,
  entries: FavoriteEntry[],
): string {
  const loadouts = readStored();
  const now = new Date().toISOString();
  const trimmedName = name.trim() || "Unnamed loadout";
  const assetIds = entries.map((e) => e.assetId);

  if (id) {
    const idx = loadouts.findIndex((l) => l.id === id);
    if (idx >= 0) {
      loadouts[idx] = {
        ...loadouts[idx],
        name: trimmedName,
        assetIds,
        entries: [...entries],
        savedAt: now,
      };
      writeStored(loadouts);
      return id;
    }
  }

  const newId = generateId();
  loadouts.unshift({
    id: newId,
    name: trimmedName,
    assetIds,
    entries: [...entries],
    savedAt: now,
  });
  writeStored(loadouts);
  return newId;
}

/** Delete a loadout by id. */
export function deleteAssetLoadout(id: string): void {
  const loadouts = readStored().filter((l) => l.id !== id);
  writeStored(loadouts);
}

/** Rename a loadout. */
export function renameAssetLoadout(id: string, name: string): void {
  const loadouts = readStored();
  const idx = loadouts.findIndex((l) => l.id === id);
  if (idx >= 0) {
    loadouts[idx] = {
      ...loadouts[idx],
      name: name.trim() || loadouts[idx].name,
      savedAt: new Date().toISOString(),
    };
    writeStored(loadouts);
  }
}
