"use client";

import { useMemo, useState, useCallback, useRef, useEffect } from "react";
import { useVATData } from "@/contexts/VATDataContext";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import {
  ABC_TOOLTIP,
  ORA_TOOLTIP,
  ASSET_TYPES,
  ASSET_TYPE_LABELS,
} from "@/lib/constants";
import type { AssetLoadout } from "@/lib/assetLoadoutStorage";
import { resolveAssetIdsByName } from "@/lib/assetUtils";
import { fetchAikidoTeams } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { ThemedTooltip } from "@/components/ui/ThemedTooltip";
import { SearchInput } from "@/components/ui/SearchInput";
import { mono, sans } from "@/lib/styles";

const FINDING_STATUS_OPTS = [
  "Needs Justification",
  "Justified",
  "Verified",
  "Needs Rework",
  "Needs Reverified",
];
const ABC_OPTS = ["Compliant", "Compliant With Warnings", "Non-compliant"];

interface FilterSidebarProps {
  filterFindingStatuses?: Set<string>;
  onFilterFindingStatusesChange: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  filterAssetTypes?: Set<string>;
  onFilterAssetTypesChange: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  filterABC?: Set<string>;
  onFilterABCChange: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  filterVerifiedRange?: [number, number];
  onFilterVerifiedRangeChange: (v: [number, number]) => void;
  filterORARange?: [number, number];
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
  onClose?: () => void;
}

function countActiveFilters(p: {
  filterFindingStatuses: Set<string>;
  filterAssetTypes: Set<string>;
  filterABC: Set<string>;
  filterVerifiedRange: [number, number];
  filterORARange: [number, number];
}): number {
  let n = 0;
  if (p.filterFindingStatuses.size > 0) n += 1;
  if (p.filterAssetTypes.size > 0) n += 1;
  if (p.filterABC.size > 0) n += 1;
  if (p.filterVerifiedRange[0] > 0 || p.filterVerifiedRange[1] < 100) n += 1;
  if (p.filterORARange[0] > 0 || p.filterORARange[1] < 100) n += 1;
  return n;
}

export function FilterSidebar({
  filterFindingStatuses = new Set(),
  onFilterFindingStatusesChange,
  filterAssetTypes = new Set(),
  onFilterAssetTypesChange,
  filterABC = new Set(),
  onFilterABCChange,
  filterVerifiedRange = [0, 100],
  onFilterVerifiedRangeChange,
  filterORARange = [0, 100],
  onFilterORARangeChange,
  showArchived,
  onShowArchivedToggle,
  onlyFavorites,
  onOnlyFavoritesToggle,
  showEmptyAssets,
  onShowEmptyAssetsToggle,
  needsJustification,
  onNeedsJustificationToggle,
  onApply,
  applyLabel = "Apply",
  onClose,
}: FilterSidebarProps) {
  const activeCount = useMemo(
    () =>
      countActiveFilters({
        filterFindingStatuses,
        filterAssetTypes,
        filterABC,
        filterVerifiedRange,
        filterORARange,
      }),
    [
      filterFindingStatuses,
      filterAssetTypes,
      filterABC,
      filterVerifiedRange,
      filterORARange,
    ],
  );

  const clearAll = () => {
    onFilterFindingStatusesChange(new Set());
    onFilterAssetTypesChange(new Set());
    onFilterABCChange(new Set());
    onFilterVerifiedRangeChange([0, 100]);
    onFilterORARangeChange([0, 100]);
  };

  return (
    <aside
      className="filter-sidebar filter-sidebar-modern"
      style={{
        width: 240,
        minWidth: 240,
        flex: 1,
        minHeight: 0,
        background: "var(--app-card-bg)",
        borderRight: "1px solid var(--app-border-subtle)",
        padding: 16,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
      aria-label="Filters"
    >
      <div
        className="filter-sidebar-scroll"
        style={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          overflowX: "hidden",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 16,
          }}
        >
          <h2
            className="modern-section-label"
            style={{
              ...mono,
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: "0.08em",
              color: "var(--app-fg)",
              textTransform: "uppercase",
              margin: 0,
            }}
          >
            Filters
          </h2>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {onClose && (
              <button
                type="button"
                onClick={onClose}
                aria-label="Close filters"
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--app-muted)",
                  fontSize: 14,
                  cursor: "pointer",
                  padding: 4,
                  ...sans,
                }}
              >
                ✕
              </button>
            )}
            {activeCount > 0 && (
              <button
                type="button"
                onClick={clearAll}
                aria-label="Clear all filters"
                className="modern-chip"
                style={{
                  background: "transparent",
                  color: "var(--app-muted)",
                  fontSize: 11,
                  cursor: "pointer",
                  textDecoration: "underline",
                  ...sans,
                }}
              >
                Clear all
              </button>
            )}
          </div>
        </div>

        <div
          style={{ marginBottom: 16 }}
          role="group"
          aria-labelledby="filter-favorites-label"
        >
          <span
            id="filter-favorites-label"
            style={{
              ...mono,
              fontSize: 10,
              fontWeight: 600,
              color: "var(--app-fg-group)",
              display: "block",
              marginBottom: 8,
            }}
          >
            Favorites
          </span>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 8,
            }}
          >
            <label
              htmlFor="only-favorites-switch"
              style={{
                ...sans,
                fontSize: 12,
                color: "var(--app-fg-secondary)",
                cursor: "pointer",
                flex: 1,
              }}
            >
              Only Favorites
            </label>
            <button
              id="only-favorites-switch"
              type="button"
              role="switch"
              aria-checked={onlyFavorites}
              aria-label="Show only favorite findings"
              onClick={onOnlyFavoritesToggle}
              onKeyDown={(e) => {
                if (e.key === " " || e.key === "Enter") {
                  e.preventDefault();
                  onOnlyFavoritesToggle();
                }
              }}
              tabIndex={0}
              style={{
                width: 40,
                height: 22,
                borderRadius: 11,
                background: onlyFavorites
                  ? "var(--app-accent-emerald)"
                  : "var(--app-border)",
                position: "relative",
                cursor: "pointer",
                flexShrink: 0,
                border: "none",
                padding: 0,
              }}
            >
              <span
                style={{
                  position: "absolute",
                  top: 2,
                  left: onlyFavorites ? 20 : 2,
                  width: 18,
                  height: 18,
                  borderRadius: 9,
                  background: "#fff",
                  transition: "left 0.15s ease-out",
                }}
                aria-hidden
              />
            </button>
          </div>
        </div>

        <div
          style={{ marginBottom: 16 }}
          role="group"
          aria-labelledby="filter-empty-assets-label"
        >
          <span
            id="filter-empty-assets-label"
            style={{
              ...mono,
              fontSize: 10,
              fontWeight: 600,
              color: "var(--app-fg-group)",
              display: "block",
              marginBottom: 8,
            }}
          >
            Assets
          </span>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 8,
            }}
          >
            <label
              htmlFor="show-empty-assets-switch"
              style={{
                ...sans,
                fontSize: 12,
                color: "var(--app-fg-secondary)",
                cursor: "pointer",
                flex: 1,
              }}
            >
              Show empty assets
            </label>
            <button
              id="show-empty-assets-switch"
              type="button"
              role="switch"
              aria-checked={showEmptyAssets}
              aria-label="Show assets that have no findings"
              onClick={onShowEmptyAssetsToggle}
              onKeyDown={(e) => {
                if (e.key === " " || e.key === "Enter") {
                  e.preventDefault();
                  onShowEmptyAssetsToggle();
                }
              }}
              tabIndex={0}
              style={{
                width: 40,
                height: 22,
                borderRadius: 11,
                background: showEmptyAssets
                  ? "var(--app-accent-emerald)"
                  : "var(--app-border)",
                position: "relative",
                cursor: "pointer",
                flexShrink: 0,
                border: "none",
                padding: 0,
              }}
            >
              <span
                style={{
                  position: "absolute",
                  top: 2,
                  left: showEmptyAssets ? 20 : 2,
                  width: 18,
                  height: 18,
                  borderRadius: 9,
                  background: "#fff",
                  transition: "left 0.15s ease-out",
                }}
                aria-hidden
              />
            </button>
          </div>
        </div>

        <AssetLoadoutsSection />

        <FilterCheckboxSection
          label="Finding Statuses"
          selected={filterFindingStatuses}
          options={FINDING_STATUS_OPTS}
          onChange={onFilterFindingStatusesChange}
        />

        <FilterCheckboxSection
          label="Asset Type"
          selected={filterAssetTypes}
          options={[...ASSET_TYPES]}
          onChange={onFilterAssetTypesChange}
          optionLabels={Object.fromEntries(
            ASSET_TYPES.map((t) => [t, ASSET_TYPE_LABELS[t]]),
          )}
        />

        <FilterCheckboxSection
          label="Acceptance Baseline Criteria"
          title={ABC_TOOLTIP}
          selected={filterABC}
          options={ABC_OPTS}
          onChange={onFilterABCChange}
        />

        <CollapsiblePanel label="Findings Verified" defaultOpen={true}>
          <RangeSlider
            min={0}
            max={100}
            value={filterVerifiedRange}
            onChange={onFilterVerifiedRangeChange}
            suffix="%"
          />
        </CollapsiblePanel>

        <CollapsiblePanel
          label="Operational Risk Assessment"
          title={ORA_TOOLTIP}
          defaultOpen={true}
        >
          <RangeSlider
            min={0}
            max={100}
            value={filterORARange}
            onChange={onFilterORARangeChange}
            suffix="%"
          />
        </CollapsiblePanel>

        <CollapsiblePanel label="Options" defaultOpen={true}>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                cursor: "pointer",
                ...sans,
                fontSize: 12,
                color: "var(--app-fg-secondary)",
              }}
            >
              <input
                type="checkbox"
                checked={showArchived}
                onChange={onShowArchivedToggle}
                aria-label="Include archived findings"
                style={{ accentColor: "var(--app-accent-emerald)" }}
              />
              Include archived
            </label>

            <GroupFindingsToggle />

            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
              }}
            >
              <label
                htmlFor="needs-justification-switch"
                style={{
                  ...sans,
                  fontSize: 12,
                  color: "var(--app-fg-secondary)",
                  cursor: "pointer",
                  flex: 1,
                }}
              >
                Needs justification only
              </label>
              <button
                id="needs-justification-switch"
                type="button"
                role="switch"
                aria-checked={needsJustification}
                aria-label="Show only findings that need justification"
                onClick={onNeedsJustificationToggle}
                onKeyDown={(e) => {
                  if (e.key === " " || e.key === "Enter") {
                    e.preventDefault();
                    onNeedsJustificationToggle();
                  }
                }}
                tabIndex={0}
                style={{
                  width: 40,
                  height: 22,
                  borderRadius: 11,
                  background: needsJustification
                    ? "var(--app-accent-emerald)"
                    : "var(--app-border)",
                  position: "relative",
                  cursor: "pointer",
                  flexShrink: 0,
                  border: "none",
                  padding: 0,
                }}
              >
                <span
                  style={{
                    position: "absolute",
                    top: 2,
                    left: needsJustification ? 20 : 2,
                    width: 18,
                    height: 18,
                    borderRadius: 9,
                    background: "#fff",
                    transition: "left 0.15s ease-out",
                  }}
                  aria-hidden
                />
              </button>
            </div>
          </div>
        </CollapsiblePanel>
      </div>

      {onApply && (
        <button
          type="button"
          onClick={onApply}
          aria-label={applyLabel}
          className="modern-card"
          style={{
            width: "100%",
            marginTop: "auto",
            flexShrink: 0,
            background: "var(--app-accent-emerald)",
            borderRadius: 6,
            padding: "10px 16px",
            color: "#fff",
            fontSize: 12,
            fontWeight: 600,
            cursor: "pointer",
            ...sans,
          }}
        >
          {applyLabel}
        </button>
      )}
    </aside>
  );
}

function AssetLoadoutsSection() {
  const {
    loadouts,
    allAssets,
    favoriteAssetIds,
    favoriteEntries,
    applyLoadout,
    saveLoadout,
    deleteLoadout,
    renameLoadout,
  } = useVATData();
  const { token } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [saveMode, setSaveMode] = useState<"idle" | "saving" | "editing">(
    "idle",
  );
  const [saveName, setSaveName] = useState("");
  const [editId, setEditId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const dropdownRef = useRef<HTMLDivElement>(null);

  const filteredLoadouts = useMemo(() => {
    if (!searchQuery.trim()) return loadouts;
    const q = searchQuery.toLowerCase().trim();
    return loadouts.filter((l) => l.name.toLowerCase().includes(q));
  }, [loadouts, searchQuery]);

  // The "current loadout" is whichever one's asset-id set matches the active
  // favoriteAssetIds exactly. There is no explicit selected-id stored —
  // applyLoadout simply sets favoriteEntries — so we derive the active
  // loadout from the data. If the user has added/removed favorites since
  // applying a loadout, none match and we show the count fallback.
  const activeLoadout = useMemo(() => {
    if (favoriteAssetIds.size === 0) return null;
    for (const l of loadouts) {
      const ids = l.assetIds ?? [];
      if (ids.length !== favoriteAssetIds.size) continue;
      if (ids.every((id) => favoriteAssetIds.has(id))) return l;
    }
    return null;
  }, [loadouts, favoriteAssetIds]);

  const handleSaveNew = useCallback(() => {
    const name = saveName.trim();
    if (name && favoriteEntries.length > 0) {
      saveLoadout(null, name, favoriteEntries);
      setSaveName("");
      setSaveMode("idle");
    }
  }, [saveName, favoriteEntries, saveLoadout]);

  const handleSaveOverwrite = useCallback(
    (id: string) => {
      const name = editName.trim();
      if (name && favoriteEntries.length > 0) {
        saveLoadout(id, name, favoriteEntries);
        setEditId(null);
        setEditName("");
        setSaveMode("idle");
      }
    },
    [editName, favoriteEntries, saveLoadout],
  );

  const handleRename = useCallback(
    (id: string) => {
      const name = editName.trim();
      if (name) {
        renameLoadout(id, name);
        setEditId(null);
        setEditName("");
        setSaveMode("idle");
      }
    },
    [editName, renameLoadout],
  );

  const [importState, setImportState] = useState<
    { phase: "idle" | "running" } | { phase: "done"; message: string }
  >({ phase: "idle" });

  // Pull Aikido teams and save each one as a loadout of the VAT assets it owns.
  // Teams whose repos/containers were never ingested resolve to nothing and are
  // skipped rather than saved empty. Existing loadouts with the same name are
  // overwritten so a re-import tracks team membership changes.
  const handleImportAikidoTeams = useCallback(async () => {
    setImportState({ phase: "running" });
    try {
      const teams = await fetchAikidoTeams({ token: token ?? undefined });
      const byName = new Map(loadouts.map((l) => [l.name.toLowerCase(), l.id]));
      let imported = 0;
      let skipped = 0;
      for (const team of teams) {
        const assetIds = resolveAssetIdsByName(team.assetNames, allAssets);
        if (assetIds.length === 0) {
          skipped++;
          continue;
        }
        await saveLoadout(
          byName.get(team.name.toLowerCase()) ?? null,
          team.name,
          assetIds.map((assetId) => ({ assetId })),
        );
        imported++;
      }
      setImportState({
        phase: "done",
        message:
          imported === 0
            ? "No Aikido team matched a known asset"
            : `Imported ${imported} team${imported === 1 ? "" : "s"}${skipped > 0 ? ` · ${skipped} with no matching assets` : ""}`,
      });
    } catch {
      setImportState({ phase: "done", message: "Aikido team import failed" });
    }
  }, [allAssets, loadouts, saveLoadout, token]);

  const handleApply = useCallback(
    (loadout: AssetLoadout) => {
      applyLoadout(loadout);
      setDropdownOpen(false);
    },
    [applyLoadout],
  );

  useEffect(() => {
    if (!dropdownOpen) return;
    const onDocClick = (e: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target as Node)
      ) {
        setDropdownOpen(false);
        setSearchQuery("");
      }
    };
    document.addEventListener("click", onDocClick);
    return () => document.removeEventListener("click", onDocClick);
  }, [dropdownOpen]);

  return (
    <div
      style={{ marginBottom: 16 }}
      role="group"
      aria-labelledby="loadouts-label"
    >
      <span
        id="loadouts-label"
        style={{
          ...mono,
          fontSize: 10,
          fontWeight: 600,
          color: "var(--app-fg-group)",
          display: "block",
          marginBottom: 8,
        }}
      >
        Loadouts
      </span>
      <div style={{ position: "relative" }} ref={dropdownRef}>
        <button
          type="button"
          onClick={() => setDropdownOpen((o) => !o)}
          aria-expanded={dropdownOpen}
          aria-haspopup="listbox"
          aria-label="Select loadout"
          style={{
            width: "100%",
            padding: "6px 10px",
            fontSize: 11,
            textAlign: "left",
            background: "var(--app-card-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 4,
            color: "var(--app-fg)",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 8,
            ...sans,
          }}
        >
          <span
            style={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              display: "flex",
              alignItems: "center",
              gap: 6,
              minWidth: 0,
            }}
          >
            {activeLoadout ? (
              <>
                <span
                  aria-hidden
                  style={{
                    flexShrink: 0,
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: "var(--ui-accent)",
                    boxShadow:
                      "0 0 0 2px color-mix(in srgb, var(--ui-accent) 25%, transparent)",
                  }}
                />
                <span
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontWeight: 600,
                  }}
                  title={activeLoadout.name}
                >
                  {activeLoadout.name}
                </span>
                <span
                  style={{
                    flexShrink: 0,
                    color: "var(--app-muted)",
                    fontSize: 10,
                  }}
                >
                  · {activeLoadout.assetIds.length}
                </span>
              </>
            ) : loadouts.length === 0 ? (
              <span style={{ color: "var(--app-muted)" }}>No loadouts</span>
            ) : favoriteAssetIds.size > 0 ? (
              <span style={{ color: "var(--app-muted)" }}>
                Custom selection · {favoriteAssetIds.size}
              </span>
            ) : (
              <span style={{ color: "var(--app-muted)" }}>
                Select loadout ({loadouts.length} saved)
              </span>
            )}
          </span>
          <span
            style={{ flexShrink: 0, color: "var(--app-muted)", fontSize: 10 }}
          >
            {dropdownOpen ? "▲" : "▼"}
          </span>
        </button>

        {dropdownOpen && (
          <div
            role="listbox"
            style={{
              position: "absolute",
              top: "100%",
              left: 0,
              right: 0,
              marginTop: 4,
              padding: 8,
              background: "var(--app-card-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
              boxShadow: "0 4px 12px rgba(0,0,0,0.25)",
              zIndex: 100,
              maxHeight: 280,
              display: "flex",
              flexDirection: "column",
              gap: 6,
            }}
          >
            <SearchInput
              value={searchQuery}
              onValueChange={setSearchQuery}
              onKeyDown={(e) => e.stopPropagation()}
              placeholder="Search loadouts…"
              style={{
                width: "100%",
                padding: "6px 8px",
                fontSize: 11,
                borderRadius: 4,
                border: "1px solid var(--app-border)",
                background: "var(--app-bg)",
                color: "var(--app-fg)",
                ...sans,
              }}
            />

            <div
              style={{
                flex: 1,
                minHeight: 0,
                overflowY: "auto",
                overflowX: "hidden",
                display: "flex",
                flexDirection: "column",
                gap: 4,
              }}
            >
              {filteredLoadouts.length === 0 && (
                <span
                  style={{
                    ...sans,
                    fontSize: 11,
                    color: "var(--app-fg-secondary)",
                    padding: 4,
                  }}
                >
                  {searchQuery.trim()
                    ? "No matching loadouts"
                    : "Save favorites as named loadouts for quick switching."}
                </span>
              )}
              {filteredLoadouts.map((loadout) => (
                <div
                  key={loadout.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 4,
                    minWidth: 0,
                  }}
                >
                  {editId === loadout.id ? (
                    <div
                      style={{
                        flex: 1,
                        minWidth: 0,
                        display: "flex",
                        gap: 4,
                        flexWrap: "wrap",
                      }}
                    >
                      <input
                        type="text"
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        onKeyDown={(e) => {
                          e.stopPropagation();
                          if (e.key === "Enter") {
                            if (saveMode === "saving")
                              handleSaveOverwrite(loadout.id);
                            else handleRename(loadout.id);
                          }
                          if (e.key === "Escape") {
                            setEditId(null);
                            setEditName("");
                            setSaveMode("idle");
                          }
                        }}
                        placeholder={
                          saveMode === "saving"
                            ? "Name (overwrite)"
                            : "New name"
                        }
                        autoFocus
                        style={{
                          flex: "1 1 80px",
                          minWidth: 60,
                          padding: "4px 8px",
                          fontSize: 11,
                          borderRadius: 4,
                          border: "1px solid var(--app-border)",
                          background: "var(--app-bg)",
                          color: "var(--app-fg)",
                          ...sans,
                        }}
                      />
                      <button
                        type="button"
                        onClick={() =>
                          saveMode === "saving"
                            ? handleSaveOverwrite(loadout.id)
                            : handleRename(loadout.id)
                        }
                        aria-label={
                          saveMode === "saving"
                            ? "Overwrite loadout"
                            : "Save rename"
                        }
                        style={{
                          padding: "4px 8px",
                          fontSize: 10,
                          background: "var(--app-accent-emerald)",
                          color: "#fff",
                          border: "none",
                          borderRadius: 4,
                          cursor: "pointer",
                          ...sans,
                        }}
                      >
                        Save
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setEditId(null);
                          setEditName("");
                          setSaveMode("idle");
                        }}
                        aria-label="Cancel"
                        style={{
                          padding: "4px 8px",
                          fontSize: 10,
                          background: "none",
                          color: "var(--app-muted)",
                          border: "none",
                          cursor: "pointer",
                          ...sans,
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <>
                      <button
                        type="button"
                        onClick={() => handleApply(loadout)}
                        aria-label={`Apply loadout ${loadout.name}`}
                        aria-current={
                          activeLoadout?.id === loadout.id ? "true" : undefined
                        }
                        style={{
                          flex: 1,
                          minWidth: 0,
                          padding: "5px 8px",
                          fontSize: 11,
                          textAlign: "left",
                          background:
                            activeLoadout?.id === loadout.id
                              ? "color-mix(in srgb, var(--ui-accent) 18%, transparent)"
                              : "var(--app-bg)",
                          border:
                            activeLoadout?.id === loadout.id
                              ? "1px solid color-mix(in srgb, var(--ui-accent) 50%, transparent)"
                              : "1px solid var(--app-border)",
                          borderRadius: 4,
                          color: "var(--app-fg)",
                          cursor: "pointer",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          fontWeight:
                            activeLoadout?.id === loadout.id ? 600 : 400,
                          ...sans,
                        }}
                      >
                        {activeLoadout?.id === loadout.id && (
                          <span
                            aria-hidden
                            style={{
                              display: "inline-block",
                              width: 5,
                              height: 5,
                              borderRadius: "50%",
                              background: "var(--ui-accent)",
                              marginRight: 6,
                              verticalAlign: "middle",
                            }}
                          />
                        )}
                        {loadout.name}
                        <span
                          style={{ color: "var(--app-muted)", marginLeft: 4 }}
                        >
                          ({loadout.entries?.length ?? loadout.assetIds.length})
                        </span>
                      </button>
                      <div style={{ display: "flex", flexShrink: 0, gap: 2 }}>
                        <ThemedTooltip
                          content="Overwrite with current"
                          placement="top"
                        >
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setEditId(loadout.id);
                              setEditName(loadout.name);
                              setSaveMode("saving");
                            }}
                            aria-label={`Overwrite ${loadout.name}`}
                            style={{
                              width: 22,
                              height: 22,
                              padding: 0,
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              background: "none",
                              border: "none",
                              borderRadius: 4,
                              color: "var(--app-fg-secondary)",
                              cursor: "pointer",
                              fontSize: 11,
                            }}
                          >
                            ↻
                          </button>
                        </ThemedTooltip>
                        <ThemedTooltip content="Rename" placement="top">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setEditId(loadout.id);
                              setEditName(loadout.name);
                              setSaveMode("editing");
                            }}
                            aria-label={`Rename ${loadout.name}`}
                            style={{
                              width: 22,
                              height: 22,
                              padding: 0,
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              background: "none",
                              border: "none",
                              borderRadius: 4,
                              color: "var(--app-fg-secondary)",
                              cursor: "pointer",
                              fontSize: 11,
                            }}
                          >
                            ✎
                          </button>
                        </ThemedTooltip>
                        <ThemedTooltip content="Delete" placement="top">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              deleteLoadout(loadout.id);
                            }}
                            aria-label={`Delete ${loadout.name}`}
                            style={{
                              width: 22,
                              height: 22,
                              padding: 0,
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              background: "none",
                              border: "none",
                              borderRadius: 4,
                              color: "var(--app-danger, #ef4444)",
                              cursor: "pointer",
                              fontSize: 12,
                            }}
                          >
                            ×
                          </button>
                        </ThemedTooltip>
                      </div>
                    </>
                  )}
                </div>
              ))}
            </div>

            <button
              type="button"
              onClick={handleImportAikidoTeams}
              disabled={importState.phase === "running"}
              title="Create a loadout per Aikido team from the repos and containers it owns"
              style={{
                padding: "8px 10px",
                fontSize: 11,
                background: "none",
                border: "1px dashed var(--app-border)",
                borderRadius: 4,
                color:
                  importState.phase === "running"
                    ? "var(--app-muted)"
                    : "var(--app-fg)",
                cursor:
                  importState.phase === "running" ? "default" : "pointer",
                textAlign: "left",
                ...sans,
              }}
            >
              {importState.phase === "running"
                ? "Pulling Aikido teams…"
                : "↓ Import Aikido teams"}
            </button>
            {importState.phase === "done" && (
              <span
                role="status"
                style={{
                  fontSize: 10,
                  color: "var(--app-muted)",
                  padding: "0 2px",
                  ...sans,
                }}
              >
                {importState.message}
              </span>
            )}

            {saveMode === "idle" ? (
              <button
                type="button"
                onClick={() => setSaveMode("saving")}
                style={{
                  padding: "8px 10px",
                  fontSize: 11,
                  background: "none",
                  border: "1px dashed var(--app-border)",
                  borderRadius: 4,
                  color: "var(--app-accent-emerald)",
                  cursor: "pointer",
                  textAlign: "left",
                  ...sans,
                }}
              >
                + Save current
              </button>
            ) : saveMode === "saving" && !editId ? (
              <div
                style={{
                  display: "flex",
                  gap: 4,
                  alignItems: "center",
                  flexWrap: "wrap",
                }}
              >
                <input
                  type="text"
                  value={saveName}
                  onChange={(e) => setSaveName(e.target.value)}
                  onKeyDown={(e) => {
                    e.stopPropagation();
                    if (e.key === "Enter") handleSaveNew();
                    if (e.key === "Escape") {
                      setSaveName("");
                      setSaveMode("idle");
                    }
                  }}
                  placeholder="Loadout name"
                  autoFocus
                  style={{
                    flex: "1 1 80px",
                    minWidth: 60,
                    padding: "6px 8px",
                    fontSize: 11,
                    borderRadius: 4,
                    border: "1px solid var(--app-border)",
                    background: "var(--app-bg)",
                    color: "var(--app-fg)",
                    ...sans,
                  }}
                />
                <button
                  type="button"
                  onClick={handleSaveNew}
                  style={{
                    padding: "6px 10px",
                    fontSize: 11,
                    background: "var(--app-accent-emerald)",
                    color: "#fff",
                    border: "none",
                    borderRadius: 4,
                    cursor: "pointer",
                    ...sans,
                  }}
                >
                  Save
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSaveName("");
                    setSaveMode("idle");
                  }}
                  style={{
                    padding: "6px 10px",
                    fontSize: 11,
                    background: "none",
                    color: "var(--app-muted)",
                    border: "none",
                    cursor: "pointer",
                    ...sans,
                  }}
                >
                  Cancel
                </button>
              </div>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}

function GroupFindingsToggle() {
  const { preferences, setPreferences } = useUserPreferences();
  const groupFindings = preferences.groupFindings ?? true;
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 8,
      }}
    >
      <label
        htmlFor="group-findings-switch"
        style={{
          ...sans,
          fontSize: 12,
          color: "var(--app-fg-secondary)",
          cursor: "pointer",
          flex: 1,
        }}
      >
        Group findings{" "}
        <span style={{ opacity: 0.8 }}>
          ({groupFindings ? "groups" : "instances"})
        </span>
      </label>
      <button
        id="group-findings-switch"
        type="button"
        role="switch"
        aria-checked={groupFindings}
        aria-label="Group same findings across sources"
        onClick={() => setPreferences({ groupFindings: !groupFindings })}
        onKeyDown={(e) => {
          if (e.key === " " || e.key === "Enter") {
            e.preventDefault();
            setPreferences({ groupFindings: !groupFindings });
          }
        }}
        tabIndex={0}
        style={{
          width: 40,
          height: 22,
          borderRadius: 11,
          background: groupFindings
            ? "var(--app-accent-emerald)"
            : "var(--app-border)",
          position: "relative",
          cursor: "pointer",
          flexShrink: 0,
          border: "none",
          padding: 0,
        }}
      >
        <span
          style={{
            position: "absolute",
            top: 2,
            left: groupFindings ? 20 : 2,
            width: 18,
            height: 18,
            borderRadius: 9,
            background: "#fff",
            transition: "left 0.15s ease-out",
          }}
          aria-hidden
        />
      </button>
    </div>
  );
}

function FilterCheckboxSection({
  label,
  title,
  selected,
  options,
  onChange,
  optionLabels,
}: {
  label: string;
  title?: string;
  selected: Set<string>;
  options: string[];
  onChange: (v: Set<string> | ((prev: Set<string>) => Set<string>)) => void;
  optionLabels?: Record<string, string>;
}) {
  const displayLabel = (opt: string) => optionLabels?.[opt] ?? opt;
  const addAll = () => onChange(new Set(options));
  const clear = () => onChange(new Set());
  const labelId = `filter-${label.replace(/\s/g, "-")}-label`;

  return (
    <div style={{ marginBottom: 16 }} role="group" aria-labelledby={labelId}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 8,
        }}
      >
        {title ? (
          <ThemedTooltip content={title} placement="right">
            <span
              id={labelId}
              style={{
                ...mono,
                fontSize: 10,
                fontWeight: 600,
                color: "var(--app-fg-group)",
              }}
            >
              {label}
            </span>
          </ThemedTooltip>
        ) : (
          <span
            id={labelId}
            style={{
              ...mono,
              fontSize: 10,
              fontWeight: 600,
              color: "var(--app-fg-group)",
            }}
          >
            {label}
          </span>
        )}
        <div style={{ display: "flex", gap: 8 }}>
          <button
            type="button"
            onClick={addAll}
            aria-label={`Add all ${label.toLowerCase()}`}
            style={{
              background: "none",
              border: "none",
              color: "var(--app-accent-emerald)",
              fontSize: 10,
              cursor: "pointer",
              ...sans,
            }}
          >
            Add All
          </button>
          <button
            type="button"
            onClick={clear}
            aria-label={`Clear ${label.toLowerCase()}`}
            style={{
              background: "none",
              border: "none",
              color: "var(--app-muted)",
              fontSize: 10,
              cursor: "pointer",
              ...sans,
            }}
          >
            Clear
          </button>
        </div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {options.map((opt) => (
          <label
            key={opt}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              cursor: "pointer",
              ...sans,
              fontSize: 12,
              color: "var(--app-fg-secondary)",
            }}
          >
            <input
              type="checkbox"
              checked={selected.has(opt)}
              onChange={(e) => {
                if (e.target.checked) {
                  onChange((prev) => new Set([...Array.from(prev), opt]));
                } else {
                  onChange((prev) => {
                    const n = new Set(prev);
                    n.delete(opt);
                    return n;
                  });
                }
              }}
              aria-label={displayLabel(opt)}
              style={{ accentColor: "var(--app-accent-emerald)" }}
            />
            {displayLabel(opt)}
          </label>
        ))}
      </div>
    </div>
  );
}

function RangeSlider({
  min,
  max,
  value,
  onChange,
  suffix = "",
}: {
  min: number;
  max: number;
  value: [number, number];
  onChange: (v: [number, number]) => void;
  suffix?: string;
}) {
  const [low, high] = [value[0], value[1]];
  const lowPct = ((low - min) / (max - min)) * 100;
  const highPct = ((high - min) / (max - min)) * 100;
  const midPct = (lowPct + highPct) / 2;
  const buffer = 6; /* overlap so thumbs aren't clipped at boundary */
  return (
    <div style={{ marginBottom: 4 }}>
      <div className="range-slider-track">
        <div
          className="range-slider-filled"
          style={{
            left: `${lowPct}%`,
            right: `${100 - highPct}%`,
          }}
        />
        <div className="range-slider-inputs">
          <input
            type="range"
            min={min}
            max={max}
            value={low}
            onChange={(e) => {
              const v = Number(e.target.value);
              onChange([Math.min(v, high), high]);
            }}
            aria-label="Minimum value"
            className="range-slider-input-min"
            style={{
              clipPath: `inset(0 ${Math.max(0, 100 - midPct - buffer)}% 0 0)`,
            }}
          />
          <input
            type="range"
            min={min}
            max={max}
            value={high}
            onChange={(e) => {
              const v = Number(e.target.value);
              onChange([low, Math.max(v, low)]);
            }}
            aria-label="Maximum value"
            className="range-slider-input-max"
            style={{
              clipPath: `inset(0 0 0 ${Math.max(0, midPct - buffer)}%)`,
            }}
          />
        </div>
      </div>
      <div className="range-slider-values">
        <span className="range-slider-value">
          {low}
          {suffix}
        </span>
        <span className="range-slider-value">
          {high}
          {suffix}
        </span>
      </div>
    </div>
  );
}

function CollapsiblePanel({
  label,
  title,
  defaultOpen,
  children,
}: {
  label: string;
  title?: string;
  defaultOpen: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const id = `filter-collapse-${label
    .replace(/\s/g, "-")
    .replace(/[()]/g, "")}`;
  const btnId = `filter-collapse-btn-${label
    .replace(/\s/g, "-")
    .replace(/[()]/g, "")}`;

  return (
    <div style={{ marginBottom: 16 }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={id}
        id={btnId}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          width: "100%",
          background: "none",
          border: "none",
          padding: 0,
          marginBottom: open ? 8 : 0,
          cursor: "pointer",
          ...mono,
          fontSize: 10,
          fontWeight: 600,
          color: "var(--app-fg-group)",
        }}
      >
        {title ? (
          <ThemedTooltip content={title} placement="right">
            <span>{label}</span>
          </ThemedTooltip>
        ) : (
          label
        )}
        <span
          style={{
            transform: open ? "rotate(180deg)" : "rotate(0deg)",
            transition: "transform 0.2s ease-out",
            fontSize: 12,
          }}
          aria-hidden
        >
          ▼
        </span>
      </button>
      {open && (
        <div id={id} role="region" aria-labelledby={btnId}>
          {children}
        </div>
      )}
    </div>
  );
}
