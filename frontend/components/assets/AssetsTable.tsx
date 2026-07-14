"use client";

import { useState, useMemo, useCallback, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ChevronDown, ChevronUp } from "lucide-react";
import { AssetActionBar } from "@/components/assets/AssetActionBar";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { useVATData } from "@/contexts/VATDataContext";
import {
  ABC_TOOLTIP,
  ORA_TOOLTIP,
  ASSET_TYPE_LABELS,
  SEV_ORDER,
  SEV,
} from "@/lib/constants";
import {
  assetTagSortKey,
  containerTagListForAsset,
  getAssetTypeFromAsset,
  pickLatestVersionTag,
} from "@/lib/assetUtils";
import { isOpenRisk } from "@/lib/metricSemantics";
import { effectiveGroupKey } from "@/lib/findingGroupUtils";
import { ThemedTooltip } from "@/components/ui/ThemedTooltip";
import { SearchInput } from "@/components/ui/SearchInput";
import { mono, sans } from "@/lib/styles";

function buildAssetUrl(
  assetId: string,
  getFavoriteContext: (id: string) => { branch?: string; tag?: string } | null,
): string {
  const base = `/assets/${encodeURIComponent(assetId)}`;
  const ctx = getFavoriteContext(assetId);
  if (!ctx?.branch && !ctx?.tag) return base;
  const params = new URLSearchParams();
  if (ctx.branch) params.set("branch", ctx.branch);
  if (ctx.tag) params.set("tag", ctx.tag);
  return `${base}?${params.toString()}`;
}

const ROW_PADDING = {
  compact: "4px 14px",
  default: "8px 14px",
  comfortable: "12px 14px",
} as const;

const HEADER_PADDING = {
  compact: "4px 14px",
  default: "6px 14px",
  comfortable: "10px 14px",
} as const;
import type { Asset } from "@/types";
import type { Finding } from "@/types";
import type { Source } from "@/types";

interface AssetsTableProps {
  displayedAssets: Asset[];
  /** When true, count by group (e.g. 2 groups); when false, count each instance (e.g. 3 findings). */
  groupFindings?: boolean;
  sources: Source[];
  selected: Finding | null;
  checked: Set<string>;
  showArchived: boolean;
  archivedCount: number;
  total: number;
  filterAssetTypes: Set<string>;
  onFilterAssetTypesChange: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  favoriteAssetIds: Set<string>;
  onToggleFavorite: (assetId: string) => void;
  search: string;
  onSearchChange: (v: string) => void;
  searchPlaceholder?: string;
  onSelect: (f: Finding) => void;
  onCheck: (id: string, val: boolean) => void;
  onBulkAction: (status: string, justification: string) => void;
  onDeselectAll: () => void;
}

const STATUS_PRIORITY = [
  "Open",
  "In Review",
  "Risk Accepted",
  "Reopened",
  "Rejected",
  "Resolved",
  "False Positive",
  "Suppressed",
  "Not Applicable",
  "Approved",
  "Mitigated",
  "Duplicate",
];

const GROUP_STATUS_PRIORITY = [
  "Open",
  "Synced to Tracker",
  "In Review",
  "Risk Accepted",
  "Reopened",
  "Rejected",
  "Resolved",
  "False Positive",
  "Suppressed",
  "Not Applicable",
  "Approved",
  "Mitigated",
  "Duplicate",
] as const;

function groupedStatusBreakdown(findings: Finding[]): Record<string, number> {
  const byGroup = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = effectiveGroupKey(f);
    const list = byGroup.get(key) ?? [];
    list.push(f);
    byGroup.set(key, list);
  }
  const out: Record<string, number> = {};
  for (const list of byGroup.values()) {
    const statuses = new Set(
      list.map((f) => (f.status ?? "").trim()).filter((s) => s.length > 0),
    );
    const chosen =
      GROUP_STATUS_PRIORITY.find((s) => statuses.has(s)) ??
      list[0]?.status ??
      "Open";
    out[chosen] = (out[chosen] ?? 0) + 1;
  }
  return out;
}

function formatStatusSummary(breakdown: Record<string, number>): string {
  // Merge legacy "Synced to Tracker" into Open — tracked is now a separate column
  const merged = { ...breakdown };
  if (merged["Synced to Tracker"]) {
    merged["Open"] = (merged["Open"] ?? 0) + merged["Synced to Tracker"];
    delete merged["Synced to Tracker"];
  }
  const parts: string[] = [];
  for (const s of STATUS_PRIORITY) {
    const n = merged[s];
    if (n && n > 0) parts.push(`${n} ${s.toLowerCase()}`);
  }
  return parts.slice(0, 4).join(" · ") || "—";
}

function getABC(asset: Asset): string {
  if (asset.verifiedPct === 100) return "Compliant";
  if (asset.verifiedPct > 0) return "Compliant With Warnings";
  return "Non-compliant";
}

const ABC_ORDER = ["Compliant", "Compliant With Warnings", "Non-compliant"];

function normalizeSeverity(s: string): string {
  const lower = (s ?? "").toLowerCase().trim();
  if (lower === "info" || lower === "informational") return "Informational";
  if (lower === "critical") return "Critical";
  if (lower === "high") return "High";
  if (lower === "medium" || lower === "moderate") return "Medium";
  if (lower === "low") return "Low";
  return s
    ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase()
    : "Informational";
}

/** First column is the bulk-select checkbox (28px), second is the favorite heart
 * (28px). Tags is column 5 — must not use a fixed narrow width or chips
 * truncate in the wrong column. */
const ASSETS_TABLE_GRID_COLS =
  "28px 28px minmax(280px, 3fr) 90px minmax(220px, 2fr) 90px 90px 90px minmax(150px, 1.4fr) 1fr";

function AssetTagsCell({ asset }: { asset: Asset }) {
  const isContainer = getAssetTypeFromAsset(asset) === "container";
  const baseSpanStyle = {
    ...mono,
    fontSize: 11,
    color: "var(--app-fg)",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  } as const;

  if (!isContainer) {
    return <span style={baseSpanStyle}>{asset.tag ?? "—"}</span>;
  }

  const tags = containerTagListForAsset(asset);
  if (tags.length === 0) {
    return <span style={baseSpanStyle}>{asset.tag ?? "—"}</span>;
  }

  const { primary, restCount } = pickLatestVersionTag(tags);
  return (
    <div
      role="group"
      aria-label="Image tags"
      style={{
        display: "flex",
        flexWrap: "nowrap",
        alignItems: "center",
        gap: 6,
        minWidth: 0,
        width: "100%",
        ...mono,
      }}
    >
      {primary && (
        <span
          title={tags.join(", ")}
          style={{
            fontSize: 10,
            color: "var(--app-fg)",
            padding: "2px 6px",
            borderRadius: 4,
            border: "1px solid var(--app-border-subtle)",
            background: "var(--app-input-bg)",
            minWidth: 0,
            flex: "0 1 auto",
            maxWidth: "min(100%, 44ch)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {primary}
        </span>
      )}
      {restCount > 0 && (
        <span
          style={{
            fontSize: 10,
            color: "var(--app-muted)",
            flexShrink: 0,
          }}
        >
          +{restCount}
        </span>
      )}
      {asset.digestConflictOpen && (
        <ThemedTooltip content="Digest conflict: one or more tags map to multiple digests. Open the asset page to review.">
          <span
            aria-label="Digest conflict on this asset"
            style={{
              fontSize: 11,
              color: "var(--app-danger)",
              cursor: "default",
              lineHeight: 1,
              flexShrink: 0,
            }}
          >
            ⚠
          </span>
        </ThemedTooltip>
      )}
    </div>
  );
}

/** Sortable column config: label, sort key. Empty sortKey = not sortable.
 * The first two columns (bulk-select checkbox, favorite heart) are control
 * cells with no header — the layout adds explicit cells for them so the
 * grid stays aligned with the row template. */
const ASSET_COLUMNS: { label: string; sortKey: string }[] = [
  { label: "", sortKey: "" },
  { label: "", sortKey: "" },
  { label: "Asset", sortKey: "name" },
  { label: "Type", sortKey: "type" },
  { label: "Tags", sortKey: "tag" },
  { label: "Findings Verified", sortKey: "verified" },
  { label: "ABC", sortKey: "abc" },
  { label: "ORA", sortKey: "ora" },
  { label: "Severity (Open)", sortKey: "" },
  { label: "Finding Statuses", sortKey: "statuses" },
];

export function AssetsTable({
  displayedAssets,
  groupFindings = true,
  sources,
  selected,
  checked,
  showArchived,
  archivedCount,
  total,
  filterAssetTypes,
  onFilterAssetTypesChange,
  favoriteAssetIds,
  onToggleFavorite,
  search,
  onSearchChange,
  searchPlaceholder = "Search assets, CVE, component, team…",
  onSelect,
  onCheck,
  onBulkAction,
  onDeselectAll,
}: AssetsTableProps) {
  const router = useRouter();
  const { preferences } = useUserPreferences();
  const { getFavoriteContextForAsset, refetch, refreshing } = useVATData();
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const handleManualRefresh = useCallback(async () => {
    setRefreshError(null);
    try {
      window.localStorage.removeItem("vat:lastFindingsSnapshot:v2");
    } catch {
      // ignore
    }
    try {
      await refetch({ includeAuxiliary: true });
    } catch (e) {
      setRefreshError(e instanceof Error ? e.message : "refresh failed");
    }
  }, [refetch]);
  const density = preferences.tableDensity ?? "default";
  /** Use context directly so severity counts update immediately when toggle changes (prop can lag) */
  const effectiveGroupFindings =
    preferences.groupFindings ?? groupFindings ?? true;
  const [sortBy, setSortBy] = useState("name");
  const [visibleCount, setVisibleCount] = useState(200);

  const getAssetHref = useCallback(
    (assetId: string) => buildAssetUrl(assetId, getFavoriteContextForAsset),
    [getFavoriteContextForAsset],
  );

  const sortedAssets = useMemo(() => {
    const [sortKey, desc] = (() => {
      const d = sortBy.endsWith("-desc");
      return [d ? sortBy.slice(0, -5) : sortBy, d] as const;
    })();
    const validKeys = new Set([
      "name",
      "type",
      "tag",
      "verified",
      "abc",
      "ora",
      "statuses",
    ]);
    const key = validKeys.has(sortKey) ? sortKey : "name";
    return [...displayedAssets].sort((a, b) => {
      let cmp = 0;
      if (key === "name") cmp = (a.name ?? "").localeCompare(b.name ?? "");
      else if (key === "type")
        cmp = ASSET_TYPE_LABELS[getAssetTypeFromAsset(a)].localeCompare(
          ASSET_TYPE_LABELS[getAssetTypeFromAsset(b)],
        );
      else if (key === "tag")
        cmp = assetTagSortKey(a).localeCompare(assetTagSortKey(b));
      else if (key === "verified") cmp = a.verifiedPct - b.verifiedPct;
      else if (key === "abc")
        cmp = ABC_ORDER.indexOf(getABC(a)) - ABC_ORDER.indexOf(getABC(b));
      else if (key === "ora") cmp = a.oraPct - b.oraPct;
      else if (key === "statuses")
        cmp = formatStatusSummary(a.statusBreakdown).localeCompare(
          formatStatusSummary(b.statusBreakdown),
        );
      return desc ? -cmp : cmp;
    });
  }, [displayedAssets, sortBy]);

  useEffect(() => {
    setVisibleCount(200);
  }, [sortBy, displayedAssets.length, density]);

  // Select-all-visible checkbox state. "All" = every visible asset is checked;
  // "indeterminate" = some-but-not-all visible. Toggling either checks the
  // current visible page (cap by visibleCount so a 50k-row dataset doesn't
  // accidentally select everything; the bar shows the running count).
  const visibleAssetIds = useMemo(
    () => sortedAssets.slice(0, visibleCount).map((a) => a.id),
    [sortedAssets, visibleCount],
  );
  const visibleCheckedCount = useMemo(
    () => visibleAssetIds.filter((id) => checked.has(id)).length,
    [visibleAssetIds, checked],
  );
  const allVisibleChecked =
    visibleAssetIds.length > 0 &&
    visibleCheckedCount === visibleAssetIds.length;
  const someVisibleChecked =
    visibleCheckedCount > 0 && !allVisibleChecked;
  const handleToggleAllVisible = useCallback(() => {
    if (allVisibleChecked) {
      for (const id of visibleAssetIds) onCheck(id, false);
    } else {
      for (const id of visibleAssetIds) onCheck(id, true);
    }
  }, [allVisibleChecked, visibleAssetIds, onCheck]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const sev of SEV_ORDER) counts[sev] = 0;
    if (effectiveGroupFindings) {
      // Count by group: one per unique group key per asset (matches Asset detail page when grouped)
      // Only count open findings so totals align with Report Builder.
      const seenGroups = new Set<string>();
      for (const asset of displayedAssets) {
        for (const f of asset.findings) {
          if (!isOpenRisk(f.status)) continue;
          const gk = effectiveGroupKey(f);
          const dedupeKey = `${asset.id}:${gk}`;
          if (seenGroups.has(dedupeKey)) continue;
          seenGroups.add(dedupeKey);
          const s = normalizeSeverity(f.severity ?? "Informational");
          const key = (SEV_ORDER as readonly string[]).includes(s)
            ? s
            : "Informational";
          counts[key] = (counts[key] ?? 0) + 1;
        }
      }
    } else {
      // Count each instance — no deduplication; each finding in the array counts (matches Asset detail page when ungrouped)
      // Only count open findings so totals align with Report Builder.
      for (const asset of displayedAssets) {
        for (const f of asset.findings) {
          if (!isOpenRisk(f.status)) continue;
          const s = normalizeSeverity(f.severity ?? "Informational");
          const key = (SEV_ORDER as readonly string[]).includes(s)
            ? s
            : "Informational";
          counts[key] = (counts[key] ?? 0) + 1;
        }
      }
    }
    return SEV_ORDER.map((sev) => ({ severity: sev, count: counts[sev] ?? 0 }));
  }, [displayedAssets, effectiveGroupFindings]);

  const statusBreakdownByAsset = useMemo(() => {
    const out = new Map<string, Record<string, number>>();
    for (const asset of displayedAssets) {
      out.set(
        asset.id,
        effectiveGroupFindings
          ? groupedStatusBreakdown(asset.findings)
          : asset.statusBreakdown,
      );
    }
    return out;
  }, [displayedAssets, effectiveGroupFindings]);

  // Per-asset open-finding counts by severity — powers the per-row Severity
  // chips. Computed the same group/instance-aware way as the toolbar's
  // aggregate `severityCounts` so per-row chips sum to the toolbar totals.
  const severityCountsByAsset = useMemo(() => {
    const out = new Map<string, Record<string, number>>();
    for (const asset of displayedAssets) {
      const counts: Record<string, number> = {};
      for (const sev of SEV_ORDER) counts[sev] = 0;
      const seenGroups = new Set<string>();
      for (const f of asset.findings) {
        if (!isOpenRisk(f.status)) continue;
        if (effectiveGroupFindings) {
          const gk = effectiveGroupKey(f);
          if (seenGroups.has(gk)) continue;
          seenGroups.add(gk);
        }
        const s = normalizeSeverity(f.severity ?? "Informational");
        const key = (SEV_ORDER as readonly string[]).includes(s)
          ? s
          : "Informational";
        counts[key] = (counts[key] ?? 0) + 1;
      }
      out.set(asset.id, counts);
    }
    return out;
  }, [displayedAssets, effectiveGroupFindings]);

  // Resolve the checked Set to actual Asset objects for the docked action bar.
  // Pulling from sortedAssets (the full-set memo) so checks survive scroll
  // virtualization and search filters within the same loadout view.
  const selectedAssets = useMemo(
    () => sortedAssets.filter((a) => checked.has(a.id)),
    [sortedAssets, checked],
  );

  return (
    <>
    <div
      className="assets-table-shell"
      style={{
        width: "100%",
        flex: 1,
        minHeight: 0,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      <section className="vat-tab-hero modern-card">
        <div>
          <p className="vat-tab-eyebrow">Asset Intelligence</p>
          <h2 className="vat-tab-title">Findings Workspace</h2>
          <p className="vat-tab-subtitle">
            Search, sort, and prioritize vulnerable assets with severity and
            compliance context.
          </p>
        </div>
        <div className="vat-tab-hero-chips">
          <span className="vat-tab-chip">
            {displayedAssets.length.toLocaleString()} visible
          </span>
          <span className="vat-tab-chip">{total.toLocaleString()} total</span>
          <button
            type="button"
            onClick={handleManualRefresh}
            disabled={refreshing}
            title="Force a fresh fetch and clear the cached snapshot"
            style={{
              fontSize: 12,
              padding: "4px 10px",
              borderRadius: 999,
              border: "1px solid var(--app-border, #ccc)",
              background: "transparent",
              color: "inherit",
              cursor: refreshing ? "wait" : "pointer",
            }}
          >
            {refreshing ? "Refreshing…" : "↻ Refresh"}
          </button>
          {refreshError && (
            <span style={{ color: "var(--app-error, #b00020)", fontSize: 12 }}>
              {refreshError}
            </span>
          )}
        </div>
      </section>

      <div className="assets-table-toolbar" style={{ flexShrink: 0 }}>
        <div
          className="assets-table-stats"
          style={{
            display: "flex",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 10,
            marginBottom: 12,
          }}
        >
          <span
            style={{
              ...sans,
              fontSize: 12,
              color: "var(--app-muted)",
            }}
          >
            {filterAssetTypes.size > 0 || displayedAssets.length !== total
              ? `${displayedAssets.length} of ${total} assets`
              : `${total} asset${total === 1 ? "" : "s"}`}
          </span>
          <span style={{ color: "var(--app-border-subtle)", fontSize: 10 }}>
            |
          </span>
          {severityCounts
            .filter(({ count }) => count > 0)
            .map(({ severity, count }) => {
              const s = SEV[severity] ?? SEV.Informational;
              return (
                <span
                  className="assets-table-sev-chip"
                  key={severity}
                  style={{
                    ...mono,
                    fontSize: 11,
                    padding: "3px 8px",
                    borderRadius: 4,
                    background: s.bg,
                    color: s.c,
                    border: `1px solid ${s.c}40`,
                  }}
                >
                  {severity}: {count.toLocaleString()}
                </span>
              );
            })}
        </div>
        <SearchInput
          value={search}
          onValueChange={onSearchChange}
          placeholder={searchPlaceholder}
          aria-label="Search"
          className="modern-input"
          style={{
            width: "100%",
            borderRadius: 6,
            padding: "10px 14px",
            color: "var(--app-fg)",
            fontSize: 13,
            marginBottom: 12,
            ...sans,
          }}
        />

        {/* Asset bulk actions are rendered in a docked floating bar — see
         * AssetActionBar at the bottom of this component. The legacy
         * finding-level BulkBar is intentionally not shown here: applying
         * a status (e.g. False Positive) to every finding inside an asset
         * is unsafe at the asset-list scope. Use the FindingsTable inside
         * an asset's detail view for finding-level bulk operations. */}
      </div>

      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
      >
        <div
          className="modern-card assets-table-header"
          style={{
            flexShrink: 0,
            display: "grid",
            gridTemplateColumns: ASSETS_TABLE_GRID_COLS,
            gap: 8,
            padding: HEADER_PADDING[density],
            background: "var(--app-header-bg)",
            borderRadius: "4px 4px 0 0",
            borderBottom: "none",
          }}
        >
          {ASSET_COLUMNS.map((col, i) => {
            // First column: bulk-select header checkbox.
            if (i === 0) {
              return (
                <div
                  key="select-all"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                  title={
                    allVisibleChecked
                      ? "Deselect all visible"
                      : "Select all visible"
                  }
                >
                  <input
                    type="checkbox"
                    aria-label="Select all visible assets"
                    checked={allVisibleChecked}
                    ref={(el) => {
                      if (el) el.indeterminate = someVisibleChecked;
                    }}
                    onChange={handleToggleAllVisible}
                    onClick={(e) => e.stopPropagation()}
                    style={{ cursor: "pointer" }}
                  />
                </div>
              );
            }
            const isSortable = !!col.sortKey;
            const isActive =
              sortBy === col.sortKey || sortBy === `${col.sortKey}-desc`;
            const isDesc = sortBy.endsWith("-desc");
            const handleClick = () => {
              if (!isSortable) return;
              if (isActive) {
                setSortBy(isDesc ? col.sortKey : `${col.sortKey}-desc`);
              } else {
                setSortBy(col.sortKey);
              }
            };
            const spanStyle = {
              ...mono,
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: "0.1em",
              color: isActive ? "var(--app-fg)" : "var(--app-muted)",
              textTransform: "uppercase" as const,
              display: "flex" as const,
              alignItems: "center" as const,
              gap: 4,
              cursor: isSortable ? "pointer" : undefined,
              userSelect: "none" as const,
            };
            const content = (
              <>
                {col.label}
                {isSortable &&
                  isActive &&
                  (isDesc ? (
                    <ChevronDown size={10} />
                  ) : (
                    <ChevronUp size={10} />
                  ))}
              </>
            );
            if (col.label === "ABC") {
              return (
                <ThemedTooltip key={i} content={ABC_TOOLTIP} placement="top">
                  <span
                    onClick={handleClick}
                    role={isSortable ? "button" : undefined}
                    tabIndex={isSortable ? 0 : undefined}
                    onKeyDown={
                      isSortable
                        ? (e) => e.key === "Enter" && handleClick()
                        : undefined
                    }
                    style={spanStyle}
                  >
                    {content}
                  </span>
                </ThemedTooltip>
              );
            }
            if (col.label === "ORA") {
              return (
                <ThemedTooltip key={i} content={ORA_TOOLTIP} placement="top">
                  <span
                    onClick={handleClick}
                    role={isSortable ? "button" : undefined}
                    tabIndex={isSortable ? 0 : undefined}
                    onKeyDown={
                      isSortable
                        ? (e) => e.key === "Enter" && handleClick()
                        : undefined
                    }
                    style={spanStyle}
                  >
                    {content}
                  </span>
                </ThemedTooltip>
              );
            }
            return (
              <span
                key={i}
                onClick={handleClick}
                role={isSortable ? "button" : undefined}
                tabIndex={isSortable ? 0 : undefined}
                onKeyDown={
                  isSortable
                    ? (e) => e.key === "Enter" && handleClick()
                    : undefined
                }
                style={spanStyle}
              >
                {content}
              </span>
            );
          })}
        </div>
        <div
          className="modern-card assets-table-body"
          style={{
            flex: 1,
            minHeight: 0,
            // Dark base surface so rows read like the individual asset
            // findings table (near-black), not the lighter card panel.
            background: "var(--app-bg)",
            borderRadius: "0 0 4px 4px",
            overflow: "auto",
          }}
          onScroll={(event) => {
            const target = event.currentTarget;
            if (target.scrollTop + target.clientHeight >= target.scrollHeight - 160) {
              setVisibleCount((prev) => Math.min(prev + 150, sortedAssets.length));
            }
          }}
        >
          {sortedAssets.length === 0 ? (
            <div
              style={{
                ...sans,
                fontSize: 12,
                color: "var(--app-muted)",
                padding: 40,
                textAlign: "center",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: 8,
              }}
            >
              <span>No assets match current filters.</span>
              {total > 0 && filterAssetTypes.size > 0 && (
                <span style={{ fontSize: 11, color: "var(--app-muted)" }}>
                  Try clearing the Asset Type filter to include Package and Path
                  assets (e.g. from push sources).
                </span>
              )}
            </div>
          ) : (
            sortedAssets.slice(0, visibleCount).map((asset) => (
              <div
                key={asset.id}
                className="assets-table-row"
                onClick={() => router.push(getAssetHref(asset.id))}
                style={{
                  display: "grid",
                  gridTemplateColumns: ASSETS_TABLE_GRID_COLS,
                  gap: 8,
                  padding: ROW_PADDING[density],
                  cursor: "pointer",
                  alignItems: "start",
                  background: checked.has(asset.id)
                    ? "var(--app-input-bg)"
                    : selected && asset.findings.some((f) => f.id === selected.id)
                      ? "var(--app-input-bg)"
                      : "transparent",
                  borderBottom: "1px solid var(--app-border-subtle)",
                  transition: "background 0.1s",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <input
                    type="checkbox"
                    aria-label={`Select ${asset.name}`}
                    checked={checked.has(asset.id)}
                    onChange={(e) => onCheck(asset.id, e.target.checked)}
                    onClick={(e) => e.stopPropagation()}
                    style={{ cursor: "pointer" }}
                  />
                </div>
                <button
                  className="assets-table-favorite"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onToggleFavorite(asset.id);
                  }}
                  aria-label={
                    favoriteAssetIds.has(asset.id) ? "Unfavorite" : "Favorite"
                  }
                  style={{
                    background: "none",
                    border: "none",
                    padding: 0,
                    cursor: "pointer",
                    fontSize: 18,
                    color: favoriteAssetIds.has(asset.id)
                      ? "var(--app-danger)"
                      : "var(--app-muted)",
                  }}
                >
                  {favoriteAssetIds.has(asset.id) ? "♥" : "♡"}
                </button>
                <Link
                  href={getAssetHref(asset.id)}
                  onClick={(e) => e.stopPropagation()}
                  style={{
                    ...mono,
                    fontSize: 12,
                    fontWeight: 600,
                    color: "var(--app-accent)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    minWidth: 0,
                    textDecoration: "none",
                  }}
                >
                  {asset.name}
                </Link>
                <span
                  style={{
                    ...mono,
                    fontSize: 10,
                    color: "var(--app-muted)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {ASSET_TYPE_LABELS[getAssetTypeFromAsset(asset)]}
                </span>
                <div style={{ minWidth: 0, paddingTop: 2 }}>
                  <AssetTagsCell asset={asset} />
                </div>
                <span
                  style={{ ...mono, fontSize: 11, color: "var(--app-success)" }}
                >
                  {asset.verifiedPct}%
                </span>
                <span
                  style={{
                    ...mono,
                    fontSize: 10,
                    color:
                      getABC(asset) === "Compliant"
                        ? "var(--app-success)"
                        : getABC(asset) === "Compliant With Warnings"
                          ? "var(--app-warning)"
                          : "var(--app-danger)",
                  }}
                >
                  {getABC(asset)}
                </span>
                <span style={{ ...mono, fontSize: 11, color: "var(--app-fg)" }}>
                  {asset.oraPct}%
                </span>
                <div
                  style={{
                    display: "flex",
                    flexWrap: "wrap",
                    gap: 4,
                    alignItems: "center",
                    minWidth: 0,
                  }}
                >
                  {(() => {
                    const c = severityCountsByAsset.get(asset.id);
                    const chips = SEV_ORDER.filter((sev) => (c?.[sev] ?? 0) > 0);
                    if (chips.length === 0)
                      return (
                        <span
                          style={{
                            ...mono,
                            fontSize: 10,
                            color: "var(--app-muted)",
                          }}
                        >
                          —
                        </span>
                      );
                    return chips.map((sev) => {
                      const s = SEV[sev] ?? SEV.Informational;
                      return (
                        <span
                          key={sev}
                          title={`${sev}: ${c![sev]} open`}
                          style={{
                            ...mono,
                            fontSize: 10,
                            padding: "1px 5px",
                            borderRadius: 3,
                            background: s.bg,
                            color: s.c,
                            border: `1px solid ${s.c}40`,
                            whiteSpace: "nowrap",
                          }}
                        >
                          {sev[0]}
                          {c![sev]}
                        </span>
                      );
                    });
                  })()}
                </div>
                <div
                  style={{
                    ...sans,
                    fontSize: 10,
                    color: "var(--app-fg)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {formatStatusSummary(
                    statusBreakdownByAsset.get(asset.id) ??
                      asset.statusBreakdown,
                  )}
                </div>
              </div>
            ))
          )}
          {sortedAssets.length > visibleCount && (
            <div
              style={{
                ...mono,
                fontSize: 10,
                color: "var(--app-muted)",
                padding: "10px 14px",
                textAlign: "center",
              }}
            >
              Showing {visibleCount} of {sortedAssets.length} assets. Scroll to
              load more.
            </div>
          )}
        </div>
      </div>
    </div>
    <AssetActionBar
      selectedAssets={selectedAssets}
      onDeselect={onDeselectAll}
    />
    </>
  );
}
