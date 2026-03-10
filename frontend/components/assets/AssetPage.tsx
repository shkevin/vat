"use client";

import { useState, useMemo, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useVATData } from "@/contexts/VATDataContext";
import { getAssetById, computeMetricsFromFindings, getFindingTag, getAssetTypeFromAsset } from "@/lib/assetUtils";
import { getGroupedFindings } from "@/lib/findingGroupUtils";
import { FINDING_TYPES, SEV_ORDER, SEV } from "@/lib/constants";
import { displayTitle, displaySourceName } from "@/lib/utils";
import { FindingRow } from "@/components/findings/FindingRow";
import { BulkBar } from "@/components/findings/BulkBar";
import { DetailPanel } from "@/components/detail/DetailPanel";
import { WaiversTab } from "@/components/waivers/WaiversTab";
import { SBOMTab } from "@/components/sbom/SBOMTab";
import { ReviewQueue } from "@/components/review/ReviewQueue";
import { AssetSubTabs, type AssetTabId } from "@/components/assets/AssetSubTabs";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { useAuth } from "@/contexts/AuthContext";
import { mono, sans } from "@/lib/styles";
import { ChevronDown, ChevronUp, GitBranch, Tag } from "lucide-react";
import { ThemedSelect } from "@/components/ui/ThemedSelect";
import { MultiSelectFilter } from "@/components/ui/MultiSelectFilter";
import { ABC_TOOLTIP, ORA_TOOLTIP } from "@/lib/constants";
import { ThemedTooltip } from "@/components/ui/ThemedTooltip";
import { useAssetFilters } from "@/hooks/useAssetFilters";

const HEADER_PADDING = {
  compact: "4px 14px",
  default: "6px 14px",
  comfortable: "10px 14px",
} as const;
import type { AppConfig } from "@/config/app";
import type { Asset, Finding, Source } from "@/types";

const SORT_OPTS = [
  { value: "severity", label: "Severity" },
  { value: "status", label: "Approval Status" },
  { value: "cve", label: "CVE ID" },
  { value: "title", label: "Title" },
  { value: "source", label: "Source" },
  { value: "sla", label: "SLA Due" },
] as const;

/** Sortable column config: grid index, label, sort key. Empty string = not sortable. */
const FINDINGS_COLUMNS: { label: string; sortKey: string }[] = [
  { label: "", sortKey: "" },
  { label: "", sortKey: "" },
  { label: "", sortKey: "" },
  { label: "CVE / ID", sortKey: "cve" },
  { label: "Title / Component", sortKey: "title" },
  { label: "Status", sortKey: "status" },
  { label: "Tracked", sortKey: "" },
  { label: "Severity", sortKey: "severity" },
  { label: "Source", sortKey: "source" },
  { label: "SLA", sortKey: "sla" },
];
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

/** Static status options for filter — always show all, with counts */
const STATUS_OPTIONS = [...STATUS_PRIORITY, "Archived"];

function formatStatusSummary(breakdown: Record<string, number>): string {
  const parts: string[] = [];
  for (const s of STATUS_PRIORITY) {
    const n = breakdown[s];
    if (n && n > 0) parts.push(`${n} ${s.toLowerCase()}`);
  }
  return parts.slice(0, 4).join(" · ") || "—";
}


interface AssetPageProps {
  config: AppConfig;
}

export function AssetPage({ config }: AssetPageProps) {
  const params = useParams();
  const assetId = typeof params.id === "string" ? decodeURIComponent(params.id) : null;
  const data = useVATData();
  const { preferences, setPreferences } = useUserPreferences();
  const { user } = useAuth();
  const readOnly = user?.role === "read_only";
  const isAdmin = user?.role === "admin";
  const density = preferences.tableDensity ?? "default";
  const [assetTab, setAssetTab] = useState<AssetTabId>("findings");
  const [selectedSourceIndex, setSelectedSourceIndex] = useState<number | undefined>();

  const {
    loading,
    error,
    refetch,
    findings,
    sources,
    tracker,
    trackers,
    sbom,
    setSbom,
    waivers,
    reviewQueue,
    selected,
    setSelected,
    checked,
    handleUpdate,
    handleArchive,
    handleUnarchive,
    handleRevert,
    handleOverrideFingerprint,
    handleBulk,
    toggleCheck,
    clearChecked,
    favoriteAssetIds,
    getFavoriteContextForAsset,
    toggleFavorite,
    reportAssets,
    showArchived,
    setShowArchived,
  } = data;

  const asset = useMemo(() => {
    if (!assetId) return null;
    const fromReport = reportAssets.find((a) => a.id === assetId);
    if (fromReport) return fromReport;
    return getAssetById(findings, assetId, SEV_ORDER);
  }, [assetId, findings, reportAssets]);

  const assetWaivers = useMemo(
    () => (asset ? waivers.filter((f) => asset.findings.some((af) => af.id === f.id)) : []),
    [asset, waivers]
  );

  const assetReviewQueue = useMemo(
    () => (asset ? reviewQueue.filter((f) => asset.findings.some((af) => af.id === f.id)) : []),
    [asset, reviewQueue]
  );

  const assetSbom = useMemo(() => {
    if (!asset) return [];
    const name = asset.name.toLowerCase();
    return sbom.filter(
      (p) =>
        (p.component ?? "").toLowerCase().includes(name) ||
        name.includes((p.component ?? p.name ?? "").toLowerCase())
    );
  }, [asset, sbom]);

  const filters = useAssetFilters(assetId);
  const {
    statusFilter,
    severityFilter,
    sourceFilter,
    findingTypeFilter,
    findingsSearch,
    sortBy,
    branchFilter,
    tagFilter,
    hasRestored,
    setStatusFilter,
    setSeverityFilter,
    setSourceFilter,
    setFindingTypeFilter,
    setFindingsSearch,
    setSortBy,
    setBranchFilter,
    setTagFilter,
  } = filters;

  // Sync status filter "Archived" <-> showArchived (fetch archived, active, or both)
  const handleStatusFilterChange = useCallback(
    (v: Set<string>) => {
      setStatusFilter(v);
      const hasArchived = v.has("Archived");
      const hasOthers = [...v].some((x) => x !== "Archived");
      setShowArchived(hasArchived && hasOthers ? "both" : hasArchived);
    },
    [setStatusFilter, setShowArchived]
  );

  // When statusFilter is restored from localStorage, sync showArchived
  const hasArchivedInFilter = statusFilter.has("Archived");
  const hasOtherStatusInFilter = [...statusFilter].some((x) => x !== "Archived");
  useEffect(() => {
    const target = hasArchivedInFilter && hasOtherStatusInFilter ? "both" : hasArchivedInFilter;
    if (target !== showArchived) {
      setShowArchived(target);
    }
  }, [hasArchivedInFilter, hasOtherStatusInFilter, showArchived, setShowArchived]);

  const prevAssetIdRef = useRef<string | null>(null);
  const hasInitializedBranchRef = useRef(false);
  const hasInitializedTagRef = useRef(false);

  const assetType = useMemo(() => (asset ? getAssetTypeFromAsset(asset) : null), [asset]);
  const uniqueBranches = useMemo(() => {
    if (!asset || assetType !== "repo") return [];
    const fromFindings = [...new Set(asset.findings.map((f) => f.branch).filter(Boolean))] as string[];
    if (fromFindings.length > 0) return fromFindings;
    const fromAsset = (asset.branch ?? "")
      .split(",")
      .map((b) => b.trim())
      .filter(Boolean);
    return fromAsset;
  }, [asset, assetType]);
  const uniqueTags = useMemo(() => {
    if (!asset || assetType !== "container") return [];
    const fromFindings = [...new Set(asset.findings.map(getFindingTag).filter(Boolean))] as string[];
    if (fromFindings.length > 0) return fromFindings;
    if (asset.tag) return [asset.tag];
    return ["latest"];
  }, [asset, assetType]);

  useEffect(() => {
    if (assetId !== prevAssetIdRef.current) {
      prevAssetIdRef.current = assetId;
      hasInitializedBranchRef.current = false;
      hasInitializedTagRef.current = false;
    }
    // Only set default branch/tag when we haven't restored from URL or localStorage
    if (hasRestored) {
      hasInitializedBranchRef.current = true;
      hasInitializedTagRef.current = true;
      return;
    }
    const favoriteCtx = assetId ? getFavoriteContextForAsset(assetId) : null;
    if (assetType === "repo" && uniqueBranches.length > 0 && !hasInitializedBranchRef.current) {
      if (!branchFilter) {
        hasInitializedBranchRef.current = true;
        const favBranch = favoriteCtx?.branch && uniqueBranches.includes(favoriteCtx.branch) ? favoriteCtx.branch : null;
        const defaultBranch = favBranch ?? (uniqueBranches.includes("main") ? "main" : uniqueBranches[0]!);
        setBranchFilter(defaultBranch);
      } else {
        hasInitializedBranchRef.current = true;
      }
    } else if (assetType === "repo" && uniqueBranches.length === 0) {
      hasInitializedBranchRef.current = true;
      if (branchFilter) setBranchFilter("");
    }
    if (assetType === "container" && uniqueTags.length > 0 && !hasInitializedTagRef.current) {
      if (!tagFilter) {
        hasInitializedTagRef.current = true;
        const favTag = favoriteCtx?.tag && uniqueTags.includes(favoriteCtx.tag) ? favoriteCtx.tag : null;
        const defaultTag = favTag ?? (uniqueTags.includes("latest") ? "latest" : uniqueTags[0]!);
        setTagFilter(defaultTag);
      } else {
        hasInitializedTagRef.current = true;
      }
    } else if (assetType === "container" && uniqueTags.length === 0) {
      hasInitializedTagRef.current = true;
      if (tagFilter) setTagFilter("");
    }
  }, [assetId, assetType, uniqueBranches, uniqueTags, branchFilter, tagFilter, hasRestored, setBranchFilter, setTagFilter, getFavoriteContextForAsset]);

  const branchTagFilteredFindings = useMemo(() => {
    if (!asset) return [];
    let list = asset.findings;
    if (branchFilter && assetType === "repo") {
      list = list.filter((f) => {
        const b = f.branch ?? "";
        return b === branchFilter || (branchFilter === "main" && !b);
      });
    }
    if (tagFilter && assetType === "container") {
      list = list.filter((f) => {
        const t = getFindingTag(f) ?? "";
        return t === tagFilter || (tagFilter === "latest" && !t);
      });
    }
    return list;
  }, [asset, branchFilter, tagFilter, assetType]);

  const metricsFromAsset = useMemo(() => {
    if (!asset) return { verifiedPct: 0, oraPct: 100 };
    return computeMetricsFromFindings(branchTagFilteredFindings, SEV_ORDER);
  }, [asset, branchTagFilteredFindings]);

  const statusOptionsWithCounts = useMemo(() => {
    const list = branchTagFilteredFindings;
    const statusForFilter = (s: string | undefined) =>
      s === "Synced to Tracker" ? "Open" : s;
    const counts: Record<string, number> = {};
    for (const s of STATUS_OPTIONS) counts[s] = 0;
    for (const f of list) {
      const s = statusForFilter(f.status);
      if (s && counts[s] !== undefined) counts[s]++;
    }
    if (list.some((f) => f.archived)) {
      counts["Archived"] = list.filter((f) => f.archived).length;
    }
    return STATUS_OPTIONS.map((s) => ({
      value: s,
      label: s,
      count: counts[s] ?? 0,
    }));
  }, [branchTagFilteredFindings]);

  const uniqueColumnValues = useMemo(() => {
    const list = branchTagFilteredFindings;
    const statusForFilter = (s: string | undefined) =>
      s === "Synced to Tracker" ? "Open" : s;
    const statuses = [...new Set(list.map((f) => statusForFilter(f.status)).filter(Boolean))] as string[];
    const severities = [...new Set(list.map((f) => f.severity).filter(Boolean))] as string[];
    // Include sources from findings AND configured sources (e.g. OpenSCAP) so users can filter
    // even when a source has 0 findings (e.g. Chainguard images passing all STIG checks)
    const fromFindings = [...new Set(list.map((f) => f.source).filter(Boolean))] as string[];
    const fromConfig = sources.map((s) => s.id).filter(Boolean);
    const sourcesList = [...new Set([...fromFindings, ...fromConfig])].sort();
    const types = [...new Set(list.map((f) => f.findingType).filter(Boolean))] as string[];
    return {
      statuses: statuses.sort((a, b) => STATUS_PRIORITY.indexOf(a) - STATUS_PRIORITY.indexOf(b)),
      severities: severities.sort((a, b) => SEV_ORDER.indexOf(a as (typeof SEV_ORDER)[number]) - SEV_ORDER.indexOf(b as (typeof SEV_ORDER)[number])),
      sources: sourcesList,
      types: types.sort(),
    };
  }, [branchTagFilteredFindings, sources]);

  const filteredFindings = useMemo(() => {
    if (!asset) return [];
    let list = branchTagFilteredFindings;
    const statusesToFilter = [...statusFilter].filter((x) => x !== "Archived");
    const hasArchived = statusFilter.has("Archived");
    if (statusFilter.size > 0) {
      list = list.filter((f) => {
        const s = f.status === "Synced to Tracker" ? "Open" : f.status;
        const matchesStatus = statusesToFilter.length > 0 && s && statusesToFilter.includes(s);
        const matchesArchived = hasArchived && f.archived;
        return matchesArchived || matchesStatus;
      });
    }
    if (severityFilter.size > 0) {
      list = list.filter((f) => f.severity && severityFilter.has(f.severity));
    }
    if (sourceFilter.size > 0) {
      list = list.filter((f) => f.source && sourceFilter.has(f.source));
    }
    if (findingTypeFilter.size > 0) {
      list = list.filter((f) => f.findingType && findingTypeFilter.has(f.findingType));
    }
    if (findingsSearch.trim()) {
      const q = findingsSearch.toLowerCase().trim();
      list = list.filter(
        (f) =>
          f.cveId.toLowerCase().includes(q) ||
          (f.title ?? "").toLowerCase().includes(q) ||
          displayTitle(f).toLowerCase().includes(q) ||
          (f.component ?? "").toLowerCase().includes(q) ||
          (f.team ?? "").toLowerCase().includes(q) ||
          (f.owner ?? "").toLowerCase().includes(q)
      );
    }
    const validSortKeys = new Set(["severity", "status", "cve", "title", "source", "sla"]);
    const [sortKey, desc] = (() => {
      const d = sortBy.endsWith("-desc");
      const key = d ? sortBy.slice(0, -5) : sortBy;
      if (!validSortKeys.has(key)) return ["severity", false] as const;
      return [key, d] as const;
    })();
    const sorted = [...list].sort((a, b) => {
      let cmp = 0;
      if (sortKey === "severity") {
        cmp =
          SEV_ORDER.indexOf(a.severity as (typeof SEV_ORDER)[number]) -
          SEV_ORDER.indexOf(b.severity as (typeof SEV_ORDER)[number]);
      } else if (sortKey === "status") {
        const statusOrder = ["Open", "In Review", "Rejected", "Reopened", "Risk Accepted", "Resolved", "False Positive", "Suppressed", "Not Applicable", "Approved", "Mitigated", "Duplicate"];
        cmp = statusOrder.indexOf(a.status) - statusOrder.indexOf(b.status);
      } else if (sortKey === "cve") {
        cmp = (a.cveId ?? "").localeCompare(b.cveId ?? "");
      } else if (sortKey === "title") {
        cmp = displayTitle(a).localeCompare(displayTitle(b));
      } else if (sortKey === "source") {
        cmp = (a.source ?? "").localeCompare(b.source ?? "");
      } else if (sortKey === "sla") {
        cmp = (a.slaDue ?? "").localeCompare(b.slaDue ?? "");
      }
      return desc ? -cmp : cmp;
    });
    return sorted;
  }, [
    asset,
    branchTagFilteredFindings,
    findingsSearch,
    sortBy,
    statusFilter,
    severityFilter,
    sourceFilter,
    findingTypeFilter,
  ]);

  const groupFindings = preferences.groupFindings ?? true;

  const displayRows = useMemo(() => {
    if (!groupFindings) {
      const sorted = [...filteredFindings].sort((a, b) =>
        SEV_ORDER.indexOf(a.severity as (typeof SEV_ORDER)[number]) -
        SEV_ORDER.indexOf(b.severity as (typeof SEV_ORDER)[number])
      );
      return sorted.flatMap((f) => {
        const srcCount = f.sources?.length ?? 0;
        if (srcCount > 1) {
          return f.sources!.map((s, i) => ({
            finding: f,
            groupCount: undefined as number | undefined,
            sourceIndex: i,
            sourceName: s.name ?? "",
          }));
        }
        return [{ finding: f, groupCount: undefined, sourceIndex: undefined as number | undefined, sourceName: undefined as string | undefined }];
      });
    }
    const groups = getGroupedFindings(filteredFindings, SEV_ORDER);
    return groups.flatMap(({ findings: list }) => {
      const worst = list.reduce((a, b) =>
        SEV_ORDER.indexOf(a.severity as (typeof SEV_ORDER)[number]) <
        SEV_ORDER.indexOf(b.severity as (typeof SEV_ORDER)[number])
          ? a
          : b
      );
      const srcCount = worst.sources?.length ?? 0;
      const count = list.length > 1 ? list.length : Math.max(1, srcCount);
      return [{ finding: worst, groupCount: count, sourceIndex: undefined as number | undefined, sourceName: undefined as string | undefined }];
    });
  }, [filteredFindings, groupFindings]);

  const severityCounts = useMemo(() => {
    const CLOSED = ["Resolved", "False Positive", "Duplicate", "Not Applicable", "Approved", "Suppressed"];
    const openRows = displayRows.filter((r) => !CLOSED.includes(r.finding.status ?? ""));
    const counts: Record<string, number> = {};
    for (const sev of SEV_ORDER) counts[sev] = 0;
    for (const r of openRows) {
      const s = r.finding.severity ?? "Informational";
      counts[s] = (counts[s] ?? 0) + 1;
    }
    return SEV_ORDER.map((sev) => ({
      severity: sev,
      count: counts[sev] ?? 0,
    }));
  }, [displayRows]);

  const mainContent = (() => {
    if (loading && !error) {
      return (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            minHeight: 300,
            color: "var(--app-accent)",
            ...mono,
            fontSize: 12,
          }}
        >
          ▣ Loading…
        </div>
      );
    }

    if (error) {
      return (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            minHeight: 300,
            color: "var(--app-danger)",
            gap: 12,
            ...mono,
            fontSize: 12,
          }}
        >
          <span>Failed to load: {error}</span>
          <button
            onClick={() => refetch()}
            style={{
              background: "var(--app-card-bg)",
              border: "1px solid var(--app-accent)",
              borderRadius: 4,
              padding: "8px 16px",
              color: "var(--app-accent)",
              cursor: "pointer",
              ...sans,
            }}
          >
            Retry
          </button>
        </div>
      );
    }

    if (!assetId || !asset) {
      return (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            minHeight: 300,
            color: "var(--app-muted)",
            gap: 8,
            ...sans,
          }}
        >
          <span>Asset not found</span>
          <Link
            href="/"
            style={{
              color: "var(--app-accent)",
              textDecoration: "underline",
              fontSize: 13,
            }}
          >
            ← Back to Assets
          </Link>
        </div>
      );
    }

    if (assetTab === "waivers") {
      return (
        <WaiversTab
          waivers={assetWaivers}
          onSelect={setSelected}
        />
      );
    }

    if (assetTab === "sbom") {
      return (
        <SBOMTab
          sbom={assetSbom.length > 0 ? assetSbom : sbom}
          findings={asset.findings}
          onImport={(pkg) => setSbom((prev) => [...prev, ...pkg])}
          assetId={assetId ?? asset?.name}
        />
      );
    }

    if (assetTab === "review") {
      return (
        <ReviewQueue
          reviewQueue={assetReviewQueue}
          sources={sources}
          tracker={tracker}
          onSelect={setSelected}
        />
      );
    }

    if (assetTab === "findings" && asset) {
      return (
        <div
          style={{
            width: "100%",
            flex: 1,
            minHeight: 0,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
          <div style={{ flexShrink: 0, marginBottom: 16 }}>
        <Link
          href="/"
          style={{
            color: "var(--app-accent)",
            textDecoration: "none",
            fontSize: 13,
            marginBottom: 12,
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            ...sans,
          }}
        >
          ← Back to Assets
        </Link>

        {/* Asset header */}
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 20,
            alignItems: "flex-start",
            marginTop: 12,
            padding: 20,
            background: "var(--app-card-bg)",
            borderRadius: 8,
            border: "1px solid var(--app-border)",
          }}
        >
          {/* Asset name + branch/tag dropdown */}
          <div style={{ display: "flex", gap: 14, alignItems: "flex-start", flex: 1, minWidth: 0 }}>
            <div
              style={{
                width: 48,
                height: 48,
                borderRadius: 6,
                background: "var(--app-input-bg)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
                ...mono,
                fontSize: 20,
                fontWeight: 700,
                color: "var(--app-muted)",
              }}
            >
              {asset.name.charAt(0).toUpperCase()}
            </div>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <h1
                  style={{
                    ...mono,
                    fontSize: 18,
                    fontWeight: 700,
                    color: "var(--app-fg)",
                    margin: 0,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {asset.name}
                </h1>
                <button
                  type="button"
                  onClick={() =>
                    asset &&
                    toggleFavorite(asset.id, {
                      branch: branchFilter || undefined,
                      tag: tagFilter || undefined,
                    })
                  }
                  aria-label={favoriteAssetIds.has(asset.id) ? "Unfavorite" : "Favorite"}
                  style={{
                    background: "none",
                    border: "none",
                    padding: 0,
                    cursor: "pointer",
                    flexShrink: 0,
                    fontSize: 20,
                    color: favoriteAssetIds.has(asset.id) ? "var(--app-danger)" : "var(--app-muted)",
                  }}
                >
                  {favoriteAssetIds.has(asset.id) ? "♥" : "♡"}
                </button>
              </div>
              <div style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}>
                {asset.tag && `Tag: ${asset.tag} · `}
                {displayRows.length} findings
                {(branchFilter || tagFilter) && ` (of ${asset.findings.length})`}
              </div>
            </div>
          </div>

          {/* Branch / Tag dropdown */}
          {(assetType === "repo" || assetType === "container") && (
            <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
              {assetType === "repo" && (
                <ThemedSelect
                  value={branchFilter}
                  options={[
                    { value: "", label: uniqueBranches.length > 0 ? "All branches" : "—" },
                    ...uniqueBranches.map((b) => ({ value: b, label: b })),
                  ]}
                  onChange={(v) => setBranchFilter(v)}
                  icon={<GitBranch size={14} style={{ color: "var(--app-muted)", flexShrink: 0 }} />}
                  aria-label="Filter by branch"
                />
              )}
              {assetType === "container" && (
                <ThemedSelect
                  value={tagFilter}
                  options={[
                    { value: "", label: uniqueTags.length > 0 ? "All tags" : "—" },
                    ...uniqueTags.map((t) => ({ value: t, label: t })),
                  ]}
                  onChange={(v) => setTagFilter(v)}
                  icon={<Tag size={14} style={{ color: "var(--app-muted)", flexShrink: 0 }} />}
                  aria-label="Filter by tag"
                />
              )}
            </div>
          )}

          {/* Metric pills + severity breakdown */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 12,
            }}
          >
            <div
              style={{
                display: "flex",
                gap: 10,
                flexWrap: "wrap",
                alignItems: "center",
              }}
            >
              <span
                style={{
                  ...mono,
                  fontSize: 11,
                  padding: "6px 12px",
                  borderRadius: 20,
                  background: "color-mix(in srgb, var(--app-accent) 15%, transparent)",
                  color: "var(--app-accent)",
                }}
              >
                Findings Verified: {metricsFromAsset.verifiedPct}%
              </span>
              <ThemedTooltip content={ABC_TOOLTIP} placement="top">
                <span
                  style={{
                    ...mono,
                    fontSize: 11,
                    padding: "6px 12px",
                    borderRadius: 20,
                    background:
                      metricsFromAsset.verifiedPct === 100
                        ? "color-mix(in srgb, var(--app-success) 15%, transparent)"
                        : metricsFromAsset.verifiedPct > 0
                          ? "color-mix(in srgb, var(--app-warning) 15%, transparent)"
                          : "color-mix(in srgb, var(--app-danger) 15%, transparent)",
                    color:
                      metricsFromAsset.verifiedPct === 100
                        ? "var(--app-success)"
                        : metricsFromAsset.verifiedPct > 0
                          ? "var(--app-warning)"
                          : "var(--app-danger)",
                  }}
                >
                  ABC: {metricsFromAsset.verifiedPct === 100 ? "Compliant" : metricsFromAsset.verifiedPct > 0 ? "Compliant With Warnings" : "Non-compliant"}
                </span>
              </ThemedTooltip>
              <ThemedTooltip content={ORA_TOOLTIP} placement="top">
                <span
                  style={{
                    ...mono,
                    fontSize: 11,
                    padding: "6px 12px",
                    borderRadius: 20,
                    background: "color-mix(in srgb, var(--app-muted) 15%, transparent)",
                    color: "var(--app-fg)",
                  }}
                >
                  ORA: {metricsFromAsset.oraPct}%
                </span>
              </ThemedTooltip>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {severityCounts.map(({ severity, count }) => {
                  const s = SEV[severity] ?? SEV.Informational;
                  return (
                    <span
                      key={severity}
                      style={{
                        ...mono,
                        fontSize: 11,
                        padding: "4px 10px",
                        borderRadius: 20,
                        background: s.bg,
                        color: s.c,
                        border: `1px solid ${s.c}40`,
                      }}
                    >
                      {severity}: {count}
                    </span>
                  );
                })}
              </div>
          </div>
        </div>

        {/* Sort, multi-filter by column, search */}
        <div
          style={{
            display: "flex",
            gap: 10,
            marginTop: 14,
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              cursor: "pointer",
              ...sans,
              fontSize: 12,
              color: "var(--app-muted)",
            }}
          >
            <input
              type="checkbox"
              checked={groupFindings}
              onChange={(e) => setPreferences({ groupFindings: e.target.checked })}
              aria-label="Group findings"
              style={{ accentColor: "var(--app-accent-emerald)" }}
            />
            Group findings
          </label>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}>Sort:</span>
            <select
              value={sortBy.endsWith("-desc") ? sortBy.slice(0, -5) : sortBy}
              onChange={(e) => setSortBy(e.target.value as (typeof SORT_OPTS)[number]["value"])}
              style={{
                background: "var(--app-input-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: "6px 12px",
                color: "var(--app-fg)",
                fontSize: 12,
                ...mono,
              }}
            >
              {SORT_OPTS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          <MultiSelectFilter
            label="Type"
            options={uniqueColumnValues.types.map((t) => ({
              value: t,
              label: `${FINDING_TYPES[t]?.icon ?? ""} ${FINDING_TYPES[t]?.label ?? t}`.trim(),
            }))}
            selected={findingTypeFilter}
            onChange={setFindingTypeFilter}
          />
          <MultiSelectFilter
            label="Status"
            options={statusOptionsWithCounts}
            selected={statusFilter}
            onChange={handleStatusFilterChange}
          />
          <MultiSelectFilter
            label="Severity"
            options={uniqueColumnValues.severities.map((s) => ({ value: s, label: s }))}
            selected={severityFilter}
            onChange={setSeverityFilter}
          />
          <MultiSelectFilter
            label="Source"
            options={uniqueColumnValues.sources.map((id) => {
              const cfg = sources.find((s) => s.id === id);
              const label = displaySourceName(cfg?.name ?? id) || id;
              return { value: id, label };
            })}
            selected={sourceFilter}
            onChange={setSourceFilter}
          />
          <input
            type="search"
            value={findingsSearch}
            onChange={(e) => setFindingsSearch(e.target.value)}
            placeholder="Search CVE, title, component, team…"
            aria-label="Search findings"
            style={{
              flex: 1,
              minWidth: 200,
              background: "var(--app-input-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
              padding: "8px 14px",
              color: "var(--app-fg)",
              fontSize: 13,
              ...sans,
            }}
          />
        </div>
        {checked.size > 0 && (
          <BulkBar
            count={checked.size}
            onAction={handleBulk}
            onDeselect={clearChecked}
          />
        )}
      </div>

      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          border: "1px solid var(--app-border)",
          borderRadius: 2,
        }}
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "26px 4px 32px 130px 1fr 160px 60px 100px 90px 80px",
            gap: 8,
            padding: HEADER_PADDING[density],
            background: "var(--app-header-bg)",
            ...mono,
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: "0.1em",
            color: "var(--app-muted)",
            textTransform: "uppercase",
          }}
        >
          {FINDINGS_COLUMNS.map((col, i) => {
            const isSortable = !!col.sortKey;
            const isActive = sortBy === col.sortKey || sortBy === `${col.sortKey}-desc`;
            const isDesc = sortBy.endsWith("-desc");
            const handleClick = () => {
              if (!isSortable) return;
              if (isActive) {
                setSortBy(isDesc ? col.sortKey : `${col.sortKey}-desc`);
              } else {
                setSortBy(col.sortKey);
              }
            };
            return (
              <span
                key={i}
                onClick={handleClick}
                role={isSortable ? "button" : undefined}
                tabIndex={isSortable ? 0 : undefined}
                onKeyDown={isSortable ? (e) => e.key === "Enter" && handleClick() : undefined}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 4,
                  cursor: isSortable ? "pointer" : undefined,
                  userSelect: "none",
                  color: isActive ? "var(--app-fg)" : undefined,
                }}
              >
                {col.label}
                {isSortable && isActive && (isDesc ? <ChevronDown size={10} /> : <ChevronUp size={10} />)}
              </span>
            );
          })}
        </div>
        <div
          style={{
            flex: 1,
            minHeight: 0,
            overflow: "auto",
          }}
        >
          {displayRows.length === 0 ? (
            <div
              style={{
                ...sans,
                fontSize: 12,
                color: "var(--app-muted)",
                padding: 40,
                textAlign: "center",
              }}
            >
              {findingsSearch ? "No findings match your search." : "No findings."}
            </div>
          ) : (
            displayRows.map(({ finding: f, groupCount, sourceIndex, sourceName }) => (
              <FindingRow
                key={sourceIndex != null ? `${f.id}-${sourceIndex}` : f.id}
                finding={f}
                sources={sources}
                selected={selected?.id === f.id && (sourceIndex == null || selectedSourceIndex === sourceIndex)}
                checked={checked.has(f.id)}
                onCheck={(v) => toggleCheck(f.id, v)}
                onClick={() => {
                  setSelected(f);
                  setSelectedSourceIndex(sourceIndex);
                }}
                groupCount={groupCount}
                instanceSource={sourceName}
              />
            ))
          )}
        </div>

        <div
          style={{
            flexShrink: 0,
            padding: "6px 14px",
            background: "var(--app-header-bg)",
            borderTop: "1px solid var(--app-border)",
            ...mono,
            fontSize: 11,
            color: "var(--app-muted)",
          }}
        >
          {displayRows.length}{" "}
          {groupFindings
            ? displayRows.length === 1
              ? "group"
              : "groups"
            : displayRows.length === 1
              ? "finding"
              : "findings"}
          {groupFindings && displayRows.length !== filteredFindings.length && ` (${filteredFindings.length} total)`}
        </div>
        </div>

      {selected && (
        <DetailPanel
          finding={selected}
          allFindings={branchTagFilteredFindings}
          sources={sources}
          tracker={tracker}
          trackers={trackers}
          onClose={() => {
            setSelected(null);
            setSelectedSourceIndex(undefined);
          }}
          onUpdate={handleUpdate}
          onArchive={handleArchive}
          onUnarchive={handleUnarchive}
          onRevert={handleRevert}
          onOverrideFingerprint={handleOverrideFingerprint}
          readOnly={readOnly}
          isAdmin={isAdmin}
          repoBaseUrl={config.repoBaseUrl}
          repoUrlType={config.repoUrlType}
          groupFindings={groupFindings}
          selectedSourceIndex={!groupFindings ? selectedSourceIndex : undefined}
        />
      )}
        </div>
      );
    }

    return null;
  })();

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        flex: 1,
        minHeight: 0,
      }}
    >
      <AssetSubTabs
        config={config}
        currentTab={assetTab}
        onTabChange={setAssetTab}
      />
      <main
        style={{
          flex: 1,
          minHeight: 0,
          overflow: "auto",
          padding: 20,
          display: "flex",
          flexDirection: "column",
        }}
      >
        {mainContent}
      </main>
    </div>
  );
}
