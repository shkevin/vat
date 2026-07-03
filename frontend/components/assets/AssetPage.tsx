"use client";

import { useState, useMemo, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { useVATData } from "@/contexts/VATDataContext";
import {
  deriveAssets,
  computeMetricsFromFindings,
  getFindingTag,
  getAssetTypeFromAsset,
  getAssetDisplayTitle,
  mergeSuggestionTargetAlreadyRepresentedOnAsset,
  resolveAssetForPage,
  sameAssetIdentity,
  containerVariantKeyForFinding,
  containerVariantKeysForFindings,
  defaultContainerVariantKey,
  formatContainerVariantOptionLabel,
  getFindingImageDigest,
} from "@/lib/assetUtils";
import { getGroupedFindings } from "@/lib/findingGroupUtils";
import { FINDING_TYPES, SEV_ORDER, SEV } from "@/lib/constants";
import { displayTitle } from "@/lib/utils";
import {
  buildSourceFilterOptions,
  sourceFilterKey,
} from "@/lib/sourceFilterOptions";
import { FindingRow } from "@/components/findings/FindingRow";
import { BulkBar } from "@/components/findings/BulkBar";
import { DetailPanel } from "@/components/detail/DetailPanel";
import { WaiversTab } from "@/components/waivers/WaiversTab";
import { SBOMTab } from "@/components/sbom/SBOMTab";
import { ReviewQueue } from "@/components/review/ReviewQueue";
import {
  AssetSubTabs,
  type AssetTabId,
} from "@/components/assets/AssetSubTabs";
import { useUserPreferences } from "@/contexts/UserPreferencesContext";
import { useAuth } from "@/contexts/AuthContext";
import { mono, sans } from "@/lib/styles";
import {
  ChevronDown,
  ChevronUp,
  GitBranch,
  MoreHorizontal,
  Tag,
} from "lucide-react";
import { ThemedSelect } from "@/components/ui/ThemedSelect";
import { MultiSelectFilter } from "@/components/ui/MultiSelectFilter";
import { ABC_TOOLTIP, ORA_TOOLTIP } from "@/lib/constants";
import { ThemedTooltip } from "@/components/ui/ThemedTooltip";
import { SearchInput } from "@/components/ui/SearchInput";
import { useAssetFilters } from "@/hooks/useAssetFilters";
import {
  acknowledgeAssetDigestConflict,
  deleteAssetMergeReview,
  deleteAsset,
  fetchAssetDigestConflicts,
  fetchAssetMergeSuggestions,
  fetchAssetMergeReviews,
  fetchAssetAliases,
  fetchFinding,
  fetchSbomPackages,
  groupAssetInto,
  upsertAssetMergeReview,
  type AssetMergeReviewRecord,
  type AssetDigestConflictRecord,
  type AssetMergeSuggestion,
  unmergeAssetFrom,
} from "@/lib/api";
import { chooseFindingForDetail, toDetailFinding } from "@/lib/findingDetail";

const HEADER_PADDING = {
  compact: "4px 14px",
  default: "6px 14px",
  comfortable: "10px 14px",
} as const;
import type { AppConfig } from "@/config/app";
import type { Asset, Finding, Source } from "@/types";
import {
  normalizeContainerRef,
  containerDisplayPathWithoutRegistry,
} from "@/lib/containerRefNormalization";
import { useQuery } from "@tanstack/react-query";

/** SBOM row shape shared with SBOMTab (structural). */
type AssetSbomPackage = {
  id: string;
  name: string;
  version: string;
  license: string;
  licenseRisk?: string;
  component: string;
  language: string;
};

function findingMatchesContainerVariant(
  f: Finding,
  variantFilter: string,
  allFindings: Finding[],
): boolean {
  if (!variantFilter) return true;
  return containerVariantKeyForFinding(f, allFindings) === variantFilter;
}

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
  const searchParams = useSearchParams();
  const router = useRouter();
  const assetId =
    typeof params.id === "string" ? decodeURIComponent(params.id) : null;
  const data = useVATData();
  const { preferences, setPreferences } = useUserPreferences();
  const { user, token } = useAuth();
  const readOnly = user?.role === "read_only";
  const isAdmin = user?.role === "admin";
  const canReviewAssets = user?.role === "admin" || user?.role === "reviewer";
  const density = preferences.tableDensity ?? "default";
  const [assetTab, setAssetTab] = useState<AssetTabId>("findings");
  const [deletingAsset, setDeletingAsset] = useState(false);
  const [unmergingAsset, setUnmergingAsset] = useState(false);
  const [groupTargetAssetId, setGroupTargetAssetId] = useState("");
  const [unmergeSourceAssetId, setUnmergeSourceAssetId] = useState("");
  const [aliasSourceOptions, setAliasSourceOptions] = useState<string[]>([]);
  const [groupingAsset, setGroupingAsset] = useState(false);
  const [showAdminActions, setShowAdminActions] = useState(false);
  const [mergeSuggestions, setMergeSuggestions] = useState<
    AssetMergeSuggestion[]
  >([]);
  const [mergeSuggestionsLoading, setMergeSuggestionsLoading] = useState(false);
  const [mergeSuggestionsError, setMergeSuggestionsError] = useState<
    string | null
  >(null);
  const [mergeReviews, setMergeReviews] = useState<AssetMergeReviewRecord[]>(
    [],
  );
  const [mergeReviewsLoading, setMergeReviewsLoading] = useState(false);
  const [digestConflicts, setDigestConflicts] = useState<
    AssetDigestConflictRecord[]
  >([]);
  const [digestConflictsLoading, setDigestConflictsLoading] = useState(false);
  const [digestConflictActionTag, setDigestConflictActionTag] = useState<
    string | null
  >(null);
  const [mergeReviewActionTargetId, setMergeReviewActionTargetId] = useState<
    string | null
  >(null);
  const [approvingTargetId, setApprovingTargetId] = useState<string | null>(
    null,
  );
  const [pendingAdminAction, setPendingAdminAction] = useState<
    "group" | "unmerge" | "delete" | null
  >(null);
  const [actionConfirmText, setActionConfirmText] = useState("");
  const [adminActionError, setAdminActionError] = useState<string | null>(null);
  const [targetSearchOpen, setTargetSearchOpen] = useState(false);
  const [selectedSourceIndex, setSelectedSourceIndex] = useState<
    number | undefined
  >();
  const [selectedDetail, setSelectedDetail] = useState<Finding | null>(null);
  const [selectedDetailError, setSelectedDetailError] = useState<string | null>(
    null,
  );
  const adminActionsRef = useRef<HTMLDivElement | null>(null);
  const targetSearchRef = useRef<HTMLDivElement | null>(null);
  /** User explicitly chose "All image variants"; do not auto-scope to one digest. */
  const containerVariantUserChoseAllRef = useRef(false);

  const {
    loading,
    refreshing,
    error,
    refetch,
    findings,
    sources,
    tracker,
    trackers,
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

  useEffect(() => {
    if (!selected?.id) {
      setSelectedDetail(null);
      setSelectedDetailError(null);
      return;
    }

    let cancelled = false;
    setSelectedDetail(null);
    setSelectedDetailError(null);
    fetchFinding(selected.id, { token, userEmail: user?.email })
      .then((fullFinding) => {
        if (!cancelled) setSelectedDetail(toDetailFinding(fullFinding));
      })
      .catch((err) => {
        if (!cancelled) {
          setSelectedDetailError(
            err instanceof Error ? err.message : "Failed to load finding details",
          );
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selected?.id, token, user?.email]);

  const findingForDetail = useMemo(
    () => chooseFindingForDetail(selected, selectedDetail),
    [selected, selectedDetail],
  );

  useEffect(() => {
    const qTab = (searchParams.get("tab") || "").toLowerCase();
    if (qTab === "review") setAssetTab("review");
    else if (qTab === "sbom") setAssetTab("sbom");
    else if (qTab === "waivers") setAssetTab("waivers");
    else if (qTab === "findings") setAssetTab("findings");
  }, [searchParams]);

  useEffect(() => {
    containerVariantUserChoseAllRef.current = false;
  }, [assetId]);

  const asset = useMemo(() => {
    if (!assetId) return null;
    return resolveAssetForPage(assetId, reportAssets, findings, SEV_ORDER);
  }, [assetId, findings, reportAssets]);

  /** Short title for header; full canonical ref in `asset.id` when they differ. */
  const assetDisplayTitle = useMemo(
    () => (asset ? getAssetDisplayTitle(asset) : ""),
    [asset],
  );

  const targetAssetOptions = useMemo(() => {
    const merged = new Set<string>();
    for (const a of reportAssets) merged.add(a.id);
    for (const a of deriveAssets(findings, SEV_ORDER)) merged.add(a.id);
    if (asset?.id) merged.delete(asset.id);
    return Array.from(merged).filter(Boolean).sort();
  }, [asset?.id, findings, reportAssets]);
  const filteredTargetAssetOptions = useMemo(() => {
    const q = groupTargetAssetId.trim().toLowerCase();
    if (!q) return targetAssetOptions.slice(0, 100);
    return targetAssetOptions
      .filter((id) => id.toLowerCase().includes(q))
      .slice(0, 100);
  }, [groupTargetAssetId, targetAssetOptions]);

  useEffect(() => {
    if (!showAdminActions) return;
    const onDocClick = (e: MouseEvent) => {
      if (
        adminActionsRef.current &&
        !adminActionsRef.current.contains(e.target as Node)
      ) {
        setShowAdminActions(false);
      }
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [showAdminActions]);

  useEffect(() => {
    if (!targetSearchOpen) return;
    const onDocClick = (e: MouseEvent) => {
      if (
        targetSearchRef.current &&
        !targetSearchRef.current.contains(e.target as Node)
      ) {
        setTargetSearchOpen(false);
      }
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [targetSearchOpen]);

  const assetWaivers = useMemo(
    () =>
      asset
        ? waivers.filter(
            (f) =>
              asset.findings.some((af) => af.id === f.id) ||
              f.image === asset.id ||
              f.component === asset.id ||
              f.componentBase === asset.id,
          )
        : [],
    [asset, waivers],
  );

  const assetReviewQueue = useMemo(
    () =>
      asset
        ? reviewQueue.filter((f) => asset.findings.some((af) => af.id === f.id))
        : [],
    [asset, reviewQueue],
  );

  const loadMergeSuggestions = useCallback(async () => {
    if (!asset?.id || !canReviewAssets) {
      setMergeSuggestions([]);
      setMergeSuggestionsError(null);
      return;
    }
    setMergeSuggestionsLoading(true);
    setMergeSuggestionsError(null);
    try {
      const res = await fetchAssetMergeSuggestions(asset.id, {
        token: token ?? undefined,
        userEmail: user?.email,
      });
      setMergeSuggestions(res.suggestions ?? []);
    } catch (err) {
      setMergeSuggestionsError(
        err instanceof Error ? err.message : "Failed to load merge suggestions",
      );
    } finally {
      setMergeSuggestionsLoading(false);
    }
  }, [asset?.id, canReviewAssets, token, user?.email]);

  const loadMergeReviews = useCallback(async () => {
    if (!asset?.id || !canReviewAssets) {
      setMergeReviews([]);
      return;
    }
    setMergeReviewsLoading(true);
    try {
      const res = await fetchAssetMergeReviews(asset.id, {
        token: token ?? undefined,
        userEmail: user?.email,
      });
      setMergeReviews(res.reviews ?? []);
    } catch (err) {
      setMergeSuggestionsError(
        err instanceof Error ? err.message : "Failed to load merge reviews",
      );
    } finally {
      setMergeReviewsLoading(false);
    }
  }, [asset?.id, canReviewAssets, token, user?.email]);

  const refreshMergeReviewData = useCallback(async () => {
    await Promise.all([
      loadMergeSuggestions(),
      loadMergeReviews(),
      (async () => {
        if (!asset?.id || !canReviewAssets) {
          setDigestConflicts([]);
          return;
        }
        setDigestConflictsLoading(true);
        try {
          const res = await fetchAssetDigestConflicts(asset.id, {
            token: token ?? undefined,
            userEmail: user?.email,
          });
          setDigestConflicts(res.conflicts ?? []);
        } catch (err) {
          setMergeSuggestionsError(
            err instanceof Error
              ? err.message
              : "Failed to load digest conflicts",
          );
        } finally {
          setDigestConflictsLoading(false);
        }
      })(),
    ]);
  }, [
    asset?.id,
    canReviewAssets,
    loadMergeReviews,
    loadMergeSuggestions,
    token,
    user?.email,
  ]);

  const setDigestConflictAcknowledged = useCallback(
    async (tag: string, acknowledged: boolean) => {
      if (!asset?.id || !canReviewAssets || !tag) return;
      setDigestConflictActionTag(tag);
      setMergeSuggestionsError(null);
      try {
        await acknowledgeAssetDigestConflict(asset.id, tag, acknowledged, {
          token: token ?? undefined,
          userEmail: user?.email,
        });
        await refreshMergeReviewData();
      } catch (err) {
        setMergeSuggestionsError(
          err instanceof Error
            ? err.message
            : "Failed to update digest conflict status",
        );
      } finally {
        setDigestConflictActionTag(null);
      }
    },
    [asset?.id, canReviewAssets, refreshMergeReviewData, token, user?.email],
  );

  useEffect(() => {
    if (assetTab !== "review") return;
    void refreshMergeReviewData();
  }, [assetTab, refreshMergeReviewData]);

  useEffect(() => {
    if (!asset?.id || !canReviewAssets) return;
    void loadMergeSuggestions();
  }, [asset?.id, canReviewAssets, loadMergeSuggestions]);

  const mergeSuggestionsVisible = useMemo(() => {
    if (!asset) return [];
    return mergeSuggestions.filter(
      (s) =>
        !mergeSuggestionTargetAlreadyRepresentedOnAsset(
          s.target_asset_id,
          asset,
        ),
    );
  }, [mergeSuggestions, asset]);

  const digestMergeBannerHints = useMemo(
    () =>
      mergeSuggestionsVisible.filter(
        (s) =>
          s.strategy === "digest" &&
          s.confidence === "high" &&
          s.review_status !== "approved" &&
          s.review_status !== "denied",
      ),
    [mergeSuggestionsVisible],
  );

  const approveMergeSuggestion = useCallback(
    async (targetAssetId: string) => {
      if (!asset?.id || !isAdmin || !targetAssetId) return;
      setApprovingTargetId(targetAssetId);
      setMergeSuggestionsError(null);
      try {
        const suggestion = mergeSuggestions.find(
          (s) => s.target_asset_id === targetAssetId,
        );
        // Backend enforces approved review BEFORE group merge.
        // Keep UI flow aligned to avoid guaranteed 409 responses.
        await upsertAssetMergeReview(
          asset.id,
          targetAssetId,
          {
            status: "approved",
            note: "Approved from asset review",
            strategy: suggestion?.strategy,
            score: suggestion?.score,
            confidence: suggestion?.confidence,
            details: suggestion?.details,
          },
          {
            token: token ?? undefined,
            userEmail: user?.email,
          },
        );
        await groupAssetInto(asset.id, targetAssetId, {
          token: token ?? undefined,
          userEmail: user?.email,
        });
        await refetch({ silent: true });
        router.push(`/assets/${encodeURIComponent(targetAssetId)}`);
      } catch (err) {
        setMergeSuggestionsError(
          err instanceof Error ? err.message : "Failed to approve merge",
        );
      } finally {
        setApprovingTargetId(null);
      }
    },
    [asset?.id, isAdmin, mergeSuggestions, refetch, router, token, user?.email],
  );

  const denyMergeSuggestion = useCallback(
    async (s: AssetMergeSuggestion) => {
      if (!asset?.id || !canReviewAssets) return;
      setMergeReviewActionTargetId(s.target_asset_id);
      setMergeSuggestionsError(null);
      try {
        await upsertAssetMergeReview(
          asset.id,
          s.target_asset_id,
          {
            status: "denied",
            note: "Denied from asset review",
            strategy: s.strategy,
            score: s.score,
            confidence: s.confidence,
            details: s.details,
          },
          {
            token: token ?? undefined,
            userEmail: user?.email,
          },
        );
        await refreshMergeReviewData();
      } catch (err) {
        setMergeSuggestionsError(
          err instanceof Error
            ? err.message
            : "Failed to deny merge suggestion",
        );
      } finally {
        setMergeReviewActionTargetId(null);
      }
    },
    [asset?.id, canReviewAssets, refreshMergeReviewData, token, user?.email],
  );

  const setMergeReviewStatus = useCallback(
    async (
      targetAssetId: string,
      status: "pending" | "approved" | "denied",
      note: string,
    ) => {
      if (!asset?.id || !canReviewAssets) return;
      setMergeReviewActionTargetId(targetAssetId);
      setMergeSuggestionsError(null);
      try {
        await upsertAssetMergeReview(
          asset.id,
          targetAssetId,
          { status, note },
          { token: token ?? undefined, userEmail: user?.email },
        );
        await refreshMergeReviewData();
      } catch (err) {
        setMergeSuggestionsError(
          err instanceof Error ? err.message : "Failed to update merge review",
        );
      } finally {
        setMergeReviewActionTargetId(null);
      }
    },
    [asset?.id, canReviewAssets, refreshMergeReviewData, token, user?.email],
  );

  const removeMergeReview = useCallback(
    async (targetAssetId: string) => {
      if (!asset?.id || !canReviewAssets) return;
      setMergeReviewActionTargetId(targetAssetId);
      setMergeSuggestionsError(null);
      try {
        await deleteAssetMergeReview(asset.id, targetAssetId, {
          token: token ?? undefined,
          userEmail: user?.email,
        });
        await refreshMergeReviewData();
      } catch (err) {
        setMergeSuggestionsError(
          err instanceof Error ? err.message : "Failed to delete merge review",
        );
      } finally {
        setMergeReviewActionTargetId(null);
      }
    },
    [asset?.id, canReviewAssets, refreshMergeReviewData, token, user?.email],
  );

  // Registry-stripped component paths for this asset (asset id + each finding's
  // image). These are what the backend stores as SBOM `component`, so they make
  // reliable substring queries. Single-segment ids (e.g. "kamiwaza-debug") are
  // used as-is since stripping would wrongly add a "library/" prefix.
  const assetSbomComponents = useMemo(() => {
    if (!asset) return [];
    const set = new Set<string>();
    const add = (ref: string | null | undefined) => {
      const r = (ref ?? "").trim();
      if (!r) return;
      set.add(r.includes("/") ? containerDisplayPathWithoutRegistry(r) : r);
    };
    add(asset.id);
    for (const f of asset.findings ?? []) add(f.image);
    return Array.from(set).filter(Boolean).slice(0, 12);
  }, [asset]);

  // Fetch this asset's SBOM directly from the backend (component filter) instead
  // of client-filtering a globally capped list — that cap hid SBOM for most
  // assets. Only runs when the SBOM tab is open.
  const assetSbomQuery = useQuery({
    queryKey: ["asset-sbom", asset?.id, assetSbomComponents],
    enabled:
      assetTab === "sbom" && !!asset && assetSbomComponents.length > 0,
    staleTime: 60_000,
    queryFn: async () => {
      const auth = { token: token ?? undefined, userEmail: user?.email };
      const lists = await Promise.all(
        assetSbomComponents.map((c) =>
          fetchSbomPackages({ component: c, limit: 5000 }, auth).catch(
            () => [],
          ),
        ),
      );
      const byId = new Map<string, (typeof lists)[number][number]>();
      for (const list of lists) for (const p of list) byId.set(p.id, p);
      return Array.from(byId.values()).map(
        (p): AssetSbomPackage => ({
          id: p.id,
          name: p.name,
          version: p.version,
          license: p.licenseId ?? "",
          licenseRisk: p.licenseRisk,
          component: p.component ?? "",
          language: p.language ?? "",
        }),
      );
    },
  });

  // Local override so the client-side import preview (onImport) still works.
  const [sbomImportOverride, setSbomImportOverride] = useState<
    AssetSbomPackage[] | null
  >(null);
  useEffect(() => {
    setSbomImportOverride(null);
  }, [asset?.id]);
  const assetSbom = sbomImportOverride ?? assetSbomQuery.data ?? [];

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
    [setStatusFilter, setShowArchived],
  );

  // When statusFilter is restored from localStorage, sync showArchived
  const hasArchivedInFilter = statusFilter.has("Archived");
  const hasOtherStatusInFilter = [...statusFilter].some(
    (x) => x !== "Archived",
  );
  useEffect(() => {
    const target =
      hasArchivedInFilter && hasOtherStatusInFilter
        ? "both"
        : hasArchivedInFilter;
    if (target !== showArchived) {
      setShowArchived(target);
    }
  }, [
    hasArchivedInFilter,
    hasOtherStatusInFilter,
    showArchived,
    setShowArchived,
  ]);

  const prevAssetIdRef = useRef<string | null>(null);
  const hasInitializedBranchRef = useRef(false);
  const hasInitializedTagRef = useRef(false);

  const assetType = useMemo(
    () => (asset ? getAssetTypeFromAsset(asset) : null),
    [asset],
  );
  const uniqueBranches = useMemo(() => {
    if (!asset || assetType !== "repo") return [];
    const fromFindings = [
      ...new Set(asset.findings.map((f) => f.branch).filter(Boolean)),
    ] as string[];
    if (fromFindings.length > 0) return fromFindings;
    const fromAsset = (asset.branch ?? "")
      .split(",")
      .map((b) => b.trim())
      .filter(Boolean);
    return fromAsset;
  }, [asset, assetType]);
  /** One entry per manifest digest when known; else one per tag (legacy without digest). */
  const containerVariantKeys = useMemo(() => {
    if (!asset || assetType !== "container") return [];
    return containerVariantKeysForFindings(asset.findings);
  }, [asset, assetType]);

  /** Dropdown labels: one row per digest (or per tag when digest unknown). */
  const containerVariantSelectOptions = useMemo(() => {
    if (!asset || assetType !== "container") return [];
    return containerVariantKeys.map((key) => {
      const group = asset.findings.filter(
        (f) => containerVariantKeyForFinding(f, asset.findings) === key,
      );
      const label = formatContainerVariantOptionLabel(group, asset.findings);
      return { value: key, label };
    });
  }, [asset, assetType, containerVariantKeys]);

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
    if (
      assetType === "repo" &&
      uniqueBranches.length > 0 &&
      !hasInitializedBranchRef.current
    ) {
      if (!branchFilter) {
        hasInitializedBranchRef.current = true;
        const favBranch =
          favoriteCtx?.branch && uniqueBranches.includes(favoriteCtx.branch)
            ? favoriteCtx.branch
            : null;
        const defaultBranch =
          favBranch ??
          (uniqueBranches.includes("main") ? "main" : uniqueBranches[0]!);
        setBranchFilter(defaultBranch);
      } else {
        hasInitializedBranchRef.current = true;
      }
    } else if (assetType === "repo" && uniqueBranches.length === 0) {
      hasInitializedBranchRef.current = true;
      if (branchFilter) setBranchFilter("");
    }
    if (
      assetType === "container" &&
      containerVariantKeys.length > 0 &&
      !hasInitializedTagRef.current
    ) {
      if (!tagFilter) {
        hasInitializedTagRef.current = true;
        const favVariant =
          favoriteCtx?.tag && containerVariantKeys.includes(favoriteCtx.tag)
            ? favoriteCtx.tag
            : null;
        const latestVariant =
          defaultContainerVariantKey(
            containerVariantKeys,
            asset?.findings ?? [],
          ) ?? containerVariantKeys[0]!;
        setTagFilter(favVariant ?? latestVariant);
      } else {
        hasInitializedTagRef.current = true;
      }
    } else if (assetType === "container" && containerVariantKeys.length === 0) {
      hasInitializedTagRef.current = true;
      if (tagFilter) setTagFilter("");
    }
  }, [
    assetId,
    asset,
    assetType,
    uniqueBranches,
    containerVariantKeys,
    branchFilter,
    tagFilter,
    hasRestored,
    setBranchFilter,
    setTagFilter,
    getFavoriteContextForAsset,
  ]);

  /**
   * VMS-style remediation: scope findings to one image digest (variant) by default.
   * Different digests are different runnable images; mixing them obscures per-digest work.
   * Covers the hasRestored path where init skips (tag stayed ""), and reinforces empty → first variant.
   */
  useEffect(() => {
    if (!asset || assetType !== "container") return;
    if (containerVariantKeys.length <= 1) return;
    if (tagFilter) return;
    if (containerVariantUserChoseAllRef.current) return;
    const latest =
      defaultContainerVariantKey(containerVariantKeys, asset.findings) ??
      containerVariantKeys[0]!;
    setTagFilter(latest);
  }, [asset, assetType, tagFilter, containerVariantKeys, setTagFilter]);

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
      list = list.filter((f) =>
        findingMatchesContainerVariant(f, tagFilter, asset.findings),
      );
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
    const statuses = [
      ...new Set(list.map((f) => statusForFilter(f.status)).filter(Boolean)),
    ] as string[];
    const severities = [
      ...new Set(list.map((f) => f.severity).filter(Boolean)),
    ] as string[];
    // Include sources from findings AND configured sources (e.g. OpenSCAP) so users can filter
    // even when a source has 0 findings (e.g. Chainguard images passing all STIG checks)
    const fromFindings = [
      ...new Set(list.map((f) => f.source).filter(Boolean)),
    ] as string[];
    const fromConfig = sources.map((s) => s.id).filter(Boolean);
    const sourcesList = [...new Set([...fromFindings, ...fromConfig])].sort();
    const types = [
      ...new Set(list.map((f) => f.findingType).filter(Boolean)),
    ] as string[];
    return {
      statuses: statuses.sort(
        (a, b) => STATUS_PRIORITY.indexOf(a) - STATUS_PRIORITY.indexOf(b),
      ),
      severities: severities.sort(
        (a, b) =>
          SEV_ORDER.indexOf(a as (typeof SEV_ORDER)[number]) -
          SEV_ORDER.indexOf(b as (typeof SEV_ORDER)[number]),
      ),
      sources: sourcesList,
      types: types.sort(),
    };
  }, [branchTagFilteredFindings, sources]);

  const sourceOptionsWithCounts = useMemo(() => {
    return buildSourceFilterOptions(branchTagFilteredFindings, sources);
  }, [branchTagFilteredFindings, sources]);

  const sourceNamesById = useMemo(
    () => new Map(sources.map((source) => [source.id, source.name])),
    [sources],
  );
  const normalizedSourceFilter = useMemo(
    () =>
      new Set(
        [...sourceFilter]
          .map((source) => sourceFilterKey(source, sourceNamesById.get(source)))
          .filter(Boolean),
      ),
    [sourceFilter, sourceNamesById],
  );

  const filteredFindings = useMemo(() => {
    if (!asset) return [];
    let list = branchTagFilteredFindings;
    const statusesToFilter = [...statusFilter].filter((x) => x !== "Archived");
    const hasArchived = statusFilter.has("Archived");
    if (statusFilter.size > 0) {
      list = list.filter((f) => {
        const s = f.status === "Synced to Tracker" ? "Open" : f.status;
        const matchesStatus =
          statusesToFilter.length > 0 && s && statusesToFilter.includes(s);
        const matchesArchived = hasArchived && f.archived;
        return matchesArchived || matchesStatus;
      });
    }
    if (severityFilter.size > 0) {
      list = list.filter((f) => f.severity && severityFilter.has(f.severity));
    }
    if (normalizedSourceFilter.size > 0) {
      list = list.filter(
        (f) =>
          f.source &&
          normalizedSourceFilter.has(
            sourceFilterKey(f.source, sourceNamesById.get(f.source)),
          ),
      );
    }
    if (findingTypeFilter.size > 0) {
      list = list.filter(
        (f) => f.findingType && findingTypeFilter.has(f.findingType),
      );
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
          (f.owner ?? "").toLowerCase().includes(q),
      );
    }
    const validSortKeys = new Set([
      "severity",
      "status",
      "cve",
      "title",
      "source",
      "sla",
    ]);
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
        const statusOrder = [
          "Open",
          "In Review",
          "Rejected",
          "Reopened",
          "Risk Accepted",
          "Resolved",
          "False Positive",
          "Suppressed",
          "Not Applicable",
          "Approved",
          "Mitigated",
          "Duplicate",
        ];
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
    normalizedSourceFilter,
    sourceNamesById,
    findingTypeFilter,
  ]);

  const groupFindings = preferences.groupFindings ?? true;

  type DisplayRow = {
    finding: Finding;
    groupCount: number | undefined;
    sourceIndex: number | undefined;
    sourceName: string | undefined;
  };

  const displayRows = useMemo<DisplayRow[]>(() => {
    if (!groupFindings) {
      const sorted = [...filteredFindings].sort(
        (a, b) =>
          SEV_ORDER.indexOf(a.severity as (typeof SEV_ORDER)[number]) -
          SEV_ORDER.indexOf(b.severity as (typeof SEV_ORDER)[number]),
      );
      return sorted.flatMap<DisplayRow>((f) => {
        const srcCount = f.sources?.length ?? 0;
        if (srcCount > 1) {
          return f.sources!.map<DisplayRow>((s, i) => ({
            finding: f,
            groupCount: undefined,
            sourceIndex: i,
            sourceName: s.name ?? "",
          }));
        }
        return [
          {
            finding: f,
            groupCount: undefined,
            sourceIndex: undefined,
            sourceName: undefined,
          },
        ];
      });
    }
    const groups = getGroupedFindings(filteredFindings, SEV_ORDER);
    return groups.flatMap<DisplayRow>(({ findings: list }) => {
      const worst = list.reduce((a, b) =>
        SEV_ORDER.indexOf(a.severity as (typeof SEV_ORDER)[number]) <
        SEV_ORDER.indexOf(b.severity as (typeof SEV_ORDER)[number])
          ? a
          : b,
      );
      const srcCount = worst.sources?.length ?? 0;
      const count = list.length > 1 ? list.length : Math.max(1, srcCount);
      return [
        {
          finding: worst,
          groupCount: count,
          sourceIndex: undefined,
          sourceName: undefined,
        },
      ];
    });
  }, [filteredFindings, groupFindings]);

  const severityCounts = useMemo(() => {
    const CLOSED = [
      "Resolved",
      "False Positive",
      "Duplicate",
      "Not Applicable",
      "Approved",
      "Suppressed",
    ];
    const openRows = displayRows.filter(
      (r) => !CLOSED.includes(r.finding.status ?? ""),
    );
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

  const runDeleteAsset = useCallback(async () => {
    if (!asset || deletingAsset) return;
    setDeletingAsset(true);
    try {
      await deleteAsset(asset.id, {
        token: token ?? undefined,
        userEmail: user?.email,
      });
      setSelected(null);
      await refetch({ silent: true });
      router.push("/");
    } catch (err) {
      setAdminActionError(
        err instanceof Error ? err.message : "Failed to delete asset",
      );
    } finally {
      setDeletingAsset(false);
    }
  }, [asset, deletingAsset, refetch, router, setSelected, token, user?.email]);

  const runGroupAsset = useCallback(async () => {
    if (!asset || groupingAsset) return;
    const target = groupTargetAssetId.trim();
    if (!target) {
      setAdminActionError("Enter a target asset id");
      return;
    }
    if (target === asset.id) {
      setAdminActionError("Target asset must be different from current asset");
      return;
    }
    setGroupingAsset(true);
    try {
      const result = await groupAssetInto(asset.id, target, {
        token: token ?? undefined,
        userEmail: user?.email,
      });
      setSelected(null);
      await refetch({ silent: true });
      router.push(`/assets/${encodeURIComponent(result.target_asset_id)}`);
    } catch (err) {
      setAdminActionError(
        err instanceof Error
          ? err.message
          : "Failed to group asset into target",
      );
    } finally {
      setGroupingAsset(false);
    }
  }, [
    asset,
    groupTargetAssetId,
    groupingAsset,
    refetch,
    router,
    setSelected,
    token,
    user?.email,
  ]);

  const runUnmergeAsset = useCallback(async () => {
    if (!asset || unmergingAsset) return;
    const sourceId = unmergeSourceAssetId.trim();
    if (!sourceId) {
      setAdminActionError("Select a merged source asset to unmerge");
      return;
    }
    setUnmergingAsset(true);
    try {
      await unmergeAssetFrom(asset.id, sourceId, {
        token: token ?? undefined,
        userEmail: user?.email,
      });
      setSelected(null);
      await refetch({ silent: true });
      setPendingAdminAction(null);
    } catch (err) {
      setAdminActionError(
        err instanceof Error ? err.message : "Failed to unmerge asset alias",
      );
    } finally {
      setUnmergingAsset(false);
    }
  }, [
    asset,
    refetch,
    setSelected,
    token,
    unmergeSourceAssetId,
    unmergingAsset,
    user?.email,
  ]);

  const closeAdminDialog = useCallback(() => {
    if (deletingAsset || groupingAsset || unmergingAsset) return;
    setPendingAdminAction(null);
    setActionConfirmText("");
    setAdminActionError(null);
    setTargetSearchOpen(false);
  }, [deletingAsset, groupingAsset, unmergingAsset]);

  const openAdminActionDialog = useCallback(
    (action: "group" | "unmerge" | "delete") => {
      if (!asset) return;
      setShowAdminActions(false);
      setPendingAdminAction(action);
      setActionConfirmText("");
      setAdminActionError(null);
      if (action === "group") {
        // Always start empty so user intentionally chooses a target.
        setGroupTargetAssetId("");
        setTargetSearchOpen(false);
      }
      if (action === "unmerge") {
        setUnmergeSourceAssetId("");
        setAliasSourceOptions([]);
        void fetchAssetAliases(asset.id, {
          token: token ?? undefined,
          userEmail: user?.email,
        })
          .then((data) => {
            const ids = (data.aliases || []).map((a) => a.source_asset_id);
            setAliasSourceOptions(ids);
          })
          .catch((err) => {
            setAdminActionError(
              err instanceof Error
                ? err.message
                : "Failed to load merged aliases",
            );
          });
      }
    },
    [asset, token, user?.email],
  );

  const handleConfirmAdminAction = useCallback(async () => {
    if (!asset || !pendingAdminAction) return;
    const expected = asset.id;
    if (actionConfirmText.trim() !== expected) {
      setAdminActionError(`Type "${expected}" to confirm`);
      return;
    }
    setAdminActionError(null);
    if (pendingAdminAction === "delete") {
      await runDeleteAsset();
      return;
    }
    if (pendingAdminAction === "unmerge") {
      await runUnmergeAsset();
      return;
    }
    await runGroupAsset();
  }, [
    actionConfirmText,
    asset,
    pendingAdminAction,
    runDeleteAsset,
    runGroupAsset,
    runUnmergeAsset,
  ]);

  const mainContent = (() => {
    if (loading && !error && findings.length === 0) {
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

    if (!assetId) {
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

    if (!asset && (loading || refreshing)) {
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
          ▣ Resolving asset…
        </div>
      );
    }

    if (!asset) {
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
      return <WaiversTab waivers={assetWaivers} onSelect={setSelected} />;
    }

    if (assetTab === "sbom") {
      if (assetSbomQuery.isLoading && assetSbom.length === 0) {
        return (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              minHeight: 200,
              color: "var(--app-accent)",
              ...mono,
              fontSize: 12,
            }}
          >
            ▣ Loading SBOM…
          </div>
        );
      }
      return (
        <SBOMTab
          sbom={assetSbom}
          findings={asset.findings}
          onImport={(pkg) => setSbomImportOverride(pkg)}
          assetId={assetId ?? asset?.id}
        />
      );
    }

    if (assetTab === "review") {
      const strategyLabel: Record<AssetMergeSuggestion["strategy"], string> = {
        digest: "Digest",
        exact_ref: "Exact image/ref",
        sbom_similarity: "SBOM similarity",
        name_heuristic: "Name heuristic",
      };
      const detailLabel: Record<string, string> = {
        reason: "Reason",
        sourceAssetId: "Source asset",
        targetAssetId: "Target asset",
        sourceName: "Source normalized name",
        targetName: "Target normalized name",
        nameSimilarity: "Name similarity",
        exactNormalizedNameMatch: "Exact normalized name match",
        sharedNameTokens: "Shared name tokens",
        sharedRefs: "Shared refs",
        sharedRefCount: "Shared ref count",
        sharedDigests: "Shared digests",
        sharedDigestCount: "Shared digest count",
        packageJaccard: "SBOM Jaccard",
        sourcePackageCount: "Source package count",
        targetPackageCount: "Target package count",
        sharedPackageCount: "Shared package count",
        sharedPackages: "Shared packages",
      };
      return (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {canReviewAssets && (
            <section
              style={{
                background: "var(--app-card-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 8,
                padding: 14,
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: 10,
                }}
              >
                <div>
                  <div
                    style={{
                      ...mono,
                      fontSize: 10,
                      fontWeight: 700,
                      letterSpacing: "0.12em",
                      textTransform: "uppercase",
                      color: "var(--app-muted)",
                      marginBottom: 4,
                    }}
                  >
                    Asset Merge Review
                  </div>
                  <div
                    style={{ ...sans, fontSize: 13, color: "var(--app-muted)" }}
                  >
                    Suggestions are non-destructive until you approve.
                  </div>
                  {asset?.digestConflictOpen && (
                    <div
                      style={{
                        marginTop: 8,
                        ...sans,
                        fontSize: 12,
                        color: "var(--app-danger)",
                      }}
                    >
                      Digest conflict detected for one or more tags on this
                      asset. Review tag/digest observations before approving
                      merges.
                    </div>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => void refreshMergeReviewData()}
                  disabled={mergeSuggestionsLoading || digestConflictsLoading}
                  style={{
                    ...mono,
                    fontSize: 11,
                    borderRadius: 6,
                    border: "1px solid var(--app-border)",
                    background: "transparent",
                    color: "var(--app-accent)",
                    padding: "6px 10px",
                    cursor:
                      mergeSuggestionsLoading || digestConflictsLoading
                        ? "not-allowed"
                        : "pointer",
                    opacity:
                      mergeSuggestionsLoading || digestConflictsLoading
                        ? 0.7
                        : 1,
                  }}
                >
                  {mergeSuggestionsLoading || digestConflictsLoading
                    ? "Refreshing…"
                    : "Refresh"}
                </button>
              </div>

              {mergeSuggestionsError && (
                <div
                  style={{
                    marginTop: 10,
                    border:
                      "1px solid color-mix(in srgb, var(--app-danger) 60%, transparent)",
                    background:
                      "color-mix(in srgb, var(--app-danger) 10%, transparent)",
                    color: "var(--app-danger)",
                    borderRadius: 6,
                    padding: "8px 10px",
                    ...sans,
                    fontSize: 12,
                  }}
                >
                  {mergeSuggestionsError}
                </div>
              )}

              <div
                style={{
                  marginTop: 12,
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                  gap: 10,
                }}
              >
                <div
                  style={{
                    border: "1px solid var(--app-border)",
                    borderRadius: 6,
                    padding: "10px 12px",
                    background: "var(--app-input-bg)",
                  }}
                >
                  <div
                    style={{
                      ...mono,
                      fontSize: 10,
                      letterSpacing: "0.08em",
                      textTransform: "uppercase",
                      color: "var(--app-muted)",
                      marginBottom: 6,
                    }}
                  >
                    Observed Tags
                  </div>
                  {(asset?.observedTags ?? []).length === 0 ? (
                    <div
                      style={{
                        ...sans,
                        fontSize: 12,
                        color: "var(--app-muted)",
                      }}
                    >
                      No observed tags captured yet.
                    </div>
                  ) : (
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 6,
                      }}
                    >
                      {(asset?.observedTags ?? []).map((t) => (
                        <div key={t.tag} style={{ ...mono, fontSize: 11 }}>
                          <span style={{ color: "var(--app-fg)" }}>
                            {t.tag}
                          </span>
                          <span style={{ color: "var(--app-muted)" }}>
                            {" "}
                            · seen{" "}
                            {Math.max(1, Number(t.observationCount ?? 0))}
                            {t.lastSeenAt ? ` · last ${t.lastSeenAt}` : ""}
                            {t.lastDigest ? ` · ${t.lastDigest}` : ""}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div
                  style={{
                    border: "1px solid var(--app-border)",
                    borderRadius: 6,
                    padding: "10px 12px",
                    background: "var(--app-input-bg)",
                  }}
                >
                  <div
                    style={{
                      ...mono,
                      fontSize: 10,
                      letterSpacing: "0.08em",
                      textTransform: "uppercase",
                      color: "var(--app-muted)",
                      marginBottom: 6,
                    }}
                  >
                    Digest Conflicts
                  </div>
                  {digestConflictsLoading ? (
                    <div
                      style={{
                        ...sans,
                        fontSize: 12,
                        color: "var(--app-muted)",
                      }}
                    >
                      Loading conflicts...
                    </div>
                  ) : digestConflicts.length === 0 ? (
                    <div
                      style={{
                        ...sans,
                        fontSize: 12,
                        color: "var(--app-muted)",
                      }}
                    >
                      No digest conflicts recorded.
                    </div>
                  ) : (
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 8,
                      }}
                    >
                      {digestConflicts.map((c) => {
                        const isOpen = c.status === "open";
                        const busy = digestConflictActionTag === c.tag;
                        return (
                          <div
                            key={`${c.tag}-${c.id}`}
                            style={{
                              border: "1px solid var(--app-border)",
                              borderRadius: 6,
                              padding: "8px 10px",
                            }}
                          >
                            <div
                              style={{
                                ...mono,
                                fontSize: 11,
                                color: "var(--app-fg)",
                              }}
                            >
                              tag {c.tag} · status {c.status}
                            </div>
                            <div
                              style={{
                                ...mono,
                                fontSize: 10,
                                color: "var(--app-muted)",
                                marginTop: 4,
                                lineHeight: 1.35,
                              }}
                            >
                              Digests: {(c.digests ?? []).join(", ")}
                            </div>
                            <div
                              style={{
                                ...mono,
                                fontSize: 10,
                                color: "var(--app-muted)",
                                marginTop: 2,
                                lineHeight: 1.35,
                              }}
                            >
                              First seen: {c.first_seen_at ?? "n/a"} · Last
                              seen: {c.last_seen_at ?? "n/a"}
                            </div>
                            {canReviewAssets && (
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() =>
                                  void setDigestConflictAcknowledged(
                                    c.tag,
                                    isOpen,
                                  )
                                }
                                style={{
                                  ...mono,
                                  fontSize: 10,
                                  marginTop: 6,
                                  borderRadius: 6,
                                  border: "1px solid var(--app-border)",
                                  background: "transparent",
                                  color: "var(--app-accent)",
                                  padding: "4px 8px",
                                  cursor: busy ? "not-allowed" : "pointer",
                                  opacity: busy ? 0.7 : 1,
                                }}
                              >
                                {busy
                                  ? "Updating..."
                                  : isOpen
                                    ? "Acknowledge"
                                    : "Mark Open"}
                              </button>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              {!mergeSuggestionsLoading &&
                mergeSuggestionsVisible.length === 0 && (
                  <div
                    style={{
                      marginTop: 10,
                      ...sans,
                      fontSize: 12,
                      color: "var(--app-muted)",
                    }}
                  >
                    No merge suggestions for this asset.
                  </div>
                )}

              {mergeSuggestionsVisible.length > 0 && (
                <div
                  style={{
                    marginTop: 12,
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                  }}
                >
                  {mergeSuggestionsVisible.map((s) => (
                    <div
                      key={`${s.source_asset_id}-${s.target_asset_id}`}
                      style={{
                        border: "1px solid var(--app-border)",
                        borderRadius: 6,
                        padding: "10px 12px",
                        background: "var(--app-input-bg)",
                        display: "flex",
                        flexWrap: "wrap",
                        alignItems: "center",
                        gap: 10,
                      }}
                    >
                      <div style={{ minWidth: 260, flex: 1 }}>
                        <div
                          style={{
                            ...mono,
                            fontSize: 12,
                            color: "var(--app-fg)",
                          }}
                        >
                          {s.target_asset_id}
                        </div>
                        <div
                          style={{
                            ...mono,
                            fontSize: 10,
                            color: "var(--app-muted)",
                            marginTop: 4,
                          }}
                        >
                          {strategyLabel[s.strategy]} · confidence{" "}
                          {s.confidence} · score {s.score.toFixed(2)}
                        </div>
                        {Object.keys(s.details ?? {}).length > 0 && (
                          <details style={{ marginTop: 8 }}>
                            <summary
                              style={{
                                ...mono,
                                fontSize: 10,
                                color: "var(--app-accent)",
                                cursor: "pointer",
                                userSelect: "none",
                              }}
                            >
                              Reason details
                            </summary>
                            <div
                              style={{
                                marginTop: 6,
                                borderLeft: "2px solid var(--app-border)",
                                paddingLeft: 8,
                                display: "flex",
                                flexDirection: "column",
                                gap: 4,
                              }}
                            >
                              {typeof s.details?.reason === "string" &&
                                s.details.reason.trim().length > 0 && (
                                  <div
                                    style={{
                                      ...sans,
                                      fontSize: 12,
                                      color: "var(--app-fg)",
                                      lineHeight: 1.45,
                                      marginBottom: 2,
                                    }}
                                  >
                                    {s.details.reason.trim()}
                                  </div>
                                )}
                              {Object.entries(s.details)
                                .filter(([k]) => k !== "reason")
                                .map(([k, v]) => (
                                  <div
                                    key={k}
                                    style={{
                                      ...mono,
                                      fontSize: 10,
                                      color: "var(--app-muted)",
                                      lineHeight: 1.35,
                                    }}
                                  >
                                    <span style={{ color: "var(--app-fg)" }}>
                                      {detailLabel[k] ?? k}
                                    </span>
                                    :{" "}
                                    {Array.isArray(v)
                                      ? v.join(", ")
                                      : typeof v === "object" && v !== null
                                        ? JSON.stringify(v)
                                        : String(v)}
                                  </div>
                                ))}
                            </div>
                          </details>
                        )}
                      </div>
                      <div style={{ display: "flex", gap: 8 }}>
                        <button
                          type="button"
                          onClick={() => void denyMergeSuggestion(s)}
                          disabled={
                            mergeReviewActionTargetId === s.target_asset_id ||
                            approvingTargetId === s.target_asset_id
                          }
                          style={{
                            ...mono,
                            fontSize: 11,
                            borderRadius: 6,
                            border: "1px solid var(--app-danger)",
                            background: "transparent",
                            color: "var(--app-danger)",
                            padding: "6px 10px",
                            cursor:
                              mergeReviewActionTargetId === s.target_asset_id ||
                              approvingTargetId === s.target_asset_id
                                ? "not-allowed"
                                : "pointer",
                            opacity:
                              mergeReviewActionTargetId === s.target_asset_id ||
                              approvingTargetId === s.target_asset_id
                                ? 0.7
                                : 1,
                          }}
                        >
                          {mergeReviewActionTargetId === s.target_asset_id
                            ? "Saving…"
                            : "Deny"}
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            void approveMergeSuggestion(s.target_asset_id)
                          }
                          disabled={
                            !isAdmin ||
                            Boolean(approvingTargetId) ||
                            mergeReviewActionTargetId === s.target_asset_id
                          }
                          style={{
                            ...mono,
                            fontSize: 11,
                            borderRadius: 6,
                            border: "1px solid var(--app-accent)",
                            background: "transparent",
                            color: "var(--app-accent)",
                            padding: "6px 10px",
                            cursor:
                              !isAdmin ||
                              approvingTargetId ||
                              mergeReviewActionTargetId === s.target_asset_id
                                ? "not-allowed"
                                : "pointer",
                            opacity:
                              !isAdmin ||
                              approvingTargetId ||
                              mergeReviewActionTargetId === s.target_asset_id
                                ? 0.7
                                : 1,
                          }}
                          title={
                            isAdmin
                              ? undefined
                              : "Admin role required to approve merge"
                          }
                        >
                          {!isAdmin
                            ? "Admin required"
                            : approvingTargetId === s.target_asset_id
                              ? "Approving…"
                              : "Approve merge"}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div style={{ marginTop: 14 }}>
                <div
                  style={{
                    ...mono,
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: "0.12em",
                    textTransform: "uppercase",
                    color: "var(--app-muted)",
                    marginBottom: 8,
                  }}
                >
                  Past Merge Reviews
                </div>
                {mergeReviewsLoading && (
                  <div
                    style={{ ...sans, fontSize: 12, color: "var(--app-muted)" }}
                  >
                    Loading history…
                  </div>
                )}
                {!mergeReviewsLoading && mergeReviews.length === 0 && (
                  <div
                    style={{ ...sans, fontSize: 12, color: "var(--app-muted)" }}
                  >
                    No past merge reviews for this asset.
                  </div>
                )}
                {mergeReviews.length > 0 && (
                  <div
                    style={{ display: "flex", flexDirection: "column", gap: 8 }}
                  >
                    {mergeReviews.map((r) => (
                      <div
                        key={`${r.source_asset_id}-${r.target_asset_id}`}
                        style={{
                          border: "1px solid var(--app-border)",
                          borderRadius: 6,
                          padding: "9px 10px",
                          background: "var(--app-card-bg)",
                          display: "flex",
                          flexWrap: "wrap",
                          alignItems: "center",
                          gap: 10,
                        }}
                      >
                        <div style={{ minWidth: 280, flex: 1 }}>
                          <div
                            style={{
                              ...mono,
                              fontSize: 12,
                              color: "var(--app-fg)",
                            }}
                          >
                            {r.target_asset_id}
                          </div>
                          <div
                            style={{
                              ...mono,
                              fontSize: 10,
                              color: "var(--app-muted)",
                            }}
                          >
                            status {r.status}
                            {r.updated_at ? ` · updated ${r.updated_at}` : ""}
                            {r.note ? ` · ${r.note}` : ""}
                          </div>
                        </div>
                        <div style={{ display: "flex", gap: 8 }}>
                          <button
                            type="button"
                            onClick={() =>
                              void setMergeReviewStatus(
                                r.target_asset_id,
                                "pending",
                                "Reopened for review",
                              )
                            }
                            disabled={
                              mergeReviewActionTargetId === r.target_asset_id
                            }
                            style={{
                              ...mono,
                              fontSize: 11,
                              borderRadius: 6,
                              border: "1px solid var(--app-border)",
                              background: "transparent",
                              color: "var(--app-muted)",
                              padding: "5px 8px",
                            }}
                          >
                            Reopen
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              void removeMergeReview(r.target_asset_id)
                            }
                            disabled={
                              mergeReviewActionTargetId === r.target_asset_id
                            }
                            style={{
                              ...mono,
                              fontSize: 11,
                              borderRadius: 6,
                              border: "1px solid var(--app-border)",
                              background: "transparent",
                              color: "var(--app-danger)",
                              padding: "5px 8px",
                            }}
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </section>
          )}
          <ReviewQueue
            reviewQueue={assetReviewQueue}
            sources={sources}
            tracker={tracker}
            onSelect={setSelected}
          />
        </div>
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
              <div
                style={{
                  display: "flex",
                  gap: 14,
                  alignItems: "flex-start",
                  flex: 1,
                  minWidth: 0,
                }}
              >
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
                  {assetDisplayTitle.charAt(0).toUpperCase()}
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      marginBottom: 6,
                    }}
                  >
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
                      title={asset.id}
                    >
                      {assetDisplayTitle}
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
                      aria-label={
                        favoriteAssetIds.has(asset.id)
                          ? "Unfavorite"
                          : "Favorite"
                      }
                      style={{
                        background: "none",
                        border: "none",
                        padding: 0,
                        cursor: "pointer",
                        flexShrink: 0,
                        fontSize: 20,
                        color: favoriteAssetIds.has(asset.id)
                          ? "var(--app-danger)"
                          : "var(--app-muted)",
                      }}
                    >
                      {favoriteAssetIds.has(asset.id) ? "♥" : "♡"}
                    </button>
                  </div>
                  <div
                    style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}
                  >
                    {assetDisplayTitle !== asset.id && (
                      <span
                        style={{
                          display: "block",
                          marginBottom: 4,
                          wordBreak: "break-all",
                        }}
                      >
                        {asset.id}
                      </span>
                    )}
                    {asset.tag && `Tag: ${asset.tag} · `}
                    {displayRows.length} findings
                    {(branchFilter || tagFilter) &&
                      ` (of ${asset.findings.length})`}
                  </div>
                </div>
              </div>

              {/* Branch / Tag dropdown */}
              {(assetType === "repo" || assetType === "container") && (
                <div
                  style={{
                    display: "flex",
                    gap: 16,
                    alignItems: "center",
                    flexWrap: "wrap",
                  }}
                >
                  {assetType === "repo" && (
                    <ThemedSelect
                      value={branchFilter}
                      options={[
                        {
                          value: "",
                          label:
                            uniqueBranches.length > 0 ? "All branches" : "—",
                        },
                        ...uniqueBranches.map((b) => ({ value: b, label: b })),
                      ]}
                      onChange={(v) => setBranchFilter(v)}
                      icon={
                        <GitBranch
                          size={14}
                          style={{ color: "var(--app-muted)", flexShrink: 0 }}
                        />
                      }
                      aria-label="Filter by branch"
                    />
                  )}
                  {assetType === "container" && (
                    <ThemedSelect
                      value={tagFilter}
                      options={[
                        {
                          value: "",
                          label:
                            containerVariantKeys.length > 0
                              ? "All image variants"
                              : "—",
                        },
                        ...containerVariantSelectOptions,
                      ]}
                      onChange={(v) => {
                        if (v === "")
                          containerVariantUserChoseAllRef.current = true;
                        else containerVariantUserChoseAllRef.current = false;
                        setTagFilter(v);
                      }}
                      icon={
                        <Tag
                          size={14}
                          style={{ color: "var(--app-muted)", flexShrink: 0 }}
                        />
                      }
                      aria-label="Filter by image variant"
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
                      background:
                        "color-mix(in srgb, var(--app-accent) 15%, transparent)",
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
                      ABC:{" "}
                      {metricsFromAsset.verifiedPct === 100
                        ? "Compliant"
                        : metricsFromAsset.verifiedPct > 0
                          ? "Compliant With Warnings"
                          : "Non-compliant"}
                    </span>
                  </ThemedTooltip>
                  <ThemedTooltip content={ORA_TOOLTIP} placement="top">
                    <span
                      style={{
                        ...mono,
                        fontSize: 11,
                        padding: "6px 12px",
                        borderRadius: 20,
                        background:
                          "color-mix(in srgb, var(--app-muted) 15%, transparent)",
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
              {digestMergeBannerHints.length > 0 &&
                !mergeSuggestionsLoading && (
                  <div
                    role="status"
                    style={{
                      width: "100%",
                      flexBasis: "100%",
                      marginTop: 4,
                      padding: "10px 12px",
                      borderRadius: 6,
                      border:
                        "1px solid color-mix(in srgb, var(--app-accent) 45%, transparent)",
                      background:
                        "color-mix(in srgb, var(--app-accent) 10%, transparent)",
                      ...sans,
                      fontSize: 13,
                      color: "var(--app-fg)",
                    }}
                  >
                    <strong style={{ color: "var(--app-accent)" }}>
                      Digest merge suggestion
                    </strong>
                    {" — "}
                    {digestMergeBannerHints.length === 1
                      ? `This asset likely matches another image by manifest digest (${digestMergeBannerHints[0].target_asset_id}).`
                      : `${digestMergeBannerHints.length} high-confidence digest matches are available.`}{" "}
                    <button
                      type="button"
                      onClick={() => setAssetTab("review")}
                      style={{
                        ...sans,
                        marginLeft: 8,
                        fontSize: 13,
                        border: "none",
                        background: "transparent",
                        color: "var(--app-accent)",
                        cursor: "pointer",
                        textDecoration: "underline",
                        padding: 0,
                      }}
                    >
                      Open Asset Merge Review
                    </button>
                  </div>
                )}
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
                  onChange={(e) =>
                    setPreferences({ groupFindings: e.target.checked })
                  }
                  aria-label="Group findings"
                  style={{ accentColor: "var(--app-accent-emerald)" }}
                />
                Group findings
              </label>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span
                  style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}
                >
                  Sort:
                </span>
                <select
                  value={
                    sortBy.endsWith("-desc") ? sortBy.slice(0, -5) : sortBy
                  }
                  onChange={(e) =>
                    setSortBy(
                      e.target.value as (typeof SORT_OPTS)[number]["value"],
                    )
                  }
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
                  label: `${FINDING_TYPES[t]?.icon ?? ""} ${
                    FINDING_TYPES[t]?.label ?? t
                  }`.trim(),
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
                options={uniqueColumnValues.severities.map((s) => ({
                  value: s,
                  label: s,
                }))}
                selected={severityFilter}
                onChange={setSeverityFilter}
              />
              <MultiSelectFilter
                label="Source"
                options={sourceOptionsWithCounts}
                selected={normalizedSourceFilter}
                onChange={setSourceFilter}
              />
              <SearchInput
                value={findingsSearch}
                onValueChange={setFindingsSearch}
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
                gridTemplateColumns:
                  "26px 4px 32px 130px 1fr 160px 60px 100px 90px 80px",
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
                    {isSortable &&
                      isActive &&
                      (isDesc ? (
                        <ChevronDown size={10} />
                      ) : (
                        <ChevronUp size={10} />
                      ))}
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
                  {findingsSearch
                    ? "No findings match your search."
                    : "No findings."}
                </div>
              ) : (
                displayRows.map(
                  ({ finding: f, groupCount, sourceIndex, sourceName }) => (
                    <FindingRow
                      key={
                        sourceIndex != null ? `${f.id}-${sourceIndex}` : f.id
                      }
                      finding={f}
                      sources={sources}
                      selected={
                        selected?.id === f.id &&
                        (sourceIndex == null ||
                          selectedSourceIndex === sourceIndex)
                      }
                      checked={checked.has(f.id)}
                      onCheck={(v) => toggleCheck(f.id, v)}
                      onClick={() => {
                        setSelected(f);
                        setSelectedSourceIndex(sourceIndex);
                      }}
                      groupCount={groupCount}
                      instanceSource={sourceName}
                    />
                  ),
                )
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
              {groupFindings &&
                displayRows.length !== filteredFindings.length &&
                ` (${filteredFindings.length} total)`}
            </div>
          </div>

          {findingForDetail && (
            <DetailPanel
              finding={findingForDetail}
              detailLoadError={selectedDetailError}
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
              selectedSourceIndex={
                !groupFindings ? selectedSourceIndex : undefined
              }
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
        isAdmin={canReviewAssets}
        currentTab={assetTab}
        onTabChange={setAssetTab}
        rightContent={
          isAdmin ? (
            <div ref={adminActionsRef} style={{ position: "relative" }}>
              <button
                type="button"
                onClick={() => setShowAdminActions((v) => !v)}
                aria-label="Open asset admin actions"
                style={{
                  ...mono,
                  fontSize: 11,
                  borderRadius: 6,
                  border:
                    "1px solid color-mix(in srgb, var(--app-accent) 50%, var(--app-border))",
                  background:
                    "color-mix(in srgb, var(--app-accent) 12%, var(--app-input-bg))",
                  color: "var(--app-accent)",
                  padding: "4px 10px",
                  cursor: "pointer",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <MoreHorizontal size={13} />
                Asset actions
              </button>
              {showAdminActions && (
                <div
                  style={{
                    position: "absolute",
                    zIndex: 40,
                    right: 0,
                    top: "calc(100% + 6px)",
                    minWidth: 220,
                    borderRadius: 10,
                    border:
                      "1px solid color-mix(in srgb, var(--app-accent) 25%, var(--app-border))",
                    background:
                      "color-mix(in srgb, var(--app-card-bg) 92%, var(--app-header-bg))",
                    boxShadow: "0 14px 36px rgba(0,0,0,0.28)",
                    overflow: "hidden",
                  }}
                >
                  <button
                    type="button"
                    onClick={() => openAdminActionDialog("group")}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      background: "transparent",
                      border: "none",
                      borderBottom:
                        "1px solid color-mix(in srgb, var(--app-border) 70%, transparent)",
                      padding: "10px 12px",
                      color: "var(--app-fg)",
                      cursor: "pointer",
                      ...sans,
                      fontSize: 12,
                    }}
                  >
                    Group / Merge asset
                  </button>
                  <button
                    type="button"
                    onClick={() => openAdminActionDialog("unmerge")}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      background: "transparent",
                      border: "none",
                      borderBottom:
                        "1px solid color-mix(in srgb, var(--app-border) 70%, transparent)",
                      padding: "10px 12px",
                      color: "var(--app-fg)",
                      cursor: "pointer",
                      ...sans,
                      fontSize: 12,
                    }}
                  >
                    Unmerge alias
                  </button>
                  <button
                    type="button"
                    onClick={() => openAdminActionDialog("delete")}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      background: "transparent",
                      border: "none",
                      padding: "10px 12px",
                      color:
                        "color-mix(in srgb, var(--app-danger) 92%, var(--app-fg))",
                      cursor: "pointer",
                      ...sans,
                      fontSize: 12,
                    }}
                  >
                    Delete asset
                  </button>
                </div>
              )}
            </div>
          ) : null
        }
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
        {pendingAdminAction && asset && (
          <div
            role="dialog"
            aria-modal="true"
            onClick={closeAdminDialog}
            style={{
              position: "fixed",
              inset: 0,
              zIndex: 60,
              background: "color-mix(in srgb, #000 62%, transparent)",
              display: "grid",
              placeItems: "center",
              padding: 16,
            }}
          >
            <div
              onClick={(e) => e.stopPropagation()}
              style={{
                width: "min(560px, calc(100vw - 32px))",
                borderRadius: 10,
                border:
                  "1px solid color-mix(in srgb, var(--app-accent) 25%, var(--app-border))",
                background:
                  "color-mix(in srgb, var(--app-card-bg) 94%, var(--app-header-bg))",
                boxShadow: "0 18px 44px rgba(0,0,0,0.32)",
                padding: 16,
                display: "flex",
                flexDirection: "column",
                gap: 12,
              }}
            >
              <h3
                style={{
                  margin: 0,
                  ...mono,
                  fontSize: 14,
                  color: "var(--app-fg)",
                }}
              >
                {pendingAdminAction === "delete"
                  ? "Delete asset"
                  : pendingAdminAction === "unmerge"
                    ? "Unmerge alias"
                    : "Group / Merge asset"}
              </h3>
              <p
                style={{
                  margin: 0,
                  ...sans,
                  fontSize: 12,
                  color: "var(--app-muted)",
                  lineHeight: 1.45,
                }}
              >
                {pendingAdminAction === "delete"
                  ? "This permanently deletes the asset record and matching findings."
                  : pendingAdminAction === "unmerge"
                    ? "This removes an alias previously merged into this asset and restores recorded finding mappings."
                    : "This merges the current asset into a canonical target and remaps existing + future findings."}
              </p>
              {pendingAdminAction === "group" && (
                <>
                  <label
                    style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}
                  >
                    Target asset id
                  </label>
                  <div ref={targetSearchRef} style={{ position: "relative" }}>
                    <SearchInput
                      value={groupTargetAssetId}
                      onValueChange={(value) => {
                        setGroupTargetAssetId(value);
                        setTargetSearchOpen(true);
                      }}
                      onFocus={() => setTargetSearchOpen(true)}
                      placeholder="Search and select target asset…"
                      style={{
                        ...mono,
                        fontSize: 12,
                        padding: "8px 10px",
                        borderRadius: 6,
                        border:
                          "1px solid color-mix(in srgb, var(--app-accent) 30%, var(--app-border))",
                        background: "var(--app-input-bg)",
                        color: "var(--app-fg)",
                        width: "100%",
                      }}
                    />
                    {targetSearchOpen && (
                      <div
                        style={{
                          position: "absolute",
                          top: "calc(100% + 4px)",
                          left: 0,
                          right: 0,
                          zIndex: 80,
                          maxHeight: 220,
                          overflowY: "auto",
                          borderRadius: 6,
                          border:
                            "1px solid color-mix(in srgb, var(--app-accent) 20%, var(--app-border))",
                          background:
                            "color-mix(in srgb, var(--app-card-bg) 96%, var(--app-header-bg))",
                          boxShadow: "0 10px 30px rgba(0,0,0,0.25)",
                        }}
                      >
                        {filteredTargetAssetOptions.length === 0 ? (
                          <div
                            style={{
                              padding: "8px 10px",
                              ...sans,
                              fontSize: 12,
                              color: "var(--app-muted)",
                            }}
                          >
                            No matching assets
                          </div>
                        ) : (
                          filteredTargetAssetOptions.map((id) => (
                            <button
                              key={id}
                              type="button"
                              onClick={() => {
                                setGroupTargetAssetId(id);
                                setTargetSearchOpen(false);
                              }}
                              style={{
                                width: "100%",
                                border: "none",
                                background:
                                  id === groupTargetAssetId
                                    ? "color-mix(in srgb, var(--app-accent) 15%, transparent)"
                                    : "transparent",
                                color: "var(--app-fg)",
                                textAlign: "left",
                                padding: "8px 10px",
                                cursor: "pointer",
                                ...mono,
                                fontSize: 12,
                              }}
                            >
                              {id}
                            </button>
                          ))
                        )}
                      </div>
                    )}
                  </div>
                </>
              )}
              {pendingAdminAction === "unmerge" && (
                <>
                  <label
                    style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}
                  >
                    Source asset id to unmerge
                  </label>
                  <select
                    value={unmergeSourceAssetId}
                    onChange={(e) => setUnmergeSourceAssetId(e.target.value)}
                    style={{
                      ...mono,
                      fontSize: 12,
                      padding: "8px 10px",
                      borderRadius: 6,
                      border:
                        "1px solid color-mix(in srgb, var(--app-accent) 30%, var(--app-border))",
                      background: "var(--app-input-bg)",
                      color: "var(--app-fg)",
                    }}
                  >
                    <option value="">Select merged source…</option>
                    {aliasSourceOptions.map((id) => (
                      <option key={id} value={id}>
                        {id}
                      </option>
                    ))}
                  </select>
                </>
              )}
              <label
                style={{ ...mono, fontSize: 11, color: "var(--app-muted)" }}
              >
                Type{" "}
                <span style={{ color: "var(--app-danger)" }}>{asset.id}</span>{" "}
                to confirm
              </label>
              <input
                value={actionConfirmText}
                onChange={(e) => setActionConfirmText(e.target.value)}
                placeholder={asset.id}
                style={{
                  ...mono,
                  fontSize: 12,
                  padding: "8px 10px",
                  borderRadius: 6,
                  border:
                    "1px solid color-mix(in srgb, var(--app-accent) 30%, var(--app-border))",
                  background: "var(--app-input-bg)",
                  color: "var(--app-fg)",
                }}
              />
              {adminActionError && (
                <div
                  style={{
                    border:
                      "1px solid color-mix(in srgb, var(--app-danger) 60%, transparent)",
                    background:
                      "color-mix(in srgb, var(--app-danger) 10%, transparent)",
                    color: "var(--app-danger)",
                    borderRadius: 6,
                    padding: "8px 10px",
                    ...sans,
                    fontSize: 12,
                  }}
                >
                  {adminActionError}
                </div>
              )}
              <div
                style={{
                  display: "flex",
                  justifyContent: "flex-end",
                  gap: 8,
                  marginTop: 4,
                }}
              >
                <button
                  type="button"
                  onClick={closeAdminDialog}
                  disabled={deletingAsset || groupingAsset || unmergingAsset}
                  style={{
                    ...mono,
                    fontSize: 11,
                    borderRadius: 6,
                    border: "1px solid var(--app-border)",
                    background: "transparent",
                    color: "var(--app-fg)",
                    padding: "6px 10px",
                    cursor:
                      deletingAsset || groupingAsset || unmergingAsset
                        ? "not-allowed"
                        : "pointer",
                    opacity:
                      deletingAsset || groupingAsset || unmergingAsset
                        ? 0.7
                        : 1,
                  }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleConfirmAdminAction}
                  disabled={deletingAsset || groupingAsset || unmergingAsset}
                  style={{
                    ...mono,
                    fontSize: 11,
                    borderRadius: 6,
                    border: "1px solid var(--app-danger)",
                    background: "transparent",
                    color: "var(--app-danger)",
                    padding: "6px 10px",
                    cursor:
                      deletingAsset || groupingAsset || unmergingAsset
                        ? "not-allowed"
                        : "pointer",
                    opacity:
                      deletingAsset || groupingAsset || unmergingAsset
                        ? 0.7
                        : 1,
                  }}
                >
                  {deletingAsset
                    ? "Deleting…"
                    : groupingAsset
                      ? "Grouping…"
                      : unmergingAsset
                        ? "Unmerging…"
                        : pendingAdminAction === "delete"
                          ? "Delete asset"
                          : pendingAdminAction === "unmerge"
                            ? "Unmerge alias"
                            : "Group asset"}
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
