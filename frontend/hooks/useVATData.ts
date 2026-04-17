"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { now, daysLeft, computeAlerts } from "@/lib/utils";
import {
  archiveFinding,
  bulkUpdateFindings,
  fetchSettings,
  fetchSbomPackages,
  fetchVATData,
  type VATDataResponse,
  overrideFindingFingerprint,
  putSettingsLabels,
  putSettingsSources,
  putSettingsTracker,
  revertFinding,
  unarchiveFinding,
  updateFinding,
} from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { loadSettingsFromStorage, saveToStorage } from "@/lib/settingsStorage";
import {
  DEFAULT_TRACKER,
  DEFAULT_LABELS,
  SAMPLE_SBOM,
  SEV_ORDER,
} from "@/lib/constants";
import {
  deriveAssets,
  getAssetDisplayTitle,
  getAssetTypeFromAsset,
  assetIdForFinding,
} from "@/lib/assetUtils";
import {
  FAVORITES_KEY,
  loadFavoriteEntries,
  saveFavoriteEntries,
  type FavoriteEntry,
} from "@/lib/userSettings";
import {
  ASSET_LOADOUTS_KEY,
  loadAssetLoadouts,
  saveAssetLoadout,
  deleteAssetLoadout as deleteLoadoutStorage,
  renameAssetLoadout as renameLoadoutStorage,
  type AssetLoadout,
} from "@/lib/assetLoadoutStorage";
import type {
  Asset,
  Finding,
  Source,
  Tracker,
  WatchedLabel,
  Alert,
} from "@/types";

const VAT_SNAPSHOT_KEY = "vat:lastFindingsSnapshot:v1";
const SNAPSHOT_MAX_FINDINGS = 1500;
const SNAPSHOT_MAX_RAW_BYTES = 3_000_000;

/** Map API response to Finding type */
function toFinding(raw: Record<string, unknown>): Finding {
  return {
    ...raw,
    id: String(raw.id),
    findingType: String(raw.findingType),
    cveId: String(raw.cveId),
    severity: String(raw.severity),
    status: String(raw.status),
    source: raw.source ? String(raw.source) : undefined,
    component: raw.component ? String(raw.component) : undefined,
    image: raw.image ? String(raw.image) : undefined,
    branch: raw.branch ? String(raw.branch) : undefined,
    tag: raw.tag ? String(raw.tag) : undefined,
    sources: Array.isArray(raw.sources)
      ? (raw.sources as Finding["sources"])
      : [],
    audit: Array.isArray(raw.audit) ? (raw.audit as Finding["audit"]) : [],
    regressionOf: Array.isArray(raw.regressionOf)
      ? (raw.regressionOf as string[])
      : undefined,
    regressionCount:
      typeof raw.regressionCount === "number" ? raw.regressionCount : 0,
    attestation: (raw.attestation as Finding["attestation"]) ?? null,
    archived: Boolean(raw.archived),
    slaDue: raw.slaDue ? String(raw.slaDue) : undefined,
    trackerId: raw.trackerId ? String(raw.trackerId) : undefined,
    trackerComment: Boolean(raw.trackerComment),
    team: raw.team ? String(raw.team) : undefined,
    owner: raw.owner ? String(raw.owner) : undefined,
    justification: raw.justification ? String(raw.justification) : undefined,
    previousStatus:
      raw.previousStatus != null ? String(raw.previousStatus) : null,
    sourceIssueGroupId: raw.sourceIssueGroupId
      ? String(raw.sourceIssueGroupId)
      : undefined,
    sourceGroupSeverity: raw.sourceGroupSeverity
      ? String(raw.sourceGroupSeverity)
      : undefined,
    groupKey:
      raw.groupKey != null && String(raw.groupKey).trim()
        ? String(raw.groupKey)
        : undefined,
    correlationKey:
      raw.correlationKey != null ? String(raw.correlationKey) : undefined,
    correlationConfidence:
      raw.correlationConfidence != null
        ? String(raw.correlationConfidence)
        : undefined,
    filePath: raw.filePath ? String(raw.filePath) : undefined,
    line: typeof raw.line === "number" ? raw.line : undefined,
    snippetMasked: raw.snippetMasked ? String(raw.snippetMasked) : undefined,
    externalLinks: Array.isArray(raw.externalLinks)
      ? (raw.externalLinks as Finding["externalLinks"])
      : undefined,
  } as Finding;
}

/** Auto-reopen expired waivers on load (client-side) */
function applyWaiverExpiry(findings: Finding[]): Finding[] {
  return findings.map((finding) => {
    if (finding.status !== "Risk Accepted" || !finding.attestation?.expiresAt) {
      return finding;
    }
    const d = daysLeft(finding.attestation.expiresAt);
    if (d === null || d >= 0) return finding;

    return {
      ...finding,
      status: "Open",
      previousStatus: "Risk Accepted",
      attestation: {
        ...finding.attestation,
        expiredAt: now(),
      },
      audit: [
        ...finding.audit,
        {
          ts: now(),
          user: "system",
          action: "Waiver expired — auto-reopened",
          note: `Waiver ${finding.attestation.waiverRef || ""} expired ${
            finding.attestation.expiresAt
          }`,
        },
      ],
    };
  });
}

function normalizeSettings(
  settingsRes: Awaited<ReturnType<typeof fetchSettings>>,
): {
  sources: Source[];
  tracker: Tracker;
  trackers: Tracker[];
  labels: WatchedLabel[];
} {
  const src = (settingsRes.sources ?? []) as unknown as Source[];
  const trkList = (settingsRes.trackers ?? []) as unknown as Tracker[];
  const trk =
    settingsRes.tracker && Object.keys(settingsRes.tracker).length
      ? (settingsRes.tracker as unknown as Tracker)
      : trkList.length
        ? trkList.find((t) => !t.useAikidoTracking) ?? trkList[0]
        : ({} as unknown as Tracker);
  const lbl = (settingsRes.labels ?? []) as unknown as WatchedLabel[];
  return { sources: src, tracker: trk, trackers: trkList, labels: lbl };
}

function mapSbom(
  sbomRes: Awaited<ReturnType<typeof fetchSbomPackages>>,
): Array<{
  id: string;
  name: string;
  version: string;
  license: string;
  licenseRisk?: string;
  component: string;
  language: string;
}> {
  const apiSbom = Array.isArray(sbomRes) ? sbomRes : [];
  if (apiSbom.length === 0) return SAMPLE_SBOM;
  return apiSbom.map((p) => ({
    id: p.id,
    name: p.name,
    version: p.version,
    license: p.licenseId ?? "",
    licenseRisk: p.licenseRisk,
    component: p.component ?? "",
    language: p.language ?? "",
  }));
}

function loadVatSnapshot(): {
  findings: Finding[];
  assets: Asset[];
  updatedAt: number;
} | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(VAT_SNAPSHOT_KEY);
    if (!raw) return null;
    if (raw.length > SNAPSHOT_MAX_RAW_BYTES) return null;
    const parsed = JSON.parse(raw) as {
      findings?: Finding[];
      assets?: Asset[];
      updatedAt?: number;
    };
    if (!Array.isArray(parsed.findings) || !Array.isArray(parsed.assets))
      return null;
    if (typeof parsed.updatedAt !== "number") return null;
    return {
      findings: parsed.findings,
      assets: parsed.assets,
      updatedAt: parsed.updatedAt,
    };
  } catch {
    return null;
  }
}

function saveVatSnapshot(findings: Finding[], assets: Asset[]) {
  if (typeof window === "undefined") return;
  if (findings.length > SNAPSHOT_MAX_FINDINGS) return;
  try {
    window.localStorage.setItem(
      VAT_SNAPSHOT_KEY,
      JSON.stringify({
        findings,
        assets,
        updatedAt: Date.now(),
      }),
    );
  } catch {
    // Ignore quota/serialization issues; cache is best-effort.
  }
}

export interface UseVATDataReturn {
  findings: Finding[];
  sources: Source[];
  tracker: Tracker;
  trackers: Tracker[];
  labels: WatchedLabel[];
  sbom: Array<{
    id: string;
    name: string;
    version: string;
    license: string;
    licenseRisk?: string;
    component: string;
    language: string;
  }>;
  setSbom: React.Dispatch<React.SetStateAction<typeof SAMPLE_SBOM>>;
  loading: boolean;
  refreshing: boolean;
  error: string | null;
  refetch: (opts?: {
    silent?: boolean;
    includeAuxiliary?: boolean;
  }) => Promise<void>;

  selected: Finding | null;
  setSelected: (f: Finding | null) => void;
  checked: Set<string>;
  view: string;
  setView: (v: string) => void;

  filterFindingStatuses: Set<string>;
  setFilterFindingStatuses: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  filterABC: Set<string>;
  setFilterABC: (v: Set<string> | ((prev: Set<string>) => Set<string>)) => void;
  filterVerifiedRange: [number, number];
  setFilterVerifiedRange: (v: [number, number]) => void;
  filterORARange: [number, number];
  setFilterORARange: (v: [number, number]) => void;
  filterAssetTypes: Set<string>;
  setFilterAssetTypes: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  onlyFavorites: boolean;
  setOnlyFavorites: (v: boolean | ((prev: boolean) => boolean)) => void;
  /** When true, assets with no findings appear in the list. Default false hides them. */
  showEmptyAssets: boolean;
  setShowEmptyAssets: (v: boolean | ((prev: boolean) => boolean)) => void;
  favoriteAssetIds: Set<string>;
  favoriteEntries: FavoriteEntry[];
  toggleFavorite: (
    assetId: string,
    context?: { branch?: string; tag?: string },
  ) => void;
  isFavoriteInContext: (
    assetId: string,
    context?: { branch?: string; tag?: string },
  ) => boolean;
  /** Returns branch/tag from a favorite entry for this asset (for defaulting asset page view). */
  getFavoriteContextForAsset: (
    assetId: string,
  ) => { branch?: string; tag?: string } | null;
  /** Saved asset loadouts — named sets of favorite asset IDs for quick switching */
  loadouts: AssetLoadout[];
  applyLoadout: (
    loadout: AssetLoadout,
    options?: { enableOnlyFavorites?: boolean },
  ) => void;
  saveLoadout: (
    id: string | null,
    name: string,
    entries: FavoriteEntry[],
  ) => void;
  deleteLoadout: (id: string) => void;
  renameLoadout: (id: string, name: string) => void;
  search: string;
  setSearch: (v: string) => void;
  searchFields: Set<string>;
  setSearchFields: (
    v: Set<string> | ((prev: Set<string>) => Set<string>),
  ) => void;
  showArchived: boolean | "both";
  setShowArchived: (
    v: boolean | "both" | ((prev: boolean | "both") => boolean | "both"),
  ) => void;
  needsJustification: boolean;
  setNeedsJustification: (v: boolean | ((prev: boolean) => boolean)) => void;

  handleUpdate: (upd: Finding) => void;
  handleArchive: (id: string, reason: string) => void;
  handleUnarchive: (id: string) => void;
  handleRevert: (id: string, reason: string) => void;
  handleOverrideFingerprint: (id: string) => void;
  handleBulk: (status: string, justification: string) => void;
  onSourcesChange: (sources: Source[]) => void;
  onTrackerChange: (tracker: Tracker) => void;
  onLabelsChange: (labels: WatchedLabel[]) => void;
  toggleCheck: (id: string, val: boolean) => void;
  clearChecked: () => void;
  navigateToFinding: (fId: string) => void;

  alerts: Alert[];
  active: Finding[];
  archivedCount: number;
  reviewQueue: Finding[];
  waivers: Finding[];
  total: number;
  open: number;
  inRev: number;
  overdue: number;
  waiverExpiring: number;
  displayed: Finding[];
  displayedAssets: Asset[];
  /** All assets from displayed findings — for report builder to filter independently */
  allAssets: Asset[];
  /** Assets from ALL findings — for report so counts/widgets are correct regardless of dashboard filters */
  reportAssets: Asset[];
  /** Findings filtered by sidebar (displayedAssets) — report respects sidebar filters */
  reportFilteredFindings: Finding[];
  totalAssets: number;
}

/** Internal hook — use via VATDataContext's useVATData. */
export function useVATDataCore(): UseVATDataReturn {
  const { token, user } = useAuth();
  const queryClient = useQueryClient();
  const userEmail = user?.email ?? undefined;
  const auth = { token: token ?? undefined, userEmail };
  const [snapshot] = useState(() => loadVatSnapshot());
  const [findings, setFindings] = useState<Finding[]>(
    () => snapshot?.findings ?? [],
  );
  const [assetsFromApi, setAssetsFromApi] = useState<Asset[] | null>(
    () => snapshot?.assets ?? null,
  );
  const [sources, setSources] = useState<Source[]>([]);
  const [tracker, setTracker] = useState<Tracker>(DEFAULT_TRACKER);
  const [trackers, setTrackers] = useState<Tracker[]>([]);
  const [labels, setLabels] = useState<WatchedLabel[]>(DEFAULT_LABELS);
  const [sbom, setSbom] = useState(SAMPLE_SBOM);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [view, setView] = useState("findings");
  const [search, setSearch] = useState("");
  const [searchFields, setSearchFields] = useState<Set<string>>(new Set());
  const [showArchived, setShowArchived] = useState<boolean | "both">(false);
  const [needsJustification, setNeedsJustification] = useState(false);

  const [filterFindingStatuses, setFilterFindingStatuses] = useState<
    Set<string>
  >(new Set());
  const [filterABC, setFilterABC] = useState<Set<string>>(new Set());
  const [filterVerifiedRange, setFilterVerifiedRange] = useState<
    [number, number]
  >([0, 100]);
  const [filterORARange, setFilterORARange] = useState<[number, number]>([
    0, 100,
  ]);
  const [filterAssetTypes, setFilterAssetTypes] = useState<Set<string>>(
    new Set(),
  );
  const [onlyFavorites, setOnlyFavorites] = useState(false);
  const [showEmptyAssets, setShowEmptyAssets] = useState(false);
  const [favoriteEntries, setFavoriteEntries] = useState<FavoriteEntry[]>(
    () => {
      if (typeof window === "undefined") return [];
      return loadFavoriteEntries();
    },
  );

  const favoriteAssetIds = useMemo(
    () => new Set(favoriteEntries.map((e) => e.assetId)),
    [favoriteEntries],
  );

  /** Sync favorites from localStorage (e.g. after another tab changes them or on focus) */
  const syncFavoritesFromStorage = useCallback(() => {
    if (typeof window === "undefined") return;
    const entries = loadFavoriteEntries();
    setFavoriteEntries((prev) => {
      if (
        prev.length !== entries.length ||
        entries.some(
          (e, i) =>
            prev[i]?.assetId !== e.assetId ||
            prev[i]?.branch !== e.branch ||
            prev[i]?.tag !== e.tag,
        )
      ) {
        return entries;
      }
      return prev;
    });
  }, []);

  /** Load favorites from localStorage on mount (avoids hydration mismatch; initializer may run on server) */
  useEffect(() => {
    syncFavoritesFromStorage();
  }, [syncFavoritesFromStorage]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const onStorage = (e: StorageEvent) => {
      if (e.key === FAVORITES_KEY) syncFavoritesFromStorage();
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [syncFavoritesFromStorage]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const onFocus = () => syncFavoritesFromStorage();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [syncFavoritesFromStorage]);

  const toggleFavorite = useCallback(
    (assetId: string, context?: { branch?: string; tag?: string }) => {
      setFavoriteEntries((prev) => {
        const hasAny = prev.some((e) => e.assetId === assetId);
        const next = hasAny
          ? prev.filter((e) => e.assetId !== assetId)
          : [...prev, { assetId, branch: context?.branch, tag: context?.tag }];
        saveFavoriteEntries(next);
        return next;
      });
    },
    [],
  );

  const isFavoriteInContext = useCallback(
    (assetId: string, context?: { branch?: string; tag?: string }) => {
      const branch = context?.branch?.trim() || undefined;
      const tag = context?.tag?.trim() || undefined;
      return favoriteEntries.some(
        (e) =>
          e.assetId === assetId &&
          (((e.branch ?? "") === (branch ?? "") &&
            (e.tag ?? "") === (tag ?? "")) ||
            (!e.branch && !e.tag)),
      );
    },
    [favoriteEntries],
  );

  const getFavoriteContextForAsset = useCallback(
    (assetId: string): { branch?: string; tag?: string } | null => {
      const entry = favoriteEntries.find(
        (e) => e.assetId === assetId && (e.branch || e.tag),
      );
      if (!entry) return null;
      return { branch: entry.branch, tag: entry.tag };
    },
    [favoriteEntries],
  );

  const [loadouts, setLoadouts] = useState<AssetLoadout[]>(() => {
    if (typeof window === "undefined") return [];
    return loadAssetLoadouts();
  });

  const syncLoadoutsFromStorage = useCallback(() => {
    if (typeof window === "undefined") return;
    setLoadouts(loadAssetLoadouts());
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const onStorage = (e: StorageEvent) => {
      if (e.key === ASSET_LOADOUTS_KEY) syncLoadoutsFromStorage();
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [syncLoadoutsFromStorage]);

  const applyLoadout = useCallback(
    (loadout: AssetLoadout, options?: { enableOnlyFavorites?: boolean }) => {
      const entries: FavoriteEntry[] = loadout.entries?.length
        ? loadout.entries
        : loadout.assetIds.map((id) => ({ assetId: id }));
      setFavoriteEntries(entries);
      saveFavoriteEntries(entries);
      if (options?.enableOnlyFavorites !== false) {
        setOnlyFavorites(true);
      }
    },
    [],
  );

  const saveLoadout = useCallback(
    (id: string | null, name: string, entries: FavoriteEntry[]) => {
      saveAssetLoadout(id, name, entries);
      setLoadouts(loadAssetLoadouts());
    },
    [],
  );

  const deleteLoadout = useCallback((id: string) => {
    deleteLoadoutStorage(id);
    setLoadouts(loadAssetLoadouts());
  }, []);

  const renameLoadout = useCallback((id: string, name: string) => {
    renameLoadoutStorage(id, name);
    setLoadouts(loadAssetLoadouts());
  }, []);

  const vatQuery = useQuery({
    queryKey: [
      "vat-data",
      token ?? "",
      userEmail ?? "",
      showArchived,
      showEmptyAssets,
    ],
    enabled: Boolean(token || userEmail),
    initialData: snapshot
      ? ({
          findings: snapshot.findings as unknown as VATDataResponse["findings"],
          assets: snapshot.assets as unknown as VATDataResponse["assets"],
        } satisfies VATDataResponse)
      : undefined,
    initialDataUpdatedAt: snapshot?.updatedAt,
    queryFn: async () => {
      const params: Record<string, string | string[] | number | boolean> = {
        full: false,
        page_size: 500,
        include_assets: true,
        include_asset_findings: false,
        include_zero_assets: showEmptyAssets,
        page: 1,
      };
      if (showArchived !== "both") params.archived = showArchived;
      const first = await fetchVATData(params, auth);
      if (!first.meta?.hasMore) return first;

      const allFindings = [...first.findings];
      let page = 2;
      while (page <= 20) {
        const next = await fetchVATData(
          {
            ...params,
            page,
            include_assets: false,
            include_zero_assets: false,
          },
          auth,
        );
        allFindings.push(...next.findings);
        if (!next.meta?.hasMore) break;
        page += 1;
      }

      return {
        ...first,
        findings: allFindings,
      };
    },
    refetchInterval: () =>
      typeof document !== "undefined" && document.visibilityState === "visible"
        ? 45_000
        : false,
    refetchOnReconnect: true,
  });

  const settingsQuery = useQuery({
    queryKey: ["vat-settings", token ?? "", userEmail ?? ""],
    enabled: Boolean(token || userEmail),
    queryFn: async () => fetchSettings(auth),
    staleTime: 60_000,
  });

  const sbomQuery = useQuery({
    queryKey: ["vat-sbom", token ?? "", userEmail ?? ""],
    enabled: Boolean(token || userEmail),
    queryFn: async () => fetchSbomPackages({ limit: 1000 }, auth),
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    if (!vatQuery.data) return;
    const mapped = vatQuery.data.findings.map((r) =>
      toFinding(r as unknown as Record<string, unknown>),
    );
    const withExpiry = applyWaiverExpiry(mapped);
    const findingById = new Map<string, Finding>(
      withExpiry.map((f) => [f.id, f] as const),
    );
    const findingsByAssetId = new Map<string, Finding[]>();
    for (const finding of withExpiry) {
      const aid = assetIdForFinding(finding);
      if (!aid) continue;
      const bucket = findingsByAssetId.get(aid) ?? [];
      bucket.push(finding);
      findingsByAssetId.set(aid, bucket);
    }
    setFindings(withExpiry);
    const apiAssets = (vatQuery.data.assets ?? []).map((a) => {
      const findings =
        Array.isArray(a.findings) && a.findings.length > 0
          ? (a.findings ?? []).map((r) =>
              toFinding(r as unknown as Record<string, unknown>),
            )
          : Array.isArray(a.findingIds) && a.findingIds.length > 0
            ? a.findingIds
                .map((fid) => findingById.get(String(fid)))
                .filter((f): f is Finding => Boolean(f))
            : (findingsByAssetId.get(String(a.id ?? "")) ?? []);
      const id = String(a.id ?? "");
      return {
        ...a,
        id,
        name: getAssetDisplayTitle({
          id,
          name: (a.name as string | undefined) ?? id,
          type: (a as Record<string, unknown>).type as string | undefined,
        }),
        findings,
      } as Asset;
    });

    // IMPORTANT: /vat-data returns assets based on the first findings page when pagination is active.
    // Merge backend asset metadata with frontend-derived assets from ALL loaded findings
    // so summary cards and severity chips reflect the full loaded result set.
    const derivedAssets = deriveAssets(withExpiry, SEV_ORDER);
    const derivedById = new Map<string, Asset>(derivedAssets.map((a) => [a.id, a]));
    const mergedAssets: Asset[] = apiAssets.map((apiAsset) => {
      const derived = derivedById.get(apiAsset.id);
      if (!derived) return apiAsset;
      return {
        ...apiAsset,
        findings: derived.findings,
        openCount: derived.openCount,
        inReviewCount: derived.inReviewCount,
        statusBreakdown: derived.statusBreakdown,
        worstSeverity: derived.worstSeverity,
        overdueCount: derived.overdueCount,
        verifiedPct: derived.verifiedPct,
        oraPct: derived.oraPct,
      };
    });
    const apiIds = new Set(apiAssets.map((a) => a.id));
    for (const derived of derivedAssets) {
      if (apiIds.has(derived.id)) continue;
      mergedAssets.push({
        ...derived,
        name: getAssetDisplayTitle({
          id: derived.id,
          name: derived.name ?? derived.id,
          type: derived.type,
        }),
      });
    }

    setAssetsFromApi(mergedAssets);
    saveVatSnapshot(withExpiry, mergedAssets);
  }, [vatQuery.data]);

  useEffect(() => {
    if (!settingsQuery.data) return;
    const normalized = normalizeSettings(settingsQuery.data);
    setSources(normalized.sources);
    setTracker(normalized.tracker);
    setTrackers(normalized.trackers);
    if (normalized.labels.length) setLabels(normalized.labels);
    saveToStorage({
      sources: settingsQuery.data.sources ?? [],
      tracker: settingsQuery.data.tracker ?? {},
      labels: settingsQuery.data.labels ?? [],
    });
  }, [settingsQuery.data]);

  useEffect(() => {
    if (!settingsQuery.error) return;
    const stored = loadSettingsFromStorage();
    setSources((stored.sources ?? []) as unknown as Source[]);
    const single =
      stored.tracker && Object.keys(stored.tracker).length
        ? ({ ...DEFAULT_TRACKER, ...stored.tracker } as unknown as Tracker)
        : ({} as unknown as Tracker);
    setTracker(single);
    setTrackers(single && single.name ? [single] : []);
    if (stored.labels?.length)
      setLabels(stored.labels as unknown as WatchedLabel[]);
  }, [settingsQuery.error]);

  useEffect(() => {
    if (!sbomQuery.data) return;
    setSbom(mapSbom(sbomQuery.data));
  }, [sbomQuery.data]);

  const refetch = useCallback(
    async (opts?: { silent?: boolean; includeAuxiliary?: boolean }) => {
      await vatQuery.refetch();
      if (opts?.includeAuxiliary) {
        await Promise.all([settingsQuery.refetch(), sbomQuery.refetch()]);
      }
    },
    [vatQuery, settingsQuery, sbomQuery],
  );

  const invalidateVatData = useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: ["vat-data"] });
  }, [queryClient]);

  const handleUpdate = useCallback(
    async (upd: Finding) => {
      try {
        const raw = await updateFinding(
          upd.id,
          {
            status: upd.status,
            justification: upd.justification,
            compensatingControls: upd.compensatingControls,
            reviewerNote: upd.reviewerNote,
            suppressionScope: upd.suppressionScope ?? undefined,
            attestation: upd.attestation ?? undefined,
          },
          auth,
        );
        const mapped = toFinding(raw as unknown as Record<string, unknown>);
        setFindings((prev) =>
          prev.map((f) => (f.id === mapped.id ? mapped : f)),
        );
        setSelected(mapped);
      } catch (err) {
        await invalidateVatData();
        throw err;
      }
    },
    [invalidateVatData, token, user?.email],
  );

  const handleArchive = useCallback(
    async (id: string, reason: string) => {
      try {
        await archiveFinding(id, reason, auth);
        setSelected((prev) => (prev?.id === id ? null : prev));
        await invalidateVatData();
      } catch (err) {
        await invalidateVatData();
        throw err;
      }
    },
    [invalidateVatData, token, user?.email],
  );

  const handleUnarchive = useCallback(
    async (id: string) => {
      try {
        await unarchiveFinding(id, auth);
        await invalidateVatData();
      } catch {
        await invalidateVatData();
      }
    },
    [invalidateVatData, token, user?.email],
  );

  const handleRevert = useCallback(
    async (id: string, reason: string) => {
      try {
        const raw = await revertFinding(id, reason, auth);
        const mapped = toFinding(raw as unknown as Record<string, unknown>);
        setFindings((prev) =>
          prev.map((f) => (f.id === mapped.id ? mapped : f)),
        );
        setSelected(mapped);
      } catch (err) {
        await invalidateVatData();
        throw err;
      }
    },
    [invalidateVatData, token, user?.email],
  );

  const handleOverrideFingerprint = useCallback(
    async (id: string) => {
      try {
        const raw = await overrideFindingFingerprint(id, auth);
        const mapped = toFinding(raw as unknown as Record<string, unknown>);
        setFindings((prev) =>
          prev.map((f) => (f.id === mapped.id ? mapped : f)),
        );
        setSelected(mapped);
      } catch (err) {
        await invalidateVatData();
        throw err;
      }
    },
    [invalidateVatData, token, user?.email],
  );

  const handleBulk = useCallback(
    async (status: string, justification: string) => {
      const ids = Array.from(checked);
      if (ids.length === 0) return;
      try {
        await bulkUpdateFindings(ids, status, justification, auth);
        setChecked(new Set());
        await invalidateVatData();
      } catch (err) {
        await invalidateVatData();
        throw err;
      }
    },
    [checked, invalidateVatData, token, user?.email],
  );

  const onSourcesChange = useCallback(
    async (next: Source[]) => {
      try {
        await putSettingsSources(
          next as unknown as Array<Record<string, unknown>>,
          auth,
        );
        setSources(next);
        saveToStorage({
          sources: next as unknown as Array<Record<string, unknown>>,
        });
        await queryClient.invalidateQueries({ queryKey: ["vat-settings"] });
      } catch {
        saveToStorage({
          sources: next as unknown as Array<Record<string, unknown>>,
        });
        setSources(next);
      }
    },
    [queryClient, token, user?.email],
  );

  const onTrackerChange = useCallback(
    async (next: Tracker) => {
      try {
        await putSettingsTracker(
          next as unknown as Record<string, unknown>,
          auth,
        );
        setTracker(next);
        saveToStorage({ tracker: next as unknown as Record<string, unknown> });
        await queryClient.invalidateQueries({ queryKey: ["vat-settings"] });
      } catch {
        saveToStorage({ tracker: next as unknown as Record<string, unknown> });
        setTracker(next);
      }
    },
    [queryClient, token, user?.email],
  );

  const onLabelsChange = useCallback(
    async (next: WatchedLabel[]) => {
      try {
        await putSettingsLabels(
          next as unknown as Array<Record<string, unknown>>,
          auth,
        );
        setLabels(next);
        saveToStorage({
          labels: next as unknown as Array<Record<string, unknown>>,
        });
        await queryClient.invalidateQueries({ queryKey: ["vat-settings"] });
      } catch {
        saveToStorage({
          labels: next as unknown as Array<Record<string, unknown>>,
        });
        setLabels(next);
      }
    },
    [queryClient, token, user?.email],
  );

  const toggleCheck = useCallback((id: string, val: boolean) => {
    setChecked((prev) => {
      const n = new Set(prev);
      val ? n.add(id) : n.delete(id);
      return n;
    });
  }, []);

  const navigateToFinding = useCallback(
    (fId: string) => {
      const f = findings.find((x) => x.id === fId);
      if (f) {
        setSelected(f);
        setView("findings");
      }
    },
    [findings],
  );

  const alerts = useMemo(() => computeAlerts(findings, daysLeft), [findings]);
  const active = useMemo(() => findings.filter((f) => !f.archived), [findings]);
  const archivedCount = useMemo(
    () => findings.filter((f) => f.archived).length,
    [findings],
  );
  const reviewQueue = useMemo(
    () => active.filter((f) => f.status === "In Review"),
    [active],
  );
  const total = active.length;
  const open = active.filter((f) => f.status === "Open").length;
  const inRev = reviewQueue.length;
  const overdue = active.filter((f) => {
    if (
      [
        "Resolved",
        "False Positive",
        "Duplicate",
        "Not Applicable",
        "Approved",
        "Suppressed",
      ].includes(f.status)
    )
      return false;
    const d = daysLeft(f.slaDue);
    return d !== null && d < 0;
  }).length;
  const waiverExpiring = active.filter((f) => {
    const d = daysLeft(f.attestation?.expiresAt);
    return !!f.attestation && d !== null && d >= 0 && d <= 30;
  }).length;

  const waivers = useMemo(
    () => active.filter((f) => f.status === "Risk Accepted" && f.attestation),
    [active],
  );

  const displayed = useMemo(() => {
    let list = showArchived ? findings : active;
    if (needsJustification) {
      list = list.filter(
        (f) =>
          (f.status === "Open" || f.status === "In Review") &&
          !f.justification?.trim(),
      );
    }
    return [...list].sort(
      (a, b) =>
        SEV_ORDER.indexOf(a.severity as (typeof SEV_ORDER)[number]) -
        SEV_ORDER.indexOf(b.severity as (typeof SEV_ORDER)[number]),
    );
  }, [findings, active, showArchived, needsJustification]);

  const displayedAssets = useMemo(() => {
    const displayedIds = new Set(displayed.map((f) => f.id));
    let assets: Asset[] =
      assetsFromApi != null
        ? assetsFromApi.filter(
            (a) =>
              a.findings.length === 0 ||
              a.findings.some((f) => displayedIds.has(f.id)),
          )
        : deriveAssets(displayed, SEV_ORDER);

    if (onlyFavorites) {
      assets = assets.filter((a) => favoriteAssetIds.has(a.id));
    }

    const FINDING_STATUS_OPTS = [
      "Needs Justification",
      "Justified",
      "Verified",
      "Needs Rework",
      "Needs Reverified",
    ];
    const ABC_OPTS = ["Compliant", "Compliant With Warnings", "Non-compliant"];

    if (filterFindingStatuses.size > 0) {
      const hasStatus = (asset: Asset, status: string): boolean => {
        for (const f of asset.findings) {
          if (status === "Needs Justification") {
            if (f.status === "Open") return true;
            if (f.status === "In Review" && !f.justification?.trim())
              return true;
          } else if (status === "Justified") {
            if (f.status === "In Review" && f.justification?.trim())
              return true;
          } else if (status === "Verified") {
            if (
              [
                "Resolved",
                "False Positive",
                "Approved",
                "Suppressed",
                "Not Applicable",
                "Duplicate",
              ].includes(f.status)
            )
              return true;
          } else if (status === "Needs Rework" && f.status === "Rejected")
            return true;
          else if (status === "Needs Reverified" && f.status === "Reopened")
            return true;
        }
        return false;
      };
      assets = assets.filter((a) =>
        FINDING_STATUS_OPTS.some(
          (s) => filterFindingStatuses.has(s) && hasStatus(a, s),
        ),
      );
    }

    if (filterABC.size > 0) {
      const matchesABC = (asset: Asset, abc: string): boolean => {
        if (abc === "Compliant") return asset.verifiedPct === 100;
        if (abc === "Compliant With Warnings")
          return asset.verifiedPct > 0 && asset.verifiedPct < 100;
        if (abc === "Non-compliant") return asset.verifiedPct === 0;
        return false;
      };
      assets = assets.filter((a) =>
        ABC_OPTS.some((abc) => filterABC.has(abc) && matchesABC(a, abc)),
      );
    }

    assets = assets.filter(
      (a) =>
        a.verifiedPct >= filterVerifiedRange[0] &&
        a.verifiedPct <= filterVerifiedRange[1],
    );
    assets = assets.filter(
      (a) => a.oraPct >= filterORARange[0] && a.oraPct <= filterORARange[1],
    );

    if (filterAssetTypes.size > 0) {
      assets = assets.filter((a) =>
        filterAssetTypes.has(getAssetTypeFromAsset(a)),
      );
    }

    if (search.trim()) {
      const q = search.toLowerCase().trim();
      assets = assets.filter(
        (a) =>
          (a.name ?? "").toLowerCase().includes(q) ||
          (a.id ?? "").toLowerCase().includes(q),
      );
    }

    if (!showEmptyAssets) {
      assets = assets.filter((a) => a.findings.length > 0);
    }

    return assets;
  }, [
    assetsFromApi,
    displayed,
    onlyFavorites,
    favoriteAssetIds,
    filterFindingStatuses,
    filterABC,
    filterVerifiedRange,
    filterORARange,
    filterAssetTypes,
    search,
    showEmptyAssets,
  ]);

  const allAssets = useMemo(() => {
    if (assetsFromApi != null) {
      const displayedIds = new Set(displayed.map((f) => f.id));
      return assetsFromApi.filter(
        (a) =>
          a.findings.length === 0 ||
          a.findings.some((f) => displayedIds.has(f.id)),
      );
    }
    return deriveAssets(displayed, SEV_ORDER);
  }, [assetsFromApi, displayed]);

  /** Assets derived from ALL findings — for report so counts/widgets are correct regardless of dashboard filters. */
  const reportAssets = useMemo(() => {
    if (assetsFromApi != null) return assetsFromApi;
    return deriveAssets(findings, SEV_ORDER);
  }, [assetsFromApi, findings]);

  /** Findings that belong to displayedAssets — report respects sidebar filters (status, ABC, verified, ORA, asset type, favorites). */
  const reportFilteredFindings = useMemo(() => {
    const aidSet = new Set(displayedAssets.map((a) => a.id));
    return findings.filter((f) => {
      const aid = assetIdForFinding(f);
      return aid != null && aidSet.has(aid);
    });
  }, [findings, displayedAssets]);

  const totalAssets = useMemo(() => {
    if (assetsFromApi != null) return assetsFromApi.length;
    return deriveAssets(active, SEV_ORDER).length;
  }, [assetsFromApi, active]);

  const loading = vatQuery.isLoading && findings.length === 0;
  const refreshing = vatQuery.isFetching;
  const error = vatQuery.error instanceof Error ? vatQuery.error.message : null;

  return {
    findings,
    sources,
    tracker,
    trackers,
    labels,
    sbom,
    setSbom,
    loading,
    refreshing,
    error,
    refetch,
    selected,
    setSelected,
    checked,
    view,
    setView,
    filterFindingStatuses,
    setFilterFindingStatuses,
    filterABC,
    setFilterABC,
    filterVerifiedRange,
    setFilterVerifiedRange,
    filterORARange,
    setFilterORARange,
    filterAssetTypes,
    setFilterAssetTypes,
    onlyFavorites,
    setOnlyFavorites,
    showEmptyAssets,
    setShowEmptyAssets,
    favoriteAssetIds,
    favoriteEntries,
    toggleFavorite,
    isFavoriteInContext,
    getFavoriteContextForAsset,
    loadouts,
    applyLoadout,
    saveLoadout,
    deleteLoadout,
    renameLoadout,
    search,
    setSearch,
    searchFields,
    setSearchFields,
    showArchived,
    setShowArchived,
    needsJustification,
    setNeedsJustification,
    handleUpdate,
    handleArchive,
    handleUnarchive,
    handleRevert,
    handleOverrideFingerprint,
    handleBulk,
    onSourcesChange,
    onTrackerChange,
    onLabelsChange,
    toggleCheck,
    clearChecked: () => setChecked(new Set()),
    navigateToFinding,
    alerts,
    active,
    archivedCount,
    reviewQueue,
    waivers,
    total,
    open,
    inRev,
    overdue,
    waiverExpiring,
    displayed,
    displayedAssets,
    allAssets,
    reportAssets,
    reportFilteredFindings,
    totalAssets,
  };
}
