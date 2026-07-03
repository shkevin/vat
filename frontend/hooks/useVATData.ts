"use client";

import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { usePathname } from "next/navigation";
import {
  keepPreviousData,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useDashboardFilters } from "@/hooks/useDashboardFilters";
import { now, daysLeft, computeAlerts } from "@/lib/utils";
import {
  archiveFinding,
  bulkUpdateFindings,
  createLoadout as apiCreateLoadout,
  deleteLoadout as apiDeleteLoadout,
  fetchSettings,
  fetchSbomPackages,
  fetchLedgerWaivers,
  fetchVATData,
  type LedgerWaiver,
  type VATDataResponse,
  type LoadoutDTO,
  listLoadouts as apiListLoadouts,
  overrideFindingFingerprint,
  putSettingsLabels,
  putSettingsSources,
  putSettingsTracker,
  revertFinding,
  unarchiveFinding,
  updateFinding,
  updateLoadout as apiUpdateLoadout,
} from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { loadSettingsFromStorage, saveToStorage } from "@/lib/settingsStorage";
import {
  loadoutBootstrapKey,
  shouldRunLoadoutBootstrap,
} from "@/lib/loadoutBootstrapGate";
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
  isOpenRisk,
  isOverdueOpenRisk,
  isRiskAccepted,
  isVerifiedDisposition,
} from "@/lib/metricSemantics";
// Dashboard filters have a single persistence store (vat-dashboard-filters),
// written by useDashboardFilters. useVATData reads it once for a correct first
// paint; there is no second sidebar store.
import { loadDashboardFiltersFromStorage } from "@/lib/dashboardFilterStorage";
import {
  FAVORITES_KEY,
  loadFavoriteEntries,
  saveFavoriteEntries,
  type FavoriteEntry,
} from "@/lib/userSettings";
import {
  ASSET_LOADOUTS_KEY,
  loadAssetLoadouts,
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

// v1 = full-finding snapshot (capped 1500). v2 = slim projection — drops the
// heavy free-form fields (audit history, prose like description/justification,
// attestation, external link list) that aren't needed for first-paint and
// would otherwise bust localStorage at fleet scale. Bumped to v2 so old
// oversized v1 entries (silently rejected by previous size cap) don't leak in.
// v3 invalidates bundle snapshots that may contain stale per-image digests
// restored before the cleaned API payload arrives.
const VAT_SNAPSHOT_KEY = "vat:lastFindingsSnapshot:v3";

// The snapshot is a best-effort first-paint cache in localStorage (sync read, so
// it must fit the ~5MB per-origin quota). After the v2 slim projection + storing
// each finding once (dehydrated assets), a slim finding is ~1.6KB, so the 6MB cap
// covers deployments up to ~3.5k findings. Larger deployments exceed the cap and
// fall back to the "Loading VAT" splash on refresh — correct, since a synchronous
// store can't hold tens of MB. (Async stores like IndexedDB don't help: they
// can't be read before the first paint anyway.)
const SNAPSHOT_MAX_FINDINGS = 50_000;
const SNAPSHOT_MAX_RAW_BYTES = 6_000_000;

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
    if (!isRiskAccepted(finding.status) || !finding.attestation?.expiresAt) {
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

/**
 * Snapshot persists each finding ONCE (top-level `findings`); assets carry only
 * finding IDs and are rehydrated on load. Previously every finding was stored
 * twice — slim in `findings` and full nested in `assets[].findings` — which
 * ~doubled the payload and pushed mid-size deployments over the size cap.
 */
type SnapshotAsset = Omit<Asset, "findings"> & { findingIds: string[] };

export function dehydrateSnapshotAssets(assets: Asset[]): SnapshotAsset[] {
  return assets.map(({ findings, ...rest }) => ({
    ...rest,
    findingIds: findings.map((f) => f.id),
  }));
}

export function rehydrateSnapshotAssets(
  assets: Array<SnapshotAsset | Asset>,
  findings: Finding[],
): Asset[] {
  const byId = new Map(findings.map((f) => [f.id, f] as const));
  return assets.map((a) => {
    // Back-compat: older snapshots stored full nested findings — keep as-is.
    const nested = (a as Asset).findings;
    if (Array.isArray(nested) && nested.length > 0) return a as Asset;
    const { findingIds = [], ...rest } = a as SnapshotAsset;
    return {
      ...(rest as Omit<Asset, "findings">),
      findings: findingIds
        .map((id) => byId.get(String(id)))
        .filter((f): f is Finding => Boolean(f)),
    };
  });
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
      assets?: Array<SnapshotAsset | Asset>;
      updatedAt?: number;
    };
    if (!Array.isArray(parsed.findings) || !Array.isArray(parsed.assets))
      return null;
    if (typeof parsed.updatedAt !== "number") return null;
    return {
      findings: parsed.findings,
      assets: rehydrateSnapshotAssets(parsed.assets, parsed.findings),
      updatedAt: parsed.updatedAt,
    };
  } catch {
    return null;
  }
}

/**
 * Slim a Finding for snapshot persistence: keep every field the report engine,
 * filter bar, and finding cards read on first paint; drop the heavy free-form
 * payload (audit history, prose, attestation, external links). At fleet scale
 * this is the difference between "snapshot fits in localStorage and the next
 * refresh skips the full-page splash" and "snapshot silently fails to save".
 *
 * Once the React Query refetch completes (within seconds), the full Finding
 * objects replace the slim snapshot in memory — slim is first-paint only.
 */
function slimFindingForSnapshot(f: Finding): Finding {
  return {
    ...f,
    // Drop arrays/objects that can be large per finding.
    audit: [],
    externalLinks: undefined,
    regressionOf: undefined,
    attestation: null,
    // Drop free-form prose. Kept fields (title, cveId, etc.) are sufficient
    // for the issue list and report widgets.
    description: undefined,
    justification: undefined,
    compensatingControls: undefined,
    reviewerNote: undefined,
    snippetMasked: null,
    archivedReason: null,
    // Sources array carries match-detail metadata we don't need at first paint;
    // keep names only so feed-match detection (atoms.tsx, feedProvenance) keeps
    // working off the slim snapshot.
    sources: f.sources?.map((s) => ({ name: s.name, importedAt: s.importedAt })) ?? [],
  };
}

function saveVatSnapshot(findings: Finding[], assets: Asset[]) {
  if (typeof window === "undefined") return;
  if (findings.length > SNAPSHOT_MAX_FINDINGS) return;
  try {
    const slim = findings.map(slimFindingForSnapshot);
    const payload = JSON.stringify({
      findings: slim,
      assets: dehydrateSnapshotAssets(assets),
      updatedAt: Date.now(),
    });
    if (payload.length > SNAPSHOT_MAX_RAW_BYTES) return;
    window.localStorage.setItem(VAT_SNAPSHOT_KEY, payload);
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
  /** The single dashboard-filter URL state + writer (nuqs). Owned here so there
   * is one instance app-wide; MainAppShell/VAT read it from context. */
  dashboardState: ReturnType<typeof useDashboardFilters>[0];
  setDashboardState: ReturnType<typeof useDashboardFilters>[1];
}

function ledgerWaiverToFinding(w: LedgerWaiver): Finding {
  return {
    id: w.findingId ?? w.decisionId,
    findingType: w.findingType as Finding["findingType"],
    fingerprintId: w.subjectKey,
    cveId: w.cveId,
    severity: (w.severity ?? "Medium") as Finding["severity"],
    status: "Risk Accepted",
    title: w.title ?? undefined,
    component: w.component ?? undefined,
    image: w.image ?? undefined,
    ruleId: w.ruleId ?? undefined,
    controlRef: w.controlRef ?? undefined,
    attestation: (w.attestation ?? undefined) as Finding["attestation"],
    justification: w.justification ?? undefined,
    sources: [],
    audit: [],
  };
}

/** Internal hook — use via VATDataContext's useVATData. */
export function useVATDataCore(): UseVATDataReturn {
  const { token, user } = useAuth();
  const queryClient = useQueryClient();
  const userEmail = user?.email ?? undefined;
  const auth = useMemo(
    () => ({ token: token ?? undefined, userEmail }),
    [token, userEmail],
  );
  // queryKey scope: stable per-user id, NOT the bearer JWT. Token rotation
  // shouldn't thrash the cache, and DevTools / persistence shouldn't leak
  // the bearer.
  const userScope = user?.id ?? "anon";
  // The single app-wide dashboard-filter instance (nuqs URL + one persistence
  // store). MainAppShell/VAT consume it from context instead of calling the hook
  // themselves, so there is exactly one restore/persist/URL owner.
  const pathname = usePathname();
  const isAssetPage = Boolean(pathname?.startsWith("/assets/"));
  const [dashboardState, setDashboardState] = useDashboardFilters();
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
  // Dashboard filter state hydrates once from the single persistence store
  // (vat-dashboard-filters) so the first paint is correct. The URL (nuqs, via
  // the single useDashboardFilters instance above) is the source of truth
  // thereafter; the one sync effect below keeps this working copy in step, and
  // useDashboardFilters owns the single write-back to storage.
  const [_filterInit] = useState(() => loadDashboardFiltersFromStorage() ?? {});
  // ponytail: search is ephemeral (resets on refresh) — never restored or in the URL.
  const [search, setSearch] = useState("");
  // searchFields (search scope) is ephemeral too — not persisted, resets on refresh.
  const [searchFields, setSearchFields] = useState<Set<string>>(
    () => new Set(),
  );
  const [showArchived, setShowArchived] = useState<boolean | "both">(
    () => _filterInit.archived ?? false,
  );
  const [needsJustification, setNeedsJustification] = useState(
    () => _filterInit.needsJustification ?? false,
  );

  const [filterFindingStatuses, setFilterFindingStatuses] = useState<
    Set<string>
  >(() => new Set(_filterInit.status ?? []));
  const [filterABC, setFilterABC] = useState<Set<string>>(
    () => new Set(_filterInit.abc ?? []),
  );
  const [filterVerifiedRange, setFilterVerifiedRange] = useState<
    [number, number]
  >(() => [_filterInit.verifiedMin ?? 0, _filterInit.verifiedMax ?? 100]);
  const [filterORARange, setFilterORARange] = useState<[number, number]>(
    () => [_filterInit.oraMin ?? 0, _filterInit.oraMax ?? 100],
  );
  const [filterAssetTypes, setFilterAssetTypes] = useState<Set<string>>(
    () => new Set(_filterInit.assetTypes ?? []),
  );
  const [onlyFavorites, setOnlyFavorites] = useState(
    () => _filterInit.favorites ?? false,
  );
  const [showEmptyAssets, setShowEmptyAssets] = useState(
    () => _filterInit.showEmptyAssets ?? false,
  );
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

  // Persistence of dashboard filters is owned solely by useDashboardFilters
  // (single writer to vat-dashboard-filters). This working copy is kept in sync
  // from the URL by the one sync effect below, so no separate persist/cross-tab
  // wiring lives here anymore.

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

  // Loadouts are server-persisted (path B). The localStorage helpers stay
  // around as a one-shot migration source — on first authenticated load,
  // any pre-existing localStorage loadouts are pushed to the backend and
  // then the localStorage entry is cleared.
  const [loadouts, setLoadouts] = useState<AssetLoadout[]>([]);
  const loadoutBootstrapKeyRef = useRef<string | null>(null);

  const dtoToLoadout = useCallback((l: LoadoutDTO): AssetLoadout => ({
    id: l.id,
    name: l.name,
    assetIds: l.asset_ids ?? [],
    entries: (l.entries ?? undefined) as FavoriteEntry[] | undefined,
    savedAt: l.updated_at ?? l.created_at ?? new Date().toISOString(),
  }), []);

  const refreshLoadouts = useCallback(async () => {
    if (typeof window === "undefined") return;
    if (!token && !userEmail) return;
    try {
      const list = await apiListLoadouts(auth);
      setLoadouts(list.map(dtoToLoadout));
    } catch {
      // network blip — keep current state
    }
  }, [auth, dtoToLoadout, token, userEmail]);

  // One-shot localStorage → backend migration. Runs once per session when
  // the user is authenticated and the backend has no loadouts yet for them.
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (!token && !userEmail) return;
    const nextBootstrapKey = loadoutBootstrapKey(token, userEmail);
    if (
      !shouldRunLoadoutBootstrap(
        loadoutBootstrapKeyRef.current,
        nextBootstrapKey,
      )
    ) {
      return;
    }
    loadoutBootstrapKeyRef.current = nextBootstrapKey;
    let cancelled = false;
    (async () => {
      try {
        const remote = await apiListLoadouts(auth);
        if (cancelled) return;
        let migrated = false;
        if (remote.length === 0) {
          const local = loadAssetLoadouts();
          if (local.length > 0) {
            for (const l of local) {
              try {
                await apiCreateLoadout(
                  {
                    name: l.name,
                    asset_ids: l.assetIds,
                    entries: l.entries?.map((e) => ({
                      assetId: e.assetId,
                      branch: e.branch ?? undefined,
                      tag: e.tag ?? undefined,
                    })),
                    shared_with_team: false,
                  },
                  auth,
                );
                migrated = true;
              } catch {
                // skip individual migration failures; user can retry
              }
            }
            try {
              window.localStorage.removeItem(ASSET_LOADOUTS_KEY);
            } catch {
              // localStorage may be sandboxed
            }
          }
        }
        if (cancelled) return;
        if (migrated) {
          await refreshLoadouts();
        } else {
          setLoadouts(remote.map(dtoToLoadout));
        }
      } catch {
        loadoutBootstrapKeyRef.current = null;
        // initial fetch failed; will retry on next refresh
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [auth, dtoToLoadout, refreshLoadouts, token, userEmail]);

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
    async (id: string | null, name: string, entries: FavoriteEntry[]) => {
      const asset_ids = entries.map((e) => e.assetId);
      const apiEntries = entries.map((e) => ({
        assetId: e.assetId,
        branch: e.branch ?? undefined,
        tag: e.tag ?? undefined,
      }));
      try {
        if (id) {
          await apiUpdateLoadout(
            id,
            { name, asset_ids, entries: apiEntries },
            auth,
          );
        } else {
          await apiCreateLoadout(
            { name, asset_ids, entries: apiEntries, shared_with_team: false },
            auth,
          );
        }
        await refreshLoadouts();
      } catch (e) {
        // Surface the failure but don't crash — bubble through; caller may toast.
        // eslint-disable-next-line no-console
        console.warn("saveLoadout failed:", e);
      }
    },
    [auth, refreshLoadouts],
  );

  const deleteLoadout = useCallback(
    async (id: string) => {
      try {
        const target = loadouts.find((l) => l.id === id);
        await apiDeleteLoadout(id, auth);
        // Optimistic local-state update so the UI reflects the change immediately.
        setLoadouts((prev) => prev.filter((l) => l.id !== id));
        // If the deleted loadout is currently applied, clear hearts and disable
        // favorites-only mode so the view resets to the full asset set.
        if (target) {
          const normalizedCurrent = favoriteEntries.map((e) => ({
            assetId: e.assetId,
            branch: e.branch ?? "",
            tag: e.tag ?? "",
          }));
          const targetEntries: FavoriteEntry[] = target.entries?.length
            ? target.entries
            : target.assetIds.map((assetId) => ({
                assetId,
                branch: undefined,
                tag: undefined,
              }));
          const normalizedTarget = targetEntries.map((e) => ({
            assetId: e.assetId,
            branch: e.branch ?? "",
            tag: e.tag ?? "",
          }));
          const sortKey = (e: { assetId: string; branch: string; tag: string }) =>
            `${e.assetId}|${e.branch}|${e.tag}`;
          const currentSig = normalizedCurrent
            .slice()
            .sort((a, b) => sortKey(a).localeCompare(sortKey(b)))
            .map(sortKey)
            .join(";");
          const targetSig = normalizedTarget
            .slice()
            .sort((a, b) => sortKey(a).localeCompare(sortKey(b)))
            .map(sortKey)
            .join(";");
          if (currentSig === targetSig) {
            setFavoriteEntries([]);
            saveFavoriteEntries([]);
            setOnlyFavorites(false);
          }
        }
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn("deleteLoadout failed:", e);
      }
    },
    [auth, loadouts, favoriteEntries],
  );

  const renameLoadout = useCallback(
    async (id: string, name: string) => {
      try {
        await apiUpdateLoadout(id, { name }, auth);
        await refreshLoadouts();
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn("renameLoadout failed:", e);
      }
    },
    [auth, refreshLoadouts],
  );

  // showEmptyAssets is deliberately NOT in the key: empty assets are always
  // fetched (they cost ~nothing — findings dominate the payload) and the toggle
  // is a pure client-side filter in displayedAssets. Keeping it out avoids a
  // full refetch (and the keepPreviousData "loads some, then the rest" stagger)
  // every time the toggle flips.
  const vatQueryKey = ["vat-data", userScope, showArchived] as const;
  const vatQuery = useQuery({
    queryKey: vatQueryKey,
    enabled: Boolean(token || userEmail),
    initialData: snapshot
      ? ({
          findings: snapshot.findings as unknown as VATDataResponse["findings"],
          assets: snapshot.assets as unknown as VATDataResponse["assets"],
        } satisfies VATDataResponse)
      : undefined,
    initialDataUpdatedAt: snapshot?.updatedAt,
    // Keep previously-rendered data visible during in-session refetches so
    // toggle/filter changes don't blank to "Loading VAT" while waiting on the
    // next payload. Combined with the localStorage snapshot, the splash only
    // appears on a genuinely cold first load.
    placeholderData: keepPreviousData,
    queryFn: async () => {
      // Single full=true fetch. The two-phase fast-first-paint experiment
      // (c2a624b → 853f99e) was reverted: Phase 1's partial findings + asset
      // sample broke widgets (severity badges, report widgets) for the
      // ~3-4s window before Phase 2 settled. Accept the ~3.4s wait per
      // refresh in exchange for correct stats from the first paint.
      //
      // No 10k cap here — full=true streams all findings on a single DB
      // pass, so the silent tail-truncation bug 84570c9 fixed stays fixed.
      const params: Record<string, string | string[] | number | boolean> = {
        full: true,
        limit: 0,
        include_assets: true,
        include_asset_findings: false,
        include_zero_assets: true,
      };
      if (showArchived !== "both") params.archived = showArchived;
      return fetchVATData(params, auth);
    },
    refetchInterval: () =>
      typeof document !== "undefined" && document.visibilityState === "visible"
        ? 45_000
        : false,
    refetchOnReconnect: true,
  });

  const settingsQuery = useQuery({
    queryKey: ["vat-settings", userScope],
    enabled: Boolean(token || userEmail),
    queryFn: async () => fetchSettings(auth),
    staleTime: 60_000,
  });

  const sbomQuery = useQuery({
    queryKey: ["vat-sbom", userScope],
    enabled: Boolean(token || userEmail),
    queryFn: async () => fetchSbomPackages({ limit: 1000 }, auth),
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
  });

  const waiversQuery = useQuery({
    queryKey: ["vat-waivers", userScope],
    enabled: Boolean(token || userEmail),
    queryFn: async () => fetchLedgerWaivers(undefined, auth),
    staleTime: 30_000,
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

    // Merge finding-derived metrics into persisted assets only. Derived-only
    // asset groups are intentionally not appended; deleting an asset row should
    // hide the asset card without deleting the underlying finding evidence.
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
        await Promise.all([
          settingsQuery.refetch(),
          sbomQuery.refetch(),
          waiversQuery.refetch(),
        ]);
      }
    },
    [vatQuery, settingsQuery, sbomQuery, waiversQuery],
  );

  const invalidateVatData = useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: ["vat-data"] });
    await queryClient.invalidateQueries({ queryKey: ["vat-waivers"] });
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
  const open = active.filter((f) => isOpenRisk(f.status)).length;
  const inRev = reviewQueue.length;
  const overdue = active.filter((f) =>
    isOverdueOpenRisk(f.status, f.slaDue),
  ).length;
  const waivers = useMemo(() => {
    if (waiversQuery.data && waiversQuery.data.length > 0) {
      return applyWaiverExpiry(waiversQuery.data.map(ledgerWaiverToFinding));
    }
    return active.filter((f) => isRiskAccepted(f.status) && f.attestation);
  }, [waiversQuery.data, active]);

  const waiverExpiring = useMemo(
    () =>
      waivers.filter((f) => {
        const d = daysLeft(f.attestation?.expiresAt);
        return !!f.attestation && d !== null && d >= 0 && d <= 30;
      }).length,
    [waivers],
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
            if (isVerifiedDisposition(f.status)) return true;
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

  // The ONE place that mirrors the URL (nuqs) into this working copy. Reads
  // current values via a ref so the effect only depends on the URL state +
  // loading (not on the values it writes). Search is never synced — it's
  // ephemeral and never in the URL.
  const filterSyncRef = useRef({
    view,
    filterFindingStatuses,
    filterABC,
    filterVerifiedRange,
    filterORARange,
    filterAssetTypes,
    showArchived,
    onlyFavorites,
    showEmptyAssets,
    needsJustification,
  });
  filterSyncRef.current = {
    view,
    filterFindingStatuses,
    filterABC,
    filterVerifiedRange,
    filterORARange,
    filterAssetTypes,
    showArchived,
    onlyFavorites,
    showEmptyAssets,
    needsJustification,
  };
  const lastUrlStateRef = useRef<string>("");
  const prevLoadingRef = useRef(loading);
  useEffect(() => {
    if (isAssetPage) return;
    // When loading finishes, force re-apply so URL state wins over initial defaults.
    if (prevLoadingRef.current && !loading) lastUrlStateRef.current = "";
    prevLoadingRef.current = loading;

    const s = dashboardState;
    const urlKey = JSON.stringify({
      tab: s.tab,
      status: s.status ?? [],
      abc: s.abc ?? [],
      verifiedMin: s.verifiedMin,
      verifiedMax: s.verifiedMax,
      oraMin: s.oraMin,
      oraMax: s.oraMax,
      assetTypes: s.assetTypes ?? [],
      archived: s.archived,
      favorites: s.favorites,
      showEmptyAssets: s.showEmptyAssets,
      needsJustification: s.needsJustification,
    });
    if (lastUrlStateRef.current === urlKey) return;
    lastUrlStateRef.current = urlKey;

    const d = filterSyncRef.current;
    if (s.tab !== d.view) setView(s.tab);
    const statusSet = new Set(s.status ?? []);
    if (
      statusSet.size !== d.filterFindingStatuses.size ||
      [...statusSet].some((x) => !d.filterFindingStatuses.has(x))
    ) {
      setFilterFindingStatuses(statusSet);
    }
    const abcSet = new Set(s.abc ?? []);
    if (
      abcSet.size !== d.filterABC.size ||
      [...abcSet].some((x) => !d.filterABC.has(x))
    ) {
      setFilterABC(abcSet);
    }
    const vr: [number, number] = [s.verifiedMin ?? 0, s.verifiedMax ?? 100];
    if (vr[0] !== d.filterVerifiedRange[0] || vr[1] !== d.filterVerifiedRange[1]) {
      setFilterVerifiedRange(vr);
    }
    const or: [number, number] = [s.oraMin ?? 0, s.oraMax ?? 100];
    if (or[0] !== d.filterORARange[0] || or[1] !== d.filterORARange[1]) {
      setFilterORARange(or);
    }
    const atSet = new Set(s.assetTypes ?? []);
    if (
      atSet.size !== d.filterAssetTypes.size ||
      [...atSet].some((x) => !d.filterAssetTypes.has(x))
    ) {
      setFilterAssetTypes(atSet);
    }
    if (s.archived !== d.showArchived) setShowArchived(s.archived);
    if (s.favorites !== d.onlyFavorites) setOnlyFavorites(s.favorites);
    if (s.showEmptyAssets !== d.showEmptyAssets)
      setShowEmptyAssets(s.showEmptyAssets);
    if (s.needsJustification !== d.needsJustification)
      setNeedsJustification(s.needsJustification);
  }, [isAssetPage, dashboardState, loading]);

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
    dashboardState,
    setDashboardState,
  };
}
