"use client";

import type { VATDashboardData, VATReportIssue } from "./vatReportAdapter";
import {
  computeReportRiskScore,
  getReportRiskLevel,
  computeMTTR,
  computeABCComplianceForIssues,
  computeAgingBuckets,
  computeRepoRiskScores,
  computeContainerRiskScores,
  computeAssetMix,
  computeReachabilityMatrix,
  getTopVulnerabilities,
  computeAvgMttr,
  computeScannerBreakdown,
  computeTrendData,
  computeTrendMetrics,
  computePeriodOverPeriodChange,
  countTotalIssues,
  isOpen,
  getIssuesForRepos,
  getIssuesForAssets,
  resolveOpenCounts,
  issueMatchesContainer,
  getEffectiveContainers,
  getAssetTypeForIssue,
  type SeverityCounts,
  type RepoRiskScore,
  type ContainerRiskScore,
  type AssetMix,
  type MTTRData,
  type AgingBucket,
  type TopVulnerability,
  type ScannerBreakdown,
  type TrendDataPoint,
} from "./metrics";
import type {
  ReportDefinition,
  ReportFilters,
  ReportContext,
  CanvasDefinition,
  WidgetDefinition,
  WidgetType,
} from "./report-types";
import {
  widgetLayoutForSingleColumn,
  widgetLayoutFullWidth,
  inferColumnsFromWidgets,
} from "./report-types";
import { renderWidget } from "./report-widgets";
import {
  getReportFilterConfig,
  buildReportFilterBarStructure,
} from "./report-filter";
import { getReportBrandingOverride } from "@/config/report";

/** Preview-mode caps for widget display. Keeps preview performant; full report shows all data. */
const PREVIEW_LIMITS: Partial<Record<WidgetType, Record<string, number>>> = {
  issueList: { limit: 50 },
};

/** Merge widget config with preview caps when in preview mode. */
function applyPreviewLimits(
  type: WidgetType,
  config: Record<string, unknown>,
  preview: boolean,
): Record<string, unknown> {
  if (!preview) return config;
  const caps = PREVIEW_LIMITS[type];
  if (!caps) return config;
  return { ...config, ...caps };
}

// ---------------------------------------------------------------------------
// Report themes (branding + color schemes)
// ---------------------------------------------------------------------------

export interface ReportBranding {
  companyName: string;
  tagline: string;
  websiteUrl: string;
  logoUrl: string;
  primaryColor: string;
  headerBgColor: string;
  headerTextColor: string;
  /** Optional: full document palette. When set, theme applies to body, cards, tables, etc. */
  bodyBg?: string;
  bodyFg?: string;
  borderColor?: string;
  mutedColor?: string;
  cardBg?: string;
  tableHeaderBg?: string;
  tableRowAltBg?: string;
  /** Optional: link color. Use when primaryColor is too dark on the background (e.g. dark themes). */
  linkColor?: string;
}

export interface ReportTheme {
  id: string;
  name: string;
  branding: ReportBranding;
}

/** Default theme - dark, emerald accent. Branding overridable via NEXT_PUBLIC_REPORT_* env vars. */
export const THEME_DEFAULT: ReportTheme = {
  id: "default",
  name: "Default",
  branding: {
    companyName: "",
    tagline: "",
    websiteUrl: "",
    logoUrl: "",
    primaryColor: "#10b981",
    headerBgColor: "#000000",
    headerTextColor: "#ffffff",
    bodyBg: "#0a0a0a",
    bodyFg: "#f8fafc",
    borderColor: "#334155",
    mutedColor: "#94a3b8",
    cardBg: "#171717",
    tableHeaderBg: "#1e1e1e",
    tableRowAltBg: "#262626",
    linkColor: "#34d399",
  },
};

/** Light - clean, neutral light theme */
export const THEME_LIGHT: ReportTheme = {
  id: "light",
  name: "Light",
  branding: {
    companyName: "",
    tagline: "",
    websiteUrl: "",
    logoUrl: "",
    primaryColor: "#64748b",
    headerBgColor: "#ffffff",
    headerTextColor: "#0f172a",
    bodyBg: "#f1f5f9",
    bodyFg: "#0f172a",
    borderColor: "#cbd5e1",
    mutedColor: "#64748b",
    cardBg: "#ffffff",
    tableHeaderBg: "#f8fafc",
    tableRowAltBg: "#f1f5f9",
    linkColor: "#0284c7",
  },
};

/** Slate - dark slate with clear hierarchy */
export const THEME_SLATE: ReportTheme = {
  id: "slate",
  name: "Slate",
  branding: {
    companyName: "Security Report",
    tagline: "Vulnerability Management",
    websiteUrl: "",
    logoUrl: "",
    primaryColor: "#475569",
    headerBgColor: "#1a2332",
    headerTextColor: "#f1f5f9",
    bodyBg: "#0f172a",
    bodyFg: "#f1f5f9",
    borderColor: "#334155",
    mutedColor: "#94a3b8",
    cardBg: "#1e293b",
    tableHeaderBg: "#252d3d",
    tableRowAltBg: "#1a2332",
    linkColor: "#38bdf8",
  },
};

/** Dracula - navy-purple, bright accents */
export const THEME_DRACULA: ReportTheme = {
  id: "dracula",
  name: "Dracula",
  branding: {
    companyName: "",
    tagline: "",
    websiteUrl: "",
    logoUrl: "",
    primaryColor: "#8be9fd",
    headerBgColor: "#21222c",
    headerTextColor: "#f8f8f2",
    bodyBg: "#282a36",
    bodyFg: "#f8f8f2",
    borderColor: "#44475a",
    mutedColor: "#6272a4",
    cardBg: "#343746",
    tableHeaderBg: "#424450",
    tableRowAltBg: "#44475a",
    linkColor: "#8be9fd",
  },
};

/** Nord - arctic, minimal blues */
export const THEME_NORD: ReportTheme = {
  id: "nord",
  name: "Nord",
  branding: {
    companyName: "",
    tagline: "",
    websiteUrl: "",
    logoUrl: "",
    primaryColor: "#88c0d0",
    headerBgColor: "#2e3440",
    headerTextColor: "#eceff4",
    bodyBg: "#2e3440",
    bodyFg: "#eceff4",
    borderColor: "#4c566a",
    mutedColor: "#4c566a",
    cardBg: "#3b4252",
    tableHeaderBg: "#434c5e",
    tableRowAltBg: "#4c566a",
    linkColor: "#88c0d0",
  },
};

/** Catppuccin Mocha - cozy pastel dark */
export const THEME_CATPPUCCIN: ReportTheme = {
  id: "catppuccin",
  name: "Catppuccin Mocha",
  branding: {
    companyName: "",
    tagline: "",
    websiteUrl: "",
    logoUrl: "",
    primaryColor: "#89b4fa",
    headerBgColor: "#181825",
    headerTextColor: "#cdd6f4",
    bodyBg: "#1e1e2e",
    bodyFg: "#cdd6f4",
    borderColor: "#45475a",
    mutedColor: "#6c7086",
    cardBg: "#313244",
    tableHeaderBg: "#45475a",
    tableRowAltBg: "#363a4f",
    linkColor: "#89b4fa",
  },
};

/** Tokyo Night - deep indigo, neon accents */
export const THEME_TOKYO_NIGHT: ReportTheme = {
  id: "tokyo-night",
  name: "Tokyo Night",
  branding: {
    companyName: "",
    tagline: "",
    websiteUrl: "",
    logoUrl: "",
    primaryColor: "#7aa2f7",
    headerBgColor: "#0d0f17",
    headerTextColor: "#a9b1d6",
    bodyBg: "#16161e",
    bodyFg: "#a9b1d6",
    borderColor: "#3d59a1",
    mutedColor: "#787c99",
    cardBg: "#1f2335",
    tableHeaderBg: "#14141b",
    tableRowAltBg: "#24283b",
    linkColor: "#7aa2f7",
  },
};

/** VAT theme - dark, cyan accent (matches VAT UI) */
export const THEME_VAT: ReportTheme = {
  id: "vat",
  name: "VAT",
  branding: {
    companyName: "VAT",
    tagline: "Vulnerability Assessment Tracker",
    websiteUrl: "",
    logoUrl: "/vat-logo.svg",
    primaryColor: "#38bdf8",
    headerBgColor: "#040911",
    headerTextColor: "#e2e8f0",
    bodyBg: "#040911",
    bodyFg: "#e2e8f0",
    borderColor: "#1a2540",
    mutedColor: "#475569",
    cardBg: "#070f1e",
    tableHeaderBg: "#0d1a2e",
    tableRowAltBg: "#0f172a",
    linkColor: "#38bdf8",
  },
};

export const REPORT_THEMES: ReportTheme[] = [
  THEME_VAT,
  THEME_DEFAULT,
  THEME_LIGHT,
  THEME_SLATE,
  THEME_DRACULA,
  THEME_NORD,
  THEME_CATPPUCCIN,
  THEME_TOKYO_NIGHT,
];

/** @deprecated Use getReportTheme(themeId) */
export const REPORT_BRANDING: ReportBranding = applyBrandingOverride(
  THEME_DEFAULT.branding,
);

export function getReportTheme(themeId?: string | null): ReportBranding {
  const raw = themeId || "default";
  const id = raw === "kamiwaza" ? "default" : raw; /* migrate old preference */
  const theme = REPORT_THEMES.find((t) => t.id === id);
  const base = theme?.branding ?? THEME_DEFAULT.branding;
  return id === "default" ? applyBrandingOverride(base) : base;
}

/** Apply NEXT_PUBLIC_REPORT_* overrides to default theme branding. Override logo, company name, etc. */
function applyBrandingOverride(branding: ReportBranding): ReportBranding {
  const over = getReportBrandingOverride();
  if (!over.logoUrl && !over.companyName && !over.tagline && !over.websiteUrl)
    return branding;
  return {
    ...branding,
    ...(over.logoUrl != null && { logoUrl: over.logoUrl }),
    ...(over.companyName != null && { companyName: over.companyName }),
    ...(over.tagline != null && { tagline: over.tagline }),
    ...(over.websiteUrl != null && { websiteUrl: over.websiteUrl }),
  };
}

// ---------------------------------------------------------------------------
// Canvas report: context (filtered data for widgets)
// ---------------------------------------------------------------------------

const REPORT_CONTEXT_MAX_REPOS = 100;
const REPORT_CONTEXT_MAX_TOP_VULNS = 200;

/** Calendar week Mon–Sun (matches Aikido). */
function getCalendarWeekBounds(now: Date): { weekStart: Date; weekEnd: Date } {
  const day = now.getDay();
  const diffToMonday = (day - 1 + 7) % 7;
  const weekStart = new Date(now);
  weekStart.setDate(now.getDate() - diffToMonday);
  weekStart.setHours(0, 0, 0, 0);
  const weekEnd = new Date(weekStart);
  weekEnd.setDate(weekStart.getDate() + 6);
  weekEnd.setHours(23, 59, 59, 999);
  return { weekStart, weekEnd };
}

/** Resolve date filters: use preset (30/90/120/365 days) or custom dateFrom/dateTo.
 * Aligns to Mon–Sun calendar weeks to match Aikido/vulnerability-dashboard. */
function resolveDateFilters(filters: ReportFilters): {
  dateFrom: string | null;
  dateTo: string | null;
} {
  if (filters.dateRangePreset) {
    const now = new Date();
    const { weekEnd } = getCalendarWeekBounds(now);
    const anchor = new Date(now);
    anchor.setDate(anchor.getDate() - filters.dateRangePreset);
    const { weekStart } = getCalendarWeekBounds(anchor);
    const fmt = (d: Date) =>
      `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
        d.getDate(),
      ).padStart(2, "0")}`;
    return { dateFrom: fmt(weekStart), dateTo: fmt(weekEnd) };
  }
  return { dateFrom: filters.dateFrom, dateTo: filters.dateTo };
}

export interface ComputeReportContextOptions {
  /** Unfiltered issues for period-over-period trend. */
  allIssuesForPeriodComparison?: VATReportIssue[];
}

export function computeReportContext(
  data: VATDashboardData,
  filters: ReportFilters,
  options?: ComputeReportContextOptions,
): ReportContext {
  let issues = data.issues;

  if (filters.repoFilter.length > 0) {
    issues = getIssuesForAssets(issues, data.issueGroups, filters.repoFilter);
  }
  if (filters.branchFilter) {
    issues = issues.filter((i) => i.branch === filters.branchFilter);
  }
  const { dateFrom, dateTo } = resolveDateFilters(filters);
  const countMode = filters.countMode ?? "groups";
  const issuesForTrend = [...issues];
  const periodChangeIssues =
    options?.allIssuesForPeriodComparison &&
    options.allIssuesForPeriodComparison.length > 0
      ? (() => {
          let all = options.allIssuesForPeriodComparison;
          if (filters.repoFilter.length > 0) {
            all = getIssuesForAssets(all, data.issueGroups, filters.repoFilter);
          }
          if (filters.branchFilter) {
            all = all.filter((i) => i.branch === filters.branchFilter);
          }
          return all;
        })()
      : issues;
  const periodChange = computePeriodOverPeriodChange(
    periodChangeIssues,
    dateFrom,
    dateTo,
    countMode,
  );
  const dateRange =
    dateFrom && dateTo
      ? `${new Date(dateFrom).toLocaleDateString("en-US", {
          month: "short",
          day: "numeric",
          year: "numeric",
        })} – ${new Date(dateTo).toLocaleDateString("en-US", {
          month: "short",
          day: "numeric",
          year: "numeric",
        })}`
      : null;
  let effectivePeriodDays: number | null =
    dateFrom && dateTo
      ? Math.round(
          (new Date(dateTo).getTime() - new Date(dateFrom).getTime()) /
            86400000,
        )
      : null;
  // When no date filter: infer period from data span (e.g. dashboard pre-filtered to N days)
  if (effectivePeriodDays == null && issues.length > 0) {
    const dates = issues
      .map((i) => new Date(i.first_detected_at ?? 0).getTime())
      .filter((t) => t > 0);
    if (dates.length > 0) {
      const minT = Math.min(...dates);
      const maxT = Math.max(...dates);
      effectivePeriodDays = Math.max(1, Math.round((maxT - minT) / 86400000));
    }
  }
  if (dateFrom) {
    const from = new Date(dateFrom + "T00:00:00.000Z").getTime();
    issues = issues.filter(
      (i) => new Date(i.first_detected_at).getTime() >= from,
    );
  }
  if (dateTo) {
    // Use end of day so issues on dateTo are included (midnight would exclude same-day detections)
    const to = new Date(dateTo + "T23:59:59.999Z").getTime();
    issues = issues.filter(
      (i) => new Date(i.first_detected_at).getTime() <= to,
    );
  }
  if (filters.severityFilter.length > 0) {
    const allowed = new Set(filters.severityFilter.map((s) => s.toLowerCase()));
    issues = issues.filter((i) =>
      allowed.has((i.severity ?? "").toLowerCase()),
    );
  }

  const openIssues = issues.filter(isOpen);
  const hasFilters =
    filters.repoFilter.length > 0 ||
    !!filters.branchFilter ||
    filters.severityFilter.length > 0 ||
    !!dateFrom ||
    !!dateTo;
  const { totalOpen, counts } = resolveOpenCounts(openIssues, {
    countMode,
    issueCounts: data.issueCounts ?? undefined,
    issueGroups: data.issueGroups,
    hasFilters,
  });
  const riskScore = computeReportRiskScore(counts);
  const mttr = computeMTTR(issues, countMode);
  const assetFilter = new Set(filters.repoFilter);
  const reposForRisk =
    assetFilter.size > 0
      ? data.repos.filter((r) => assetFilter.has(r.name))
      : data.repos;
  const containersForRisk =
    assetFilter.size > 0
      ? (data.containers ?? []).filter((c) => assetFilter.has(c.name))
      : data.containers ?? [];
  const repoRisk = computeRepoRiskScores(
    issues,
    reposForRisk,
    data.issueGroups,
    countMode,
  ).slice(0, REPORT_CONTEXT_MAX_REPOS);
  const containerRisk = computeContainerRiskScores(
    containersForRisk,
    data.issues ?? [],
    data.issueGroups ?? [],
    countMode,
    data.repos ?? [],
  ).slice(0, REPORT_CONTEXT_MAX_REPOS);
  const assetMix = computeAssetMix(
    issues,
    data.repos,
    data.containers ?? [],
    data.vms ?? [],
    countMode,
    data.packageRepos ?? [],
  );
  const teams = (data.teams ?? []).map((t) => ({ id: t.id, name: t.name }));
  const reachabilityMatrix = computeReachabilityMatrix(
    issues,
    undefined,
    countMode,
  );
  const topVulns = getTopVulnerabilities(
    issues,
    data.issueGroups,
    REPORT_CONTEXT_MAX_TOP_VULNS,
    countMode,
  );

  return {
    workspace: data.workspace.name,
    date: new Date().toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    }),
    dateRange,
    effectivePeriodDays,
    dateFrom,
    dateTo,
    repoFilter: filters.repoFilter,
    branchFilter: filters.branchFilter,
    notes: filters.notes,
    totalIssues: countTotalIssues(issues, countMode),
    openIssues: totalOpen,
    counts,
    riskScore,
    riskLevel: getReportRiskLevel(riskScore),
    avgMttr: computeAvgMttr(mttr),
    mttr,
    aging: computeAgingBuckets(issues, countMode),
    repoRisk,
    containerRisk,
    assetMix,
    teams,
    topVulns,
    scanners: computeScannerBreakdown(openIssues, countMode),
    trends: computeTrendData(issues, countMode),
    filteredIssues: issues,
    issuesForTrend,
    activityLog: data.activityLog as ReportContext["activityLog"],
    soc2Compliance: data.soc2Compliance ?? undefined,
    nis2Compliance: data.nis2Compliance ?? undefined,
    iso27001Compliance: data.iso27001Compliance ?? undefined,
    reachabilityMatrix:
      reachabilityMatrix.length > 0 ? reachabilityMatrix : undefined,
    abcCompliance: (() => {
      const abc = computeABCComplianceForIssues(issues, countMode);
      return {
        compliant: abc.compliant,
        maxCountExceeded: abc.maxCountExceeded,
        justificationOverdue: abc.justificationOverdue,
        remediationOverdue: abc.remediationOverdue,
        cveAgeExceeded: abc.cveAgeExceeded,
      };
    })(),
    ciScans: data.ciScans as ReportContext["ciScans"],
    taskProjects: data.taskProjects as ReportContext["taskProjects"],
    tasksByGroupId: data.tasksByGroupId as ReportContext["tasksByGroupId"],
    aikidoBaseUrl: undefined,
    repoIdByName: (() => {
      const m: Record<string, number> = {};
      for (const r of data.repos) {
        m[r.name] = r.id;
        const lc = r.name.toLowerCase();
        if (lc !== r.name) m[lc] = r.id;
      }
      for (const c of data.containers ?? []) {
        if (m[c.name] !== undefined) continue;
        m[c.name] = c.id;
        const lc = c.name.toLowerCase();
        if (lc !== c.name && m[lc] === undefined) m[lc] = c.id;
      }
      return m;
    })(),
    issueGroups: data.issueGroups,
    vmNames: (data.vms ?? []).map((v) => v.name),
    packageNames: (data.packageRepos ?? []).map((p) => p.name),
    external: filters.external ?? false,
    countMode,
    cveDetailsByCveId: data.cveDetailsByCveId,
    periodChange: periodChange ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// Canvas report: build HTML from definition
// ---------------------------------------------------------------------------

/** Compute column span (1–3) for a widget in a canvas with N columns. */
function widgetColSpan(width: number, columns: 1 | 2 | 3): number {
  const unitsPerCol = 12 / columns;
  return Math.min(columns, Math.max(1, Math.round(width / unitsPerCol)));
}

function buildReportBodyFromDefinition(
  context: ReportContext,
  definition: ReportDefinition,
  options?: { preview?: boolean },
): string {
  const preview = options?.preview ?? false;
  const parts: string[] = [];
  for (let i = 0; i < definition.canvases.length; i++) {
    if (i > 0) {
      parts.push(
        '<div class="canvas-page-break" style="page-break-before: always;"></div>',
      );
    }
    const canvas = definition.canvases[i];
    const columns = (inferColumnsFromWidgets(canvas.widgets) ?? 1) as 1 | 2 | 3;
    const sortedWidgets = [...canvas.widgets].sort((a, b) => {
      const ra = a.layout?.row ?? 0;
      const rb = b.layout?.row ?? 0;
      if (ra !== rb) return ra - rb;
      return (a.layout?.col ?? 0) - (b.layout?.col ?? 0);
    });
    if (columns === 1) {
      for (const widget of sortedWidgets) {
        const config = applyPreviewLimits(
          widget.type as WidgetType,
          widget.config || {},
          preview,
        );
        const html = renderWidget(widget.type as WidgetType, context, config);
        if (html) parts.push(html);
      }
    } else {
      const gridStyle = `display:grid;grid-template-columns:repeat(${columns}, 1fr);gap:16px;grid-auto-rows:auto;align-items:start;`;
      const widgetParts: string[] = [];
      for (const widget of sortedWidgets) {
        const layout = widget.layout;
        const width = layout?.width ?? 12;
        const span = widgetColSpan(width, columns);
        const config = applyPreviewLimits(
          widget.type as WidgetType,
          widget.config || {},
          preview,
        );
        const html = renderWidget(widget.type as WidgetType, context, config);
        if (html) {
          widgetParts.push(
            `<div class="report-widget-cell" style="grid-column:span ${span};min-width:0;">${html}</div>`,
          );
        }
      }
      parts.push(
        `<div class="canvas-grid report-canvas-multicol" style="${gridStyle}">${widgetParts.join(
          "",
        )}</div>`,
      );
    }
  }
  return parts.join("\n");
}

/** Minimal issue shape for client-side filter re-computation. */
interface ReportDataIssue {
  s: string;
  sc: number;
  r: string;
  b: string;
  d: string;
  c: string | null;
  st: string;
  g?: number;
  /** Scanner type for trend "Types" filter (e.g. SAST, container scan). */
  scanner?: string;
  /** Asset type: Code, Container, VM, Package, Other. */
  at?: string;
}

/** Build payload for client-side aggregate widget updates (summary, trend). */
function buildReportDataPayload(
  context: ReportContext,
  definition: ReportDefinition,
  options?: { maxIssues?: number },
): {
  issues: ReportDataIssue[];
  issuesForTrend?: ReportDataIssue[];
  dateFrom: string | null;
  dateTo: string | null;
  primaryColor: string;
  countMode: string;
  containers: string[];
  vmNames: string[];
  truncated?: boolean;
  serverCounts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  totalOpen?: number;
  serverTrendMetrics?: {
    openOneWeekAgo: number;
    resolvedThisWeek: number;
    resolvedLastWeek: number;
    newThisWeek: number;
    newLastWeek: number;
  };
} | null {
  const branding = getReportTheme(definition.themeId);
  const { dateFrom, dateTo } = resolveDateFilters(definition.filters);
  // Prefer context.countMode — it's the source of truth for computed metrics (openIssues, counts).
  // Ensures report widgets and client-side filter script use the same count mode.
  const countMode =
    context.countMode ?? definition.filters.countMode ?? "groups";
  const maxIssues = options?.maxIssues;
  const repoNames = context.repoRisk.map((r) => r.repo);
  const containerNames = context.containerRisk.map((c) => c.repo);
  const vmNames = context.vmNames ?? [];
  const packageNames = context.packageNames ?? [];
  const toPayload = (list: typeof context.filteredIssues) =>
    list.map((i) => {
      const at = getAssetTypeForIssue(
        i.repository,
        repoNames,
        containerNames,
        vmNames,
        packageNames,
      );
      return {
        s: i.severity ?? "",
        sc: i.severity_score ?? 0,
        r: i.repository ?? "",
        b: i.branch ?? "",
        d: i.first_detected_at ?? "",
        c: i.closed_at ?? null,
        st: i.status ?? "",
        g: i.issue_group_id ?? undefined,
        scanner: i.scanner_type ?? undefined,
        at,
      };
    });
  const fullIssues = toPayload(context.filteredIssues);
  let issues = fullIssues;
  const truncated = maxIssues != null && fullIssues.length > maxIssues;
  if (truncated) {
    issues = fullIssues.slice(0, maxIssues);
  }
  let issuesForTrend: ReportDataIssue[] | undefined =
    context.issuesForTrend && context.issuesForTrend !== context.filteredIssues
      ? toPayload(context.issuesForTrend)
      : undefined;
  if (
    issuesForTrend != null &&
    maxIssues != null &&
    issuesForTrend.length > maxIssues
  ) {
    issuesForTrend = issuesForTrend.slice(0, maxIssues);
  }
  const containers = context.containerRisk.map((c) => c.repo).filter(Boolean);
  const result: ReturnType<typeof buildReportDataPayload> = {
    issues,
    issuesForTrend,
    dateFrom,
    dateTo,
    primaryColor: branding.primaryColor,
    countMode,
    containers,
    vmNames,
    // Always include server-computed counts so client uses authoritative values when no filters.
    // Fixes instances-mode showing wrong count (e.g. 2 instead of 3) due to client-side recomputation.
    serverCounts: context.counts,
    totalOpen: context.openIssues,
  };
  if (truncated) {
    result.truncated = true;
    const trendIssues = context.issuesForTrend ?? context.filteredIssues;
    const metrics = computeTrendMetrics(trendIssues, countMode);
    result.serverTrendMetrics = {
      openOneWeekAgo: metrics.openOneWeekAgo,
      resolvedThisWeek: metrics.resolvedThisWeek,
      resolvedLastWeek: metrics.resolvedLastWeek,
      newThisWeek: metrics.newThisWeek,
      newLastWeek: metrics.newLastWeek,
    };
  }
  return result;
}

/** Escape JSON for safe embedding in HTML script tags (prevents </script> break-out). */
function jsonForScript(obj: unknown): string {
  return JSON.stringify(obj).replace(/<\//g, "\\u003c/");
}

function buildReportFilterBar(
  filterConfig: {
    severities: string[];
    assetTypes: string[];
    assets: string[];
    branches: string[];
  },
  borderColor: string,
  mutedColor: string,
  primaryColor: string,
  reportData?: {
    issues: ReportDataIssue[];
    issuesForTrend?: ReportDataIssue[];
    dateFrom: string | null;
    dateTo: string | null;
    primaryColor: string;
    countMode?: string;
    containers?: string[];
    vmNames?: string[];
  } | null,
): string {
  var payload = reportData ?? null;
  return (
    buildReportFilterBarStructure(
      filterConfig,
      borderColor,
      mutedColor,
      false,
    ) +
    `
<script>
(function(){
  function init(){
  var cfg = ${jsonForScript(filterConfig)};
  var reportData = ${payload ? jsonForScript(payload) : "null"};
  var bars = Array.prototype.slice.call(document.querySelectorAll(".report-filter-bar"));
  if (bars.length === 0) return;
  var cfgKey = { severity: "severities", assetType: "assetTypes", asset: "assets", branch: "branches" };
  var state = {
    severity: new Set(cfg.severities || []),
    assetType: new Set(cfg.assetTypes || []),  // all selected = no filter
    asset: new Set(cfg.assets || []),
    branch: new Set(cfg.branches || [])
  };
  var labels = { severity: "Severity", assetType: "Asset type", asset: "Asset", branch: "Branch" };
  var filterableSelector = "[data-filter-severity],[data-filter-asset-type],[data-filter-repo],[data-filter-branch],[data-filter-container]";
  function repoMatchesRepo(issueRepo, repoName) {
    if (!issueRepo || !repoName) return false;
    var a = (issueRepo + "").trim().toLowerCase();
    var b = (repoName + "").trim().toLowerCase();
    if (!a || !b) return false;
    if (a === b) return true;
    if (a.endsWith("/" + b)) return true;
    if (b.endsWith("/" + a)) return true;
    if (a.endsWith(b) && (a.length === b.length || a[a.length - b.length - 1] === "/")) return true;
    if (b.endsWith(a) && (b.length === a.length || b[b.length - a.length - 1] === "/")) return true;
    return false;
  }
  function elMatchesSelectedAsset(val) {
    if (!val) return false;
    if (state.asset.has(val)) return true;
    return Array.from(state.asset).some(function(a) { return repoMatchesRepo(val, a) || repoMatchesContainer(val, a); });
  }
  var elsCache = null;
  var sectionsCache = null;
  var hasDescendantCache = null;
  function cacheElements() {
    var root = document.querySelector(".report-filterable-root");
    if (!root) { elsCache = []; sectionsCache = []; return; }
    elsCache = Array.prototype.slice.call(root.querySelectorAll(filterableSelector));
    sectionsCache = Array.prototype.slice.call(root.querySelectorAll(".section"));
    var parentSet = new Set();
    elsCache.forEach(function(el) {
      var first = el.querySelector(filterableSelector);
      if (first && first !== el) parentSet.add(el);
    });
    hasDescendantCache = parentSet;
  }
  function getEls() {
    if (!elsCache) cacheElements();
    return elsCache;
  }
  var REPO_BRANCH_SEP = "|";
  var CLOSED_STATUSES = new Set(["closed","resolved","ignored","auto_ignored","false positive","suppressed","approved","duplicate","not applicable","rejected"]);
  function isOpenStatus(st) { var s = (st || "").toLowerCase(); return !CLOSED_STATUSES.has(s); }
  function normSev(i) {
    var s = (i.s || "").toLowerCase().trim();
    var sc = i.sc != null ? i.sc : 0;
    if (s === "critical") return "critical";
    if (s === "high") return "high";
    if (s === "medium" || s === "moderate") return "medium";
    if (s === "low") return "low";
    if (s === "info" || s === "informational" || s === "none") return "info";
    if (sc >= 9) return "critical";
    if (sc >= 7) return "high";
    if (sc >= 4) return "medium";
    if (sc >= 0.1) return "low";
    return "info";
  }
  function normContainerName(n) {
    if (!n) return "";
    var s = (n + "").trim().toLowerCase();
    var colonIdx = s.lastIndexOf(":");
    if (colonIdx > 0 && s.slice(colonIdx + 1).indexOf("/") < 0) s = s.slice(0, colonIdx);
    return s;
  }
  function repoMatchesContainer(repo, container) {
    if (!repo || !container) return false;
    var a = normContainerName(repo);
    var b = normContainerName(container);
    if (!a || !b) return false;
    if (a === b) return true;
    if (b.endsWith("/" + a)) return true;
    if (a.endsWith("/" + b)) return true;
    if (b.endsWith(a) && (b.length === a.length || b[b.length - a.length - 1] === "/")) return true;
    if (a.endsWith(b) && (a.length === b.length || a[a.length - b.length - 1] === "/")) return true;
    var aNorm = a.replace(/\\/images?\\//g, "/img/");
    var bNorm = b.replace(/\\/images?\\//g, "/img/");
    if (aNorm === bNorm) return true;
    if (bNorm.endsWith("/" + aNorm)) return true;
    if (aNorm.endsWith("/" + bNorm)) return true;
    return false;
  }
  function getCountsFromData() {
    if (!reportData || !reportData.issues.length) return null;
    var assets = cfg.assets || [];
    if (reportData.truncated && reportData.serverCounts) {
      var base = { severity: reportData.serverCounts, assetType: {}, asset: {}, branch: {} };
      var containers = (reportData.containers && reportData.containers.length) ? reportData.containers : [];
      var vmNames = (reportData.vmNames && reportData.vmNames.length) ? reportData.vmNames : [];
      function isContainerOrVm(repo) {
        if (!repo) return false;
        var r = (repo || "").toLowerCase().trim();
        if (containers.some(function(c) { return repoMatchesContainer(repo, c); })) return true;
        if (vmNames.some(function(v) { var vn = (v || "").toLowerCase().trim(); return r === vn || r.endsWith("/" + vn) || vn.endsWith("/" + r); })) return true;
        return false;
      }
      reportData.issues.forEach(function(i) {
        if (i.at) base.assetType[i.at] = (base.assetType[i.at] || 0) + 1;
        if (i.r) { assets.forEach(function(a) { if (repoMatchesRepo(i.r, a) || repoMatchesContainer(i.r, a)) base.asset[a] = (base.asset[a] || 0) + 1; }); }
        if (i.b) base.branch[i.b] = (base.branch[i.b] || 0) + 1;
      });
      return base;
    }
    var countMode = reportData.countMode || "groups";
    var containers = (reportData.containers && reportData.containers.length) ? reportData.containers : [];
    var vmNames = (reportData.vmNames && reportData.vmNames.length) ? reportData.vmNames : [];
    function isContainerOrVm(repo) {
      if (!repo) return false;
      var r = (repo || "").toLowerCase().trim();
      if (containers.some(function(c) { return repoMatchesContainer(repo, c); })) return true;
      if (vmNames.some(function(v) { var vn = (v || "").toLowerCase().trim(); return r === vn || r.endsWith("/" + vn) || vn.endsWith("/" + r); })) return true;
      return false;
    }
    var openIssues = reportData.issues.filter(function(i) { return isOpenStatus(i.st); });
    var counts = { severity: {}, assetType: {}, asset: {}, branch: {} };
    var list = countMode === "groups" ? (function() {
      var byGroup = {};
      function sevRank(sev) { return (sev === "critical" ? 5 : sev === "high" ? 4 : sev === "medium" ? 3 : sev === "low" ? 2 : 1); }
      openIssues.forEach(function(i) {
        var gid = i.g != null ? i.g : (i.r + "|" + i.d + "|" + (i.s||""));
        var sev = normSev(i);
        var r = sevRank(sev);
        if (!byGroup[gid] || r > (byGroup[gid].r || 0)) byGroup[gid] = { i: i, r: r };
      });
      return Object.keys(byGroup).map(function(k) { return byGroup[k].i; });
    })() : openIssues;
    list.forEach(function(i) {
      var sev = normSev(i);
      counts.severity[sev] = (counts.severity[sev] || 0) + 1;
      if (i.at) counts.assetType[i.at] = (counts.assetType[i.at] || 0) + 1;
      if (i.r) {
        assets.forEach(function(a) { if (repoMatchesRepo(i.r, a) || repoMatchesContainer(i.r, a)) counts.asset[a] = (counts.asset[a] || 0) + 1; });
      }
      if (i.b) counts.branch[i.b] = (counts.branch[i.b] || 0) + 1;
    });
    return counts;
  }
  function getCounts() {
    var fromData = getCountsFromData();
    if (fromData) return fromData;
    var els = getEls();
    var counts = { severity: {}, assetType: {}, asset: {}, branch: {} };
    var assets = cfg.assets || [];
    els.forEach(function(el) {
      var s = (el.getAttribute("data-filter-severity") || "").toLowerCase();
      var at = (el.getAttribute("data-filter-asset-type") || "").split(REPO_BRANCH_SEP).filter(Boolean);
      var r = (el.getAttribute("data-filter-repo") || "").split(REPO_BRANCH_SEP).filter(Boolean);
      var b = (el.getAttribute("data-filter-branch") || "").split(REPO_BRANCH_SEP).filter(Boolean);
      var c = (el.getAttribute("data-filter-container") || "").split(REPO_BRANCH_SEP).filter(Boolean);
      if (s) { var sevList = s.split(/\s+/).filter(Boolean); sevList.forEach(function(v){ counts.severity[v] = (counts.severity[v] || 0) + 1; }); }
      at.forEach(function(v){ counts.assetType[v] = (counts.assetType[v] || 0) + 1; });
      b.forEach(function(v){ counts.branch[v] = (counts.branch[v] || 0) + 1; });
      var allAssetVals = r.concat(c);
      assets.forEach(function(a) {
        if (allAssetVals.some(function(v) { return repoMatchesRepo(v, a) || repoMatchesContainer(v, a); })) {
          counts.asset[a] = (counts.asset[a] || 0) + 1;
        }
      });
    });
    return counts;
  }
  function updateCounts() {
    var counts = getCounts();
    bars.forEach(function(bar) {
      bar.querySelectorAll(".report-filter-count").forEach(function(sp) {
        var dim = sp.closest(".report-filter-panel").dataset.panel;
        var val = sp.getAttribute("data-count-for");
        var n = counts[dim] && counts[dim][val];
        sp.textContent = n != null ? " (" + n + ")" : "";
      });
    });
  }
  var visibilityCache = new Map();
  var sectionVisibilityCache = new Map();
  var applyFilterTimer = null;
  var aggregateTimer = null;
  function scheduleApplyFilter() {
    if (applyFilterTimer) clearTimeout(applyFilterTimer);
    applyFilterTimer = setTimeout(function() {
      applyFilterTimer = null;
      applyFilterImmediate();
    }, 16);
  }
  function applyFilter() {
    scheduleApplyFilter();
  }
  function applyFilterImmediate() {
    var root = document.querySelector(".report-filterable-root");
    if (!root) return;
    visibilityCache.clear();
    sectionVisibilityCache.clear();
    if (elsCache && elsCache.length === 0) {
      var freshCount = root.querySelectorAll(filterableSelector).length;
      if (freshCount > 0) { elsCache = null; sectionsCache = null; hasDescendantCache = null; }
    }
    var els = getEls();
    var parentSet = hasDescendantCache || (function(){ cacheElements(); return hasDescendantCache; })();
    var rootParent = null, rootNext = null;
    if (root && root.parentNode) {
      rootParent = root.parentNode;
      rootNext = root.nextSibling;
      rootParent.removeChild(root);
    }
    var allSev = (cfg.severities || []).length;
    var allAssetType = (cfg.assetTypes || []).length;
    var allAsset = (cfg.assets || []).length;
    var allBranch = (cfg.branches || []).length;
    var noSevFilter = allSev === 0 || state.severity.size === 0 || state.severity.size === allSev;
    var noAssetTypeFilter = allAssetType === 0 || state.assetType.size === 0 || state.assetType.size === allAssetType;
    var noAssetFilter = allAsset === 0 || state.asset.size === 0 || state.asset.size === allAsset;
    var noBranchFilter = allBranch === 0 || state.branch.size === 0 || state.branch.size === allBranch;
    els.forEach(function(el) {
      var visible;
      if (parentSet.has(el)) {
        visible = true;
      } else {
        var hasSev = el.hasAttribute("data-filter-severity");
        var hasAssetType = el.hasAttribute("data-filter-asset-type");
        var hasRepo = el.hasAttribute("data-filter-repo");
        var hasBranch = el.hasAttribute("data-filter-branch");
        var hasContainer = el.hasAttribute("data-filter-container");
        var sevRaw = (el.getAttribute("data-filter-severity") || "").toLowerCase();
        var sevList = sevRaw ? sevRaw.split(/\s+/).filter(Boolean) : [];
        var assetTypeRaw = (el.getAttribute("data-filter-asset-type") || "").split(REPO_BRANCH_SEP).filter(Boolean);
        var repoRaw = el.getAttribute("data-filter-repo") || "";
        var branchRaw = el.getAttribute("data-filter-branch") || "";
        var containerRaw = el.getAttribute("data-filter-container") || "";
        var repoList = repoRaw ? repoRaw.split(REPO_BRANCH_SEP).filter(Boolean) : [];
        var branchList = branchRaw ? branchRaw.split(REPO_BRANCH_SEP).filter(Boolean) : [];
        var containerList = containerRaw ? containerRaw.split(REPO_BRANCH_SEP).filter(Boolean) : [];
        var matchSev = !hasSev || noSevFilter || sevList.some(function(s) { return state.severity.has(s); });
        var matchAssetType = !hasAssetType || noAssetTypeFilter || assetTypeRaw.length === 0 || assetTypeRaw.some(function(t) { return state.assetType.has(t); });
        var matchAsset = noAssetFilter || (repoList.length === 0 && containerList.length === 0) || repoList.some(function(r) { return elMatchesSelectedAsset(r); }) || containerList.some(function(c) { return elMatchesSelectedAsset(c); });
        var matchBranch = !hasBranch || noBranchFilter || (branchList.length === 0 ? (state.branch.has("main") || state.branch.has("master")) : branchList.some(function(b) { return state.branch.has(b); }));
        visible = matchSev && matchAssetType && matchAsset && matchBranch;
      }
      if (visibilityCache.get(el) === visible) return;
      visibilityCache.set(el, visible);
      el.style.display = visible ? "" : "none";
    });
    var sections = sectionsCache || (function(){ cacheElements(); return sectionsCache; })();
    sections.forEach(function(s) {
      var filterable = s.querySelectorAll(filterableSelector);
      if (filterable.length === 0) return;
      var visibleCount = 0;
      for (var fi = 0; fi < filterable.length; fi++) {
        var x = filterable[fi];
        if (parentSet.has(x)) continue;
        if (x.style.display !== "none") visibleCount++;
      }
      var sectionVisible = visibleCount > 0;
      if (sectionVisibilityCache.get(s) === sectionVisible) return;
      sectionVisibilityCache.set(s, sectionVisible);
      s.style.display = sectionVisible ? "" : "none";
    });
    if (rootParent && root) {
      rootParent.insertBefore(root, rootNext);
    }
    renderChips();
    if (window.__vatReportNotifyHeight) window.__vatReportNotifyHeight();
    if (reportData) {
      if (aggregateTimer) clearTimeout(aggregateTimer);
      aggregateTimer = setTimeout(function() {
        aggregateTimer = null;
        updateAggregateWidgets();
      }, 0);
    }
  }
  function updateAggregateWidgets() {
    if (!reportData || !reportData.issues.length) return;
    var countMode = (reportData.countMode || "groups");
    var trendBase = reportData.issuesForTrend || reportData.issues;
    function normSev(i) {
      var s = (i.s || "").toLowerCase().trim();
      var sc = i.sc != null ? i.sc : 0;
      if (s === "critical") return "critical";
      if (s === "high") return "high";
      if (s === "medium" || s === "moderate") return "medium";
      if (s === "low") return "low";
      if (s === "info" || s === "informational" || s === "none") return "info";
      if (sc >= 9) return "critical";
      if (sc >= 7) return "high";
      if (sc >= 4) return "medium";
      if (sc >= 0.1) return "low";
      return "info";
    }
    function sevRank(sev) { return (sev === "critical" ? 5 : sev === "high" ? 4 : sev === "medium" ? 3 : sev === "low" ? 2 : 1); }
    function countBySeverity(issues) {
      var c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      if (countMode === "groups") {
        var byGroup = {};
        issues.forEach(function(i) {
          var gid = i.g != null ? i.g : (i.r + "|" + i.d + "|" + (i.s||""));
          var sev = normSev(i);
          var r = sevRank(sev);
          if (!byGroup[gid] || r > (byGroup[gid].r || 0)) byGroup[gid] = { sev: sev, r: r };
        });
        Object.keys(byGroup).forEach(function(k) { c[byGroup[k].sev]++; });
      } else {
        issues.forEach(function(i) { c[normSev(i)]++; });
      }
      return c;
    }
    function countTotal(issues) {
      if (countMode === "groups") {
        var seen = {};
        return issues.filter(function(i) {
          var gid = i.g != null ? i.g : (i.r + "|" + i.d + "|" + (i.s||""));
          if (seen[gid]) return false;
          seen[gid] = true;
          return true;
        }).length;
      }
      return issues.length;
    }
    var allSev = (cfg.severities || []).length;
    var allAssetType = (cfg.assetTypes || []).length;
    var allAsset = (cfg.assets || []).length;
    var allBranch = (cfg.branches || []).length;
    var noSevFilter = allSev === 0 || state.severity.size === 0 || state.severity.size === allSev;
    var noAssetTypeFilter = allAssetType === 0 || state.assetType.size === 0 || state.assetType.size === allAssetType;
    var noAssetFilter = allAsset === 0 || state.asset.size === 0 || state.asset.size === allAsset;
    var noBranchFilter = allBranch === 0 || state.branch.size === 0 || state.branch.size === allBranch;
    var containers = ((reportData.containers && reportData.containers.length) ? reportData.containers : []).slice();
    var vmNames = ((reportData.vmNames && reportData.vmNames.length) ? reportData.vmNames : []).slice();
    function normContainerName(n) {
      if (!n) return "";
      var s = (n + "").trim().toLowerCase();
      var colonIdx = s.lastIndexOf(":");
      if (colonIdx > 0 && s.slice(colonIdx + 1).indexOf("/") < 0) s = s.slice(0, colonIdx);
      return s;
    }
    function repoMatchesContainer(repo, container) {
      if (!repo || !container) return false;
      var a = normContainerName(repo);
      var b = normContainerName(container);
      if (!a || !b) return false;
      if (a === b) return true;
      if (b.endsWith("/" + a)) return true;
      if (a.endsWith("/" + b)) return true;
      if (b.endsWith(a) && (b.length === a.length || b[b.length - a.length - 1] === "/")) return true;
      if (a.endsWith(b) && (a.length === b.length || a[a.length - b.length - 1] === "/")) return true;
      var aNorm = a.replace(new RegExp("/images?/", "g"), "/img/");
      var bNorm = b.replace(new RegExp("/images?/", "g"), "/img/");
      if (aNorm === bNorm) return true;
      if (bNorm.endsWith("/" + aNorm)) return true;
      if (aNorm.endsWith("/" + bNorm)) return true;
      return false;
    }
    function isContainerOrVm(repo) {
      if (!repo) return false;
      var r = (repo || "").toLowerCase().trim();
      if (containers.some(function(c) { return repoMatchesContainer(repo, c); })) return true;
      if (vmNames.some(function(v) { var vn = (v || "").toLowerCase().trim(); return r === vn || r.endsWith("/" + vn) || vn.endsWith("/" + r); })) return true;
      return false;
    }
    function matchAssetTypeForIssue(i) {
      if (noAssetTypeFilter || !i.at) return true;
      return state.assetType.has(i.at);
    }
    function matchAssetForIssue(i) {
      if (noAssetFilter || !i.r) return true;
      return elMatchesSelectedAsset(i.r);
    }
    function matchBranchForIssue(i) {
      if (noBranchFilter) return true;
      if (i.b) return state.branch.has(i.b);
      return state.branch.has("main") || state.branch.has("master");
    }
    var filtered = reportData.issues.filter(function(i) {
      var sev = normSev(i);
      var matchSev = noSevFilter || state.severity.has(sev);
      var matchBranch = matchBranchForIssue(i);
      return matchSev && matchAssetTypeForIssue(i) && matchAssetForIssue(i) && matchBranch;
    });
    var trendFiltered = trendBase.filter(function(i) {
      var sev = normSev(i);
      var matchSev = noSevFilter || state.severity.has(sev);
      var matchBranch = matchBranchForIssue(i);
      return matchSev && matchAssetTypeForIssue(i) && matchAssetForIssue(i) && matchBranch;
    });
    var openIssues = filtered.filter(function(i) { return isOpenStatus(i.st); });
    var noFilters = noSevFilter && noAssetTypeFilter && noAssetFilter && noBranchFilter;
    // Use server counts when available — authoritative for countMode (groups vs instances).
    var useServerCounts = reportData.serverCounts != null && reportData.totalOpen != null && noFilters;
    var counts = useServerCounts ? reportData.serverCounts : countBySeverity(openIssues);
    function oraPenalty(c) { var p = (c.critical||0)*10 + (c.high||0)*4; p += Math.min((c.medium||0)*0.5, 30); p += Math.min((c.low||0)*0.25, 10); return p; }
    function toReportRisk(c) { return Math.max(0, Math.min(100, Math.round(oraPenalty(c)))); }
    var riskScore = toReportRisk(counts);
    var riskLevel = riskScore >= 75 ? "Critical" : riskScore >= 50 ? "High" : riskScore >= 25 ? "Medium" : "Low";
    var criticalHigh = counts.critical + counts.high;
    var pc = null;
    if (reportData.dateFrom && reportData.dateTo) {
      var from = new Date(reportData.dateFrom); var to = new Date(reportData.dateTo);
      if (!isNaN(from.getTime()) && !isNaN(to.getTime())) {
        function openAt(d) { var ts = d.getTime(); return filtered.filter(function(i) { var det = new Date(i.d); if (isNaN(det.getTime()) || det.getTime() > ts) return false; var cls = i.c ? new Date(i.c) : null; return !cls || isNaN(cls.getTime()) || cls.getTime() > ts; }); }
        var currOpen = openAt(to).filter(function(i) { return isOpenStatus(i.st); });
        var prevOpen = openAt(from).filter(function(i) { return isOpenStatus(i.st); });
        function pct(a,b) { return b === 0 ? (a > 0 ? 100 : 0) : Math.round(((a - b) / b) * 100); }
        function dir(a,b) { return a > b ? "up" : a < b ? "down" : "flat"; }
        var currCnt = countBySeverity(currOpen);
        var prevCnt = countBySeverity(prevOpen);
        var currRisk = toReportRisk(currCnt);
        var prevRisk = toReportRisk(prevCnt);
        function avgMttrInRange(issues, start, end) {
          var days = []; var startTs = start.getTime(); var endTs = end.getTime();
          issues.forEach(function(i) {
            if (!i.c || !i.d) return;
            var closed = new Date(i.c); var detected = new Date(i.d);
            if (isNaN(closed.getTime()) || isNaN(detected.getTime()) || closed <= detected) return;
            var closedTs = closed.getTime();
            if (closedTs < startTs || closedTs > endTs) return;
            var d = (closedTs - detected.getTime()) / 86400000;
            if (isFinite(d) && d >= 0) days.push(d);
          });
          return days.length ? days.reduce(function(a,b) { return a + b; }, 0) / days.length : undefined;
        }
        var periodDays = Math.round((to.getTime() - from.getTime()) / 86400000);
        var prevStart = new Date(from); prevStart.setDate(prevStart.getDate() - periodDays);
        var currMttr = avgMttrInRange(filtered, from, to);
        var prevMttr = avgMttrInRange(filtered, prevStart, from);
        var mttrCh = (currMttr !== undefined && prevMttr !== undefined && prevMttr > 0)
          ? { pctChange: Math.round(((currMttr - prevMttr) / prevMttr) * 100), direction: currMttr > prevMttr ? "up" : currMttr < prevMttr ? "down" : "flat" }
          : null;
        var currTotal = countTotal(currOpen);
        var prevTotal = countTotal(prevOpen);
        pc = { riskScore: prevRisk === 0 && currRisk > 0 ? { pctChange: 100, direction: "up" } : prevRisk === 0 ? null : { pctChange: Math.round(((currRisk - prevRisk) / prevRisk) * 100), direction: currRisk > prevRisk ? "up" : currRisk < prevRisk ? "down" : "flat" }, openIssues: { pctChange: pct(currTotal, prevTotal), direction: dir(currTotal, prevTotal) }, criticalHigh: { pctChange: pct(currCnt.critical + currCnt.high, prevCnt.critical + prevCnt.high), direction: dir(currCnt.critical + currCnt.high, prevCnt.critical + prevCnt.high) }, mttr: mttrCh };
      }
    }
    var avgMttr = (function() {
      var days = []; var now = new Date(); var to = reportData.dateTo ? new Date(reportData.dateTo) : now; var from = reportData.dateFrom ? new Date(reportData.dateFrom) : new Date(to.getTime() - 30*86400000);
      filtered.forEach(function(i) {
        if (!i.c || !i.d) return;
        var closed = new Date(i.c); var detected = new Date(i.d);
        if (isNaN(closed.getTime()) || isNaN(detected.getTime()) || closed <= detected) return;
        if (closed.getTime() < from.getTime() || closed.getTime() > to.getTime()) return;
        var d = (closed.getTime() - detected.getTime()) / 86400000;
        if (isFinite(d) && d >= 0) days.push(d);
      });
      return days.length ? days.reduce(function(a,b) { return a + b; }, 0) / days.length : undefined;
    })();
    var trendBadge = function(ch, inline, improvementIsUp) {
      if (!ch || ch.direction === "flat" || ch.pctChange === 0) return "";
      var arrow = ch.direction === "up" ? "↑" : "↓";
      var color = improvementIsUp ? (ch.direction === "up" ? "#16a34a" : "#dc2626") : (ch.direction === "down" ? "#16a34a" : "#dc2626");
      var inner = arrow + " " + Math.abs(ch.pctChange) + "%";
      return inline ? '<span class="kpi-trend kpi-trend-inline" style="color:' + color + '">' + inner + '</span>' : '<span style="color:' + color + '">' + inner + '</span>';
    };
    var riskColor = riskLevel === "Critical" ? "#ef4444" : riskLevel === "High" ? "#f97316" : riskLevel === "Medium" ? "#eab308" : reportData.primaryColor;
    document.querySelectorAll("[data-report-aggregate=summary]").forEach(function(section) {
      var grid = section.querySelector(".kpi-grid");
      var boardHero = section.querySelector(".board-hero");
      if (boardHero) {
        var scoreEl = section.querySelector(".board-risk-score"); var levelEl = section.querySelector(".board-risk-level");
        var gaugeWrap = section.querySelector(".board-hero-viz");
        if (scoreEl) scoreEl.innerHTML = '<span style="color:' + riskColor + '">' + riskScore + '</span><span class="board-risk-max">/100</span>' + (pc && pc.riskScore ? trendBadge(pc.riskScore, true) : '');
        if (levelEl) levelEl.textContent = riskLevel + " risk";
        if (gaugeWrap) {
          var fillColor = riskLevel === "Critical" ? "#ef4444" : riskLevel === "High" ? "#f97316" : riskLevel === "Medium" ? "#eab308" : "#22c55e";
          var pct = Math.min(100, Math.max(0, riskScore)) / 100;
          var size = 120; var cx = size/2; var r = size/2 - 6;
          gaugeWrap.innerHTML = '<svg viewBox="0 0 ' + size + ' ' + size + '" class="viz-gauge" width="' + size + '" height="' + size + '"><path d="M 6 ' + cx + ' A ' + r + ' ' + r + ' 0 0 1 ' + (size-6) + ' ' + cx + '" fill="none" stroke="#e2e8f0" stroke-width="8" pathLength="100"/><path d="M 6 ' + cx + ' A ' + r + ' ' + r + ' 0 0 1 ' + (size-6) + ' ' + cx + '" fill="none" stroke="' + fillColor + '" stroke-width="8" pathLength="100" stroke-dasharray="' + (pct*100) + ' 100" stroke-linecap="round"/><text x="' + cx + '" y="' + (cx+4) + '" text-anchor="middle" font-size="18" font-weight="700" fill="' + fillColor + '">' + riskScore + '</text></svg>';
        }
      }
      if (!grid) return;
      function setKpiValue(el, valueHtml, trendHtml) {
        if (!el) return;
        el.innerHTML = valueHtml;
        var trendEl = el.nextElementSibling;
        if (trendEl && trendEl.classList && trendEl.classList.contains("kpi-trend")) {
          trendEl.innerHTML = trendHtml || "";
          trendEl.style.display = trendHtml ? "" : "none";
        }
      }
      setKpiValue(grid.querySelector(".kpi-card:nth-child(1) .kpi-value"), '<span style="color:' + riskColor + '">' + riskScore + '</span><span class="kpi-suffix">/100</span>', pc && pc.riskScore ? trendBadge(pc.riskScore, true) : "");
      var totalOpenVal = useServerCounts ? reportData.totalOpen : countTotal(openIssues);
      setKpiValue(grid.querySelector(".kpi-card:nth-child(2) .kpi-value"), String(totalOpenVal), pc && pc.openIssues ? trendBadge(pc.openIssues) : "");
      setKpiValue(grid.querySelector(".kpi-card:nth-child(3) .kpi-value"), '<span style="color:#f97316">' + criticalHigh + '</span>', pc && pc.criticalHigh ? trendBadge(pc.criticalHigh) : "");
      setKpiValue(grid.querySelector(".kpi-card:nth-child(4) .kpi-value"), avgMttr !== undefined && isFinite(avgMttr) ? String(Math.round(avgMttr)) : "—", pc && pc.mttr ? trendBadge(pc.mttr) : "");
      var detail1 = grid.querySelector(".kpi-card:nth-child(1) .kpi-detail"); if (detail1) detail1.textContent = riskLevel;
      var detail2 = grid.querySelector(".kpi-card:nth-child(2) .kpi-detail"); if (detail2) detail2.textContent = counts.critical + " critical";
      var detail4 = grid.querySelector(".kpi-card:nth-child(4) .kpi-detail"); if (detail4) detail4.textContent = avgMttr !== undefined ? "days" : "No data";
    });
    document.querySelectorAll("[data-report-aggregate=trend-stacked]").forEach(function(trendSection) {
      if (trendBase.length === 0) return;
      var trendCountMode = (trendSection.getAttribute("data-trend-count-mode") || countMode) === "instances" ? "instances" : "groups";
      var trendPeriodDays = parseInt(trendSection.getAttribute("data-trend-period-days") || "90", 10) || 90;
      var trendGranularity = (trendSection.getAttribute("data-trend-granularity") || "weekly").toLowerCase();
      var trendSevRaw = trendSection.getAttribute("data-trend-severities") || "";
      var trendTypesRaw = trendSection.getAttribute("data-trend-types") || "";
      var trendSevSet = trendSevRaw ? new Set(trendSevRaw.split("|").map(function(s){ return s.toLowerCase().trim(); })) : null;
      var trendTypesSet = trendTypesRaw ? new Set(trendTypesRaw.split("|")) : null;
      function matchTrendTypes(i) {
        if (!trendTypesSet || trendTypesSet.size === 0) return true;
        var at = i.at || "Other";
        if (trendTypesSet.has("Container") && at === "Container") return true;
        if (trendTypesSet.has("VM") && at === "VM") return true;
        if (trendTypesSet.has("Code") && at === "Code") return true;
        if (trendTypesSet.has("Package") && at === "Package") return true;
        if (trendTypesSet.has("Other") && at === "Other") return true;
        return false;
      }
      function matchTrendSeverity(i) {
        if (!trendSevSet || trendSevSet.size === 0) return true;
        return trendSevSet.has(normSev(i));
      }
      var trendFilteredScoped = trendFiltered.filter(function(i){ return matchTrendSeverity(i) && matchTrendTypes(i); });
      function countBySeverityTrend(issues) {
        var c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        if (trendCountMode === "groups") {
          var byGroup = {};
          issues.forEach(function(i) {
            var gid = i.g != null ? i.g : (i.r + "|" + i.d + "|" + (i.s||""));
            if (byGroup[gid]) return;
            byGroup[gid] = true;
            var sev = normSev(i);
            c[sev]++;
          });
        } else {
          issues.forEach(function(i) { c[normSev(i)]++; });
        }
        return c;
      }
      var now = new Date();
      var nowTs = now.getTime();
      var bucketDays = trendGranularity === "daily" ? 1 : trendGranularity === "monthly" ? 30 : 7;
      var currentWindowEnd = new Date(now);
      currentWindowEnd.setHours(23, 59, 59, 999);
      var currentWindowStart = new Date(currentWindowEnd);
      currentWindowStart.setDate(currentWindowStart.getDate() - (bucketDays - 1));
      currentWindowStart.setHours(0, 0, 0, 0);
      var previousWindowEnd = new Date(currentWindowStart.getTime() - 1);
      var previousWindowStart = new Date(previousWindowEnd);
      previousWindowStart.setDate(previousWindowStart.getDate() - (bucketDays - 1));
      previousWindowStart.setHours(0, 0, 0, 0);
      var thisStartTs = currentWindowStart.getTime();
      var thisEndTs = currentWindowEnd.getTime();
      var lastStartTs = previousWindowStart.getTime();
      var lastEndTs = previousWindowEnd.getTime();
      var countTotalTrend = function(issues) { return trendCountMode === "groups" ? (function() { var seen = {}; return issues.filter(function(i) { var gid = i.g != null ? i.g : (i.r + "|" + i.d + "|" + (i.s||"")); if (seen[gid]) return false; seen[gid] = true; return true; }).length; })() : issues.length; };
      var isResolvedStatus = function(st) { return ["resolved","closed"].indexOf((st||"").toLowerCase()) >= 0; };
      var resolvedThisWeek = 0, resolvedLastWeek = 0, newThisWeek = 0, newLastWeek = 0;
      trendFilteredScoped.forEach(function(i) {
        if (i.c && isResolvedStatus(i.st)) { var ts = new Date(i.c).getTime(); if (ts >= thisStartTs && ts <= thisEndTs) resolvedThisWeek++; else if (ts >= lastStartTs && ts <= lastEndTs) resolvedLastWeek++; }
      });
      trendFilteredScoped.forEach(function(i) {
        var st = (i.st||"").toLowerCase(); if (st === "ignored" || st === "auto_ignored" || st === "suppressed") return;
        if (i.d) { var ts = new Date(i.d).getTime(); if (ts >= thisStartTs && ts <= thisEndTs) newThisWeek++; else if (ts >= lastStartTs && ts <= lastEndTs) newLastWeek++; }
      });
      var numBuckets = Math.max(1, Math.ceil(trendPeriodDays / bucketDays));
      var trends = [];
      for (var w = numBuckets - 1; w >= 0; w--) {
        var bucketEnd = new Date(now); bucketEnd.setDate(bucketEnd.getDate() - w * bucketDays); bucketEnd.setHours(23, 59, 59, 999);
        var bucketStart = new Date(bucketEnd); bucketStart.setDate(bucketStart.getDate() - (bucketDays - 1)); bucketStart.setHours(0, 0, 0, 0);
        var label = bucketStart.toLocaleDateString("en-US", { month: "short", day: "numeric" });
        if (bucketDays >= 30) label = bucketStart.toLocaleDateString("en-US", { month: "short", year: "2-digit" });
        var openAtWeek = trendFilteredScoped.filter(function(i) {
          var det = new Date(i.d); if (isNaN(det.getTime()) || det.getTime() > bucketEnd.getTime()) return false;
          var cls = i.c ? new Date(i.c) : null; return !cls || isNaN(cls.getTime()) || cls.getTime() > bucketEnd.getTime();
        });
        var weekOpen = openAtWeek.filter(function(i) { return isOpenStatus(i.st); });
        var c = countBySeverityTrend(weekOpen);
        trends.push({ date: label, critical: c.critical, high: c.high, medium: c.medium, low: c.low, total: countTotalTrend(weekOpen) });
      }
      trends = trends.filter(function(t){ return t.total > 0; });
      var trendCurr = trends.length > 0 ? trends[trends.length - 1].total : 0;
      var trendPrev = trends.length > 1 ? trends[trends.length - 2].total : 0;
      var resThis = resolvedThisWeek;
      var resLast = resolvedLastWeek;
      var newThis = newThisWeek;
      var newLast = newLastWeek;
      var openPct = trendPrev === 0 ? (trendCurr > 0 ? 100 : 0) : Math.round(((trendCurr - trendPrev) / trendPrev) * 100);
      var resolvedPct = resLast === 0 ? (resThis > 0 ? 100 : 0) : Math.round(((resThis - resLast) / resLast) * 100);
      var newPct = newLast === 0 ? (newThis > 0 ? 100 : 0) : Math.round(((newThis - newLast) / newLast) * 100);
      var trendTopBar = trendSection.querySelector(".trend-stacked-topbar");
      if (trendTopBar) {
        var setVal = function(sel, val, pct, isGood) { var el = trendTopBar.querySelector(sel); if (el) { el.textContent = val; var card = el.closest(".kpi-card"); var trendEl = card ? card.querySelector(".kpi-trend") : null; if (trendEl) { trendEl.textContent = (pct > 0 ? "+" : "") + pct + "%"; trendEl.style.color = isGood ? "#22c55e" : "#ef4444"; } } };
        setVal(".kpi-card:nth-child(1) .value", trendCurr.toLocaleString(), openPct, trendCurr <= trendPrev);
        setVal(".kpi-card:nth-child(2) .value", resThis.toLocaleString(), resolvedPct, resThis >= resLast);
        setVal(".kpi-card:nth-child(3) .value", newThis.toLocaleString(), newPct, newThis <= newLast);
        var d1 = trendTopBar.querySelector(".kpi-card:nth-child(1) .detail"); if (d1) d1.textContent = "vs " + trendPrev.toLocaleString() + " previous period";
        var d2 = trendTopBar.querySelector(".kpi-card:nth-child(2) .detail"); if (d2) d2.textContent = "vs " + resLast.toLocaleString() + " previous period";
        var d3 = trendTopBar.querySelector(".kpi-card:nth-child(3) .detail"); if (d3) d3.textContent = "vs " + newLast.toLocaleString() + " previous period";
      }
      var wrap = trendSection.querySelector(".viz-trend-stacked-wrap");
      if (wrap && trends.length > 0) {
        var w = 560; var h = 160; var maxTotal = Math.max(1, Math.max.apply(null, trends.map(function(t) { return t.total; })));
        var yMax = maxTotal <= 10 ? 10 : maxTotal <= 50 ? 50 : maxTotal <= 200 ? 200 : maxTotal <= 500 ? 500 : Math.ceil(maxTotal / 200) * 200;
        var pad = { left: 76, right: 40, top: 24, bottom: 28 }; var chartW = w - pad.left - pad.right; var chartH = h - pad.top - pad.bottom;
        var n = trends.length; var gap = 2; var barW = Math.max(4, (chartW - (n - 1) * gap) / n);
        var colors = ["#ef4444", "#f97316", "#3b82f6", "#14b8a6"]; var keys = ["critical", "high", "medium", "low"];
        var barRects = []; var tooltips = []; var segIds = [];
        for (var i = 0; i < n; i++) {
          var t = trends[i]; var x = pad.left + i * (barW + gap); var y = pad.top + chartH;
          for (var ki = 0; ki < 4; ki++) {
            var cnt = t[keys[ki]] || 0; if (cnt <= 0) continue;
            var segH = (cnt / yMax) * chartH; y -= segH;
            var segHeight = Math.max(1, segH); var segId = "t" + i + "-" + ki; segIds.push(segId);
            barRects.push('<g class="trend-segment"><rect data-segment="' + segId + '" x="' + x + '" y="' + y + '" width="' + barW + '" height="' + segHeight + '" fill="' + colors[ki] + '" rx="0"/></g>');
            var tooltipText = (t.date + ": " + keys[ki] + " " + cnt).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            var tooltipW = Math.max(64, Math.ceil(tooltipText.length * 5.5) + 20); var cx = x + barW / 2; var ty = Math.max(pad.top - 8, y - 6);
            tooltips.push('<g class="trend-segment-tooltip" data-for="' + segId + '" transform="translate(' + cx + ',' + ty + ')" text-anchor="middle"><rect x="' + (-tooltipW/2) + '" y="-10" width="' + tooltipW + '" height="16" fill="rgba(15,23,42,0.94)" rx="4" stroke="#64748b" stroke-width="0.5"/><text x="0" y="2" font-size="9" fill="#fff">' + tooltipText + '</text></g>');
          }
        }
        var axisLine = '<line x1="' + pad.left + '" y1="' + (pad.top + chartH) + '" x2="' + (pad.left + chartW) + '" y2="' + (pad.top + chartH) + '" stroke="#e2e8f0" stroke-width="1"/>';
        var yAxisLine = '<line x1="' + (pad.left + chartW) + '" y1="' + pad.top + '" x2="' + (pad.left + chartW) + '" y2="' + (pad.top + chartH) + '" stroke="#e2e8f0" stroke-width="1"/>';
        var yTicks = [0, Math.ceil(yMax/4), Math.ceil(yMax/2), Math.ceil(3*yMax/4), yMax].filter(function(v,i,a){ return a.indexOf(v) === i; });
        var yLabels = yTicks.map(function(v) { var y = pad.top + chartH - (v/yMax)*chartH; return '<text x="' + (pad.left + chartW + 6) + '" y="' + (y + 4) + '" text-anchor="start" font-size="10" fill="#64748b">' + v + '</text>'; }).join("");
        var maxXLabels = 14;
        var xLabelIndices = [];
        if (n <= maxXLabels) { for (var xi = 0; xi < n; xi++) xLabelIndices.push(xi); }
        else { var step = (n - 1) / (maxXLabels - 1); for (var xk = 0; xk < maxXLabels; xk++) xLabelIndices.push(Math.round(xk * step)); }
        var xLabels = xLabelIndices.map(function(i) { var t = trends[i]; var x = pad.left + i * (barW + gap) + barW / 2; return '<text x="' + x + '" y="' + (h - 6) + '" text-anchor="middle" font-size="9" fill="#64748b">' + t.date + '</text>'; }).join("");
        var legend = keys.map(function(lbl, i) { var ly = pad.top - 2 + i * 14; return '<circle cx="10" cy="' + ly + '" r="4" fill="' + colors[i] + '"/><text x="20" y="' + (ly + 4) + '" text-anchor="start" font-size="10" fill="#475569">' + lbl + '</text>'; }).join("");
        var hoverCss = segIds.map(function(id) { return '.viz-trend-stacked-container:has(.viz-trend-stacked [data-segment="' + id + '"]:hover) .viz-trend-stacked-overlay [data-for="' + id + '"]{opacity:1}'; }).join("");
        var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" class="viz-trend-stacked" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' + legend + axisLine + yAxisLine + barRects.join("") + yLabels + xLabels + '</svg>';
        var overlay = '<svg viewBox="0 0 ' + w + ' ' + h + '" class="viz-trend-stacked-overlay" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" style="position:absolute;top:0;left:0;pointer-events:none"><defs><style>.trend-segment-tooltip{opacity:0;transition:opacity .03s ease-out}' + hoverCss + '</style></defs><g class="trend-tooltip-layer">' + tooltips.join("") + '</g></svg>';
        wrap.innerHTML = '<div class="viz-trend-stacked-container" style="position:relative;width:100%;height:100%;min-height:140px">' + svg + overlay + '</div>';
      } else if (wrap) {
        wrap.innerHTML = '<div class="viz-trend-empty" style="display:flex;align-items:center;justify-content:center;min-height:140px;color:#64748b;font-size:14px">No findings in selected period</div>';
      }
    });
    document.querySelectorAll("[data-report-aggregate=severity-distribution]").forEach(function(section) {
      var donutWrap = section.querySelector(".severity-donut-wrap");
      var barEl = section.querySelector(".severity-bar");
      var legendEl = section.querySelector(".severity-legend");
      var total = useServerCounts ? reportData.totalOpen : countTotal(openIssues);
      var primary = reportData.primaryColor || "#0ea5e9";
      var colors = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: primary };
      if (donutWrap) {
        var size = 100; var cx = size/2; var r = size/2 - 4;
        if (total === 0) {
          donutWrap.innerHTML = '<svg viewBox="0 0 ' + size + ' ' + size + '" class="viz-donut" width="' + size + '" height="' + size + '"><circle cx="' + cx + '" cy="' + cx + '" r="' + r + '" fill="#f1f5f9"/><text x="' + cx + '" y="' + (cx+4) + '" text-anchor="middle" font-size="12" fill="#64748b">0</text></svg>';
        } else {
          var keys = ["critical","high","medium","low"];
          var offset = 0;
          var segs = keys.map(function(k) {
            var cnt = counts[k] || 0;
            if (cnt <= 0) return "";
            var pct = cnt / total;
            var dash = pct * 100;
            var col = colors[k] || primary;
            var seg = '<circle cx="' + cx + '" cy="' + cx + '" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="8" pathLength="100" stroke-dasharray="' + dash + ' ' + (100-dash) + '" stroke-dashoffset="' + (-offset) + '" transform="rotate(-90 ' + cx + ' ' + cx + ')"/>';
            offset += dash;
            return seg;
          }).join("");
          donutWrap.innerHTML = '<svg viewBox="0 0 ' + size + ' ' + size + '" class="viz-donut" width="' + size + '" height="' + size + '"><circle cx="' + cx + '" cy="' + cx + '" r="' + r + '" fill="none" stroke="#e2e8f0" stroke-width="8" pathLength="100"/>' + segs + '<text x="' + cx + '" y="' + (cx+5) + '" text-anchor="middle" font-size="14" font-weight="700" fill="#0f172a">' + total + '</text></svg>';
        }
      }
      if (barEl && total > 0) {
        var barParts = ["critical","high","medium","low"].map(function(k) {
          var cnt = counts[k] || 0;
          return cnt > 0 ? '<div style="width:' + ((cnt/total)*100) + '%;background:' + (colors[k]||primary) + '">' + cnt + '</div>' : "";
        }).join("");
        barEl.innerHTML = barParts || '<div style="width:100%;background:#e2e8f0;color:#94a3b8">No open issues</div>';
      } else if (barEl) {
        barEl.innerHTML = '<div style="width:100%;background:#e2e8f0;color:#94a3b8">No open issues</div>';
      }
      if (legendEl) {
        legendEl.innerHTML = '<span><span class="dot" style="background:#ef4444"></span> Critical: ' + (counts.critical||0) + '</span><span><span class="dot" style="background:#f97316"></span> High: ' + (counts.high||0) + '</span><span><span class="dot" style="background:#eab308"></span> Medium: ' + (counts.medium||0) + '</span><span><span class="dot" style="background:' + primary + '"></span> Low: ' + (counts.low||0) + '</span>';
      }
    });
    document.querySelectorAll("[data-report-aggregate=severity-pills]").forEach(function(section) {
      section.querySelectorAll(".sev-pill[data-severity]").forEach(function(pill) {
        var sev = pill.getAttribute("data-severity");
        var cnt = counts[sev] || 0;
        var label = sev ? sev.charAt(0).toUpperCase() + sev.slice(1) : "";
        pill.textContent = label + " " + cnt;
      });
    });
    (function() {
      var scannerColors = ["#0ea5e9", "#8b5cf6", "#ec4899", "#f97316", "#22c55e", "#64748b", "#eab308", "#94a3b8"];
      function displaySourceName(n) { var s = (n || "").replace(/^(vat-local-|folder-scan-)/i, "").trim(); return s || n || ""; }
      var scannerMap = {};
      var list = countMode === "groups" ? (function() {
        var byGroup = {};
        return openIssues.filter(function(i) {
          var gid = i.g != null ? i.g : (i.r + "|" + (i.d || "") + "|" + (i.s || ""));
          if (byGroup[gid]) return false;
          byGroup[gid] = true;
          return true;
        });
      })() : openIssues;
      list.forEach(function(i) {
        var scanner = displaySourceName(i.scanner) || "Unknown";
        if (!scannerMap[scanner]) scannerMap[scanner] = 0;
        scannerMap[scanner]++;
      });
      var scanners = Object.keys(scannerMap).map(function(k) { return { scanner: k, count: scannerMap[k] }; }).sort(function(a, b) { return b.count - a.count; });
      var sourceTotal = scanners.reduce(function(s, sc) { return s + sc.count; }, 0);
      document.querySelectorAll("[data-report-aggregate=source-distribution]").forEach(function(section) {
        var donutWrap = section.querySelector(".severity-donut-wrap");
        var barEl = section.querySelector(".severity-bar");
        var legendEl = section.querySelector(".severity-legend");
        var size = 100; var cx = size / 2; var r = size / 2 - 4;
        if (donutWrap) {
          if (sourceTotal === 0 || scanners.length === 0) {
            donutWrap.innerHTML = '<svg viewBox="0 0 ' + size + ' ' + size + '" class="viz-donut" width="' + size + '" height="' + size + '"><circle cx="' + cx + '" cy="' + cx + '" r="' + r + '" fill="#f1f5f9"/><text x="' + cx + '" y="' + (cx + 4) + '" text-anchor="middle" font-size="12" fill="#64748b">0</text></svg>';
          } else {
            var offset = 0;
            var segs = scanners.slice(0, 8).map(function(s, i) {
              var pct = s.count / sourceTotal;
              var dash = pct * 100;
              var col = scannerColors[i % scannerColors.length];
              var seg = '<circle cx="' + cx + '" cy="' + cx + '" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="8" pathLength="100" stroke-dasharray="' + dash + ' ' + (100 - dash) + '" stroke-dashoffset="' + (-offset) + '" transform="rotate(-90 ' + cx + ' ' + cx + ')"/>';
              offset += dash;
              return seg;
            }).join("");
            donutWrap.innerHTML = '<svg viewBox="0 0 ' + size + ' ' + size + '" class="viz-donut" width="' + size + '" height="' + size + '"><circle cx="' + cx + '" cy="' + cx + '" r="' + r + '" fill="none" stroke="#e2e8f0" stroke-width="8" pathLength="100"/>' + segs + '<text x="' + cx + '" y="' + (cx + 5) + '" text-anchor="middle" font-size="14" font-weight="700" fill="#0f172a">' + sourceTotal + '</text></svg>';
          }
        }
        if (barEl && sourceTotal > 0 && scanners.length > 0) {
          var barParts = scanners.slice(0, 8).map(function(s, i) {
            var pct = (s.count / sourceTotal) * 100;
            var color = scannerColors[i % scannerColors.length];
            return pct > 0 ? '<div style="width:' + pct + '%;background:' + color + '">' + s.count + '</div>' : "";
          }).join("");
          barEl.innerHTML = barParts || '<div style="width:100%;background:#e2e8f0;color:#94a3b8">No open issues</div>';
        } else if (barEl) {
          barEl.innerHTML = '<div style="width:100%;background:#e2e8f0;color:#94a3b8">No open issues</div>';
        }
        if (legendEl && scanners.length > 0) {
          legendEl.innerHTML = scanners.slice(0, 8).map(function(s, i) {
            return '<span><span class="dot" style="background:' + scannerColors[i % scannerColors.length] + '"></span> ' + s.scanner + ': ' + s.count + '</span>';
          }).join("");
        } else if (legendEl) {
          legendEl.innerHTML = '<span>No sources</span>';
        }
      });
    })();
    document.querySelectorAll("[data-report-aggregate=risk-gauge]").forEach(function(section) {
      var gaugeWrap = section.querySelector(".board-hero-viz");
      if (!gaugeWrap) return;
      var size = parseInt(section.getAttribute("data-gauge-size") || "120", 10) || 120;
      var fillColor = riskLevel === "Critical" ? "#ef4444" : riskLevel === "High" ? "#f97316" : riskLevel === "Medium" ? "#eab308" : "#22c55e";
      var pct = Math.min(100, Math.max(0, riskScore)) / 100;
      var cx = size / 2; var r = size / 2 - 6;
      gaugeWrap.innerHTML = '<svg viewBox="0 0 ' + size + ' ' + size + '" class="viz-gauge" width="' + size + '" height="' + size + '"><path d="M 6 ' + cx + ' A ' + r + ' ' + r + ' 0 0 1 ' + (size - 6) + ' ' + cx + '" fill="none" stroke="#e2e8f0" stroke-width="8" pathLength="100"/><path d="M 6 ' + cx + ' A ' + r + ' ' + r + ' 0 0 1 ' + (size - 6) + ' ' + cx + '" fill="none" stroke="' + fillColor + '" stroke-width="8" pathLength="100" stroke-dasharray="' + (pct * 100) + ' 100" stroke-linecap="round"/><text x="' + cx + '" y="' + (cx + 4) + '" text-anchor="middle" font-size="18" font-weight="700" fill="' + fillColor + '">' + riskScore + '</text></svg>';
    });
    document.querySelectorAll("[data-report-aggregate=asset-mix]").forEach(function(section) {
      var body = section.querySelector(".asset-mix-body");
      if (!body) return;
      var mix = { code: 0, container: 0, vm: 0, package: 0, other: 0 };
      if (countMode === "groups") {
        var byGroup = {};
        openIssues.forEach(function(i) {
          var gid = i.g != null ? i.g : (i.r + "|" + i.d + "|" + (i.s || ""));
          if (byGroup[gid]) return;
          byGroup[gid] = true;
          var at = i.at || "Other";
          if (at === "Code") mix.code++;
          else if (at === "Container") mix.container++;
          else if (at === "VM") mix.vm++;
          else if (at === "Package") mix.package++;
          else mix.other++;
        });
      } else {
        openIssues.forEach(function(i) {
          var at = i.at || "Other";
          if (at === "Code") mix.code++;
          else if (at === "Container") mix.container++;
          else if (at === "VM") mix.vm++;
          else if (at === "Package") mix.package++;
          else mix.other++;
        });
      }
      var total = mix.code + mix.container + mix.vm + mix.package + mix.other;
      var size = parseInt(section.getAttribute("data-asset-mix-size") || "100", 10) || 100;
      var primary = reportData.primaryColor || "#0ea5e9";
      if (total === 0) {
        body.innerHTML = '<p class="activity-empty">No open issues to categorize.</p>';
        return;
      }
      var categories = [
        { count: mix.code, label: "Code" },
        { count: mix.container, label: "Container" },
        { count: mix.vm, label: "VM" },
        { count: mix.package, label: "Package" },
        { count: mix.other, label: "Other" }
      ].filter(function(s) { return s.count > 0; });
      if (categories.length === 1) {
        body.innerHTML = '<p class="narrative-line">All ' + total + ' issues are from ' + categories[0].label.toLowerCase() + ' repositories.</p>';
        return;
      }
      var legend = [
        { count: mix.code, label: "Code", color: primary },
        { count: mix.container, label: "Container", color: "#8b5cf6" },
        { count: mix.vm, label: "VM", color: "#ec4899" },
        { count: mix.package, label: "Package", color: "#22c55e" },
        { count: mix.other, label: "Other", color: "#94a3b8" }
      ].filter(function(s) { return s.count > 0; }).map(function(s) {
        return '<span><span class="dot" style="background:' + s.color + '"></span> ' + s.label + ' (' + s.count + ')</span>';
      }).join("");
      var segments = [
        { count: mix.code, color: primary },
        { count: mix.container, color: "#8b5cf6" },
        { count: mix.vm, color: "#ec4899" },
        { count: mix.package, color: "#22c55e" },
        { count: mix.other, color: "#94a3b8" }
      ].filter(function(s) { return s.count > 0; });
      var cx = size / 2; var r = size / 2 - 4; var offset = 0;
      var circles = segments.map(function(s) {
        var dash = (s.count / total) * 100;
        var seg = '<circle cx="' + cx + '" cy="' + cx + '" r="' + r + '" fill="none" stroke="' + s.color + '" stroke-width="8" pathLength="100" stroke-dasharray="' + dash + ' ' + (100 - dash) + '" stroke-dashoffset="' + (-offset) + '" transform="rotate(-90 ' + cx + ' ' + cx + ')"/>';
        offset += dash;
        return seg;
      }).join("");
      var donutSvg = '<svg viewBox="0 0 ' + size + ' ' + size + '" class="viz-donut" width="' + size + '" height="' + size + '"><circle cx="' + cx + '" cy="' + cx + '" r="' + r + '" fill="none" stroke="#e2e8f0" stroke-width="8" pathLength="100"/>' + circles + '<text x="' + cx + '" y="' + (cx + 5) + '" text-anchor="middle" font-size="14" font-weight="700" fill="#0f172a">' + total + '</text></svg>';
      body.innerHTML = '<div class="severity-with-donut"><div class="severity-donut-wrap">' + donutSvg + '</div><div class="severity-bar-legend severity-legend">' + legend + '</div></div>';
    });
  }
  var CHIP_COLLAPSE_THRESHOLD = 6;
  function renderChips() {
    var parts = [];
    ["severity","assetType","asset","branch"].forEach(function(dim) {
      if (!state[dim] || state[dim].size === 0) return;
      var opts = cfg[cfgKey[dim]] || [];
      if (state[dim].size >= opts.length) return;
      var n = state[dim].size;
      if (n > CHIP_COLLAPSE_THRESHOLD) {
        parts.push('<span class="report-filter-chip report-filter-chip-summary" data-dim="' + dim + '">' + labels[dim] + ': ' + n + ' selected <button type="button" class="report-filter-chip-remove" aria-label="Clear selection">×</button></span>');
      } else {
        state[dim].forEach(function(v) {
          var label = dim === "severity" ? (v.charAt(0).toUpperCase() + v.slice(1)) : (v.length > 28 ? v.slice(0,25) + "…" : v);
          parts.push('<span class="report-filter-chip" data-dim="' + dim + '" data-value="' + v.replace(/"/g,"&quot;") + '">' + labels[dim] + ': ' + label.replace(/</g,"&lt;") + ' <button type="button" class="report-filter-chip-remove" aria-label="Remove">×</button></span>');
        });
      }
    });
    var html = parts.join("");
    bars.forEach(function(bar) {
      var chips = bar.querySelector(".report-filter-chips");
      if (!chips) return;
      chips.innerHTML = html;
      chips.querySelectorAll(".report-filter-chip-remove").forEach(function(btn) {
        btn.addEventListener("click", function() {
          var chip = this.closest(".report-filter-chip");
          var dim = chip.getAttribute("data-dim");
          var val = chip.getAttribute("data-value");
          if (chip.classList.contains("report-filter-chip-summary")) {
            state[dim] = dim === "severity" ? new Set() : new Set(cfg[cfgKey[dim]] || []);
          } else {
            state[dim].delete(val);
          }
          syncCheckboxes();
          applyFilter();
        });
      });
    });
  }
  function syncCheckboxes() {
    bars.forEach(function(bar) {
      bar.querySelectorAll("input[data-filter]").forEach(function(cb) {
        var dim = cb.getAttribute("data-filter");
        cb.checked = state[dim] && state[dim].has(cb.value);
      });
    });
  }
  var filterSearchTimer = null;
  var filterSearchPending = null;
  function filterSearch(bar, dim, q) {
    q = (q || "").toLowerCase().trim();
    filterSearchPending = { bar: bar, dim: dim, q: q };
    if (filterSearchTimer) clearTimeout(filterSearchTimer);
    filterSearchTimer = setTimeout(function() {
      filterSearchTimer = null;
      var p = filterSearchPending;
      if (!p) return;
      var opts = p.bar.querySelectorAll('.report-filter-panel[data-panel="' + p.dim + '"] .report-filter-option');
      for (var i = 0; i < opts.length; i++) {
        var opt = opts[i];
        var val = (opt.getAttribute("data-value") || "").toLowerCase();
        opt.style.display = !p.q || val.indexOf(p.q) >= 0 ? "" : "none";
      }
    }, 50);
  }
  bars.forEach(function(bar) {
    bar.querySelectorAll(".report-filter-trigger").forEach(function(btn) {
      btn.addEventListener("click", function(e) {
        e.stopPropagation();
        var dd = this.closest(".report-filter-dd");
        var open = dd.classList.contains("open");
        bar.querySelectorAll(".report-filter-dd").forEach(function(d) { d.classList.remove("open"); });
        if (!open) dd.classList.add("open");
      });
    });
    bar.querySelectorAll(".report-filter-search").forEach(function(inp) {
      inp.addEventListener("input", function() {
        filterSearch(bar, this.getAttribute("data-search"), this.value);
      });
      inp.addEventListener("keydown", function(e) { e.stopPropagation(); });
    });
    bar.querySelectorAll("input[data-filter]").forEach(function(cb) {
      cb.addEventListener("change", function() {
        var dim = this.getAttribute("data-filter");
        if (this.checked) state[dim].add(this.value); else state[dim].delete(this.value);
        applyFilter();
      });
    });
    bar.querySelectorAll("[data-select-all]").forEach(function(btn) {
      btn.addEventListener("click", function() {
        var dim = this.getAttribute("data-select-all");
        state[dim] = new Set(cfg[cfgKey[dim]] || []);
        syncCheckboxes();
        applyFilter();
      });
    });
    bar.querySelectorAll("[data-clear]").forEach(function(btn) {
      if (btn.id === "report-filter-clear-all") return;
      btn.addEventListener("click", function() {
        var dim = this.getAttribute("data-clear");
        state[dim] = new Set();
        syncCheckboxes();
        applyFilter();
      });
    });
  });
  document.addEventListener("click", function(e) {
    var inAnyBar = bars.some(function(bar) { return bar.contains(e.target); });
    if (!inAnyBar) bars.forEach(function(bar) { bar.querySelectorAll(".report-filter-dd").forEach(function(d) { d.classList.remove("open"); }); });
  });
  bars.forEach(function(bar) {
    var clearAllBtn = bar.querySelector(".report-filter-clear");
    if (clearAllBtn) clearAllBtn.addEventListener("click", function() {
      state.severity = new Set();
      state.assetType = new Set(cfg.assetTypes || []);
      state.asset = new Set(cfg.assets || []);
      state.branch = new Set(cfg.branches || []);
      syncCheckboxes();
      applyFilter();
    });
  });
  document.querySelectorAll(".trend-filter-pill").forEach(function(pill) {
    var trigger = pill.querySelector(".trend-filter-pill-trigger");
    var panel = pill.querySelector(".trend-filter-pill-panel");
    if (!trigger || !panel) return;
    trigger.addEventListener("click", function(e) {
      e.stopPropagation();
      var open = pill.classList.contains("open");
      document.querySelectorAll(".trend-filter-pill").forEach(function(p) { p.classList.remove("open"); });
      if (!open) pill.classList.add("open");
    });
    panel.querySelectorAll(".trend-filter-pill-option").forEach(function(opt) {
      opt.addEventListener("click", function(e) {
        e.stopPropagation();
        var dim = pill.getAttribute("data-trend-dim");
        var val = opt.getAttribute("data-value");
        if (dim === "severity" || dim === "types") return;
        trigger.innerHTML = val + ' <span class="trend-filter-arrow">▾</span>';
        var section = pill.closest("[data-report-aggregate=trend-stacked]");
        if (section) {
          if (dim === "issues") section.dataset.trendCountMode = val === "Individual Issues" ? "instances" : "groups";
          if (dim === "daterange") section.dataset.trendPeriodDays = val === "Last 7 days" ? "7" : val === "Last 30 days" ? "30" : val === "Last 90 days" ? "90" : val === "Last 180 days" ? "180" : "365";
          if (dim === "granularity") section.dataset.trendGranularity = (val || "Weekly").toLowerCase();
        }
        pill.classList.remove("open");
        if (reportData) updateAggregateWidgets();
      });
    });
    panel.querySelectorAll("input[data-trend-severity], input[data-trend-type]").forEach(function(cb) {
      cb.addEventListener("change", function() {
        var section = pill.closest("[data-report-aggregate=trend-stacked]");
        if (!section) return;
        var dim = pill.getAttribute("data-trend-dim");
        var checkboxes = panel.querySelectorAll("input[data-trend-severity], input[data-trend-type]");
        var selected = [];
        checkboxes.forEach(function(c) { if (c.checked) selected.push(c.value); });
        var allChecked = selected.length === checkboxes.length;
        section.dataset["trend" + (dim === "severity" ? "Severities" : "Types")] = allChecked ? "" : selected.join("|");
        var label = allChecked ? (dim === "severity" ? "All severities" : "All types") : selected.length + " selected";
        trigger.innerHTML = label + ' <span class="trend-filter-arrow">▾</span>';
        if (reportData) updateAggregateWidgets();
      });
    });
    panel.querySelectorAll(".trend-filter-select-all").forEach(function(btn) {
      btn.addEventListener("click", function(e) {
        e.stopPropagation();
        var cbs = panel.querySelectorAll("input[type=checkbox]");
        var allChecked = Array.prototype.every.call(cbs, function(c) { return c.checked; });
        cbs.forEach(function(c) { c.checked = !allChecked; });
        cbs.forEach(function(c) { c.dispatchEvent(new Event("change")); });
      });
    });
  });
  document.addEventListener("click", function() {
    document.querySelectorAll(".trend-filter-pill").forEach(function(p) { p.classList.remove("open"); });
  });
  updateCounts();
  syncCheckboxes();
  applyFilterImmediate();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
</script>`
  );
}

function buildReportDocumentShell(
  title: string,
  workspace: string,
  date: string,
  dateRange: string | null,
  body: string,
  branding: ReportBranding,
  filterConfig?: {
    severities: string[];
    assetTypes: string[];
    assets: string[];
    branches: string[];
  } | null,
  reportData?: {
    issues: ReportDataIssue[];
    issuesForTrend?: ReportDataIssue[];
    dateFrom: string | null;
    dateTo: string | null;
    primaryColor: string;
    countMode?: string;
    containers?: string[];
    vmNames?: string[];
  } | null,
): string {
  const brand = branding;
  const hasBrand = !!(brand.companyName || brand.logoUrl);
  const pageTitle = brand.companyName
    ? `${title} | ${brand.companyName}`
    : title;
  const brandHeaderHtml = hasBrand
    ? `<div class="brand-header">
    <div class="brand-header-left">
      ${
        brand.logoUrl
          ? `<img src="${brand.logoUrl}" alt="${brand.companyName}" class="brand-logo" />`
          : ""
      }
      <div>
        ${
          brand.companyName
            ? `<div class="brand-name">${brand.companyName}</div>`
            : ""
        }
        ${
          brand.tagline
            ? `<div class="brand-tagline">${brand.tagline}</div>`
            : ""
        }
      </div>
    </div>
    <div class="report-title-block">
      <div class="report-title">${title}</div>
      <div class="report-workspace">${workspace}</div>
    </div>
  </div>`
    : `<div class="brand-header brand-header-minimal">
    <div class="report-title-block" style="flex:1;">
      <div class="report-title">${title}</div>
      <div class="report-workspace">${workspace}</div>
    </div>
  </div>`;
  const footerBrandText = brand.companyName
    ? brand.companyName + (brand.tagline ? ` — ${brand.tagline}` : "")
    : "Vulnerability Report";
  const footerBrandHtml =
    brand.websiteUrl && brand.companyName
      ? `<a href="${brand.websiteUrl}" target="_blank" rel="noopener">${footerBrandText}</a>`
      : footerBrandText;
  const bodyBg = brand.bodyBg ?? "#fff";
  const bodyFg = brand.bodyFg ?? "#1a1a2e";
  const borderColor = brand.borderColor ?? "#e2e8f0";
  const mutedColor = brand.mutedColor ?? "#64748b";
  const cardBg = brand.cardBg ?? "transparent";
  const tableHeaderBg = brand.tableHeaderBg ?? "#f8fafc";
  const tableRowAltBg = brand.tableRowAltBg ?? "#fafbfc";
  const headingColor = brand.bodyFg ?? "#0f172a";
  const trackBg = brand.bodyBg ? brand.borderColor ?? "#334155" : "#f1f5f9";
  const notesBg = brand.bodyBg ? "rgba(251,191,36,0.15)" : "#fffbeb";
  const notesBorder = brand.bodyBg ? "rgba(251,191,36,0.3)" : "#fef08a";
  const filterNoteBg = brand.cardBg ?? "#f8fafc";
  const advisoryCodeBg = brand.cardBg ? "rgba(255,255,255,0.08)" : "#f1f5f9";
  const badgeLowBg = brand.cardBg ? "rgba(255,255,255,0.08)" : "#f0f9ff";
  const badgeLowBorder = brand.cardBg ? brand.primaryColor : "#bae6fd";
  const footerFg = brand.mutedColor ?? "#64748b";
  const footerBrandFg = brand.bodyFg ?? "#0f172a";
  const footerMetaFg = brand.mutedColor ?? "#94a3b8";

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>${pageTitle}</title>
<style>
  @page { margin: 32px; size: A4; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: ${bodyFg}; background: ${bodyBg}; font-size: clamp(11px, 1.2vw + 0.5rem, 14px); line-height: 1.5; padding: 40px; }
  .brand-header { background: ${brand.headerBgColor}; color: ${
    brand.headerTextColor
  }; padding: 16px 24px; margin: -40px -40px 24px -40px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; }
  .brand-header-minimal .report-title-block { text-align: left; }
  .brand-header-left { display: flex; align-items: center; gap: 16px; }
  .brand-logo { height: 28px; width: auto; display: block; }
  .brand-name { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; }
  .brand-tagline { font-size: 10px; opacity: 0.85; margin-top: 2px; }
  .report-title-block { text-align: right; }
  .report-title-block .report-title { font-size: 16px; font-weight: 600; }
  .report-title-block .report-workspace { font-size: 11px; opacity: 0.9; }
  .header { border-bottom: 3px solid ${
    brand.primaryColor
  }; padding-bottom: 16px; margin-bottom: 24px; }
  .header .meta { display: flex; gap: 24px; margin-top: 8px; color: ${mutedColor}; font-size: 11px; }
  .section { margin-bottom: 24px; page-break-inside: avoid; }
  .section h2 { font-size: clamp(13px, 1.2vw + 0.5rem, 18px); font-weight: 600; color: ${headingColor}; border-bottom: 1px solid ${borderColor}; padding-bottom: 6px; margin-bottom: 12px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .kpi-card { border: 1px solid ${borderColor}; border-radius: 10px; padding: 18px 16px; text-align: center; background: ${cardBg}; display: flex; flex-direction: column; align-items: center; gap: 4px; min-height: 0; }
  .kpi-card .kpi-label, .kpi-card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; color: ${mutedColor}; }
  .kpi-card .kpi-value, .kpi-card .value { font-size: clamp(28px, 3vw + 1rem, 42px); font-weight: 700; line-height: 1.1; letter-spacing: -0.02em; }
  .kpi-card .kpi-suffix { font-size: 0.45em; font-weight: 500; color: ${mutedColor}; margin-left: 1px; }
  .kpi-card .kpi-trend { font-size: 11px; font-weight: 600; margin-top: 2px; }
  .kpi-card .kpi-trend-inline { font-size: 11px; font-weight: 600; margin-left: 6px; vertical-align: middle; }
  .kpi-card .kpi-detail, .kpi-card .detail { font-size: 11px; color: ${mutedColor}; font-weight: 500; }
  .severity-bar { display: flex; height: 24px; border-radius: 6px; overflow: hidden; margin-bottom: 8px; }
  .severity-bar div { display: flex; align-items: center; justify-content: center; color: #fff; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); font-weight: 600; }
  .severity-legend { display: flex; gap: 16px; font-size: clamp(10px, 1.1vw + 0.4rem, 13px); }
  .severity-legend span { display: flex; align-items: center; gap: 4px; }
  .severity-legend .dot { width: 10px; height: 10px; border-radius: 3px; }
  .critical-val { color: #ef4444; }
  .high-val { color: #f97316; }
  .medium-val { color: #eab308; }
  .low-val { color: ${brand.primaryColor}; }
  table { width: 100%; border-collapse: collapse; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); }
  th { text-align: left; padding: 6px 8px; background: ${tableHeaderBg}; border-bottom: 2px solid ${borderColor}; font-weight: 600; color: ${mutedColor}; }
  th.sortable { cursor: pointer; user-select: none; }
  th.sortable:hover { text-decoration: underline; }
  td { padding: 6px 8px; border-bottom: 1px solid ${borderColor}; }
  tr:nth-child(even) { background: ${tableRowAltBg}; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: clamp(9px, 1vw + 0.3rem, 12px); font-weight: 600; text-transform: uppercase; }
  .badge-critical { background: #fef2f2; color: #ef4444; border: 1px solid #fecaca; }
  .badge-high { background: #fff7ed; color: #f97316; border: 1px solid #fed7aa; }
  .badge-medium { background: #fefce8; color: #ca8a04; border: 1px solid #fef08a; }
  .badge-low { background: ${badgeLowBg}; color: ${
    brand.primaryColor
  }; border: 1px solid ${badgeLowBorder}; }
  .mono { font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace; }
  .text-right { text-align: right; }
  .filter-note { font-size: 11px; color: ${mutedColor}; margin-bottom: 12px; padding: 6px 10px; background: ${filterNoteBg}; border-radius: 6px; border: 1px solid ${borderColor}; }
  .notes { font-size: 11px; color: ${mutedColor}; margin-bottom: 16px; padding: 10px; background: ${notesBg}; border-radius: 6px; border: 1px solid ${notesBorder}; }
  .footer { border-top: 2px solid ${borderColor}; padding-top: 12px; margin-top: 24px; color: ${footerFg}; font-size: 10px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
  .footer-brand { font-weight: 600; color: ${footerBrandFg}; }
  .footer-brand a { color: ${
    brand.linkColor ?? brand.primaryColor
  }; text-decoration: none; }
  .footer-meta { color: ${footerMetaFg}; }
  .narrative-line { font-size: 11px; color: ${mutedColor}; margin-bottom: 12px; }
  .board-hero { display: flex; align-items: center; justify-content: center; gap: 24px; flex-wrap: wrap; padding: 16px 0; }
  .board-hero-viz { flex-shrink: 0; }
  .board-hero-text { text-align: center; }
  .board-risk-score { font-size: clamp(36px, 4vw + 1rem, 64px); font-weight: 800; line-height: 1; letter-spacing: -0.02em; }
  .board-risk-score .kpi-trend-inline { font-size: 11px; font-weight: 600; margin-left: 6px; vertical-align: middle; }
  .board-risk-max { font-size: clamp(16px, 1.5vw + 0.5rem, 24px); font-weight: 500; color: ${mutedColor}; margin-left: 2px; }
  .board-risk-level { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: ${mutedColor}; margin-top: 4px; }
  .board-narrative { font-size: 13px; color: ${mutedColor}; max-width: 420px; margin: 12px auto 0; line-height: 1.5; }
  .severity-with-donut { display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
  .severity-donut-wrap { flex-shrink: 0; }
  .severity-bar-legend { flex: 1; min-width: 200px; }
  .viz-donut, .viz-gauge { display: block; }
  .viz-trend-wrap { margin-bottom: 12px; }
  .viz-trend-stacked-wrap { width: 100%; min-width: 0; min-height: 140px; display: block; }
  .viz-trend-stacked-container { display: block; width: 100%; height: 100%; }
  .viz-trend-stacked { display: block; width: 100%; height: 100%; vertical-align: top; }
  .viz-trend-stacked-overlay { display: block; }
  .trend-segment { cursor: default; }
  .viz-sparkline { display: block; }
  .viz-aging-bars { margin-bottom: 12px; }
  .aging-bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); }
  .aging-bar-label { width: 72px; color: ${mutedColor}; }
  .aging-bar-track { flex: 1; max-width: 200px; height: 14px; background: ${trackBg}; border-radius: 6px; overflow: hidden; }
  .aging-bar-fill { height: 100%; border-radius: 6px; min-width: 4px; }
  .aging-bar-num { width: 28px; text-align: right; font-weight: 600; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); }
  .viz-repo-bars { margin-bottom: 12px; }
  .repo-bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 5px; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); }
  .repo-bar-label { width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: ${mutedColor}; }
  .repo-bar-track { width: 120px; height: 10px; background: ${trackBg}; border-radius: 4px; overflow: hidden; }
  .repo-bar-fill { height: 100%; border-radius: 4px; background: #94a3b8; }
  .repo-bar-fill.repo-bar-high { background: #f97316; }
  .repo-bar-fill.repo-bar-critical { background: #ef4444; }
  .repo-bar-num { width: 32px; text-align: right; font-weight: 600; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); }
  .viz-mttr-bars { margin-bottom: 12px; }
  .mttr-bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); }
  .mttr-bar-track { width: 120px; height: 12px; background: ${trackBg}; border-radius: 4px; overflow: hidden; }
  .mttr-bar-fill { height: 100%; border-radius: 4px; }
  .mttr-bar-num { width: 36px; text-align: right; font-weight: 600; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); }
  .severity-compact .severity-inline { display: flex; flex-wrap: wrap; gap: 8px; }
  .sev-pill { font-size: 10px; font-weight: 600; padding: 4px 10px; border-radius: 999px; }
  .findings-list { list-style: none; padding: 0; margin: 0; }
  .findings-list li { padding: 6px 0; border-bottom: 1px solid ${borderColor}; font-size: 11px; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  .findings-meta { font-size: 10px; color: ${mutedColor}; font-family: ui-monospace, monospace; }
  .advisory-card { border: 1px solid ${borderColor}; border-radius: 8px; padding: 14px; margin-bottom: 14px; page-break-inside: avoid; background: ${cardBg}; }
  .advisory-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
  .advisory-title { font-weight: 600; color: ${headingColor}; }
  .advisory-row { font-size: 10px; margin-bottom: 6px; }
  .advisory-row code { background: ${advisoryCodeBg}; padding: 1px 4px; border-radius: 4px; }
  .cve-link, .task-link, .aikido-link { color: ${
    brand.linkColor ?? brand.primaryColor
  }; text-decoration: none; }
  .cve-link:hover, .task-link:hover, .aikido-link:hover { text-decoration: underline; }
  .report-canvas-multicol { margin-bottom: 24px; }
  .report-widget-cell {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
    min-width: 0;
  }
  .report-widget-cell .section,
  .report-widget-cell .kpi-grid,
  .report-widget-cell .severity-bar,
  .report-widget-cell .severity-legend,
  .report-widget-cell table { width: 100%; }
  .report-widget-cell svg { max-width: 100%; height: auto; }
  .report-widget-cell .section { margin-bottom: 16px; }
  .report-widget-cell .section:last-child { margin-bottom: 0; }
  .report-filter-bar { padding: 14px 16px; margin: 0 -40px 20px -40px; background: ${filterNoteBg}; border-bottom: 1px solid ${borderColor}; position: sticky; top: 0; z-index: 100; display: flex; flex-wrap: wrap; align-items: center; gap: 12px; }
  .report-filter-bar-inline { margin: 0 0 16px 0; border-radius: 8px; border: 1px solid ${borderColor}; }
  .report-filter-facets { display: flex; flex-wrap: wrap; gap: 8px; }
  .report-filter-dd { position: relative; }
  .report-filter-trigger { font-size: 12px; padding: 6px 14px; border: 1px solid ${borderColor}; border-radius: 6px; background: ${cardBg}; color: ${bodyFg}; cursor: pointer; display: flex; align-items: center; gap: 4px; }
  .report-filter-trigger:hover { background: ${tableRowAltBg}; }
  .report-filter-arrow { font-size: 10px; opacity: 0.7; }
  .report-filter-panel { display: none; position: absolute; top: 100%; left: 0; margin-top: 4px; min-width: 220px; max-width: 320px; max-height: 320px; padding: 0; background: ${cardBg}; border: 1px solid ${borderColor}; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.12); z-index: 200; overflow: hidden; }
  .report-filter-dd.open .report-filter-panel { display: block; }
  .report-filter-search { width: 100%; padding: 8px 12px; border: none; border-bottom: 1px solid ${borderColor}; font-size: 12px; box-sizing: border-box; }
  .report-filter-search:focus { outline: 2px solid ${
    brand.primaryColor
  }; outline-offset: -2px; }
  .report-filter-panel-inner { max-height: 260px; overflow-y: auto; padding: 8px; }
  .report-filter-option { display: flex; align-items: center; gap: 8px; padding: 6px 8px; font-size: 12px; cursor: pointer; border-radius: 4px; }
  .report-filter-option:hover { background: ${tableRowAltBg}; }
  .report-filter-option input { margin: 0; flex-shrink: 0; }
  .report-filter-option-label { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .report-filter-count { font-size: 11px; color: ${mutedColor}; flex-shrink: 0; }
  .report-filter-actions { margin-top: 8px; padding-top: 8px; border-top: 1px solid ${borderColor}; display: flex; gap: 8px; }
  .report-filter-actions button { font-size: 11px; padding: 4px 8px; background: transparent; border: none; color: ${
    brand.primaryColor
  }; cursor: pointer; }
  .report-filter-actions button:hover { text-decoration: underline; }
  .report-filter-chips { display: flex; flex-wrap: wrap; gap: 6px; flex: 1; min-width: 0; }
  .report-filter-chip { display: inline-flex; align-items: center; gap: 4px; padding: 4px 8px; font-size: 11px; background: ${tableRowAltBg}; border: 1px solid ${borderColor}; border-radius: 999px; color: ${bodyFg}; }
  .report-filter-chip-remove { padding: 0 2px; margin: 0; border: none; background: transparent; color: ${mutedColor}; cursor: pointer; font-size: 14px; line-height: 1; }
  .report-filter-chip-remove:hover { color: ${bodyFg}; }
  .report-filter-clear { font-size: 11px; padding: 4px 10px; background: transparent; border: 1px solid ${borderColor}; border-radius: 4px; color: ${mutedColor}; cursor: pointer; flex-shrink: 0; }
  .report-filter-clear:hover { color: ${bodyFg}; }
  .trend-filter-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; align-items: center; }
  .trend-filter-pill { position: relative; }
  .trend-filter-pill-trigger { display: flex; align-items: center; gap: 4px; padding: 6px 12px; font-size: 12px; border-radius: 999px; border: 1px solid #e2e8f0; background: #fff; color: #0f172a; cursor: pointer; }
  .trend-filter-pill-trigger:hover { background: #f8fafc; }
  .trend-filter-pill:first-child .trend-filter-pill-trigger,
  .trend-filter-pill:nth-child(2) .trend-filter-pill-trigger,
  .trend-filter-pill:nth-child(3) .trend-filter-pill-trigger { color: var(--trend-primary, #0ea5e9); }
  .trend-filter-arrow { font-size: 10px; opacity: 0.7; }
  .trend-filter-pill-panel { display: none; position: absolute; top: 100%; left: 0; margin-top: 4px; min-width: 140px; padding: 6px; background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); z-index: 150; }
  .trend-filter-pill.open .trend-filter-pill-panel { display: block; }
  .trend-filter-pill-option { display: block; width: 100%; padding: 6px 10px; font-size: 12px; text-align: left; border: none; background: transparent; border-radius: 4px; cursor: pointer; color: #0f172a; }
  .trend-filter-pill-option:hover { background: #f1f5f9; }
  .trend-filter-panel-checkboxes { min-width: 160px; padding: 8px; }
  .trend-filter-panel-header { font-size: 11px; font-weight: 600; color: #64748b; text-transform: uppercase; margin-bottom: 8px; }
  .trend-filter-select-all { font-size: 11px; padding: 2px 0; background: none; border: none; color: var(--trend-primary, #0ea5e9); cursor: pointer; margin-bottom: 6px; }
  .trend-filter-select-all:hover { text-decoration: underline; }
  .trend-filter-checkbox { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 12px; cursor: pointer; color: #0f172a; }
  .trend-filter-checkbox:hover { color: #0ea5e9; }
  .trend-filter-checkbox input { margin: 0; }
  [data-tooltip] { position: relative; cursor: help; }
  [data-tooltip]:hover::after {
    content: attr(data-tooltip);
    position: absolute;
    bottom: 100%;
    left: 50%;
    transform: translateX(-50%) translateY(-6px);
    z-index: 100;
    min-width: 240px;
    max-width: 320px;
    padding: 10px;
    background: ${cardBg};
    border: 1px solid ${borderColor};
    border-radius: 6px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    font-size: 12px;
    line-height: 1.5;
    color: ${bodyFg};
    white-space: pre-line;
    pointer-events: none;
  }
  ${brand.bodyBg ? `.viz-donut text { fill: ${bodyFg} !important; }` : ""}
</style>
</head>
<body>
  ${
    filterConfig
      ? '<script src="https://cdnjs.cloudflare.com/ajax/libs/regression/2.0.1/regression.min.js" async></script>'
      : ""
  }
  ${brandHeaderHtml}
  <div class="header">
    <div class="meta">
      ${dateRange ? `<span>Date range: ${dateRange}</span>` : ""}
      <span>Generated: ${date}</span>
      <span>Data Source: Aikido Security</span>
      <span>Classification: Internal</span>
    </div>
  </div>
  ${
    filterConfig
      ? buildReportFilterBar(
          filterConfig,
          borderColor,
          mutedColor,
          brand.primaryColor,
          reportData,
        )
      : ""
  }
  <div class="report-filterable-root">${body}</div>
  <div class="footer">
    <span class="footer-brand">${footerBrandHtml}</span>
    <span class="footer-meta">${title} · ${workspace} · Generated ${date}</span>
  </div>
  <script>
  (function(){
    if(window.self!==window.top){
      document.documentElement.style.overflow='hidden';
      document.body.style.overflow='hidden';
      function reportSize(){
        var h=Math.max(document.body.scrollHeight,document.documentElement.scrollHeight);
        var w=Math.max(document.body.scrollWidth,document.documentElement.scrollWidth);
        try{window.parent.postMessage({type:'vat-report-size',height:h,width:w},'*');}catch(e){}
      }
      window.__vatReportNotifyHeight=reportSize;
      if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',function(){setTimeout(reportSize,200);});}
      else{setTimeout(reportSize,200);}
    }
    function initIssueInventorySort(){
      document.addEventListener('click',function(e){
        var el=e.target;
        if(!el)return;
        if(el.nodeType===3)el=el.parentElement;
        var th=el.closest?el.closest('th.sortable-status'):null;
        if(!th)return;
        var tbl=th.closest('.issue-inventory-table');
        if(!tbl)return;
        var tbody=tbl.querySelector('tbody');
        if(!tbody)return;
        var state=tbl._sortClosedFirst;
        tbl._sortClosedFirst=!state;
        var rows=Array.prototype.slice.call(tbody.querySelectorAll('tr'));
        rows.sort(function(a,b){
          var sa=a.getAttribute('data-sort-status')||'';
          var sb=b.getAttribute('data-sort-status')||'';
          var cmp=(sb==='open'?1:0)-(sa==='open'?1:0);
          return tbl._sortClosedFirst?-cmp:cmp;
        });
        rows.forEach(function(r){tbody.appendChild(r);});
        if(window.__vatReportNotifyHeight)window.__vatReportNotifyHeight();
      });
    }
    if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',initIssueInventorySort);}
    else{initIssueInventorySort();}
  })();
  </script>
</body>
</html>`;
}

export function buildReportHtmlFromDefinition(
  context: ReportContext,
  definition: ReportDefinition,
  options?: { preview?: boolean },
): string {
  const preview = options?.preview ?? false;
  const branding = getReportTheme(definition.themeId);
  const contextWithBranding: ReportContext = {
    ...context,
    branding: {
      primaryColor: branding.primaryColor,
      mutedColor: branding.mutedColor,
    },
  };
  const body = buildReportBodyFromDefinition(contextWithBranding, definition, {
    preview,
  });
  const filterConfig = getReportFilterConfig(contextWithBranding);
  // No payload truncation in preview — filter script needs full data for accurate counts.
  // Only widget display is truncated (e.g. issue inventory via PREVIEW_LIMITS).
  const reportData = buildReportDataPayload(context, definition);
  return buildReportDocumentShell(
    definition.title,
    context.workspace,
    context.date,
    context.dateRange ?? null,
    body,
    branding,
    filterConfig,
    reportData,
  );
}

/** Build a minimal HTML document for a single widget preview (e.g. hover in report builder). */
export function buildSingleWidgetPreviewHtml(
  context: ReportContext,
  type: WidgetType,
  config: Record<string, unknown>,
): string {
  const limitedConfig = applyPreviewLimits(type, config, true);
  const body = renderWidget(type, context, limitedConfig);
  const styles = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a2e; background: #fff; font-size: clamp(11px, 1.2vw + 0.5rem, 14px); line-height: 1.5; padding: 16px; }
  .section { margin-bottom: 16px; }
  .section h2 { font-size: clamp(13px, 1.2vw + 0.5rem, 18px); font-weight: 600; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 12px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
  .kpi-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; text-align: center; }
  .kpi-card .label { font-size: clamp(9px, 1vw + 0.4rem, 12px); text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; }
  .kpi-card .value { font-size: clamp(26px, 2.8vw + 1rem, 44px); font-weight: 700; margin: 4px 0; }
  .kpi-card .detail { font-size: 10px; color: #64748b; }
  .severity-bar { display: flex; height: 24px; border-radius: 6px; overflow: hidden; margin-bottom: 8px; }
  .severity-bar div { display: flex; align-items: center; justify-content: center; color: #fff; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); font-weight: 600; }
  .severity-legend { display: flex; gap: 16px; font-size: clamp(10px, 1.1vw + 0.4rem, 13px); }
  .severity-legend span { display: flex; align-items: center; gap: 4px; }
  .severity-legend .dot { width: 10px; height: 10px; border-radius: 3px; }
  .critical-val { color: #ef4444; }
  .high-val { color: #f97316; }
  .medium-val { color: #eab308; }
  .low-val { color: #0ea5e9; }
  table { width: 100%; border-collapse: collapse; font-size: clamp(10px, 1.1vw + 0.4rem, 14px); }
  th { text-align: left; padding: 6px 8px; background: #f8fafc; border-bottom: 2px solid #e2e8f0; font-weight: 600; color: #475569; }
  th.sortable { cursor: pointer; user-select: none; }
  th.sortable:hover { text-decoration: underline; }
  td { padding: 6px 8px; border-bottom: 1px solid #f1f5f9; }
  tr:nth-child(even) { background: #fafbfc; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: clamp(9px, 1vw + 0.3rem, 12px); font-weight: 600; text-transform: uppercase; }
  .badge-critical { background: #fef2f2; color: #ef4444; border: 1px solid #fecaca; }
  .badge-high { background: #fff7ed; color: #f97316; border: 1px solid #fed7aa; }
  .badge-medium { background: #fefce8; color: #ca8a04; border: 1px solid #fef08a; }
  .badge-low { background: #f0f9ff; color: #0ea5e9; border: 1px solid #bae6fd; }
  .mono { font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace; }
  .text-right { text-align: right; }
  .filter-note { font-size: 11px; color: #64748b; margin-bottom: 12px; padding: 6px 10px; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0; }
  .notes { font-size: 11px; color: #475569; margin-bottom: 16px; padding: 10px; background: #fffbeb; border-radius: 6px; border: 1px solid #fef08a; }
  .board-hero { display: flex; align-items: center; justify-content: center; gap: 24px; flex-wrap: wrap; padding: 16px 0; }
  .board-hero-viz { flex-shrink: 0; }
  .board-hero-text { text-align: center; }
  .board-risk-score { font-size: clamp(36px, 4vw + 1rem, 64px); font-weight: 800; line-height: 1; letter-spacing: -0.02em; }
  .board-risk-score .kpi-trend-inline { font-size: 11px; font-weight: 600; margin-left: 6px; vertical-align: middle; }
  .board-risk-max { font-size: clamp(16px, 1.5vw + 0.5rem, 24px); font-weight: 500; color: #64748b; margin-left: 2px; }
  .board-risk-level { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; margin-top: 4px; }
  .board-narrative { font-size: 13px; color: #475569; max-width: 420px; margin: 12px auto 0; line-height: 1.5; }
  .severity-with-donut { display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
  .severity-donut-wrap { flex-shrink: 0; }
  .severity-bar-legend { flex: 1; min-width: 200px; }
  .viz-donut, .viz-gauge { display: block; }
  .viz-trend-wrap { margin-bottom: 12px; }
  .viz-trend-stacked-wrap { width: 100%; min-width: 0; min-height: 140px; display: block; }
  .viz-trend-stacked-container { display: block; width: 100%; height: 100%; }
  .viz-trend-stacked { display: block; width: 100%; height: 100%; vertical-align: top; }
  .viz-trend-stacked-overlay { display: block; }
  .trend-segment { cursor: default; }
  .viz-sparkline { display: block; }
  .viz-aging-bars { margin-bottom: 12px; }
  .aging-bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-size: 10px; }
  .aging-bar-label { width: 72px; color: #475569; }
  .aging-bar-track { flex: 1; max-width: 200px; height: 14px; background: #f1f5f9; border-radius: 6px; overflow: hidden; }
  .aging-bar-fill { height: 100%; border-radius: 6px; min-width: 4px; }
  .aging-bar-num { width: 24px; text-align: right; font-weight: 600; }
  .viz-repo-bars { margin-bottom: 12px; }
  .repo-bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 5px; font-size: 10px; }
  .repo-bar-label { width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #475569; }
  .repo-bar-track { width: 120px; height: 10px; background: #f1f5f9; border-radius: 4px; overflow: hidden; }
  .repo-bar-fill { height: 100%; border-radius: 4px; background: #94a3b8; }
  .repo-bar-fill.repo-bar-high { background: #f97316; }
  .repo-bar-fill.repo-bar-critical { background: #ef4444; }
  .repo-bar-num { width: 28px; text-align: right; font-weight: 600; }
  .viz-mttr-bars { margin-bottom: 12px; }
  .mttr-bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-size: 10px; }
  .mttr-bar-track { width: 120px; height: 12px; background: #f1f5f9; border-radius: 4px; overflow: hidden; }
  .mttr-bar-fill { height: 100%; border-radius: 4px; }
  .mttr-bar-num { width: 32px; text-align: right; font-weight: 600; }
  .severity-compact .severity-inline { display: flex; flex-wrap: wrap; gap: 8px; }
  .sev-pill { font-size: 10px; font-weight: 600; padding: 4px 10px; border-radius: 999px; }
  .findings-list { list-style: none; padding: 0; margin: 0; }
  .findings-list li { padding: 6px 0; border-bottom: 1px solid #f1f5f9; font-size: 11px; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  .findings-meta { font-size: 10px; color: #64748b; font-family: ui-monospace, monospace; }
  .advisory-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 14px; }
  .advisory-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
  .advisory-title { font-weight: 600; color: #0f172a; }
  .advisory-row { font-size: 10px; margin-bottom: 6px; }
  .advisory-row code { background: #f1f5f9; padding: 1px 4px; border-radius: 4px; }
  .cve-link, .task-link, .aikido-link { color: #38bdf8; text-decoration: none; }
  .cve-link:hover, .task-link:hover, .aikido-link:hover { text-decoration: underline; }
  .narrative-line { font-size: 11px; color: #475569; margin-bottom: 12px; }
  .activity-empty { font-size: 11px; color: #94a3b8; font-style: italic; padding: 12px; background: #f8fafc; border-radius: 6px; border: 1px dashed #e2e8f0; }
  .trend-filter-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; align-items: center; }
  .trend-filter-pill { position: relative; }
  .trend-filter-pill-trigger { display: flex; align-items: center; gap: 4px; padding: 6px 12px; font-size: 12px; border-radius: 999px; border: 1px solid #e2e8f0; background: #fff; color: #0f172a; cursor: pointer; }
  .trend-filter-pill-trigger:hover { background: #f8fafc; }
  .trend-filter-pill:first-child .trend-filter-pill-trigger,
  .trend-filter-pill:nth-child(2) .trend-filter-pill-trigger,
  .trend-filter-pill:nth-child(3) .trend-filter-pill-trigger { color: #0ea5e9; }
  .trend-filter-arrow { font-size: 10px; opacity: 0.7; }
  .trend-filter-pill-panel { display: none; position: absolute; top: 100%; left: 0; margin-top: 4px; min-width: 140px; padding: 6px; background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); z-index: 150; }
  .trend-filter-pill.open .trend-filter-pill-panel { display: block; }
  .trend-filter-pill-option { display: block; width: 100%; padding: 6px 10px; font-size: 12px; text-align: left; border: none; background: transparent; border-radius: 4px; cursor: pointer; color: #0f172a; }
  .trend-filter-pill-option:hover { background: #f1f5f9; }
  .trend-filter-panel-checkboxes { min-width: 160px; padding: 8px; }
  .trend-filter-panel-header { font-size: 11px; font-weight: 600; color: #64748b; text-transform: uppercase; margin-bottom: 8px; }
  .trend-filter-select-all { font-size: 11px; padding: 2px 0; background: none; border: none; color: #0ea5e9; cursor: pointer; margin-bottom: 6px; }
  .trend-filter-select-all:hover { text-decoration: underline; }
  .trend-filter-checkbox { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 12px; cursor: pointer; color: #0f172a; }
  .trend-filter-checkbox:hover { color: #0ea5e9; }
  .trend-filter-checkbox input { margin: 0; }
`;
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>Widget preview</title>
<style>${styles}</style>
</head>
<body>
${body}
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// CSV from context (for canvas export)
// ---------------------------------------------------------------------------
// CSV export behavior: always exports the full filtered dataset regardless of
// report definition (canvases/widgets). Includes: report title, workspace,
// date; risk score and open-issue counts; severity breakdown; repository risk
// table (all repos in context); then full issue inventory (all filtered issues).
// Widget selection affects only PDF/HTML output.

function buildCsvContentFromContext(context: ReportContext): string {
  const r = context;
  const rows: string[][] = [];
  rows.push(["Vulnerability Report", r.workspace, r.date]);
  rows.push([]);
  rows.push(["Risk Score", String(r.riskScore), r.riskLevel]);
  rows.push(["Open Vulnerabilities", String(r.openIssues)]);
  rows.push([
    "Avg MTTR (days)",
    r.avgMttr !== undefined ? String(r.avgMttr) : "N/A",
  ]);
  rows.push([]);
  rows.push(["Severity", "Count"]);
  rows.push(["Critical", String(r.counts.critical)]);
  rows.push(["High", String(r.counts.high)]);
  rows.push(["Medium", String(r.counts.medium)]);
  rows.push(["Low", String(r.counts.low)]);
  rows.push(["Info", String(r.counts.info)]);
  rows.push([]);
  if (r.repoRisk.length > 0) {
    rows.push([
      "Repository",
      "Critical",
      "High",
      "Medium",
      "Low",
      "Total",
      "Risk Score",
    ]);
    for (const repo of r.repoRisk) {
      rows.push([
        repo.repo,
        String(repo.critical),
        String(repo.high),
        String(repo.medium),
        String(repo.low),
        String(repo.total),
        String(repo.score),
      ]);
    }
    rows.push([]);
  }
  rows.push([
    "Issue ID",
    "Title",
    "Severity",
    "Score",
    "Repository",
    "Package",
    "Version",
    "Fixed Version",
    "CVE",
    "CWE",
    "Scanner",
    "Status",
    "First Detected",
    "Closed At",
    "Source URL",
  ]);
  for (const i of r.filteredIssues) {
    rows.push([
      String(i.issue_id),
      i.title,
      i.severity,
      String(i.severity_score),
      i.repository || "",
      i.affected_package || "",
      i.affected_version || "",
      i.fixed_version || "",
      i.cve_id || "",
      i.cwe_id || "",
      i.scanner_type || "",
      i.status,
      i.first_detected_at,
      i.closed_at || "",
      i.source_url || "",
    ]);
  }
  return rows
    .map((row) =>
      row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","),
    )
    .join("\n");
}

// ---------------------------------------------------------------------------
// Export from definition (canvas API)
// ---------------------------------------------------------------------------

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function exportPdfFromDefinition(
  data: VATDashboardData,
  definition: ReportDefinition,
): void {
  const context = computeReportContext(data, definition.filters);
  const html = buildReportHtmlFromDefinition(context, definition);
  const printWindow = window.open("", "_blank");
  if (printWindow) {
    printWindow.document.write(html);
    printWindow.document.close();
    setTimeout(() => printWindow.print(), 500);
  }
}

export function exportHtmlFromDefinition(
  data: VATDashboardData,
  definition: ReportDefinition,
): void {
  const context = computeReportContext(data, definition.filters);
  const html = buildReportHtmlFromDefinition(context, definition);
  const slug = definition.title
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9-]/g, "");
  downloadBlob(
    html,
    `${slug}-${new Date().toISOString().slice(0, 10)}.html`,
    "text/html",
  );
}

export function exportCsvFromDefinition(
  data: VATDashboardData,
  definition: ReportDefinition,
): void {
  const context = computeReportContext(data, definition.filters);
  const csv = buildCsvContentFromContext(context);
  const slug = definition.title
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9-]/g, "");
  downloadBlob(
    csv,
    `${slug}-${new Date().toISOString().slice(0, 10)}.csv`,
    "text/csv",
  );
}

// ---------------------------------------------------------------------------
// Presets: saved report definitions (replace old templates)
// ---------------------------------------------------------------------------

export interface ReportPreset {
  id: string;
  name: string;
  description?: string;
  definition: ReportDefinition;
}

/** Apply single-column layout to each widget in a canvas (row = index). */
function withSingleColumnLayout<T extends { widgets: WidgetDefinition[] }>(
  canvas: T & { columns?: number },
): T & { columns: 1 } {
  return {
    ...canvas,
    columns: 1,
    widgets: canvas.widgets.map((w, i) => ({
      ...w,
      layout: widgetLayoutForSingleColumn(i),
    })),
  };
}

export const REPORT_PRESETS: ReportPreset[] = [
  {
    id: "executive",
    name: "Executive Summary",
    description:
      "High-level risk posture for leadership. 30-day window with KPIs, severity, aging, MTTR, and top vulns.",
    definition: {
      title: "Executive Summary",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 30,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "groups",
      },
      canvases: [
        withSingleColumnLayout({
          id: "c-exec",
          name: "Summary",
          widgets: [
            { id: "w-exec-1", type: "summary", config: { variant: "default" } },
            { id: "w-exec-2", type: "severityBar", config: {} },
            { id: "w-exec-3", type: "agingTable", config: {} },
            { id: "w-exec-4", type: "mttrTable", config: {} },
            { id: "w-exec-5", type: "repoTable", config: { limit: 10 } },
            { id: "w-exec-6", type: "topVulnsTable", config: { limit: 10 } },
          ],
        }),
      ],
    },
  },
  {
    id: "executive-detailed",
    name: "Executive Summary (Detailed)",
    description:
      "Executive overview with risk gauge, severity trends, and full risk rankings plus vulnerabilities for all repos and containers.",
    definition: {
      title: "Executive Summary - Detailed",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 90,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "groups",
      },
      canvases: [
        withSingleColumnLayout({
          id: "c-exec-det",
          name: "Summary",
          widgets: [
            {
              id: "w-exec-det-1",
              type: "summary",
              config: { variant: "default" },
            },
            {
              id: "w-exec-det-2",
              type: "trendStacked",
              config: { periodDays: 90 },
            },
            { id: "w-exec-det-3", type: "severityBar", config: {} },
            { id: "w-exec-det-4", type: "assetMixDonut", config: {} },
            { id: "w-exec-det-5", type: "agingTable", config: {} },
            { id: "w-exec-det-6", type: "mttrTable", config: {} },
            { id: "w-exec-det-7", type: "repoTable", config: { limit: 100 } },
            {
              id: "w-exec-det-8",
              type: "containerTable",
              config: { limit: 100 },
            },
            {
              id: "w-exec-det-9",
              type: "issueList",
              config: { limit: 100000 },
            },
          ],
        }),
      ],
    },
  },
  {
    id: "executive-detailed-yearly-instances",
    name: "Executive Summary - Yearly (All Instances)",
    description:
      "Copy of Executive Summary - Detailed with full year (365 days) and individual issue counts rather than grouped.",
    definition: {
      title: "Executive Summary - Detailed (Yearly, All Instances)",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 365,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "instances",
      },
      canvases: [
        withSingleColumnLayout({
          id: "c-exec-det-yearly",
          name: "Summary",
          widgets: [
            {
              id: "w-exec-det-y1",
              type: "summary",
              config: { variant: "default" },
            },
            {
              id: "w-exec-det-y2",
              type: "trendStacked",
              config: { periodDays: 365 },
            },
            { id: "w-exec-det-y3", type: "severityBar", config: {} },
            { id: "w-exec-det-y4", type: "sourceBar", config: {} },
            { id: "w-exec-det-y5", type: "assetMixDonut", config: {} },
            { id: "w-exec-det-y6", type: "agingTable", config: {} },
            { id: "w-exec-det-y7", type: "mttrTable", config: {} },
            { id: "w-exec-det-y8", type: "repoTable", config: { limit: 100 } },
            {
              id: "w-exec-det-y9",
              type: "containerTable",
              config: { limit: 100 },
            },
            {
              id: "w-exec-det-y10",
              type: "issueList",
              config: { limit: 100000 },
            },
          ],
        }),
      ],
    },
  },
  {
    id: "executive-summary2",
    name: "Executive Summary v2",
    description:
      "Trend-focused executive report with severity trends, reachability, and asset mix.",
    definition: {
      title: "Executive Summary",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 90,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "groups",
      },
      canvases: [
        withSingleColumnLayout({
          id: "c-exec2",
          name: "Summary",
          widgets: [
            {
              id: "w-exec2-1",
              type: "summary",
              config: { variant: "default" },
            },
            {
              id: "w-exec2-2",
              type: "trendStacked",
              config: { periodDays: 90 },
            },
            { id: "w-exec2-3", type: "severityBar", config: {} },
            { id: "w-exec2-4", type: "reachabilityMatrix", config: {} },
            { id: "w-exec2-5", type: "assetMixDonut", config: {} },
            { id: "w-exec2-6", type: "mttrTable", config: {} },
            { id: "w-exec2-7", type: "repoTable", config: { limit: 10 } },
            { id: "w-exec2-8", type: "topVulnsTable", config: { limit: 10 } },
          ],
        }),
      ],
    },
  },
  {
    id: "board",
    name: "Board One-Pager",
    description:
      "Single-page snapshot for board meetings. Risk gauge, severity pills, and top 5 findings.",
    definition: {
      title: "Board One-Pager",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 30,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "groups",
      },
      canvases: [
        withSingleColumnLayout({
          id: "c-board",
          name: "Risk at a glance",
          widgets: [
            { id: "w-board-1", type: "riskGauge", config: {} },
            { id: "w-board-2", type: "summary", config: { variant: "board" } },
            { id: "w-board-3", type: "severityPills", config: {} },
            { id: "w-board-4", type: "topVulnsList", config: { limit: 5 } },
          ],
        }),
      ],
    },
  },
  {
    id: "engineering",
    name: "Engineering Detail",
    description:
      "Full technical report with scanners, aging, MTTR, repo risk, and full issue inventory.",
    definition: {
      title: "Engineering Detail",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 30,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "groups",
      },
      canvases: [
        withSingleColumnLayout({
          id: "c-eng",
          name: "Overview",
          widgets: [
            { id: "w-eng-1", type: "summary", config: { variant: "default" } },
            { id: "w-eng-2", type: "severityDonut", config: {} },
            { id: "w-eng-3", type: "severityBar", config: {} },
            { id: "w-eng-4", type: "scannerTable", config: {} },
            { id: "w-eng-5", type: "agingBars", config: {} },
            { id: "w-eng-6", type: "agingTable", config: {} },
            { id: "w-eng-7", type: "mttrBars", config: {} },
            { id: "w-eng-8", type: "mttrTable", config: {} },
            { id: "w-eng-9", type: "repoBars", config: {} },
            { id: "w-eng-10", type: "repoTable", config: { limit: 25 } },
            { id: "w-eng-11", type: "topVulnsTable", config: { limit: 25 } },
            { id: "w-eng-12", type: "issueList", config: { limit: 100 } },
          ],
        }),
      ],
    },
  },
  {
    id: "compliance-all-frameworks",
    name: "Compliance (All Frameworks)",
    description:
      "SOC2, NIS2, and ISO 27001 side by side. Audit-ready multi-framework view.",
    definition: {
      title: "Compliance - All Frameworks",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 30,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "groups",
      },
      canvases: [
        {
          id: "c-comp-all",
          name: "Compliance",
          widgets: [
            {
              id: "w-comp-all-1",
              type: "summary",
              config: { variant: "compliance" },
              layout: widgetLayoutForSingleColumn(0),
            },
            {
              id: "w-comp-all-2",
              type: "complianceScoreCard",
              config: { framework: "soc2" },
              layout: { row: 1, col: 0, width: 4, height: 1 },
            },
            {
              id: "w-comp-all-3",
              type: "complianceScoreCard",
              config: { framework: "nis2" },
              layout: { row: 1, col: 4, width: 4, height: 1 },
            },
            {
              id: "w-comp-all-4",
              type: "complianceScoreCard",
              config: { framework: "iso27001" },
              layout: { row: 1, col: 8, width: 4, height: 1 },
            },
            {
              id: "w-comp-all-5",
              type: "reachabilityMatrix",
              config: {},
              layout: widgetLayoutForSingleColumn(2),
            },
            {
              id: "w-comp-all-6",
              type: "severityBar",
              config: {},
              layout: widgetLayoutForSingleColumn(3),
            },
            {
              id: "w-comp-all-7",
              type: "repoTable",
              config: { limit: 25 },
              layout: widgetLayoutForSingleColumn(4),
            },
          ],
        },
      ],
    },
  },
  {
    id: "compliance",
    name: "Compliance Report",
    description:
      "Audit-ready with SOC2/NIS2/ISO, reachability, and full inventory.",
    definition: {
      title: "Compliance Report",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 30,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "groups",
      },
      canvases: [
        withSingleColumnLayout({
          id: "c-compliance",
          name: "Compliance",
          widgets: [
            {
              id: "w-comp-1",
              type: "summary",
              config: { variant: "compliance" },
            },
            { id: "w-comp-2", type: "complianceScoreCard", config: {} },
            { id: "w-comp-3", type: "reachabilityMatrix", config: {} },
            { id: "w-comp-4", type: "assetMixDonut", config: {} },
            { id: "w-comp-5", type: "severityBar", config: {} },
            { id: "w-comp-6", type: "trendSparkline", config: {} },
            { id: "w-comp-7", type: "trendTable", config: {} },
            { id: "w-comp-8", type: "agingTable", config: {} },
            { id: "w-comp-9", type: "mttrTable", config: {} },
            { id: "w-comp-10", type: "repoTable", config: { limit: 50 } },
            { id: "w-comp-11", type: "containerTable", config: {} },
            { id: "w-comp-12", type: "topVulnsTable", config: { limit: 50 } },
            { id: "w-comp-13", type: "issueList", config: { limit: 500 } },
          ],
        }),
      ],
    },
  },
  {
    id: "weekly",
    name: "Weekly Digest",
    description:
      "Trend and MTTR focus for standups. 30-day trend sparkline and summary.",
    definition: {
      title: "Weekly Digest",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 30,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "groups",
      },
      canvases: [
        withSingleColumnLayout({
          id: "c-weekly",
          name: "Weekly",
          widgets: [
            {
              id: "w-weekly-1",
              type: "summary",
              config: { variant: "weekly" },
            },
            { id: "w-weekly-2", type: "severityBar", config: {} },
            { id: "w-weekly-3", type: "trendSparkline", config: {} },
            { id: "w-weekly-4", type: "trendTable", config: {} },
            { id: "w-weekly-5", type: "mttrTable", config: {} },
            { id: "w-weekly-6", type: "topVulnsTable", config: { limit: 15 } },
          ],
        }),
      ],
    },
  },
  {
    id: "vendor",
    name: "Vendor Disclosure",
    description:
      "Advisory-style findings for coordination. Summary, repo table, and advisory cards.",
    definition: {
      title: "Vendor Disclosure",
      filters: {
        repoFilter: [],
        branchFilter: null,
        severityFilter: [],
        dateRangePreset: 30,
        dateFrom: null,
        dateTo: null,
        notes: "",
        external: false,
        countMode: "groups",
      },
      canvases: [
        withSingleColumnLayout({
          id: "c-vendor",
          name: "Findings",
          widgets: [
            {
              id: "w-vendor-1",
              type: "summary",
              config: { variant: "default" },
            },
            { id: "w-vendor-2", type: "severityBar", config: {} },
            { id: "w-vendor-3", type: "repoTable", config: { limit: 20 } },
            {
              id: "w-vendor-4",
              type: "topVulnsAdvisory",
              config: { limit: 30 },
            },
            { id: "w-vendor-5", type: "issueList", config: { limit: 200 } },
          ],
        }),
      ],
    },
  },
];

/** Deep clone a preset definition so the user can edit without mutating the preset. */
export function clonePresetDefinition(preset: ReportPreset): ReportDefinition {
  return JSON.parse(JSON.stringify(preset.definition));
}

/** Initial filters from dashboard state - used to sync new reports with current view. */
export interface DashboardReportFilters {
  dateRangePeriod: 30 | 90 | 365;
  repoFilter: string | null;
  containerFilter: string | null;
  countMode: ReportFilters["countMode"];
}

/** Map dashboard date range to report filters. */
function filtersFromDashboardState(
  dashboard?: DashboardReportFilters,
): ReportFilters {
  const base: ReportFilters = {
    repoFilter: [],
    branchFilter: null,
    severityFilter: [],
    dateRangePreset: null,
    dateFrom: null,
    dateTo: null,
    notes: "",
    external: false,
    countMode: "groups",
  };
  if (!dashboard) return base;

  const { dateRangePeriod, repoFilter, containerFilter, countMode } = dashboard;

  // Sync repo filter (container-filtered data is already correct; report uses repoFilter for repo-scoped)
  if (repoFilter) {
    base.repoFilter = [repoFilter];
  }
  // containerFilter: data is already filtered at dashboard level; no report-level container filter
  base.countMode = countMode ?? "groups";

  // Sync date range from dashboard's dateRangePeriod (30, 90, or 365 days)
  if (dateRangePeriod) {
    base.dateRangePreset = dateRangePeriod as ReportFilters["dateRangePreset"];
  }

  return base;
}

/** Create a default empty report definition (one canvas, one summary widget). */
export function createDefaultReportDefinition(
  workspaceName: string,
  dashboardFilters?: DashboardReportFilters,
  themeId?: string | null,
  defaultCountMode?: "groups" | "instances",
): ReportDefinition {
  const filters = filtersFromDashboardState(dashboardFilters);
  if (defaultCountMode) filters.countMode = defaultCountMode;
  const validThemeIds = [
    "vat",
    "default",
    "light",
    "slate",
    "dracula",
    "nord",
    "catppuccin",
    "tokyo-night",
  ];
  const effectiveThemeId = (() => {
    const id = themeId === "kamiwaza" ? "default" : themeId;
    return id && validThemeIds.includes(id) ? id : "vat";
  })();
  return {
    title: `Vulnerability Report - ${workspaceName}`,
    filters,
    themeId: effectiveThemeId,
    canvases: [
      {
        id: `c-${Date.now()}`,
        name: "Page 1",
        widgets: [
          {
            id: `w-${Date.now()}`,
            type: "summary",
            config: { variant: "default" },
            layout: widgetLayoutFullWidth(0),
          },
        ],
      },
    ],
  };
}
