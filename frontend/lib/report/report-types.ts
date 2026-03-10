/**
 * Canvas-based report builder: report definition types.
 * VAT-adapted from vulnerability-dashboard.
 */

import type { VATReportIssue, VATReportIssueGroup } from "./vatReportAdapter";
import type {
  SeverityCounts,
  RepoRiskScore,
  ContainerRiskScore,
  AssetMix,
  MTTRData,
  AgingBucket,
  TopVulnerability,
  ScannerBreakdown,
  TrendDataPoint,
  PeriodChange,
  CountMode,
} from "./metrics";

/** Preset date range in days. null = use custom dateFrom/dateTo. */
export type DateRangePreset = 7 | 30 | 90 | 120 | 365 | null;

export interface ReportFilters {
  repoFilter: string[];
  branchFilter: string | null;
  severityFilter: string[];
  dateRangePreset?: DateRangePreset;
  dateFrom: string | null;
  dateTo: string | null;
  notes: string;
  external?: boolean;
  countMode?: CountMode;
}

export interface WidgetLayout {
  col: number;
  row: number;
  width: number;
  height: number;
}

export interface WidgetDefinition {
  id: string;
  type: WidgetType;
  config: Record<string, unknown>;
  layout?: WidgetLayout;
}

export const CANVAS_GRID_COLS = 12;
export const CANVAS_MAX_COLUMNS = 3;
export type CanvasColumns = 1 | 2 | 3;

export function gridUnitsPerColumn(columns: CanvasColumns): number {
  return CANVAS_GRID_COLS / columns;
}

export function snapColToLayout(col: number, columns: CanvasColumns): number {
  const units = gridUnitsPerColumn(columns);
  const snapped = Math.round(col / units) * units;
  return Math.min(CANVAS_GRID_COLS - units, Math.max(0, snapped));
}

export function snapWidthToLayout(width: number, columns: CanvasColumns): number {
  const units = gridUnitsPerColumn(columns);
  const span = Math.max(1, Math.round(width / units));
  return Math.min(columns, span) * units;
}

export function inferColumnsFromWidgets(widgets: WidgetDefinition[]): CanvasColumns {
  if (widgets.length === 0) return 1;
  const rowCounts = new Map<number, number>();
  for (const w of widgets) {
    const l = w.layout ?? { row: 0, col: 0, width: 12, height: 1 };
    const r = l.row ?? 0;
    const h = l.height ?? 1;
    for (let row = r; row < r + h; row++) {
      rowCounts.set(row, (rowCounts.get(row) ?? 0) + 1);
    }
  }
  const max = Math.max(0, ...rowCounts.values());
  return (Math.min(CANVAS_MAX_COLUMNS, Math.max(1, max)) as CanvasColumns) || 1;
}

export function widgetLayoutForSingleColumn(rowIndex: number): WidgetLayout {
  return { row: rowIndex, col: 0, width: CANVAS_GRID_COLS, height: 1 };
}

export function widgetLayoutFullWidth(rowIndex: number): WidgetLayout {
  return { row: rowIndex, col: 0, width: CANVAS_GRID_COLS, height: 1 };
}

export function normalizeCanvasRowLayouts(widgets: WidgetDefinition[]): WidgetDefinition[] {
  if (widgets.length === 0) return [];
  const rows = new Map<number, WidgetDefinition[]>();
  for (const w of widgets) {
    const l = w.layout ?? widgetLayoutFullWidth(0);
    const r = l.row ?? 0;
    if (!rows.has(r)) rows.set(r, []);
    rows.get(r)!.push(w);
  }
  const updates = new Map<string, WidgetLayout>();
  for (const [, rowWidgets] of rows) {
    const count = rowWidgets.length;
    const unitsPerWidget = CANVAS_GRID_COLS / count;
    const sorted = [...rowWidgets].sort((a, b) => (a.layout?.col ?? 0) - (b.layout?.col ?? 0));
    sorted.forEach((w, i) => {
      const prev = w.layout ?? widgetLayoutFullWidth(0);
      updates.set(w.id, {
        row: prev.row ?? 0,
        col: i * unitsPerWidget,
        width: unitsPerWidget,
        height: prev.height ?? 1,
      });
    });
  }
  return widgets.map((w) => {
    const patch = updates.get(w.id);
    if (!patch) return w;
    return { ...w, layout: patch };
  });
}

export function nextLayoutRow(widgets: WidgetDefinition[]): number {
  if (widgets.length === 0) return 0;
  let max = 0;
  for (const w of widgets) {
    const l = w.layout;
    const end = (l?.row ?? 0) + (l?.height ?? 1);
    if (end > max) max = end;
  }
  return max;
}

export const DEFAULT_DATE_RANGE_PRESET: DateRangePreset = null;

export function normalizeReportDefinitionLayout(definition: ReportDefinition): ReportDefinition {
  const filters = definition.filters;
  const branchFilter = filters.branchFilter ?? null;
  const repoFilter = Array.isArray(filters.repoFilter) ? filters.repoFilter : filters.repoFilter ? [filters.repoFilter] : [];
  const dateRangePreset =
    filters.dateRangePreset !== undefined
      ? filters.dateRangePreset
      : filters.dateFrom ?? filters.dateTo
        ? null
        : DEFAULT_DATE_RANGE_PRESET;
  return {
    ...definition,
    filters: {
      ...filters,
      repoFilter,
      branchFilter,
      dateRangePreset,
      external: filters.external ?? false,
      countMode: filters.countMode ?? "groups",
    },
    canvases: definition.canvases.map((canvas) => ({
      ...canvas,
      columns: (canvas.columns ?? 1) as CanvasColumns,
      widgets: canvas.widgets.map((w, i) => ({
        ...w,
        layout: w.layout ?? widgetLayoutForSingleColumn(i),
      })),
    })),
  };
}

export interface CanvasDefinition {
  id: string;
  name: string;
  columns?: CanvasColumns;
  widgets: WidgetDefinition[];
}

export interface ReportDefinition {
  title: string;
  filters: ReportFilters;
  canvases: CanvasDefinition[];
  themeId?: string;
}

export interface ReportContext {
  workspace: string;
  date: string;
  dateRange: string | null;
  effectivePeriodDays?: number | null;
  dateFrom?: string | null;
  dateTo?: string | null;
  repoFilter: string[];
  branchFilter: string | null;
  notes: string;
  totalIssues: number;
  openIssues: number;
  counts: SeverityCounts;
  riskScore: number;
  riskLevel: string;
  avgMttr: number | undefined;
  mttr: MTTRData[];
  aging: AgingBucket[];
  repoRisk: RepoRiskScore[];
  containerRisk: ContainerRiskScore[];
  assetMix: AssetMix;
  teams: Array<{ id: string; name: string }>;
  topVulns: TopVulnerability[];
  scanners: ScannerBreakdown[];
  trends: TrendDataPoint[];
  filteredIssues: VATReportIssue[];
  issuesForTrend?: VATReportIssue[];
  branding?: { primaryColor: string; bodyFg?: string; mutedColor?: string };
  issueGroups?: VATReportIssueGroup[];
  external?: boolean;
  countMode?: CountMode;
  cveDetailsByCveId?: Record<string, { epss_score?: number; in_kev?: boolean }>;
  /** ABC compliance (optional). */
  abcCompliance?: {
    compliant: boolean;
    maxCountExceeded: { critical: boolean; high: boolean };
    justificationOverdue: number;
    remediationOverdue: number;
    cveAgeExceeded: number;
  };
  forEmail?: boolean;
  vmNames?: string[];
  packageNames?: string[];
  activityLog?: Array<{ id?: string; action?: string; timestamp?: string; user?: string; target_type?: string; target_name?: string; details?: string }>;
  tasksByGroupId?: Record<number, Array<{ title?: string; url?: string }>>;
  repoIdByName?: Record<string, number>;
  aikidoBaseUrl?: string;
  soc2Compliance?: { score?: number; percentage?: number; status?: string; controls_total?: number; controls_passed?: number };
  nis2Compliance?: { score?: number; percentage?: number; status?: string; controls_total?: number; controls_passed?: number };
  iso27001Compliance?: { score?: number; percentage?: number; status?: string; controls_total?: number; controls_passed?: number };
  reachabilityMatrix?: Array<{ severity: string; exploitable: number; notExploitable: number; unknown: number }>;
  ciScans?: Array<{ id?: string | number; created_at?: string; timestamp?: string; success?: boolean; repo?: string }>;
  taskProjects?: Array<{ id?: string | number; name?: string; type?: string }>;
  periodChange?: {
    openIssues: PeriodChange;
    criticalHigh: PeriodChange;
    riskScore: PeriodChange | null;
    mttr: PeriodChange | null;
  } | null;
}

export type WidgetType =
  | "summary"
  | "severityDonut"
  | "severityBar"
  | "sourceBar"
  | "severityPills"
  | "riskGauge"
  | "trendSparkline"
  | "trendStacked"
  | "trendTable"
  | "agingBars"
  | "agingTable"
  | "mttrBars"
  | "mttrTable"
  | "repoBars"
  | "repoTable"
  | "topVulnsTable"
  | "topVulnsList"
  | "topVulnsAdvisory"
  | "scannerTable"
  | "scannerDonut"
  | "openVsClosed"
  | "criticalHighKpi"
  | "issueList"
  | "activityTimeline"
  | "containerBars"
  | "containerTable"
  | "assetMixDonut"
  | "teamTable"
  | "complianceScoreCard"
  | "reachabilityMatrix"
  | "ciScanFrequency"
  | "taskProjectsTable"
  | "text"
  | "slaCompliance"
  | "abcCompliance"
  | "cvssHeatmap";

export const WIDGET_DEFAULT_CONFIG: Record<WidgetType, Record<string, unknown>> = {
  summary: { variant: "default" },
  severityDonut: { size: 100 },
  severityBar: {},
  sourceBar: {},
  severityPills: {},
  riskGauge: { size: 120 },
  trendSparkline: { width: 280, height: 56 },
  trendStacked: { width: 560, height: 160, periodDays: 90 },
  trendTable: {},
  agingBars: { maxWidth: 200 },
  agingTable: {},
  mttrBars: {},
  mttrTable: {},
  repoBars: { maxRepos: 8 },
  repoTable: { limit: 25 },
  topVulnsTable: { limit: 25 },
  topVulnsList: { limit: 5 },
  topVulnsAdvisory: { limit: 30 },
  scannerTable: {},
  scannerDonut: { size: 100 },
  openVsClosed: {},
  criticalHighKpi: {},
  issueList: { limit: 100 },
  activityTimeline: { limit: 20 },
  containerBars: { maxContainers: 8 },
  containerTable: { limit: 25 },
  assetMixDonut: { size: 100 },
  teamTable: {},
  complianceScoreCard: { framework: "soc2" },
  reachabilityMatrix: {},
  ciScanFrequency: { periodDays: 30 },
  taskProjectsTable: {},
  text: { content: "" },
  slaCompliance: { criticalDays: 15, highDays: 35, mediumDays: 180, lowDays: 360 },
  abcCompliance: {},
  cvssHeatmap: { periodDays: 90, width: 560, height: 200 },
};

export const WIDGET_TYPE_LABELS: Record<WidgetType, string> = {
  summary: "Summary",
  severityDonut: "Severity donut",
  severityBar: "Severity bar",
  sourceBar: "Source distribution",
  severityPills: "Severity pills",
  riskGauge: "Risk gauge",
  trendSparkline: "Trend sparkline",
  trendStacked: "Severity trend (stacked)",
  trendTable: "Trend table",
  agingBars: "Aging bars",
  agingTable: "Aging table",
  mttrBars: "MTTR bars",
  mttrTable: "MTTR table",
  repoBars: "Repo risk bars",
  repoTable: "Repo table",
  topVulnsTable: "Top vulns table",
  topVulnsList: "Top vulns list",
  topVulnsAdvisory: "Advisory cards",
  scannerTable: "Scanner table",
  scannerDonut: "Scanner donut",
  openVsClosed: "Open vs closed",
  criticalHighKpi: "Critical & high KPI",
  issueList: "Issue list",
  activityTimeline: "Activity timeline",
  containerBars: "Container risk bars",
  containerTable: "Container table",
  assetMixDonut: "Asset mix donut",
  teamTable: "Teams table",
  complianceScoreCard: "Compliance score card",
  reachabilityMatrix: "Reachability matrix",
  ciScanFrequency: "CI scan frequency",
  taskProjectsTable: "Task projects",
  text: "Text",
  slaCompliance: "SLA compliance",
  abcCompliance: "ABC compliance",
  cvssHeatmap: "CVSS temporal heatmap",
};

export interface ReportValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateReportDefinition(
  definition: ReportDefinition,
  options?: { requireWidgetsPerCanvas?: boolean }
): ReportValidationResult {
  const errors: string[] = [];
  if (!definition.canvases.length) {
    errors.push("Report must have at least one page (canvas).");
  }
  const widgetIds = new Set<string>();
  for (const canvas of definition.canvases) {
    if (options?.requireWidgetsPerCanvas && canvas.widgets.length === 0) {
      errors.push(`Page "${canvas.name}" has no widgets.`);
    }
    for (const w of canvas.widgets) {
      if (widgetIds.has(w.id)) {
        errors.push(`Duplicate widget id: ${w.id}.`);
      }
      widgetIds.add(w.id);
    }
  }
  return {
    valid: errors.length === 0,
    errors,
  };
}
